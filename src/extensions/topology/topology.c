/*
 * topology.c - build full network topology of the 1905 nodes.
 *
 * Copyright (C) 2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>

#include <easy/easy.h>

#include "util.h"
#include "timer.h"
#include "cmdu.h"
#include "1905_tlvs.h"
#include "i1905_extension.h"


#define IEEE1905_OBJECT_TOPOLOGY	"ieee1905.topology"

static int topology_init(void **priv, struct i1905_context *ieee1905);
static int topology_exit(void *priv);


struct getter_context {
	atimer_t t;
	uint32_t tmo;
	int retry;
	uint8_t state;
	uint16_t request;
	void *module;
	void *node;
};

struct neighbor {
	time_t tsp;
	atimer_t ageout;
	struct list_head list;
	uint8_t macaddr[6];		/* 1905-al address */
	uint8_t ifmacaddr[6];		/* neighbor's interface */
	uint8_t local_ifmacaddr[6];	/* interface in this neighbor device */
	void *node;
};

struct non1905_device {
	struct list_head list;
	uint8_t macaddr[6];
	uint8_t ifmacaddr[6];
	uint8_t local_ifmacaddr[6];
	void *node;
};

struct node {
	struct getter_context *gt;
	int probed;				/* for selfnode, always = 1 */
	time_t tsp;
	uint8_t macaddr[6];
	int num_neighbor;
	int num_non1905_neighbor;
	struct list_head list;			/* next in probelist */
	struct list_head nbrlist;		/* list of 'struct neighbor' */
	struct list_head non1905_nbrlist;	/* list of 'struct non1905_device' */
};

struct net {
	int run;
	int num_nodes;
	struct list_head probelist;		/* list of struct node */
};

struct topology_private {
	void *module;
	uint16_t types[16];
	int num_types;
	int paused;
	atimer_t t;
	struct net *network;
	uint8_t alid[6];
	struct i1905_context ieee1905;
	struct ubus_context *ctx;
	struct ubus_object obj;
};


#define print_list(l,h,type)					\
do {								\
	type *__n;						\
	printf("%s { ", l);					\
	list_for_each_entry(__n, h, list) {			\
		printf(MACFMT", ", MAC2STR(__n->macaddr));	\
	}							\
	printf(" }\n");						\
} while(0)


static int topology_free_getter(struct node *dev);
static void topology_free_node(struct node *n);

int topology_send_cmdu(struct topology_private *priv, struct cmdu_buff *cmdu,
		       uint8_t *dst)
{
	uint16_t type = cmdu_get_type(cmdu);
	uint16_t mid = cmdu_get_mid(cmdu);

	return ieee1905_send_cmdu(&priv->ieee1905, dst, NULL, type, &mid,
				  cmdu->data, cmdu->datalen);
}

int topology_query(struct topology_private *priv, uint16_t cmdu_type,
		   struct node *dev, uint8_t *dst)
{
	uint32_t resp_timeout = 2; /* in seconds */
	struct getter_context *gt = dev->gt;
	struct cmdu_buff *req;
	uint16_t mid = 0;
	int ret = 0;


	req = cmdu_alloc_simple(cmdu_type, &mid);
	if (!req) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return -1;
	}

	/* fprintf(stderr, "topology: prepare CMDU 0x%04x --> " MACFMT "\n",
		cmdu_type, MAC2STR(dst)); */

	switch (cmdu_type) {
	case CMDU_TYPE_TOPOLOGY_QUERY:
		break;
	default:
		fprintf(stderr, "%s: Unexpected cmdu 0x%04x\n", __func__, cmdu_type);
		break;
	}

	cmdu_put_eom(req);
	ret = topology_send_cmdu(priv, req, dst);
	if (!ret) {
		gt->retry = 0;
		gt->tmo = resp_timeout * 1000;
		timer_set(&gt->t, gt->tmo);
	}

	cmdu_free(req);
	return ret;
}

int topology_del_node_from_network(struct topology_private *priv, struct node *r)
{
	struct node *n, *tmp1;

	list_for_each_entry_safe(n, tmp1, &priv->network->probelist, list) {
		if (!memcmp(n->macaddr, r->macaddr, 6)) {
			list_del(&n->list);
			topology_free_getter(n);
			topology_free_node(n);
			priv->network->num_nodes--;

			return 0;
		}
	}

	return 0;
}

void getter_timer_cb(atimer_t *t)
{
	struct getter_context *gt = container_of(t, struct getter_context, t);
	struct topology_private *p = (struct topology_private *)gt->module;
	struct node *dev = (struct node *)gt->node;
	int ret;


	ret = topology_query(p, gt->request, dev, dev->macaddr);
	if (ret) {
		if (gt->retry++ < 1) {
			timer_set(&gt->t, 500);
			return;
		}

		/* no topo-response from this node; remove it */
		topology_del_node_from_network(p, dev);
	}
}

int topology_alloc_getter(struct topology_private *p, struct node *dev)
{
	dev->gt = calloc(1, sizeof(struct getter_context));
	if (!dev->gt)
		return -1;

	timer_init(&dev->gt->t, getter_timer_cb);
	dev->gt->module = p;
	dev->gt->node = dev;

	return 0;
}

int topology_free_getter(struct node *dev)
{
	if (!dev->gt)
		return 0;

	timer_del(&dev->gt->t);
	dev->gt->node = NULL;
	dev->gt->module = NULL;
	free(dev->gt);
	dev->gt = NULL;

	return 0;
}

int topology_sched_getter(struct topology_private *p, struct node *n,
			  uint16_t cmdutype, uint32_t after_ms)
{
	n->gt->request = cmdutype;
	return timer_set(&n->gt->t, after_ms);
}

struct node *topology_lookup_node(uint8_t *macaddr, struct list_head *list)
{
	struct node *n;

	list_for_each_entry(n, list, list) {
		if (!memcmp(n->macaddr, macaddr, 6)) {
			return n;
		}
	}

	return NULL;
}

struct node *topology_alloc_node(uint8_t *macaddr)
{
	struct node *n;

	if (!macaddr || hwaddr_is_zero(macaddr))
		return NULL;

	n = calloc(1, sizeof(*n));
	if (!n)
		return NULL;

	memcpy(n->macaddr, macaddr, 6);
	INIT_LIST_HEAD(&n->nbrlist);
	INIT_LIST_HEAD(&n->non1905_nbrlist);
	return n;
}

static void topology_free_neighbor(struct neighbor *n)
{
	timer_del(&n->ageout);
	n->node = NULL;
	free(n);
}

void topology_free_neighbors_of_node(struct node *n)
{
	struct neighbor *d, *tmp;

	if (!n)
		return;

	list_for_each_entry_safe(d, tmp, &n->nbrlist, list) {
		list_del(&d->list);
		topology_free_neighbor(d);
	}

	n->num_neighbor = 0;
}

void topology_free_non1905_neighbors_of_node(struct node *n)
{
	struct non1905_device *d, *tmp;

	if (!n)
		return;

	list_for_each_entry_safe(d, tmp, &n->non1905_nbrlist, list) {
		list_del(&d->list);
		d->node = NULL;
		free(d);
	}

	n->num_non1905_neighbor = 0;
}

void topology_free_node(struct node *n)
{
	if (n) {
		topology_free_non1905_neighbors_of_node(n);
		topology_free_neighbors_of_node(n);
		free(n);
	}
}

struct neighbor *topology_lookup_neighbor(uint8_t *macaddr, struct list_head *list)
{
	struct neighbor *n;

	list_for_each_entry(n, list, list) {
		if (!memcmp(n->macaddr, macaddr, 6)) {
			return n;
		}
	}

	return NULL;
}

void ageout_neighbor_cb(atimer_t *t)
{
	struct neighbor *n = container_of(t, struct neighbor, ageout);
	struct node *nn = n->node;

	list_del(&n->list);
	nn->num_neighbor--;
	topology_free_neighbor(n);
}

struct neighbor *topology_alloc_neighbor(uint8_t *macaddr)
{
	struct neighbor *n;

	if (!macaddr || hwaddr_is_zero(macaddr))
		return NULL;

	n = calloc(1, sizeof(*n));
	if (!n)
		return NULL;

	memcpy(n->macaddr, macaddr, 6);
	timer_init(&n->ageout, ageout_neighbor_cb);
	time(&n->tsp);

	return n;
}

struct non1905_device *topology_alloc_non1905_neighbor(uint8_t *macaddr)
{
	struct non1905_device *n;

	if (!macaddr || hwaddr_is_zero(macaddr))
		return NULL;

	n = calloc(1, sizeof(*n));
	if (!n)
		return NULL;

	memcpy(n->macaddr, macaddr, 6);
	return n;
}

struct net *topology_alloc_net(void)
{
	struct net *n = calloc(1, sizeof(*n));

	if (!n)
		return NULL;

	INIT_LIST_HEAD(&n->probelist);
	n->num_nodes = 0;
	n->run = 1;

	return n;
}

struct topology_private *alloc_topology(void)
{
	struct topology_private *p;

	p = calloc(1, sizeof(*p));
	if (!p)
		return NULL;

	p->network = topology_alloc_net();
	if (!p->network) {
		free(p);
		return NULL;
	}

	return p;
}

int topology_alloc_root_node(struct topology_private *priv, uint8_t *aladdr)
{
	struct node *rn;

	rn = topology_alloc_node(aladdr);
	if (!rn)
		return -1;

	rn->probed = 1;
	time(&rn->tsp);
	list_add_tail(&rn->list, &priv->network->probelist);
	priv->network->num_nodes++;
	return 0;
}

int topology_net_add_nodes(struct topology_private *priv, struct node *p)
{
	struct net *network = priv->network;
	struct neighbor *e;
	struct node *n;
	int num_nodes = network->num_nodes;

	list_for_each_entry(e, &p->nbrlist, list) {
		int in_probelist = 0;

		list_for_each_entry(n, &network->probelist, list) {
			if (!memcmp(e->macaddr, n->macaddr, 6)) {
				in_probelist = 1;
				break;
			}
		}

		if (!in_probelist) {
			struct node *q = topology_alloc_node(e->macaddr);

			if (q) {
				topology_alloc_getter(priv, q);
				list_add_tail(&q->list, &network->probelist);
				network->num_nodes++;
			}
		}
	}

	if (num_nodes != network->num_nodes)
		return 1;

	return 0;
}

int topology_probe_nodes(void *arg, const char *ifname)
{
	struct topology_private *p = (struct topology_private *)arg;
	struct node *n = NULL;
	int ret = 0;
	time_t now;

	time(&now);
	list_for_each_entry(n, &p->network->probelist, list) {
		if (n->probed)
			continue;

		if (difftime(now, n->tsp) < 30)
			continue;

		ret |= topology_sched_getter(p, n, CMDU_TYPE_TOPOLOGY_QUERY, 1000);
	}

	return ret;
}

int topology_add_nbrlist_for_node(struct node *n, uint8_t *n_local_macaddr,
				  uint8_t *macaddrs, int num)
{
	int i;

	for (i = 0; i < num; i++) {
		struct neighbor *e = topology_alloc_neighbor(&macaddrs[i*6]);
		if (!e) {
			fprintf(stderr, "%s: -ENOMEM\n", __func__);
			return -1;
		}

		memcpy(e->local_ifmacaddr, n_local_macaddr, 6);
		e->node = n;
		timer_set(&e->ageout, 62000);
		list_add_tail(&e->list, &n->nbrlist);
		n->num_neighbor++;
	}

	return 0;
}

int topology_add_non1905_nbrlist_for_node(struct node *n,
					  uint8_t *xnbr_local_macaddr,
					  uint8_t *macaddrs, int num)
{
	int i;

	for (i = 0; i < num; i++) {
		struct non1905_device *e = topology_alloc_non1905_neighbor(&macaddrs[i*6]);
		if (!e) {
			fprintf(stderr, "%s: -ENOMEM\n", __func__);
			return -1;
		}

		memcpy(e->local_ifmacaddr, xnbr_local_macaddr, 6);
		e->node = n;
		list_add_tail(&e->list, &n->non1905_nbrlist);
		n->num_non1905_neighbor++;
	}

	return 0;
}

int topology_update_non1905_nbrlist_for_selfnode(struct topology_private *priv)
{
	struct i1905_non1905_ifneighbor *ent;
	struct node *selfnode;
	size_t sz = 1024;
	uint8_t buf[sz];
	int pos = 0;
	int ret;


	selfnode = list_first_entry(&priv->network->probelist, struct node, list);
	topology_free_non1905_neighbors_of_node(selfnode);

	ret = ieee1905_get_non1905_neighbors(&priv->ieee1905, buf, &sz);
	if (ret && errno == -E2BIG) {
		fprintf(stderr, "%s: required bufsize = %zu\n", __func__, sz);	//TODO
		return -1;
	}

	while (pos < sz) {
		ent = (struct i1905_non1905_ifneighbor *)&buf[pos];
		ret = topology_add_non1905_nbrlist_for_node(selfnode,
							    ent->if_macaddr,
							    &ent->non1905_macaddr[0],
							    ent->num_non1905);
		if (ret)
			break;

		pos += sizeof(struct i1905_non1905_ifneighbor) + ent->num_non1905 * 6;
	}

	return 0;
}

int topology_process_topology_response(struct topology_private *priv, struct cmdu_buff *cmdu)
{
	struct tlv_policy pol[] = {
		[0] = { .type = TLV_TYPE_DEVICE_INFORMATION_TYPE, .present = TLV_PRESENT_ONE },
		[1] = { .type = TLV_TYPE_NEIGHBOR_DEVICE_LIST, .present = TLV_PRESENT_OPTIONAL_MORE },
		[2] = { .type = TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST, .present = TLV_PRESENT_OPTIONAL_MORE },
	};
	struct tlv_device_info *devinfo;
	uint8_t aladdr[6] = {0};
	struct tlv *tv[3][16];
	struct node *e;
	int ret;


	/* fprintf(stderr, "%s: rx-ifname = '%s'\n", __func__, cmdu->dev_ifname); */
	ret = cmdu_parse_tlvs(cmdu, tv, pol, 3);
	if (ret)
		return -1;

	if (!tv[0][0]) {
		fprintf(stderr, "Error! missing TLV DEVICE_INFORMATION_TYPE\n");
		return -1;
	}

	devinfo = (struct tlv_device_info *)tv[0][0]->data;
	if (hwaddr_is_zero(devinfo->aladdr))
		return -1;

	if (hwaddr_is_zero(devinfo->aladdr)) {
		fprintf(stderr, "%s: Discard topology response from aladdr = 00:00..\n", __func__);
		return -1;
	}

	if (hwaddr_equal(priv->alid, devinfo->aladdr)) {
		fprintf(stderr, "%s: Ignore topology response from self\n", __func__);
		return 0;
	}

	memcpy(aladdr, devinfo->aladdr, 6);
	e = topology_lookup_node(aladdr, &priv->network->probelist);
	if (e) {
		topology_free_neighbors_of_node(e);
		topology_free_non1905_neighbors_of_node(e);
	} else {
		e = topology_alloc_node(aladdr);
		if (!e) {
			fprintf(stderr, "%s: -ENOMEM\n", __func__);
			return -1;
		}

		topology_alloc_getter(priv, e);
		list_add_tail(&e->list, &priv->network->probelist);
		priv->network->num_nodes++;
	}

	/* update neighbor list */
	if (tv[1][0]) {
		int num = 0;

		while (tv[1][num]) {
			struct tlv *t = tv[1][num];
			struct tlv_1905neighbor *nbr = (struct tlv_1905neighbor *)t->data;
			uint8_t nbr_local_macaddr[6] = {0};
			uint16_t rlen = tlv_length(t);
			uint8_t nbrlist[rlen];
			int n = 0;


			memcpy(nbr_local_macaddr, nbr->local_macaddr, 6);
			rlen -= 6;

			memset(nbrlist, 0, rlen);
			while (rlen >= sizeof(struct i1905_neighbor)) {
				memcpy(&nbrlist[n * 6], nbr->nbr[n].aladdr, 6);
				rlen -= sizeof(struct i1905_neighbor);
				n++;
			}

			ret = topology_add_nbrlist_for_node(e,
							    nbr_local_macaddr,
							    nbrlist,
							    n);
			num++;
		}

#if 1	//debug
	char label[64] = {0};

	sprintf(label, "%s " MACFMT " =  ", "NEIGHBOR-LIST of", MAC2STR(e->macaddr));
	print_list(label, &e->nbrlist, struct neighbor);
#endif
	}

	/* update non-1905 neighbor list */
	if (tv[2][0]) {
		int num = 0;

		while (tv[2][num]) {
			struct tlv *t = tv[2][num];
			struct tlv_non1905_neighbor *xnbr =
					(struct tlv_non1905_neighbor *)t->data;
			uint8_t xnbr_local_macaddr[6] = {0};
			uint16_t rlen = tlv_length(t);
			uint8_t xnbrlist[rlen];
			int n = 0;


			memcpy(xnbr_local_macaddr, xnbr->local_macaddr, 6);
			rlen -= 6;

			memset(xnbrlist, 0, rlen);
			while (rlen >= sizeof(struct non1905_neighbor)) {
				memcpy(&xnbrlist[n * 6], xnbr->non1905_nbr[n].macaddr, 6);
				rlen -= sizeof(struct non1905_neighbor);
				n++;
			}

			ret = topology_add_non1905_nbrlist_for_node(e,
								    xnbr_local_macaddr,
								    xnbrlist,
								    n);
			num++;
		}

#if 1	//debug
	char label2[64] = {0};

	sprintf(label2, "%s " MACFMT " =  ", "NON-1905 NEIGHBOR-LIST of", MAC2STR(e->macaddr));
	print_list(label2, &e->non1905_nbrlist, struct non1905_device);
#endif
	}

	time(&e->tsp);
	priv->network->run = topology_net_add_nodes(priv, e);

	return ret;
}

int topology_update_nbrlist_for_selfnode(struct node *self, uint8_t *ifmacaddr,
					 uint8_t *nbr_aladdr, uint8_t *nbr_ifmacaddr)
{
	struct neighbor *d, *tmp;
	struct neighbor *e;


	list_for_each_entry_safe(d, tmp, &self->nbrlist, list) {
	       if (!memcmp(d->macaddr, nbr_aladdr, 6)) {
			/* update link's macaddresses */
			memcpy(d->local_ifmacaddr, nbr_ifmacaddr, 6);
			memcpy(d->ifmacaddr, ifmacaddr, 6);
			timer_set(&d->ageout, 62000);

			return 0;
	       }
	}

	e = topology_alloc_neighbor(nbr_aladdr);
	if (!e) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return -1;
	}

	memcpy(e->local_ifmacaddr, nbr_ifmacaddr, 6);
	memcpy(e->ifmacaddr, ifmacaddr, 6);
	e->node = self;
	list_add_tail(&e->list, &self->nbrlist);
	self->num_neighbor++;
	timer_set(&e->ageout, 62000);

	return 0;
}

int topology_process_topology_discovery(struct topology_private *priv, struct cmdu_buff *cmdu)
{
	struct tlv_policy pol[] = {
		[0] = { .type = TLV_TYPE_AL_MAC_ADDRESS_TYPE, .present = TLV_PRESENT_ONE },
		[1] = { .type = TLV_TYPE_MAC_ADDRESS_TYPE, .present = TLV_PRESENT_ONE },
	};
	struct node *e, *selfnode;
	uint8_t ifmacaddr[6] = {0};
	uint8_t aladdr[6] = {0};
	struct tlv *tv[2][16];
	int ret;


	ret = cmdu_parse_tlvs(cmdu, tv, pol, 2);
	if (ret) {
		fprintf(stdout, "%s: Error! cmdu_parse_tlvs()\n", __func__);
		return -1;
	}

	if (!tv[0][0] || !tv[1][0]) {
		fprintf(stdout, "%s: Error! missing TLV(s) in topology discovery\n", __func__);
		return -1;
	}

	memcpy(aladdr, tv[0][0]->data, tlv_length(tv[0][0]));
	memcpy(ifmacaddr, tv[1][0]->data, tlv_length(tv[1][0]));
	if (hwaddr_is_zero(aladdr)) {
		fprintf(stdout, "%s: Invalid topology discovery: aladdr = " MACFMT "\n",
		    __func__, MAC2STR(aladdr));
		return -1;
	}

	/* getting topology-discovery from selfdevice through 'lo' */
	if (!memcmp(priv->alid, aladdr, 6)) {
		fprintf(stdout, "%s: Ignore topology discovery from self\n", __func__);
		return 0;
	}

	fprintf(stdout, "%s: RECEIVED Topology Discovery from " MACFMT " on = '%s'\n", __func__,
		MAC2STR(aladdr), cmdu->dev_ifname);

	selfnode = list_first_entry(&priv->network->probelist, struct node, list);
	ret = topology_update_nbrlist_for_selfnode(selfnode, cmdu->dev_macaddr,
						   aladdr, ifmacaddr);

	e = topology_lookup_node(aladdr, &priv->network->probelist);
	if (!e) {
		fprintf(stdout, "%s: ADDING " MACFMT " to probelist\n", __func__, MAC2STR(aladdr));
		e = topology_alloc_node(aladdr);
		if (!e) {
			fprintf(stderr, "%s: -ENOMEM\n", __func__);
			return -1;
		}

		topology_alloc_getter(priv, e);
		list_add_tail(&e->list, &priv->network->probelist);
		priv->network->num_nodes++;
	}

	time(&e->tsp);
	return ret;
}

void refresh_timer_cb(atimer_t *t)
{
	struct topology_private *p = container_of(t, struct topology_private, t);


	topology_update_non1905_nbrlist_for_selfnode(p);
	topology_probe_nodes(p, NULL);

	timer_set(t, 5000);
}

int topology_recv_cmdu(void *priv, struct cmdu_buff *frm)
{
	struct topology_private *p = (struct topology_private *)priv;

	if (!p->ctx || !frm)
		return -1;

	if (!p->paused) {
		uint16_t cmdutype = cmdu_get_type(frm);

		switch (cmdutype) {
		case CMDU_TYPE_TOPOLOGY_DISCOVERY:
			topology_process_topology_discovery(p, frm);
			break;
		case CMDU_TYPE_TOPOLOGY_RESPONSE:
			topology_process_topology_response(p, frm);
			break;
		default:
			break;
		}
	}

	return CMDU_OK;
}

int topology_start(void *priv)
{
	struct topology_private *p = (struct topology_private *)priv;

	p->paused = 0;
	timer_set(&p->t, 1000);

	return 0;
}

int topology_stop(void *priv)
{
	struct topology_private *p = (struct topology_private *)priv;

	timer_del(&p->t);
	p->paused = 1;

	return 0;
}

struct i1905_cmdu_extension i1905_topology_sub[] = {
	{ .type = CMDU_TYPE_TOPOLOGY_RESPONSE, .policy = EXTMODULE_CMDU_OVERRIDE },
	{ .type = CMDU_TYPE_TOPOLOGY_DISCOVERY },
};

extern struct i1905_extmodule topology;
struct i1905_extmodule topology = {
	.id = "\x10\x20\x30\x40",
	.name = "topology",
	.init = topology_init,
	.exit = topology_exit,
	.start = topology_start,
	.stop = topology_stop,
	.ext = i1905_topology_sub,
	.num_ext = sizeof(i1905_topology_sub)/sizeof(i1905_topology_sub[0]),
	.process_cmdu = topology_recv_cmdu,
};

int topology_show(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct topology_private *p = container_of(obj, struct topology_private, obj);
	struct non1905_device *non;
	void *a, *aa, *aaa, *aaaa;
	struct blob_buf bb = {0};
	struct neighbor *nbr;
	struct node *n;


	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);

	blobmsg_add_u32(&bb, "num_nodes", p->network->num_nodes);
	a = blobmsg_open_array(&bb, "nodes");
	list_for_each_entry(n, &p->network->probelist, list) {
		char n_macstr[18] = {0};
		char nbr_macstr[18] = {0};

		aa = blobmsg_open_table(&bb, "");
		hwaddr_ntoa(n->macaddr, n_macstr);
		blobmsg_add_string(&bb, "macaddress", n_macstr);
		blobmsg_add_u32(&bb, "num_neighbors", n->num_neighbor);
		blobmsg_add_u32(&bb, "num_non1905_neighbors", n->num_non1905_neighbor);

		aaa = blobmsg_open_array(&bb, "neighbors");
		list_for_each_entry(nbr, &n->nbrlist, list) {
			char nbr_lifmacstr[18] = {0};

			aaaa = blobmsg_open_table(&bb, "");
			hwaddr_ntoa(nbr->macaddr, nbr_macstr);
			hwaddr_ntoa(nbr->local_ifmacaddr, nbr_lifmacstr);

			blobmsg_add_string(&bb, "macaddress", nbr_macstr);
			blobmsg_add_string(&bb, "via", nbr_lifmacstr);
			blobmsg_close_table(&bb, aaaa);
		}
		blobmsg_close_array(&bb, aaa);

		aaa = blobmsg_open_array(&bb, "non1905_neighbors");
		list_for_each_entry(non, &n->non1905_nbrlist, list) {
			char xnbr_lifmacstr[18] = {0};

			aaaa = blobmsg_open_table(&bb, "");
			hwaddr_ntoa(non->macaddr, nbr_macstr);
			hwaddr_ntoa(non->local_ifmacaddr, xnbr_lifmacstr);

			blobmsg_add_string(&bb, "macaddress", nbr_macstr);
			blobmsg_add_string(&bb, "via", xnbr_lifmacstr);
			blobmsg_close_table(&bb, aaaa);
		}
		blobmsg_close_array(&bb, aaa);

		blobmsg_close_table(&bb, aa);
	}
	blobmsg_close_array(&bb, a);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

void topology_create_dotfile(struct net *root)
{
	struct node *p;
	struct neighbor *n;
	FILE *f;
	char fstr[] = "digraph G {\n"
			"concentrate=true\n";

	f = fopen("/tmp/topo.dot", "w+");
	if (!f) {
		printf("failed to open file topo.dot\n");
		return;
	}

	fprintf(f, "%s", fstr);
	if (root->num_nodes == 1) {
		p = list_first_entry(&root->probelist, struct node, list);
		fprintf(f, "\t\"" MACFMT "\"\n", MAC2STR(p->macaddr));
	} else {
		list_for_each_entry(p, &root->probelist, list) {
			list_for_each_entry(n, &p->nbrlist, list) {
				fprintf(f, "\t\"" MACFMT "\"-> " "\"" MACFMT "\"[taillabel=\"" MACFMT "\"];\n",
					MAC2STR(p->macaddr), MAC2STR(n->macaddr),
					MAC2STR(n->local_ifmacaddr));
			}
		}
	}

	fprintf(f, "}\n");
	fclose(f);
}

int topology_dot(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct topology_private *p = container_of(obj, struct topology_private, obj);

	topology_create_dotfile(p->network);
	return 0;
}

int topology_publish_object(void *priv, const char *objname)
{
	struct ubus_object *obj;
	struct ubus_object_type *obj_type;
	struct ubus_method *obj_methods;
	struct ubus_method m[2] = {
		UBUS_METHOD_NOARG("show", topology_show),
		UBUS_METHOD_NOARG("dot", topology_dot),
	};
	int num_methods = ARRAY_SIZE(m);
	struct topology_private *p = (struct topology_private *)priv;
	int ret;


	obj = &p->obj;
	memset(obj, 0, sizeof(*obj));
	obj_type = calloc(1, sizeof(struct ubus_object_type));
	if (!obj_type)
		return -1;

	obj_methods = calloc(num_methods, sizeof(struct ubus_method));
	if (!obj_methods) {
		free(obj_type);
		return -1;
	}

	obj->name = strdup(objname);
	memcpy(obj_methods, m, num_methods * sizeof(struct ubus_method));
	obj->methods = obj_methods;
	obj->n_methods = num_methods;

	obj_type->name = obj->name;
	obj_type->n_methods = obj->n_methods;
	obj_type->methods = obj->methods;
	obj->type = obj_type;

	ret = ubus_add_object(p->ctx, obj);
	if (ret) {
		fprintf(stderr, "Failed to add '%s' (err = %s)\n",
			objname, ubus_strerror(ret));

		free(obj_methods);
		free(obj_type);

		return ret;
	}

	fprintf(stderr, "Added UBUS object '%s'\n", objname);

	return 0;
}

void topology_remove_object(void *priv)
{
	struct topology_private *p = (struct topology_private *)priv;

	if (p && p->ctx) {
		if (p->obj.id != -1) {
			ubus_remove_object(p->ctx, &p->obj);
			free(p->obj.type);
			free((void *)p->obj.methods);
			free((void *)p->obj.name);
		}
	}
}

int topology_init(void **priv, struct i1905_context *ieee1905)
{
	struct topology_private *p;
	uint8_t aladdr[6] = {0};
	int ret;


	p = calloc(1, sizeof(struct topology_private));
	if (!p)
		return -1;

	*priv = p;
	p->module = &topology;
	if (ieee1905) {
		p->ctx = ieee1905->bus;
		memcpy(&p->ieee1905, ieee1905, sizeof(struct i1905_context));
	}

	timer_init(&p->t, refresh_timer_cb);
	ret = ieee1905_get_alid(ieee1905, aladdr);
	if (ret)
		return -1;

	fprintf(stderr, "%s: 1905 ALID: " MACFMT "\n", __func__, MAC2STR(aladdr));
	memcpy(p->alid, aladdr, 6);
	p->network = topology_alloc_net();
	if (!p->network)
		return -1;

	topology_alloc_root_node(p, aladdr);
	topology_publish_object(p, IEEE1905_OBJECT_TOPOLOGY);
	timer_set(&p->t, 1000);

	return 0;
}

static int topology_exit(void *priv)
{
	struct topology_private *p = (struct topology_private *)priv;

	if (p) {
		topology_remove_object(p);
		free(p);
	}

	return 0;
}
