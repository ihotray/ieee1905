/*
 * i1905_dm.c - IEEE-1905 datamodel related functions.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>

#include <easy/easy.h>


#include "debug.h"
#include "timer.h"
#include "util.h"
#include "bufutil.h"
#include "cmdu.h"
#include "cmdu_ackq.h"
#include "cmdufrag.h"
#include "config.h"
#include "i1905_dm.h"
#include "i1905.h"

#include "1905_tlvs.h"

#define I1905_IFLINK_AGEOUT                     65000	/* msecs */
#define I1905_NEIGHBOR_AGEOUT                   70000	/* msecs */
#define I1905_IMMEDIATE_NEIGHBOR_AGEOUT         65000	/* msecs */


#define prlink(m,a,b,c,d)	\
	dbg("%s: %s {" MACFMT ", " MACFMT " ---- " MACFMT ", " MACFMT "}\n", \
	    __func__, m, MAC2STR(a), MAC2STR(b), MAC2STR(c), MAC2STR(d));


static void i1905_dm_interface_peer_staletimer_cb(atimer_t *t)
{
	struct i1905_neighbor_interface *ifpeer =
		container_of(t, struct i1905_neighbor_interface, staletimer);
	struct i1905_interface *iface = ifpeer->iface;


	if (!iface) {
		err("link ageout: iface = NULL!\n");
		return;
	}

	dbg("%s: Deleting link " MACFMT " <---> " MACFMT"\n", __func__,
	    MAC2STR(iface->macaddr), MAC2STR(ifpeer->macaddr));

	/* only interfaces belonging to selfdevice have non-null priv */
	if (iface->priv && iface->device) {
		struct i1905_private *priv = i1905_selfdevice_to_context(iface->device);

		i1905_extmodules_notify(priv, IEEE1905_LINK_REMOVED,
					iface->aladdr,
					iface->macaddr,
					ifpeer->aladdr,
					ifpeer->macaddr,
					1);
	}

	list_del(&ifpeer->list);
	iface->num_links--;
	free(ifpeer);
}

struct i1905_bridge_tuple *i1905_dm_neighbor_brtuple_create(int num_macaddr)
{
	struct i1905_bridge_tuple *br;

	br = calloc(1, sizeof(*br) + 6 * num_macaddr);
	if (!br) {
		fprintf(stderr, "-ENOMEM\n");
		return NULL;
	}

	br->macaddrs = (uint8_t *)(br + 1);

	return br;
}

struct i1905_net_non1905_neighbor *i1905_dm_neighbor_non1905_nbr_create(void)
{
	struct i1905_net_non1905_neighbor *xnbr;

	xnbr = calloc(1, sizeof(*xnbr));
	if (!xnbr) {
		fprintf(stderr, "-ENOMEM\n");
		return NULL;
	}

	return xnbr;
}

int i1905_dm_neighbor_get_non1905_neighbors(struct i1905_device *rdev, uint8_t *macaddrs)
{
	struct i1905_interface *rif;
	int i = 0;

	list_for_each_entry(rif, &rdev->iflist, list) {
		struct i1905_net_non1905_neighbor *non;

		if (list_empty(&rif->non1905_nbrlist))
			continue;

		list_for_each_entry(non, &rif->non1905_nbrlist, list) {
			memcpy(&macaddrs[i*6], non->macaddr, 6);
			i++;
		}
	}

	return 0;
}

struct i1905_device *i1905_get_neigh_device(struct i1905_interface *iface,
					    uint8_t *aladdr)
{
	struct i1905_selfdevice *self = (struct i1905_selfdevice *)iface->device;
	struct i1905_device *rdev = NULL;

	list_for_each_entry(rdev, &self->topology.devlist, list) {
		if (hwaddr_equal(rdev->aladdr, aladdr)) {
			return rdev;
		}
	}

	return NULL;
}

struct i1905_device *i1905_dm_neighbor_lookup(struct i1905_interface *iface,
					      uint8_t *aladdr)
{
	struct i1905_selfdevice *self = (struct i1905_selfdevice *)iface->device;
	struct i1905_device *rdev = NULL;


	list_for_each_entry(rdev, &self->topology.devlist, list) {
		if (hwaddr_equal(rdev->aladdr, aladdr)) {
			/* reset ageout */
			timer_set(&rdev->agetimer, I1905_NEIGHBOR_AGEOUT);
			return rdev;
		}
	}

	return NULL;
}

struct i1905_neighbor_interface *i1905_link_create(struct i1905_interface *iface)
{
	struct i1905_neighbor_interface *ifpeer;

	ifpeer = calloc(1, sizeof(*ifpeer));
	if (!ifpeer) {
		fprintf(stderr, "-ENOMEM\n");
		return NULL;
	}

	ifpeer->iface = iface;
	ifpeer->tsp = time(NULL);
	timer_init(&ifpeer->staletimer, i1905_dm_interface_peer_staletimer_cb);
	timer_set(&ifpeer->staletimer, I1905_IFLINK_AGEOUT);
	ifpeer->media = I1905_MEDIA_UNKNOWN;
	ifpeer->has_bridge = true;

	return ifpeer;
}

struct i1905_ipv4 *i1905_dm_ipv4_create(void)
{
	struct i1905_ipv4 *ip;

	ip = calloc(1, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "-ENOMEM\n");
		return NULL;
	}

	return ip;
}

struct i1905_ipv6 *i1905_dm_ipv6_create(void)
{
	struct i1905_ipv6 *ip;

	ip = calloc(1, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "-ENOMEM\n");
		return NULL;
	}

	return ip;
}

struct i1905_neighbor_interface *i1905_link_neighbor_interface_lookup(struct i1905_interface *iface,
								      uint8_t *ifpeer_macaddr)
{
	struct i1905_neighbor_interface *ifpeer = NULL;

	list_for_each_entry(ifpeer, &iface->nbriflist, list) {
		if (hwaddr_equal(ifpeer->macaddr, ifpeer_macaddr)) {
			ifpeer->tsp = time(NULL);
			timer_set(&ifpeer->staletimer, I1905_IFLINK_AGEOUT);
			return ifpeer;
		}
	}

	return NULL;
}

struct i1905_neighbor_interface *i1905_link_neighbor_lookup(struct i1905_interface *iface,
							    uint8_t *macaddr)
{
	struct i1905_neighbor_interface *ifpeer = NULL;

	list_for_each_entry(ifpeer, &iface->nbriflist, list) {
		prlink("Lookup link", ifpeer->aladdr, ifpeer->macaddr, iface->macaddr, iface->aladdr);

		if (hwaddr_equal(ifpeer->macaddr, macaddr) ||
		    hwaddr_equal(ifpeer->aladdr, macaddr)) {

			ifpeer->tsp = time(NULL);
			timer_set(&ifpeer->staletimer, I1905_IFLINK_AGEOUT);
			return ifpeer;
		}
	}

	return NULL;
}

struct i1905_interface *i1905_dm_neighbor_interface_create(void)
{
	struct i1905_interface *rif;

	rif = calloc(1, sizeof(*rif));
	if (!rif) {
		fprintf(stderr, "-ENOMEM\n");
		return NULL;
	}

	INIT_LIST_HEAD(&rif->vendorlist);
	INIT_LIST_HEAD(&rif->nbriflist);
	INIT_LIST_HEAD(&rif->non1905_nbrlist);
	//INIT_LIST_HEAD(&rif->iflinklist);

	return rif;
}

void i1905_free_all_non1905_nbrs_of_neighbor(struct i1905_interface *iface, uint8_t *aladdr)
{
	struct i1905_device *dev;

	dev = i1905_dm_neighbor_lookup(iface, aladdr);
	if (dev) {
		struct i1905_interface *rif;

		list_for_each_entry(rif, &dev->iflist, list) {
			list_flush(&rif->non1905_nbrlist, struct i1905_net_non1905_neighbor, list);
			dev->num_neighbor_non1905 -= rif->num_neighbor_non1905;
			rif->num_neighbor_non1905 = 0;
		}
	}
}

void i1905_free_interface_links(struct i1905_interface *iface)
{
	struct i1905_neighbor_interface *ifpeer, *tmp;


	/* stop link timers and free links */
	list_for_each_entry_safe(ifpeer, tmp, &iface->nbriflist, list) {
		if (timer_pending(&ifpeer->staletimer))
			timer_del(&ifpeer->staletimer);

		/* notify link event only for links belonging to selfdevice */
		if (iface->priv && iface->device) {
			struct i1905_private *priv = i1905_selfdevice_to_context(iface->device);

			i1905_extmodules_notify(priv, IEEE1905_LINK_REMOVED,
						iface->aladdr,
						iface->macaddr,
						ifpeer->aladdr,
						ifpeer->macaddr,
						0);
		}

		list_del(&ifpeer->list);
		free(ifpeer);
	}

	iface->num_links = 0;
}


void i1905_invalidate_links(struct i1905_interface *iface)
{
	struct i1905_neighbor_interface *link;

	list_for_each_entry(link, &iface->nbriflist, list) {
		link->invalid = true;
		prlink("Invalidate link", link->aladdr, link->macaddr, iface->macaddr, iface->aladdr);
	}
}

void i1905_free_invalid_links(struct i1905_interface *iface)
{
	struct i1905_neighbor_interface *link, *tmp;


	list_for_each_entry_safe(link, tmp, &iface->nbriflist, list) {
		if (!link->invalid)
			continue;

		if (timer_pending(&link->staletimer))
			timer_del(&link->staletimer);

		prlink("Free invalid link", link->aladdr, link->macaddr, iface->macaddr, iface->aladdr);
		if (iface->priv && iface->device) {
			struct i1905_private *priv = i1905_selfdevice_to_context(iface->device);

			i1905_extmodules_notify(priv, IEEE1905_LINK_REMOVED,
						iface->aladdr,
						iface->macaddr,
						link->aladdr,
						link->macaddr,
						0);
		}

		list_del(&link->list);
		iface->num_links--;
		free(link);
	}
}

void i1905_free_all_invalid_links(struct i1905_interface *iface, uint8_t *aladdr)
{
	struct i1905_device *dev;

	dev = i1905_dm_neighbor_lookup(iface, aladdr);
	if (dev) {
		struct i1905_interface *rif;
		int i = 0;

		list_for_each_entry(rif, &dev->iflist, list) {
			i1905_free_invalid_links(rif);
			dbg("Interface " MACFMT ", num-links = %d\n",
			    MAC2STR(rif->macaddr), rif->num_links);
			i += rif->num_links;
		}
		dev->num_neighbor_1905 = i;
	}
}

void i1905_dm_neighbor_interface_free(struct i1905_interface *iface)
{
	if (!iface)
		return;

	if (iface->mediainfo)
		free(iface->mediainfo);

	i1905_free_interface_links(iface);
	list_flush(&iface->vendorlist, struct i1905_vendor_info, list);
	list_flush(&iface->non1905_nbrlist, struct i1905_net_non1905_neighbor, list);

	free(iface);
}

void i1905_dm_neighbor_free(struct i1905_device *dev)
{
	struct i1905_interface *iface, *tmp;
	struct i1905_private *priv;

	if (!dev)
		return;

	priv = i1905_selfdevice_to_context(dev->dev);
	i1905_extmodules_notify(priv, IEEE1905_NBR_REMOVED, dev->aladdr);

	list_flush(&dev->ipv4list, struct i1905_ipv4, list);
	list_flush(&dev->ipv6list, struct i1905_ipv6, list);
	list_flush(&dev->vendorlist, struct i1905_vendor_info, list);
	//list_flush(&dev->l2_nbrlist, struct i1905_l2_neighbor, list);
	list_flush(&dev->brlist, struct i1905_bridge_tuple, list);

	list_for_each_entry_safe(iface, tmp, &dev->iflist, list) {
		list_del(&iface->list);
		dev->num_interface--;
		i1905_dm_neighbor_interface_free(iface);
	}

	free(dev);
}

static void i1905_dm_neighbor_agetimer_cb(atimer_t *t)
{
	struct i1905_device *rdev = container_of(t, struct i1905_device, agetimer);
	struct i1905_selfdevice *dev = rdev->dev;
	int i;

	if (timer_pending(&rdev->immediate_nbr_agetimer))
		timer_del(&rdev->immediate_nbr_agetimer);

	list_del(&rdev->list);
	dev->topology.num_devices--;

	/* clear netregistrar */
	for (i = 0; i < IEEE80211_FREQUENCY_BAND_NUM; i++) {
		if (hwaddr_equal(dev->netregistrar[i], rdev->aladdr))
			memset(dev->netregistrar[i], 0, 6);
	}

	dbg("free neighbor device " MACFMT "\n", MAC2STR(rdev->aladdr));
	i1905_dm_neighbor_free(rdev);
}

static void i1905_dm_immediate_neighbor_agetimer_cb(atimer_t *t)
{
	struct i1905_device *rdev = container_of(t, struct i1905_device, immediate_nbr_agetimer);
	struct i1905_neighbor_interface *link = NULL;
	struct i1905_selfdevice *self = rdev->dev;
	struct i1905_interface *iface;

	dbg("invalidate immediate neighbor " MACFMT "\n", MAC2STR(rdev->aladdr));
	rdev->is_immediate_neighbor = 0;

	list_for_each_entry(iface, &self->iflist, list) {
		list_for_each_entry(link, &iface->nbriflist, list) {
			if (hwaddr_equal(link->aladdr, rdev->aladdr)) {
				if (link->direct)
					link->direct = false;
			}
		}
	}
}

struct i1905_device *i1905_dm_neighbor_create(void)
{
	struct i1905_device *rdev;

	rdev = calloc(1, sizeof(*rdev));
	if (!rdev) {
		fprintf(stderr, "-ENOMEM\n");
		return NULL;
	}

	INIT_LIST_HEAD(&rdev->ipv4list);
	INIT_LIST_HEAD(&rdev->ipv6list);
	INIT_LIST_HEAD(&rdev->vendorlist);
	INIT_LIST_HEAD(&rdev->iflist);
	//INIT_LIST_HEAD(&rdev->non1905_nbrlist);
	INIT_LIST_HEAD(&rdev->l2_nbrlist);
	INIT_LIST_HEAD(&rdev->brlist);
	//INIT_LIST_HEAD(&rdev->reglist);

	timer_init(&rdev->agetimer, i1905_dm_neighbor_agetimer_cb);
	timer_set(&rdev->agetimer, I1905_NEIGHBOR_AGEOUT);
	timer_init(&rdev->immediate_nbr_agetimer, i1905_dm_immediate_neighbor_agetimer_cb);

	return rdev;
}

#if 0
struct i1905_neighbor_interface *i1905_dm_link_lookup(struct i1905_interface *rif,
							      uint8_t *nbr_nbr_aladdr)
{
	struct i1905_neighbor_interface *nif = NULL;


	list_for_each_entry(nif, &rif->nbriflist, list) {
		if (hwaddr_equal(nif->aladdr, nbr_nbr_aladdr))
			return nif;
	}

	return NULL;
}
#endif


struct i1905_interface *i1905_dm_neighbor_interface_lookup(struct i1905_device *rdev,
							   uint8_t *ifmacaddr)
{
	struct i1905_interface *rif = NULL;


	list_for_each_entry(rif, &rdev->iflist, list) {
		if (hwaddr_equal(rif->macaddr, ifmacaddr))
			return rif;
	}

	return NULL;
}

void i1905_dm_neighbor_invalidate_all_interface(struct i1905_device *rdev)
{
	struct i1905_interface *rif = NULL;

	list_for_each_entry(rif, &rdev->iflist, list) {
		rif->invalid = true;
	}
}

void i1905_dm_neighbor_free_invalid_interfaces(struct i1905_device *rdev)
{
	struct i1905_interface *rif, *tmp;

	if (!rdev)
		return;

	list_for_each_entry_safe(rif, tmp, &rdev->iflist, list) {
		if (rif->invalid) {
			list_del(&rif->list);
			rdev->num_interface--;
			i1905_dm_neighbor_interface_free(rif);
		}
	}
}

int i1905_dm_neighbor_update_non1905_neighbors(struct i1905_interface *iface,
					       uint8_t *aladdr)
{
	struct i1905_device *rdev = NULL;


	rdev = i1905_get_neigh_device(iface, aladdr);
	if (!rdev)
		return -1;

	if (!rdev->num_neighbor_non1905)
		return 0;

	if (rdev->non1905_macaddrs) {
		free(rdev->non1905_macaddrs);
		rdev->non1905_macaddrs = NULL;
	}

	rdev->non1905_macaddrs = calloc(rdev->num_neighbor_non1905,  6 * sizeof(uint8_t));
	if (!rdev->non1905_macaddrs)
		return -1;

	return i1905_dm_neighbor_get_non1905_neighbors(rdev, rdev->non1905_macaddrs);
}

int i1905_dm_neighbor_update_non1905_nbrlist(struct i1905_device *rdev, struct tlv *t)
{
	struct tlv_non1905_neighbor *non1905_nbr =
				(struct tlv_non1905_neighbor *)t->data;
	struct i1905_interface *rif;
	int num;
	int j;


	rif = i1905_dm_neighbor_interface_lookup(rdev, non1905_nbr->local_macaddr);
	if (!rif) {
		rif = i1905_dm_neighbor_interface_create();
		if (!rif) {
			fprintf(stderr, "-ENOMEM\n");
			return -1;
		}

		memcpy(rif->macaddr, non1905_nbr->local_macaddr, 6);
		memcpy(rif->aladdr, rdev->aladdr, 6);
		rif->device = rdev;
		rif->priv = NULL;
		list_add_tail(&rif->list, &rdev->iflist);
		rdev->num_interface++;
	}

	num = (tlv_length(t) - 6) / 6;

	for (j = 0; j < num; j++) {
		struct i1905_net_non1905_neighbor *rdev_xnbr = NULL;

		rdev_xnbr = i1905_dm_neighbor_non1905_nbr_create();
		if (rdev_xnbr) {
			memcpy(rdev_xnbr->macaddr, non1905_nbr->non1905_nbr[j].macaddr, 6);
			list_add_tail(&rdev_xnbr->list, &rif->non1905_nbrlist);
			rif->num_neighbor_non1905++;
			rdev->num_neighbor_non1905++;
		}
	}

	return 0;
}

int i1905_dm_neighbor_update_nbrlist(struct i1905_interface *iface,
				     struct i1905_device *rdev, struct tlv *t)
{
	struct i1905_selfdevice *self = (struct i1905_selfdevice *)iface->device;
	struct tlv_1905neighbor *nbr = (struct tlv_1905neighbor *)t->data;
	struct i1905_interface *rif;
	uint16_t remlen = tlv_length(t);
	int j;


	rif = i1905_dm_neighbor_interface_lookup(rdev, nbr->local_macaddr);
	if (!rif) {
		rif = i1905_dm_neighbor_interface_create();
		if (!rif) {
			fprintf(stderr, "-ENOMEM\n");
			return -1;
		}

		memcpy(rif->macaddr, nbr->local_macaddr, 6);
		memcpy(rif->aladdr, rdev->aladdr, 6);
		rif->device = rdev;
		rif->priv = NULL;
		list_add_tail(&rif->list, &rdev->iflist);
		rdev->num_interface++;
	}

	/* invalidate current links over 'rif' */
	i1905_invalidate_links(rif);

	remlen -= 6;	/* local_macaddr */
	j = 0;

	while (remlen >= sizeof(struct i1905_neighbor)) {
		struct i1905_neighbor_interface *nif = NULL;


		nif = i1905_link_neighbor_lookup(rif, nbr->nbr[j].aladdr);
		if (nif) {
			nif->invalid = false;
			prlink("Valid link", nbr->nbr[j].aladdr, nif->macaddr, rif->macaddr, rif->aladdr);
		} else {
			nif = i1905_link_create(rif);
			if (!nif) {
				fprintf(stderr, "-ENOMEM\n");
				return -1;
			}
			memcpy(nif->aladdr, nbr->nbr[j].aladdr, 6);

			list_add_tail(&nif->list, &rif->nbriflist);
			rif->num_links++;
		}

		/* 'nif->macaddr' is unknown here. It will be populated from
		 * link-metric response.
		 */
		nif->has_bridge = nbr->nbr[j].has_bridge;

		/* create neighbor-neighbor device if not known */
		if (!hwaddr_equal(nif->aladdr, self->aladdr)) {
			struct i1905_device *rrdev = NULL;

			rrdev = i1905_dm_neighbor_lookup(iface, nif->aladdr);
			if (!rrdev) {
				rrdev = i1905_dm_neighbor_create();
				if (rrdev) {
					memcpy(rrdev->aladdr, nif->aladdr, 6);
					rrdev->tsp = time(NULL);
					rrdev->dev = self;
					list_add_tail(&rrdev->list, &self->topology.devlist);
					self->topology.num_devices++;
				}
			}
		}

		remlen -= sizeof(struct i1905_neighbor);
		j++;
	}

	/* Do not delete invalid links yet, as subsequent nbrlist update for the
	 * same topology-response cmdu can come with the same interface macaddr
	 * as this one.
	 * Only after seeing the all the tlv_1905neighbor entries in a topology-
	 * response can we infer if a link has become invalid or not.
	 */
#if 0
	/* delete links that are no longer valid through 'rif' */
	i1905_free_invalid_links(rif);
#endif

	return 0;
}

int i1905_is_tlv_device_bridge_caps_valid(struct tlv *t)
{
	struct tlv_device_bridge_caps *brcaps = (struct tlv_device_bridge_caps *)t->data;
	int remlen = (int)tlv_length(t) - sizeof(struct tlv_device_bridge_caps);
	struct device_bridge_tuple *tuple = NULL;
	uint8_t *ptr = t->data;
	int offset = 0;
	int i;


	if (brcaps->num_tuples > 0 && remlen >= sizeof(struct device_bridge_tuple)) {
		ptr += sizeof(struct tlv_device_bridge_caps);
		tuple = (struct device_bridge_tuple *)ptr;
	}

	for (i = 0; i < brcaps->num_tuples; i++) {
		if (remlen < sizeof(struct device_bridge_tuple))
			return 0;

		remlen -= sizeof(struct device_bridge_tuple);
		ptr += offset;
		tuple = (struct device_bridge_tuple *)ptr;
		if (remlen < tuple->num_macaddrs * sizeof(struct device_bridge_tuple_macaddr))
			return 0;

		remlen -= tuple->num_macaddrs * sizeof(struct device_bridge_tuple_macaddr);
		offset = sizeof(tuple->num_macaddrs) +
			tuple->num_macaddrs * sizeof(struct device_bridge_tuple_macaddr);
	}

	return remlen ? 0 : 1;
}

int i1905_dm_neighbor_update_brlist(struct i1905_device *rdev, struct tlv *t)
{
	struct tlv_device_bridge_caps *brcaps =
				(struct tlv_device_bridge_caps *)t->data;
	//struct i1905_bridge_tuple *bp, *tmp;
	int i;

	if (!i1905_is_tlv_device_bridge_caps_valid(t)) {
		dbg("Invalid tlv_bridge_caps; discard CMDU\n");
		return -1;
	}

	/* replace old brlist with this one.
	 * tuple->macaddrs freed automatically because it is contiguous.
	 */
	list_flush(&rdev->brlist, struct i1905_bridge_tuple, list);
	rdev->num_brtuple = 0;

#if 0
	list_for_each_entry_safe(bp, tmp, &rdev->brlist, list) {
		list_del(&bp->list);
		if (bp->num_macs) {
			free(bp->macaddrs);
		}
		free(bp);
	}
#endif

	for (i = 0; i < brcaps->num_tuples; i++) {
		struct i1905_bridge_tuple *br = NULL;
		int num_macaddrs = brcaps->tuple[i].num_macaddrs;

		if (num_macaddrs == 0)
			continue;

		br = i1905_dm_neighbor_brtuple_create(num_macaddrs);
		if (!br) {
			fprintf(stderr, "-ENOMEM\n");
			return -1;
		}

		br->num_macs = num_macaddrs;
		memcpy(br->macaddrs, brcaps->tuple[i].addr, 6 * num_macaddrs);
		list_add_tail(&br->list, &rdev->brlist);
		rdev->num_brtuple++;
	}

	return 0;
}

int i1905_is_tlv_device_info_valid(struct tlv *t)
{
	struct tlv_device_info *devinfo =
				(struct tlv_device_info *)t->data;
	struct local_interface *tif = NULL;
	int remlen = (int)tlv_length(t) - sizeof(struct tlv_device_info);
	uint8_t *ptr = t->data;
	int offset = 0;
	int i;


	if (devinfo->num_interface > 0 && remlen >= sizeof(struct local_interface)) {
		ptr += sizeof(struct tlv_device_info);
		tif = (struct local_interface *)ptr;
	}

	for (i = 0; i < devinfo->num_interface; i++) {
		if (remlen < sizeof(struct local_interface))
			return 0;

		remlen -= sizeof(struct local_interface);
		ptr += offset;
		tif = (struct local_interface *)ptr;
		if (remlen < tif->sizeof_mediainfo)
			return 0;

		if (tif->sizeof_mediainfo > 0) {
			uint16_t tif_media = buf_get_be16((uint8_t *)&tif->mediatype);

			if (tif_media == MEDIA_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET ||
			    tif_media == MEDIA_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET)
				return 0;
		}

		remlen -= tif->sizeof_mediainfo;
		offset = sizeof(struct local_interface) + tif->sizeof_mediainfo;
	}

	return remlen ? 0 : 1;
}

int i1905_dm_neighbor_update_devinfo(struct i1905_private *priv,
				     struct i1905_device *rdev, struct tlv *t)
{
	struct tlv_device_info *devinfo =
				(struct tlv_device_info *)t->data;
	int offset = sizeof(struct tlv_device_info);
	uint8_t *ptr = t->data;
	int i;


	dbg("%s: Node " MACFMT " reports %d interfaces in its latest Topology Response\n",
	    __func__, MAC2STR(rdev->aladdr), devinfo->num_interface);
	dbg("%s: Node " MACFMT " last reported %d interfaces\n",
	    __func__, MAC2STR(rdev->aladdr), rdev->num_interface);

	if (!i1905_is_tlv_device_info_valid(t)) {
		dbg("Invalid tlv_device_info; discard CMDU\n");
		return -1;
	}

	i1905_dm_neighbor_invalidate_all_interface(rdev);

	for (i = 0; i < devinfo->num_interface; i++) {
		struct local_interface *tif;
		struct i1905_interface *rif;

		ptr += offset;
		tif = (struct local_interface *)ptr;

		rif = i1905_dm_neighbor_interface_lookup(rdev, tif->macaddr);
		if (!rif) {
			rif = i1905_dm_neighbor_interface_create();
			if (!rif) {
				fprintf(stderr, "-ENOMEM\n");
				return -1;
			}

			rif->invalid = false;
			memcpy(rif->macaddr, tif->macaddr, 6);
			memcpy(rif->aladdr, rdev->aladdr, 6);
			rif->device = rdev;
			rif->priv = NULL;
			rif->media = buf_get_be16((uint8_t *)&tif->mediatype);
			if (tif->sizeof_mediainfo > 0) {
				rif->mediainfo = calloc(1, tif->sizeof_mediainfo);
				if (!rif->mediainfo) {
					fprintf(stderr, "-ENOMEM\n");
					return -1;
				}

				memcpy(rif->mediainfo, tif->mediainfo,
							tif->sizeof_mediainfo);
			}

			list_add_tail(&rif->list, &rdev->iflist);
			rdev->num_interface++;
		} else {
			rif->invalid = false;
			memcpy(rif->aladdr, rdev->aladdr, 6);
			rif->media = buf_get_be16((uint8_t *)&tif->mediatype);
			if (tif->sizeof_mediainfo > 0) {
				if (rif->mediainfo)
					free(rif->mediainfo);

				rif->mediainfo = calloc(1, tif->sizeof_mediainfo);
				if (!rif->mediainfo) {
					fprintf(stderr, "-ENOMEM\n");
					return -1;
				}

				memcpy(rif->mediainfo, tif->mediainfo,
							tif->sizeof_mediainfo);
			}
		}

		neigh_set_1905_slave(&priv->neigh_q, rif->macaddr);
		offset = sizeof(struct local_interface) + tif->sizeof_mediainfo;
	}

	dbg("%s: Num interfaces stored from Topo Response = %d\n",
	    __func__, rdev->num_interface);

	i1905_dm_neighbor_free_invalid_interfaces(rdev);

	return 0;
}

int i1905_dm_neighbor_update_link_metric(struct i1905_device *rdev, struct tlv *t)
{
	struct tlv_tx_linkmetric *txl = NULL;
	struct tlv_rx_linkmetric *rxl = NULL;
	uint16_t remlen = tlv_length(t);
	struct tx_link_info *txlinfo;
	struct rx_link_info *rxlinfo;
	struct i1905_interface *rif;
	uint16_t remlen_min = 0;
	uint8_t *rif_macaddr = NULL;
	int j = 0;


	if (remlen < 12)
		return 0;

	remlen -= 12;	/* sender's 'aladdr' and its 'neighbor_aladdr' */
	if (remlen < 6)	/* i.e. sizeof(local_macaddr) */
		return 0;

	if (t->type == TLV_TYPE_TRANSMITTER_LINK_METRIC) {
		txl = (struct tlv_tx_linkmetric *)t->data;
		txlinfo = (struct tx_link_info *)&txl->link[0];
		rif_macaddr = txlinfo->local_macaddr;
		remlen_min = sizeof(*txlinfo);
	} else if (t->type == TLV_TYPE_RECEIVER_LINK_METRIC) {
		rxl = (struct tlv_rx_linkmetric *)t->data;
		rxlinfo = (struct rx_link_info *)&rxl->link[0];
		rif_macaddr = rxlinfo->local_macaddr;
		remlen_min = sizeof(*rxlinfo);
	} else
		return -1;


	rif = i1905_dm_neighbor_interface_lookup(rdev, rif_macaddr);
	if (!rif) {
		rif = i1905_dm_neighbor_interface_create();
		if (!rif) {
			fprintf(stderr, "-ENOMEM\n");
			return -1;
		}

		memcpy(rif->macaddr, rif_macaddr, 6);
		memcpy(rif->aladdr, rdev->aladdr, 6);
		rif->device = rdev;
		rif->priv = NULL;
		list_add_tail(&rif->list, &rdev->iflist);
		rdev->num_interface++;
	}

	/* invalidate current links through 'rif' before updating below */
	i1905_invalidate_links(rif);

	while (remlen >= remlen_min) {
		struct i1905_neighbor_interface *nif;
		int newlink = 0;

		if (t->type == TLV_TYPE_TRANSMITTER_LINK_METRIC && txl) {
			txlinfo = (struct tx_link_info *)&txl->link[j];


			nif = i1905_link_neighbor_lookup(rif, txl->neighbor_aladdr);
			if (nif) {
				nif->invalid = false;
			} else {
				nif = i1905_link_create(rif);
				if (!nif) {
					fprintf(stderr, "-ENOMEM\n");
					return -1;
				}
				newlink = 1;
			}

			memcpy(nif->aladdr, txl->neighbor_aladdr, 6);
			memcpy(nif->macaddr, txlinfo->neighbor_macaddr, 6);
			BUF_PUT_BE16(nif->media, txlinfo->mediatype);
			nif->has_bridge = txlinfo->has_bridge == 0 ? false : true;
			nif->metric.br_present = txlinfo->has_bridge == 0 ? false : true;
			BUF_PUT_BE32(nif->metric.tx_errors, txlinfo->errors);
			BUF_PUT_BE32(nif->metric.tx_packets, txlinfo->packets);
			BUF_PUT_BE16(nif->metric.available, txlinfo->availability);
			BUF_PUT_BE16(nif->metric.max_rate, txlinfo->max_throughput);
			BUF_PUT_BE16(nif->metric.max_phyrate, txlinfo->phyrate);

			remlen -= sizeof(struct tx_link_info);
		} else if (t->type == TLV_TYPE_RECEIVER_LINK_METRIC && rxl) {
			rxlinfo = (struct rx_link_info *)&rxl->link[j];


			nif = i1905_link_neighbor_lookup(rif, rxl->neighbor_aladdr);
			if (nif) {
				nif->invalid = false;
			} else {
				nif = i1905_link_create(rif);
				if (!nif) {
					fprintf(stderr, "-ENOMEM\n");
					return -1;
				}
				newlink = 1;
			}

			memcpy(nif->aladdr, rxl->neighbor_aladdr, 6);
			memcpy(nif->macaddr, rxlinfo->neighbor_macaddr, 6);
			BUF_PUT_BE16(nif->media, rxlinfo->mediatype);
			BUF_PUT_BE32(nif->metric.rx_errors, rxlinfo->errors);
			BUF_PUT_BE32(nif->metric.rx_packets, rxlinfo->packets);
			nif->metric.rssi = rxlinfo->rssi;

			remlen -= sizeof(struct rx_link_info);
		}

		if (newlink) {
			list_add_tail(&nif->list, &rif->nbriflist);
			rif->num_links++;
		}

		j++;
	}

#if 0
	/* delete links that are no longer valid through 'rif' */
	i1905_free_invalid_links(rif);
#endif

	return 0;
}

int i1905_dm_neighbor_update_device_ident(struct i1905_device *rdev, struct tlv *t)
{
	struct tlv_device_identification *ident =
				(struct tlv_device_identification *)t->data;


	memset(rdev->name, 0, sizeof(rdev->name));
	memcpy(rdev->name, ident->name, 64);

	memset(rdev->manufacturer, 0, sizeof(rdev->manufacturer));
	memcpy(rdev->manufacturer, ident->manufacturer, 64);

	memset(rdev->model, 0, sizeof(rdev->model));
	memcpy(rdev->model, ident->model, 64);

	return 0;
}

int i1905_dm_neighbor_update_profile(struct i1905_device *rdev, struct tlv *t)
{
	struct tlv_1905_profile *p =
				(struct tlv_1905_profile *)t->data;


	if (p->version == PROFILE_1905_1)
		rdev->version = I1905_VERSION_DOT_1;
	else if (p->version == PROFILE_1905_1A)
		rdev->version = I1905_VERSION_DOT_1A;

	return 0;
}

int i1905_dm_neighbor_update_control_url(struct i1905_device *rdev, struct tlv *t)
{
	struct tlv_control_url *ctrl =
				(struct tlv_control_url *)t->data;
	int url_len = tlv_length(t);
	char *url;

	if (!url_len)
		return 0;

	if (rdev->url)
		free(rdev->url);

	url = calloc(tlv_length(t) + 1, sizeof(char));
	if (url)
		memcpy(url, ctrl->url, url_len);

	rdev->url = url;

	return 0;
}

int i1905_dm_neighbor_update_ipv4(struct i1905_device *rdev, struct tlv *t)
{
	struct tlv_ipv4 *ip = (struct tlv_ipv4 *)t->data;
	int offset = sizeof(struct tlv_ipv4);
	uint8_t *ptr = t->data;
	struct i1905_ipv4 *ip4;
	int i, j;


	list_flush(&rdev->ipv4list, struct i1905_ipv4, list);
	rdev->num_ipv4 = 0;

	for (i = 0; i < ip->num_interfaces; i++) {
		struct ipv4_interface *tif;

		ptr += offset;
		tif = (struct ipv4_interface *)ptr;

		if (!hwaddr_equal(rdev->aladdr, tif->macaddr)) {
			struct i1905_interface *rif;

			rif = i1905_dm_neighbor_interface_lookup(rdev, tif->macaddr);
			if (!rif) {
				rif = i1905_dm_neighbor_interface_create();
				if (!rif) {
					fprintf(stderr, "-ENOMEM\n");
					return -1;
				}

				memcpy(rif->macaddr, tif->macaddr, 6);
				memcpy(rif->aladdr, rdev->aladdr, 6);
				rif->device = rdev;
				rif->priv = NULL;
				list_add_tail(&rif->list, &rdev->iflist);
				rdev->num_interface++;
			}
			//XXX: store ipaddress per interface?
		}

		offset = sizeof(struct ipv4_interface);

		for (j = 0; j < tif->num_ipv4; j++) {
			struct ipv4_entry *e;

			ptr += offset;
			e = (struct ipv4_entry *)ptr;

			ip4 = i1905_dm_ipv4_create();
			if (!ip4) {
				fprintf(stderr, "-ENOMEM\n");
				return -ENOMEM;
			}

			memcpy(ip4->macaddr, tif->macaddr, 6);
			memcpy(&ip4->addr, e->address, sizeof(struct in_addr));
			ip4->type = e->type;
			memcpy(&ip4->dhcpserver, e->dhcpserver, sizeof(struct in_addr));
			list_add_tail(&ip4->list, &rdev->ipv4list);
			rdev->num_ipv4++;

			offset = sizeof(struct ipv4_entry);
		}
	}

	return 0;
}

int i1905_dm_neighbor_update_ipv6(struct i1905_device *rdev, struct tlv *t)
{
	struct tlv_ipv6 *ip = (struct tlv_ipv6 *)t->data;
	int offset = sizeof(struct tlv_ipv6);
	uint8_t *ptr = t->data;
	struct i1905_ipv6 *ip6;
	int i, j;


	list_flush(&rdev->ipv6list, struct i1905_ipv6, list);
	rdev->num_ipv6 = 0;

	for (i = 0; i < ip->num_interfaces; i++) {
		struct ipv6_interface *tif;

		ptr += offset;
		tif = (struct ipv6_interface *)ptr;

		if (!hwaddr_equal(rdev->aladdr, tif->macaddr)) {
			struct i1905_interface *rif;


			rif = i1905_dm_neighbor_interface_lookup(rdev, tif->macaddr);
			if (!rif) {
				rif = i1905_dm_neighbor_interface_create();
				if (!rif) {
					fprintf(stderr, "-ENOMEM\n");
					return -1;
				}

				memcpy(rif->macaddr, tif->macaddr, 6);
				memcpy(rif->aladdr, rdev->aladdr, 6);
				rif->device = rdev;
				rif->priv = NULL;
				list_add_tail(&rif->list, &rdev->iflist);
				rdev->num_interface++;
			}
			//XXX: store ipaddress per interface?
		}

		offset = sizeof(struct ipv6_interface);

		for (j = 0; j < tif->num_ipv6; j++) {
			struct ipv6_entry *e;

			ptr += offset;
			e = (struct ipv6_entry *)ptr;

			ip6 = i1905_dm_ipv6_create();
			if (!ip6) {
				fprintf(stderr, "-ENOMEM\n");
				return -ENOMEM;
			}

			memcpy(ip6->macaddr, tif->macaddr, 6);
			//TODO: linklocal address
			memcpy(&ip6->addr, e->address, sizeof(struct in6_addr));
			ip6->type = e->type;
			memcpy(&ip6->origin, e->origin, sizeof(struct in6_addr));
			list_add_tail(&ip6->list, &rdev->ipv6list);
			rdev->num_ipv6++;

			offset = sizeof(struct ipv6_entry);
		}
	}

	return 0;
}

int i1905_dm_neighbor_update(struct i1905_interface *iface, uint8_t *aladdr,
			     struct tlv *t)
{
	struct i1905_interface_private *ifpriv = iface->priv;
	struct i1905_private *priv = ifpriv ? ifpriv->i1905private : NULL;
	struct i1905_device *rdev = NULL;
	int ret = 0;


	if (!priv) {
		warn("%s: i1905 private context is NULL\n", __func__);
		return -1;
	}

	rdev = i1905_dm_neighbor_lookup(iface, aladdr);
	if (!rdev) {
		fprintf(stderr, "ALERT! received CMDU from unknown device\n");
		return -99;
	}

	rdev->upstream = iface->upstream ? true : false;

	switch (t->type) {
	case TLV_TYPE_DEVICE_INFORMATION_TYPE:
		ret = i1905_dm_neighbor_update_devinfo(priv, rdev, t);
		break;
	case TLV_TYPE_DEVICE_BRIDGING_CAPABILITIES:
		ret = i1905_dm_neighbor_update_brlist(rdev, t);
		break;
	case TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST:
		ret = i1905_dm_neighbor_update_non1905_nbrlist(rdev, t);
		break;
	case TLV_TYPE_NEIGHBOR_DEVICE_LIST:
		ret = i1905_dm_neighbor_update_nbrlist(iface, rdev, t);
		break;
	case TLV_TYPE_POWER_OFF_INTERFACE:
		break;
	case TLV_TYPE_L2_NEIGHBOR_DEVICE:
		break;
	case TLV_TYPE_TRANSMITTER_LINK_METRIC:
	case TLV_TYPE_RECEIVER_LINK_METRIC:
		ret = i1905_dm_neighbor_update_link_metric(rdev, t);
		break;
	case TLV_TYPE_DEVICE_IDENTIFICATION:
		ret = i1905_dm_neighbor_update_device_ident(rdev, t);
		break;
	case TLV_TYPE_1905_PROFILE_VERSION:
		ret = i1905_dm_neighbor_update_profile(rdev, t);
		break;
	case TLV_TYPE_CONTROL_URL:
		ret = i1905_dm_neighbor_update_control_url(rdev, t);
		break;
	case TLV_TYPE_IPV4:
		ret = i1905_dm_neighbor_update_ipv4(rdev, t);
		break;
	case TLV_TYPE_IPV6:
		ret = i1905_dm_neighbor_update_ipv6(rdev, t);
		break;
	default:
		fprintf(stderr, "%s: Unhandled TLV %d\n", __func__, t->type);
		break;
	}

	return ret;
}

int i1905_dm_neighbor_discovered(struct i1905_interface *iface, uint8_t *aladdr,
				 uint8_t *macaddr, uint16_t cmdu_type)
{
	struct i1905_selfdevice *self = (struct i1905_selfdevice *)iface->device;
	struct i1905_interface *rif = NULL;
	struct i1905_device *rdev = NULL;
	bool newlink = false;
	bool newdev = false;
	bool newnbr = false;



	rdev = i1905_dm_neighbor_lookup(iface, aladdr);
	if (!rdev) {
		rdev = i1905_dm_neighbor_create();
		if (!rdev) {
			fprintf(stderr, "%s: failed to create nbr-device\n", __func__);
			return -1;
		}

		memcpy(rdev->aladdr, aladdr, 6);
		list_add_tail(&rdev->list, &self->topology.devlist);
		self->topology.num_devices++;
		rdev->dev = self;
		dbg("%s: New neighbor " MACFMT " discovered\n",
		    __func__, MAC2STR(aladdr));
		newdev = true;
	}

	rdev->tsp = time(NULL);
	if (cmdu_type == CMDU_TYPE_TOPOLOGY_DISCOVERY) {
		if (!rdev->is_immediate_neighbor)
			newnbr = true;

		rdev->is_immediate_neighbor = 1;
		timer_set(&rdev->immediate_nbr_agetimer, I1905_IMMEDIATE_NEIGHBOR_AGEOUT);
	}

	/* send this extra discovery to help neighbors find us quicker */
	if (newdev) {
		struct i1905_interface_private *ifpriv = iface->priv;
		struct i1905_private *priv = (struct i1905_private *)ifpriv->i1905private;

		i1905_send_topology_notification(priv, iface->ifname);
		i1905_send_topology_discovery(iface);

		if (newnbr)
			i1905_extmodules_notify(priv, IEEE1905_NBR_ADDED,
						rdev->aladdr,
						macaddr,
						iface->macaddr);
	}

	/* record macaddr of origin interface if not already done */
	if (macaddr && !hwaddr_is_zero(macaddr) /* && !hwaddr_equal(aladdr, macaddr) */) {
		struct i1905_neighbor_interface *if_peer;

		list_for_each_entry(rif, &rdev->iflist, list) {
			if (hwaddr_equal(rif->macaddr, macaddr)) {
				dbg("%s: update iflink\n", __func__);

				/* add this macaddr as if_peer if not already done */
				if_peer = i1905_link_neighbor_interface_lookup(iface, macaddr);
				if (!if_peer) {
					if_peer = i1905_link_create(iface);
					newlink = true;
					dbg("%s: %s created link\n", __func__, iface->ifname);
					if (if_peer) {
						dbg("***NBR aladdr = " MACFMT " if-macaddr = " MACFMT "\n",
						    MAC2STR(aladdr), MAC2STR(macaddr));

						memcpy(if_peer->macaddr, macaddr, 6);
						memcpy(if_peer->aladdr, aladdr, 6);
						/* other fields like media, genphy and metric
						 * will be filled when available from topology
						 * response from this peer.
						 */
						list_add_tail(&if_peer->list, &iface->nbriflist);
						iface->num_links++;
					}
				}

				if (if_peer && cmdu_type == CMDU_TYPE_TOPOLOGY_DISCOVERY)
					if_peer->direct = true;

				if (newlink) {
					struct i1905_interface_private *ifpriv = iface->priv;
					struct i1905_private *priv = (struct i1905_private *)ifpriv->i1905private;

					i1905_extmodules_notify(priv, IEEE1905_LINK_ADDED,
								iface->aladdr,
								iface->macaddr,
								if_peer->aladdr,
								if_peer->macaddr,
								if_peer->direct);
				}

				return 0;
			}
		}

		rif = i1905_dm_neighbor_interface_create();
		if (!rif) {
			fprintf(stderr, "%s: failed to create nbr-iface\n", __func__);
			return -1;
		}

		memcpy(rif->macaddr, macaddr, 6);
		memcpy(rif->aladdr, aladdr, 6);
		rif->device = rdev;
		rif->priv = NULL;

		list_add_tail(&rif->list, &rdev->iflist);
		rdev->num_interface++;

		/* add this macaddr as if_peer if not already done */
		if_peer = i1905_link_neighbor_interface_lookup(iface, macaddr);
		if (!if_peer) {
			if_peer = i1905_link_create(iface);
			newlink = true;
			dbg("%s: %s created link\n", __func__, iface->ifname);
			if (if_peer) {
				dbg("+++ NBR aladdr = " MACFMT " if-macaddr = " MACFMT "\n",
				    MAC2STR(aladdr), MAC2STR(macaddr));

				memcpy(if_peer->macaddr, macaddr, 6);
				memcpy(if_peer->aladdr, aladdr, 6);
				/* other fields like media, genphy and metric
				 * will be filled when available from topology
				 * response from this peer.
				 */
				list_add_tail(&if_peer->list, &iface->nbriflist);
				iface->num_links++;
			}
		}

		if (if_peer && cmdu_type == CMDU_TYPE_TOPOLOGY_DISCOVERY)
			if_peer->direct = true;

		if (newlink) {
			struct i1905_interface_private *ifpriv = iface->priv;
			struct i1905_private *priv = (struct i1905_private *)ifpriv->i1905private;

			i1905_extmodules_notify(priv, IEEE1905_LINK_ADDED,
						iface->aladdr,
						iface->macaddr,
						if_peer->aladdr,
						if_peer->macaddr,
						if_peer->direct);
		}
	}

	return 0;
}

int i1905_dm_neighbor_changed(struct i1905_interface *iface, uint8_t *aladdr)
{
	struct i1905_selfdevice *self = (struct i1905_selfdevice *)iface->device;
	struct i1905_device *rdev = NULL;



	rdev = i1905_dm_neighbor_lookup(iface, aladdr);
	if (!rdev) {
		rdev = i1905_dm_neighbor_create();
		if (!rdev) {
			fprintf(stderr,
				"%s: failed to create nbr-device\n", __func__);
			return -1;
		}

		memcpy(rdev->aladdr, aladdr, 6);
		list_add_tail(&rdev->list, &self->topology.devlist);
		self->topology.num_devices++;
		rdev->dev = self;

		dbg("%s: New neighbor " MACFMT " discovered.\n",
		    __func__, MAC2STR(aladdr));
	}

	//rdev->changed = true;
	rdev->tsp = time(NULL);

	return 0;
}

int i1905_dm_init(struct i1905_dm *dm, struct i1905_config *cfg)
{
	struct i1905_selfdevice *self = &dm->self;

	memset(self, 0, sizeof(*self));

	self->enabled = true;
	self->url = NULL;
	memcpy(self->aladdr, cfg->macaddr, 6);
	strncpy(self->manufacturer, cfg->manufacturer, strlen(cfg->manufacturer));
	strncpy(self->model, cfg->model_name, strlen(cfg->model_name));
	strncpy(self->name, cfg->device_name, strlen(cfg->device_name));
	if (cfg->url)
		self->url = strdup(cfg->url);

	self->version = I1905_VERSION_DOT_1A;
	self->regband = I1905_REGISTRAR_NONE;
	self->num_interface = 0;
	INIT_LIST_HEAD(&self->iflist);

	self->num_master_interface = 0;
	INIT_LIST_HEAD(&self->miflist);

	self->fwd.allow = true;
	INIT_LIST_HEAD(&self->fwd.rulelist);

	self->topology.enable = 1;
	self->topology.status = 0;
	self->topology.num_devices = 0;
	INIT_LIST_HEAD(&self->topology.devlist);

	self->security.method = I1905_SECURITY_PBC;

	return 0;
}

int i1905_dm_free(struct i1905_dm *dm)
{
	struct i1905_selfdevice *self = &dm->self;
	struct i1905_device *rdev, *tmp;

	if (self->url) {
		free(self->url);
		self->url = NULL;
	}

	if (self->topology.num_devices == 0)
		return 0;

	list_for_each_entry_safe(rdev, tmp, &self->topology.devlist, list) {
		if (timer_pending(&rdev->agetimer))
			timer_del(&rdev->agetimer);

		if (timer_pending(&rdev->immediate_nbr_agetimer))
			timer_del(&rdev->immediate_nbr_agetimer);

		list_del(&rdev->list);
		i1905_dm_neighbor_free(rdev);
	}

	return 0;
}
