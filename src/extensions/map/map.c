/*
 * map.c - implements multi-ap plugin to ieee1905.
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

#include "easymesh.h"
#include "map.h"
#include "map_module.h"

#ifndef BIT
#define BIT(n)	(1U << (n))
#endif


static int map_init(void **priv, struct i1905_context *ieee1905);
static int map_exit(void *priv);

int map_notify_clients(void *priv, struct cmdu_buff *frm)
{
	struct map_private *p = (struct map_private *)priv;
	struct registered_map_module *m = NULL;
	int len = cmdu_size(frm);
	char frmbuffer[2 * len + 1];
	uint16_t type = cmdu_get_type(frm);
	uint16_t mid = cmdu_get_mid(frm);
	char originstr[18] = {0};
	char alstr[18] = {0};
	int ret = 0;


	memset(frmbuffer, 0, 2 * len + 1);
	btostr((uint8_t *)frm->cdata, len, frmbuffer);

	list_for_each_entry(m, &p->rmodlist, list) {
		struct blob_buf bb = {};

		if (!map_cmdu_mask_isset(m->module.cmdu_mask, type))
			continue;

		memset(&bb, 0, sizeof(bb));
		blob_buf_init(&bb, 0);
		blobmsg_add_u16(&bb, "type", type);
		blobmsg_add_u16(&bb, "mid", mid);
		blobmsg_add_string(&bb, "ifname", frm->dev_ifname);
		hwaddr_ntoa(frm->origin, originstr);
		blobmsg_add_string(&bb, "source", originstr);
		hwaddr_ntoa(frm->aladdr, alstr);
		blobmsg_add_string(&bb, "origin", alstr);
		blobmsg_add_string(&bb, "cmdu", frmbuffer);
		ret = ubus_notify(p->ctx, &m->notify, IEEE1905_OBJECT".cmdu", bb.head, -1);
		if (ret)
			fprintf(stderr, "Failed to notify map clients...\n");

		blob_buf_free(&bb);
	}

	return ret;
}

static void fill_random_bytes(uint8_t *buf, size_t len, unsigned int seed)
{
	int i;

	srandom(seed);
	for (i = 0; i < len; i++)
		buf[i] = random() & 0xff;
}

void fuzz_cmdu_internal(void *priv, struct cmdu_buff *frm)
{
	int mutation = cmdu_get_mid(frm) % 5;
	int len = frm->datalen;
	struct tlv *t;


	cmdu_for_each_tlv(t, frm->data, len) {
		uint16_t tlen = tlv_length(t);

		switch (mutation) {
		case 0:
			/* replace all tlv data randomly */
			fill_random_bytes(t->data, tlen, 1);
			break;
		case 1:
			/* expand tlv data by one byte */
			break;
		case 2:
			/* shrink tlv data by one byte */
			break;
		case 3:
			/* steal first tlv */
			break;
		case 4:
			/* steal last tlv */
			break;
		}
	}
}

int map_notify_clients_fuzzed_cmdu(void *priv, struct cmdu_buff *frm)
{
	struct map_private *p = (struct map_private *)priv;
	struct registered_map_module *m = NULL;
	int len = cmdu_size(frm);
	char frmbuffer[2 * len + 1];
	uint16_t type = cmdu_get_type(frm);
	uint16_t mid = cmdu_get_mid(frm);
	char originstr[18] = {0};
	char alstr[18] = {0};
	char ifname[16] = {0};
	int ret = 0;


	memset(frmbuffer, 0, 2 * len + 1);
	strncpy(ifname, frm->dev_ifname, sizeof(ifname));

	fuzz_cmdu_internal(priv, frm);
	hwaddr_ntoa(frm->origin, originstr);
	hwaddr_ntoa(frm->aladdr, alstr);
	btostr((uint8_t *)frm->cdata, len, frmbuffer);

	list_for_each_entry(m, &p->rmodlist, list) {
		struct blob_buf bb = {};

		if (!map_cmdu_mask_isset(m->module.cmdu_mask, type))
			continue;

		memset(&bb, 0, sizeof(bb));
		blob_buf_init(&bb, 0);
		blobmsg_add_u16(&bb, "type", type);
		blobmsg_add_u16(&bb, "mid", mid);
		blobmsg_add_string(&bb, "ifname", ifname);
		blobmsg_add_string(&bb, "source", originstr);
		blobmsg_add_string(&bb, "origin", alstr);
		blobmsg_add_string(&bb, "cmdu", frmbuffer);
		ret = ubus_notify(p->ctx, &m->notify, IEEE1905_OBJECT".cmdu", bb.head, -1);
		if (ret)
			fprintf(stderr, "Failed to notify map clients...\n");

		blob_buf_free(&bb);
	}

	return ret;
}

int map_event_cb(void *priv, const char *ev, size_t len)
{
	struct map_private *p = (struct map_private *)priv;
	char data[512] = {0};
	char type[32] = {0};
	struct blob_buf b;

	if (sscanf(ev, "%31s '%511[^\n]'", type, data) != 2)
		return -1;

	if (!strstr(type, "ieee1905.neighbor.") &&
	    !strstr(type, "ieee1905.link."))
		return -1;

	memset(&b, 0, sizeof(b));
	blob_buf_init(&b, 0);

	if (!blobmsg_add_json_from_string(&b, data)) {
		fprintf(stderr, "Failed to parse event: %s\n", ev);
		return -1;
	}

	ubus_send_event(p->ctx, type, b.head);
	blob_buf_free(&b);

	return 0;
}

int map_process_cmdu(void *priv, struct cmdu_buff *frm)
{
	struct map_private *p = (struct map_private *)priv;
	int ret;


	if (!frm)
		return -1;

	ret = !p->fuzz_cmdus ? map_notify_clients(p, frm) :
				map_notify_clients_fuzzed_cmdu(p, frm);

	UNUSED(ret);

	return CMDU_OK;
}

void timer_cb(atimer_t *t)
{
	UNUSED(t);
}

int map_start(void *priv)
{
	UNUSED(priv);
	return 0;
}

int map_stop(void *priv)
{
	UNUSED(priv);
	return 0;
}

struct i1905_cmdu_extension i1905_map_extension[] = {
	{ .type = CMDU_TYPE_TOPOLOGY_DISCOVERY },
	{ .type = CMDU_TYPE_TOPOLOGY_NOTIFICATION },
	{ .type = CMDU_TYPE_TOPOLOGY_QUERY },
	{ .type = CMDU_TYPE_TOPOLOGY_RESPONSE },
	{ .type = CMDU_TYPE_LINK_METRIC_QUERY },
	{ .type = CMDU_TYPE_LINK_METRIC_RESPONSE },
	{ .type = CMDU_TYPE_HIGHER_LAYER_QUERY },
	{ .type = CMDU_TYPE_HIGHER_LAYER_RESPONSE },
	{ .type = CMDU_TYPE_VENDOR_SPECIFIC },
	{ .type = CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH },
	{ .type = CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE },
	{ .type = CMDU_TYPE_AP_AUTOCONFIGURATION_WSC,
	 .policy = EXTMODULE_CMDU_OVERRIDE},
	{ .type = CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW}
};


extern struct i1905_extmodule map;
struct i1905_extmodule map = {
	.id = "\x11\x22\x33\x44",
	.name = "map",
	.init = map_init,
	.exit = map_exit,
	.start = map_start,
	.stop = map_stop,
	.ext = i1905_map_extension,
	.num_ext = sizeof(i1905_map_extension)/sizeof(i1905_map_extension[0]),
	.from_newtype = CMDU_1905_ACK,
	.to_newtype = MAP_CMDU_TYPE_MAX,
	.process_cmdu = map_process_cmdu,
	.event_cb = map_event_cb,
};

static int map_init_private(struct map_private *p)
{
	return 0;
}

int map_init(void **priv, struct i1905_context *ieee1905)
{
	struct map_private *p;

	p = calloc(1, sizeof(struct map_private));
	if (!p)
		return -1;

	*priv = p;
	memset(p->buf, 0, sizeof(p->buf));
	sprintf((char *)p->buf, "plugin 'map' private data");
	p->module = &map;

	if (ieee1905) {
		p->ctx = ieee1905->bus;
		p->ieee1905_context = ieee1905->context;
	}

	INIT_LIST_HEAD(&p->rmodlist);

	map_init_private(p);

	map_publish_object(p, IEEE1905_OBJECT_MULTIAP);

	timer_init(&p->t, timer_cb);

	return 0;
}

static int map_exit(void *priv)
{
	struct map_private *p = (struct map_private *)priv;

	if (p) {
		timer_del(&p->t);
		map_unregister_modules(p);
		map_remove_object(p);
		free(p);
	}

	return 0;
}
