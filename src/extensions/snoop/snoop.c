/*
 * snoop.c - snoop 1905 frames and dump them.
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


#define IEEE1905_OBJECT_SNOOP			"ieee1905.snoop"

struct snoop_private {
	void *module;
	int paused;
	uint16_t types[16];
	int num_types;
	struct ubus_context *ctx;
	struct ubus_object obj;
};

static int snoop_init(void **priv, struct i1905_context *ieee1905);
static int snoop_exit(void *priv);

void snoop_dump_cmdu(struct snoop_private *p, struct cmdu_buff *frm)
{
	int len = cmdu_size(frm);
	uint16_t type = cmdu_get_type(frm);
	uint16_t mid = cmdu_get_mid(frm);
	char frmbuffer[2 * len + 1];
	char originstr[18] = {0};
	struct blob_buf bb = {};
	char alstr[18] = {0};
	char typestr[8] = {0};
	int matched = 0;
	int i;


	for (i = 0; i < p->num_types; p++) {
		if (p->types[i] == type) {
			matched = 1;
			break;
		}
	}

	if (p->num_types && !matched)
		return;

	memset(frmbuffer, 0, 2 * len + 1);
	btostr((uint8_t *)frm->cdata, len, frmbuffer);

	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);
	snprintf(typestr, sizeof(typestr), "0x%04x", type);
	blobmsg_add_string(&bb, "type", typestr);
	blobmsg_add_u16(&bb, "mid", mid & 0xffff);
	blobmsg_add_string(&bb, "ifname", frm->dev_ifname);
	hwaddr_ntoa(frm->origin, originstr);
	blobmsg_add_string(&bb, "source", originstr);
	hwaddr_ntoa(frm->aladdr, alstr);
	blobmsg_add_string(&bb, "origin", alstr);
	blobmsg_add_string(&bb, "cmdu", frmbuffer);
	ubus_send_event(p->ctx, IEEE1905_OBJECT".cmdu", bb.head);
	blob_buf_free(&bb);
}

int snoop_process_cmdu(void *priv, struct cmdu_buff *frm)
{
	struct snoop_private *p = (struct snoop_private *)priv;

	if (!p->ctx || !frm)
		return -1;

	if (!p->paused)
		snoop_dump_cmdu(p, frm);

	return CMDU_OK;
}

int snoop_start(void *priv)
{
	struct snoop_private *p = (struct snoop_private *)priv;

	p->paused = 0;

	return 0;
}

int snoop_stop(void *priv)
{
	struct snoop_private *p = (struct snoop_private *)priv;

	p->paused = 1;

	return 0;
}


extern struct i1905_extmodule snoop;
struct i1905_extmodule snoop = {
	.id = "\x10\x20\x30\x40",
	.name = "snoop",
	.init = snoop_init,
	.exit = snoop_exit,
	.start = snoop_start,
	.stop = snoop_stop,
	.process_cmdu = snoop_process_cmdu,
	.num_ext = -1, /* all */
};


enum {
	SNOOP_TYPE,
	_SNOOP_POLICY_MAX,
};

static const struct blobmsg_policy snoop_policy[_SNOOP_POLICY_MAX] = {
	[SNOOP_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_ARRAY },
};


static int snoop_cmdu(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct blob_attr *tb[_SNOOP_POLICY_MAX];
	uint16_t types[16] = {0};
	struct snoop_private *p;
	struct blob_attr *attr;
	int num = 0;
	int rem;
	int i;


	p = container_of(obj, struct snoop_private, obj);
	blobmsg_parse(snoop_policy, _SNOOP_POLICY_MAX, tb,
		      blob_data(msg), blob_len(msg));

	if (!tb[SNOOP_TYPE])
		return UBUS_STATUS_INVALID_ARGUMENT;

	blobmsg_for_each_attr(attr, tb[SNOOP_TYPE], rem) {
		if (blobmsg_type(attr) == BLOBMSG_TYPE_INT16) {
			uint16_t type;
			char buf[8] = {0};
			uint16_t val;

			val = blobmsg_get_u16(attr);
			snprintf(buf, sizeof(buf), "0x%4d", val);
			type = strtoul(buf, NULL, 16);
			type &= 0xffff;
			types[num++] = type;
			if (num >= 16)
				break;
		}
	}

	memset(p->types, 0, sizeof(p->types));
	p->num_types = num;
	for (i = 0; i < num; i++)
		p->types[i] = types[i];

	return UBUS_STATUS_OK;
}

int snoop_publish_object(void *priv, const char *objname)
{
	struct ubus_object *obj;
	struct ubus_object_type *obj_type;
	struct ubus_method *obj_methods;
	struct ubus_method m[1] = {
		UBUS_METHOD("type", snoop_cmdu, snoop_policy),
	};
	int num_methods = ARRAY_SIZE(m);
	struct snoop_private *p = (struct snoop_private *)priv;
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

void snoop_remove_object(void *priv)
{
	struct snoop_private *p = (struct snoop_private *)priv;

	if (p && p->ctx) {
		if (p->obj.id != -1) {
			ubus_remove_object(p->ctx, &p->obj);
			free(p->obj.type);
			free((void *)p->obj.methods);
			free((void *)p->obj.name);
		}
	}
}

int snoop_init(void **priv, struct i1905_context *ieee1905)
{
	struct snoop_private *p;


	p = calloc(1, sizeof(struct snoop_private));
	if (!p)
		return -1;

	*priv = p;
	p->module = &snoop;
	if (ieee1905)
		p->ctx = ieee1905->bus;

	snoop_publish_object(p, IEEE1905_OBJECT_SNOOP);

	return 0;
}

static int snoop_exit(void *priv)
{
	struct snoop_private *p = (struct snoop_private *)priv;

	if (p) {
		snoop_remove_object(p);
		free(p);
	}

	return 0;
}
