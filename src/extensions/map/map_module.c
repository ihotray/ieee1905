/*
 * map_module.c - implements westside interface to map client applications.
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

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <easy/easy.h>

#include "util.h"
#include "cmdu.h"
#include "1905_tlvs.h"
#include "easymesh.h"

#include "map.h"
#include "map_module.h"


static void map_client_subscribe_cb(struct ubus_context *ctx, struct ubus_object *obj)
{
	struct registered_map_module *mod;


	mod = container_of(obj, struct registered_map_module, notify);
	fprintf(stderr, "map: '%s' %ssubscribed\n", mod->name,
		obj->has_subscribers ? "" : "un");

	if (!obj->has_subscribers) {
		list_del(&mod->list);
		if (mod->notify.id != -1) {
			int ret;

			ret = ubus_remove_object(ctx, &mod->notify);
			if (ret) {
				fprintf(stderr, "Failed to remove %x; err = %s\n",
					mod->notify.id, ubus_strerror(ret));
			}
			free(mod);
		}
	}
}

static int map_create_client_notify_object(struct map_private *p, void *notify)
{
	struct ubus_object *obj = notify;
	int ret;


	if (!obj)
		return -1;


	memset(obj, 0, sizeof(*obj));
	obj->subscribe_cb = map_client_subscribe_cb;
	ret = ubus_add_object(p->ctx, obj);
	if (ret) {
		fprintf(stderr, "Failed to add 'notify' object (err = %s)\n",
			ubus_strerror(ret));
		return ret;
	}

	fprintf(stderr, "Added notify object '0x%x'\n", obj->id);

	return 0;
}

static uint32_t map_register_multiap_module(struct map_private *p, char *name,
					 struct map_module *m)
{
	struct registered_map_module *rmod;
	int ret;


	if (!m)
		return -1;

	list_for_each_entry(rmod, &p->rmodlist, list) {
		if (!strncmp(rmod->name, name, strlen(rmod->name))) {
			fprintf(stderr, "map: %s is already registered\n", name);
			return -1;
		}
	}

	rmod = calloc(1, sizeof(*rmod));
	if (!rmod) {
		fprintf(stderr, "-ENOMEM\n");
		return -1;
	}

	strncpy(rmod->name, name, 64);
	memcpy(&rmod->module, m, sizeof(*m));
	ret = map_create_client_notify_object(p, &rmod->notify);
	if (ret) {
		free(rmod);
		return -1;
	}

	list_add_tail(&rmod->list, &p->rmodlist);

	return rmod->notify.id;
}

enum {
	REGISTER_MODULE_NAME,
	REGISTER_MODULE_DATA,
	_REGISTER_POLICY_MAX,
};

static const struct blobmsg_policy register_policy[_REGISTER_POLICY_MAX] = {
	[REGISTER_MODULE_NAME] = { .name = "module", .type = BLOBMSG_TYPE_STRING },
	[REGISTER_MODULE_DATA] = { .name = "data", .type = BLOBMSG_TYPE_STRING },
};


static int map_register_module(struct ubus_context *ctx,
			       struct ubus_object *obj,
			       struct ubus_request_data *req,
			       const char *method,
			       struct blob_attr *msg)
{
	int dlen = 2 * sizeof(struct map_module) + 1;
	struct blob_attr *tb[_REGISTER_POLICY_MAX];
	char module_data[512] = {0};
	struct map_private *p;
	char modname[64] = {0};
	struct map_module m;
	struct blob_buf bb;
	uint32_t oid;
	int datalen;



	p = container_of(obj, struct map_private, obj);

	blobmsg_parse(register_policy, _REGISTER_POLICY_MAX, tb,
		      blob_data(msg), blob_len(msg));

	if (!tb[REGISTER_MODULE_NAME] || !tb[REGISTER_MODULE_DATA]) {
		fprintf(stderr, "module name or data missing!\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	strncpy(modname, blobmsg_data(tb[REGISTER_MODULE_NAME]), 63);

	datalen = blobmsg_data_len(tb[REGISTER_MODULE_DATA]);
	memcpy(module_data, blobmsg_data(tb[REGISTER_MODULE_DATA]), datalen);
	if (datalen != dlen) {
		fprintf(stderr, "Invalid module data!\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	memset(&m, 0, sizeof(struct map_module));
	fprintf(stderr, "%s", module_data);
	strtob(module_data, sizeof(struct map_module), (unsigned char *)&m);

	fprintf(stderr, "map: registering module %s with id %x ...\n",
		modname, m.id);

	oid = map_register_multiap_module(p, modname, &m);
	if (oid == -1)
		return UBUS_STATUS_UNKNOWN_ERROR;

	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);
	blobmsg_add_u32(&bb, "oid", oid);
	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	fprintf(stderr, "map: module %s registration OK\n", modname);

	return UBUS_STATUS_OK;
}

static void map_subscribe_cb(struct ubus_context *ctx, struct ubus_object *obj)
{
	fprintf(stderr, "map: active subscribers = %d\n", obj->has_subscribers);
}

int map_create_notify_object(void *priv)
{
	struct map_private *p = (struct map_private *)priv;
	struct ubus_object *obj;
	int ret;


	fprintf(stderr, "map_private = 0x%p\n", p);
	obj = &p->obj_notify;
	memset(obj, 0, sizeof(*obj));
	obj->subscribe_cb = map_subscribe_cb;
	ret = ubus_add_object(p->ctx, obj);
	if (ret) {
		fprintf(stderr, "Failed to add 'notify' object (err = %s)\n",
			ubus_strerror(ret));
		return ret;
	}

	fprintf(stderr, "Added notify object '0x%x'\n", obj->id);

	return 0;
}

static int map_status(struct ubus_context *ctx,
			       struct ubus_object *obj,
			       struct ubus_request_data *req,
			       const char *method,
			       struct blob_attr *msg)
{
	struct registered_map_module *m = NULL;
	struct map_private *p;
	struct blob_buf bb;
	void *a, *aa;

	p = container_of(obj, struct map_private, obj);
	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);

	blobmsg_add_u8(&bb, "fuzz", p->fuzz_cmdus ? true : false);
	a = blobmsg_open_array(&bb, "modules");
	list_for_each_entry(m, &p->rmodlist, list) {
		aa = blobmsg_open_table(&bb, "");
		blobmsg_add_string(&bb, "name", m->name);
		blobmsg_add_u32(&bb, "id", m->module.id);
		blobmsg_close_table(&bb, aa);
	}
	blobmsg_close_array(&bb, a);
	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

static int map_fuzz_cmdus(struct ubus_context *ctx,
			       struct ubus_object *obj,
			       struct ubus_request_data *req,
			       const char *method,
			       struct blob_attr *msg)
{
	struct map_private *p;


	p = container_of(obj, struct map_private, obj);
	p->fuzz_cmdus = !p->fuzz_cmdus;

	fprintf(stderr, "map: cmdu fuzzing %sabled\n", p->fuzz_cmdus ? "en":"dis");

	return UBUS_STATUS_OK;
}

int map_publish_object(void *priv, const char *objname)
{
	struct ubus_object *obj;
	struct ubus_object_type *obj_type;
	struct ubus_method *obj_methods;
	struct ubus_method m[3] = {
		UBUS_METHOD("register", map_register_module, register_policy),
		UBUS_METHOD_NOARG("status", map_status),
		UBUS_METHOD_NOARG("fuzz", map_fuzz_cmdus),
	};
	int num_methods = ARRAY_SIZE(m);
	struct map_private *p = (struct map_private *)priv;
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

	/* TODO: create a notify object per-registered mapclient */
	map_create_notify_object(p);


	return 0;
}

void map_unregister_modules(void *priv)
{
	struct map_private *p = (struct map_private *)priv;
	struct registered_map_module *m, *tmp;
	int ret;

	list_for_each_entry_safe(m, tmp, &p->rmodlist, list) {
		list_del(&m->list);
		if (m->notify.id != -1) {
			ret = ubus_remove_object(p->ctx, &m->notify);
			if (ret) {
				fprintf(stderr, "Failed to remove %x; err = %s\n",
					m->notify.id, ubus_strerror(ret));
			}
			m->notify.id = -1;
			free(m);
		}
	}
}

void map_remove_object(void *priv)
{
	struct map_private *p = (struct map_private *)priv;

	if (p && p->ctx) {
		if (p->obj.id != -1) {
			ubus_remove_object(p->ctx, &p->obj);
			free(p->obj.type);
			free((void *)p->obj.methods);
			free((void *)p->obj.name);
		}

		if (p->obj_notify.id != -1)
			ubus_remove_object(p->ctx, &p->obj_notify);
	}
}
