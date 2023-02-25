/*
 * map.h - header for internal use of multi-ap plugin. Not for export.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef MAP2_I_H
#define MAP2_I_H


#include "timer.h"
#include "map_module.h"

enum {
	MAP_MODULE_NOTPRESENT,
	MAP_MODULE_REGISTERED,
	MAP_MODULE_STARTED,
	MAP_MODULE_PAUSED,
};

struct registered_map_module {
	char name[64];
	struct map_module module;
	uint32_t state;
	void *handle;
	struct ubus_subscriber sub;
	struct list_head list;
	struct ubus_object notify;
};

struct map_private {
	void *module;
	uint8_t buf[512];
	atimer_t t;
	bool fuzz_cmdus;

	struct list_head rmodlist;	/* list of registered_map_module */
	void *ieee1905_context;
	struct ubus_context *ctx;
	struct ubus_object obj;
	struct ubus_object obj_notify;
};


int map_publish_object(void *priv, const char *objname);
void map_remove_object(void *priv);
void map_unregister_modules(void *priv);

#endif /* MAP2_I_H */
