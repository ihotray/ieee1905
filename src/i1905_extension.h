/*
 * i1905_extension.h
 * IEEE-1905 extension modules definitions and functions.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef I1905_EXTENSION_H
#define I1905_EXTENSION_H


#include <stdint.h>
#include <libubox/list.h>

#ifdef __cplusplus
extern "C" {
#endif


enum cmdu_extension_policy {
	EXTMODULE_CMDU_NOP,		/* don't extend; default behavior */
	EXTMODULE_CMDU_EXTEND,		/* extend with new/changed tlvs */
	EXTMODULE_CMDU_OVERRIDE,	/* full override by extension */
};

struct i1905_cmdu_extension {
	uint16_t type;
	enum cmdu_extension_policy policy;
};

struct i1905_context {
	void *bus;
	void *context;
};

typedef int (*extmodule_init_t)(void **priv, struct i1905_context *ieee1905);
typedef int (*extmodule_exit_t)(void *priv);
typedef int (*extmodule_func_t)(void *priv);

typedef enum cmdu_process_result {
	CMDU_NOP = -2,	/* not processed */
	CMDU_NOK = -1,	/* not OK */
	CMDU_OK,
	CMDU_DONE,	/* done processing */
	CMDU_DROP,	/* discard */
	CMDU_SKIP,
} cmdu_res_t;


struct i1905_extmodule {
	char name[128];
	uint8_t id[16];
	uint32_t paused;
	void *priv;
	extmodule_init_t init;
	extmodule_exit_t exit;
	extmodule_func_t start;
	extmodule_func_t stop;
	struct i1905_cmdu_extension *ext;
	int num_ext;
	uint16_t from_newtype;
	uint16_t to_newtype;
	cmdu_res_t (*process_cmdu)(void *priv, struct cmdu_buff *rxf);
	int (*event_cb)(void *priv, const char *event, size_t len);
	void *handle;
	struct list_head list;
};

struct i1905_non1905_ifneighbor {
	uint8_t if_macaddr[6];		/* interface macaddress */
	uint32_t num_non1905;
	uint8_t non1905_macaddr[];	/* packed array of 6-byte macaddresses */
} __attribute__ ((packed));


int ieee1905_get_non1905_neighbors(void *ieee1905, void *buf, size_t *sz);

int ieee1905_send_cmdu(void *ieee1905, uint8_t *dst, uint8_t *src, uint16_t type,
		       uint16_t *mid, uint8_t *data, int len);

int ieee1905_get_alid(void *ieee1905, uint8_t *aladdr);

#ifdef __cplusplus
}
#endif

#endif /* I1905_EXTENSION_H */
