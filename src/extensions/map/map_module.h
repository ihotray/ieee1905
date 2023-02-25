/*
 * map_module.h - header file for westside interface to map client applications.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef MAP_MODULE_H
#define MAP_MODULE_H

#include <cmdu.h>

typedef uint32_t mapmodule_object_t;
typedef uint8_t mapmodule_cmdu_mask_t[16];

struct map_module {
	mapmodule_object_t id;
	mapmodule_cmdu_mask_t cmdu_mask;
	char process_cmdu_funcname[64];
};


int map_prepare_cmdu_mask(uint8_t mask[], ...);
const char *map_cmdu_type2str(uint16_t type);
const char *map_tlv_type2str(uint8_t type);

#define map_cmdu_mask_isset(m, f) \
({ \
	(!!(m[(f >= 0x8000 ? 4 : 0) + (f >= 0x8000 ? f - 0x8000 : f) / 8] & \
	(1 << ((f >= 0x8000 ? f - 0x8000 : f) % 8)))); \
})


int map_subscribe(void *bus, void *publisher,
		  const char *name, mapmodule_cmdu_mask_t *mask, void *priv,
		  int (*sub_cb)(void *bus, void *priv, void *data),
		  int (*del_cb)(void *bus, void *priv, void *data),
		  void **subscriber);

int map_unsubscribe(void *bus, void *subscriber);

enum MAP_STATUS {
	/* Existing ieee1905 error codes start at 0 offset */
	MAP_STATUS_OK = CMDU_STATUS_OK,
	MAP_STATUS_ERR_TLV_MALFORMED = CMDU_STATUS_ERR_TLV_MALFORMED,
	MAP_STATUS_ERR_TLV_NUM_LESS = CMDU_STATUS_ERR_TLV_NUM_LESS,
	MAP_STATUS_ERR_TLV_NUM_MORE = CMDU_STATUS_ERR_TLV_NUM_MORE,
	MAP_STATUS_ERR_TLV_NO_EOM = CMDU_STATUS_ERR_TLV_NO_EOM,
	MAP_STATUS_ERR_TLV_RESIDUE_DATA = CMDU_STATUS_ERR_TLV_RESIDUE_DATA,
	MAP_STATUS_ERR_TLV_LEN_INSUFFICIENT = CMDU_STATUS_ERR_TLV_LEN_INSUFFICIENT,
	MAP_STATUS_ERR_TLV_LEN_OVERFLOW = CMDU_STATUS_ERR_TLV_LEN_OVERFLOW,
	MAP_STATUS_ERR_CMDU_MALFORMED = CMDU_STATUS_ERR_CMDU_MALFORMED,
	MAP_STATUS_ERR_MISC = CMDU_STATUS_ERR_MISC,

	/* MAP plugin specific error codes start at 10000 offset */
	MAP_STATUS_ERR_FIRST = 10000,

	MAP_STATUS_ERR_CMDU_TYPE_NOT_SUPPORTED = MAP_STATUS_ERR_FIRST,
	MAP_STATUS_ERR_MAP_PROFILE_NOT_SUPPORTED,
	MAP_STATUS_ERR_MAP_POLICY_NOT_FOUND,
	MAP_STATUS_ERR_TLVS_OUTPUT_ARRAY_INSUFFICIENT,

	MAP_STATUS_ERR_AFTER_LAST
};

int *map_get_errval(void);
#define map_error (*map_get_errval())

const char *map_strerror(int err);

int map_cmdu_parse_tlvs(struct cmdu_buff *cmdu, struct tlv *tv[][16], int num_tvi, int revision);

int map_cmdu_get_multiap_profile(struct cmdu_buff *cmdu);

#endif /* MAP_MODULE_H */
