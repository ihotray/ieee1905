/*
 * policy.c - CMDU policy for Easymesh TLVs
 *
 * Copyright (C) 2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 * See LICENSE file for license related information.
 *
 */


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "util.h"
#include "bufutil.h"
#include "1905_tlvs.h"
#include "cmdu.h"
#include "easymesh.h"
#include "map_module.h"

#define CMDU_TYPE_MAP_START	CMDU_1905_ACK
#define CMDU_TYPE_MAP_END	MAP_CMDU_TYPE_MAX

struct cmdu_tlv_policy {
	size_t num;
	struct tlv_policy *pol;
};

#include "r1.c"
#include "r2.c"
#include "r3.c"
#include "r4.c"


int map_cmdu_parse_tlvs(struct cmdu_buff *cmdu, struct tlv *tv[][16], int num_tv, int revision)
{
	struct cmdu_tlv_policy *pol = NULL;
	uint16_t type;
	int idx = 0;
	int i;

	map_error = MAP_STATUS_OK;

	if (!cmdu || !cmdu->cdata) {
		map_error =  MAP_STATUS_ERR_CMDU_MALFORMED;
		return -1;
	}

	type = cmdu_get_type(cmdu);

	if (type >= CMDU_TYPE_1905_START && type <= CMDU_TYPE_1905_END) {
		idx = type;
	} else if (type >= CMDU_TYPE_MAP_START && type <= CMDU_TYPE_MAP_END) {
		idx = type - CMDU_TYPE_MAP_START + CMDU_TYPE_1905_END + 1;
	} else {
		map_error = MAP_STATUS_ERR_CMDU_TYPE_NOT_SUPPORTED;
		return -1;
	}

	switch (revision) {
	case 1:
		if (idx > ARRAY_SIZE(easymesh_policy_r1))
			return -1;

		pol = &easymesh_policy_r1[idx];
		break;
#if (EASYMESH_VERSION >= 2)
	case 2:
		if (idx > ARRAY_SIZE(easymesh_policy_r2)) {
			map_error = MAP_STATUS_ERR_MAP_POLICY_NOT_FOUND;
			return -1;
		}

		pol = &easymesh_policy_r2[idx];
		break;
#endif
#if (EASYMESH_VERSION >= 3)
	case 3:
		if (idx > ARRAY_SIZE(easymesh_policy_r3))
			return -1;

		pol = &easymesh_policy_r3[idx];
		break;
#endif
#if (EASYMESH_VERSION >= 4)
	case 4:
		if (idx > ARRAY_SIZE(easymesh_policy_r4)) {
			map_error = MAP_STATUS_ERR_MAP_POLICY_NOT_FOUND;
			return -1;
		}

		pol = &easymesh_policy_r4[idx];
		break;
#endif
	default:

		map_error = MAP_STATUS_ERR_MAP_PROFILE_NOT_SUPPORTED;
		return -1;
	}

	if (pol->pol == NULL) {
		map_error = MAP_STATUS_ERR_MAP_POLICY_NOT_FOUND;
		return -1;
	}

	if (pol->num == 0)
		return 0;

	if (num_tv < pol->num) {
		fprintf(stderr, "%s: minimum %zu tv needed!\n", __func__, pol->num);
		map_error = MAP_STATUS_ERR_TLVS_OUTPUT_ARRAY_INSUFFICIENT;
		return -1;
	}

	/* explicitly zero out the passed tlvs array before using */
	for (i = 0; i < num_tv; i++)
		memset(tv[i], 0, 16 * sizeof(struct tlv *));

	if (cmdu_parse_tlvs(cmdu, tv, pol->pol, pol->num)) {
		map_error = ieee1905_error;
		return -1;
	}

	return 0;
}
