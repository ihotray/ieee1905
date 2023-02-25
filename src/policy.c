/*
 * policy.c - 1905 tlvs policy
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

struct cmdu_tlv_policy {
	size_t num;
	struct tlv_policy *pol;
};

#define DEFINE_POLICY(t)	static struct tlv_policy i1905_policy_ ## t[]

#define P(t)			{ .num = ARRAY_SIZE(i1905_policy_ ## t), .pol = i1905_policy_ ## t }


DEFINE_POLICY(CMDU_TYPE_TOPOLOGY_DISCOVERY) = {
	{
		.type = TLV_TYPE_AL_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6
	},
	{
		.type = TLV_TYPE_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6
	},
};

DEFINE_POLICY(CMDU_TYPE_TOPOLOGY_NOTIFICATION) = {
	{
		.type = TLV_TYPE_AL_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6
	},
};

DEFINE_POLICY(CMDU_TYPE_TOPOLOGY_QUERY) = {
	/* no tlvs */
};

DEFINE_POLICY(CMDU_TYPE_TOPOLOGY_RESPONSE) = {
	{	.type = TLV_TYPE_DEVICE_INFORMATION_TYPE,
		.present = TLV_PRESENT_ONE
	},
	{	.type = TLV_TYPE_DEVICE_BRIDGING_CAPABILITIES,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	{	.type = TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	{	.type = TLV_TYPE_NEIGHBOR_DEVICE_LIST,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	{	.type = TLV_TYPE_POWER_OFF_INTERFACE,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	{	.type = TLV_TYPE_L2_NEIGHBOR_DEVICE,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
};

DEFINE_POLICY(CMDU_TYPE_VENDOR_SPECIFIC) = {
	/* user defined */
};

DEFINE_POLICY(CMDU_TYPE_LINK_METRIC_QUERY) = {
	[0] = {
		.type = TLV_TYPE_LINK_METRIC_QUERY,
		.present = TLV_PRESENT_ONE
	},
};

DEFINE_POLICY(CMDU_TYPE_LINK_METRIC_RESPONSE) = {
	[0] = {
		.type = TLV_TYPE_TRANSMITTER_LINK_METRIC,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	[1] = {
		.type = TLV_TYPE_RECEIVER_LINK_METRIC,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
};

DEFINE_POLICY(CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH) = {
	[0] = {
		.type = TLV_TYPE_AL_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6, /* macaddr */
	},
	[1] = {
		.type = TLV_TYPE_SEARCHED_ROLE,
		.present = TLV_PRESENT_ONE,
		.len = sizeof(struct tlv_searched_role),
	},
	[2] = {
		.type = TLV_TYPE_AUTOCONFIG_FREQ_BAND,
		.present = TLV_PRESENT_ONE,
		.len = sizeof(struct tlv_autoconfig_band),
	},
};

DEFINE_POLICY(CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE) = {
	[0] = {
		.type = TLV_TYPE_SUPPORTED_ROLE,
		.present = TLV_PRESENT_ONE,
		.len = sizeof(struct tlv_supported_role),
	},
	[1] = {
		.type = TLV_TYPE_SUPPORTED_FREQ_BAND,
		.present = TLV_PRESENT_ONE,
		.len = sizeof(struct tlv_supported_band),
	},
};

DEFINE_POLICY(CMDU_TYPE_AP_AUTOCONFIGURATION_WSC) = {
	[1] = {
		.type = TLV_TYPE_WSC,
		.present = TLV_PRESENT_ONE
	},
};

DEFINE_POLICY(CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW) = {
	[0] = {
		.type = TLV_TYPE_AL_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6
	},
	[1] = {
		.type = TLV_TYPE_SUPPORTED_ROLE,
		.present = TLV_PRESENT_ONE,
		.len = sizeof(struct tlv_supported_role)
	},
	[2] = {
		.type = TLV_TYPE_SUPPORTED_FREQ_BAND,
		.present = TLV_PRESENT_ONE,
		.len = sizeof(struct tlv_supported_band)
	},
};

DEFINE_POLICY(CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION) = {
	[0] = {
		.type = TLV_TYPE_AL_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6
	},
	[1] = {
		.type = TLV_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION,
		.present = TLV_PRESENT_ONE
	},
};

DEFINE_POLICY(CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION) = {
	[0] = {
		.type = TLV_TYPE_AL_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6
	},
	[1] = {
		.type = TLV_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION,
		.present = TLV_PRESENT_ONE,
		.len = sizeof(struct tlv_pbc_join_notification)
	},
};

DEFINE_POLICY(CMDU_TYPE_HIGHER_LAYER_QUERY) = {
	/* no tlvs */
};

DEFINE_POLICY(CMDU_TYPE_HIGHER_LAYER_RESPONSE) = {
	[0] = {
		.type = TLV_TYPE_AL_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6
	},
	[1] = {
		.type = TLV_TYPE_1905_PROFILE_VERSION,
		.present = TLV_PRESENT_ONE,
		.len = sizeof(struct tlv_1905_profile)
	},
	[2] = {
		.type = TLV_TYPE_DEVICE_IDENTIFICATION,
		.present = TLV_PRESENT_ONE,
		.len = sizeof(struct tlv_device_identification)
	},
	[3] = {
		.type = TLV_TYPE_CONTROL_URL,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
	[4] = {
		.type = TLV_TYPE_IPV4,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
	[5] = {
		.type = TLV_TYPE_IPV6,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
};

DEFINE_POLICY(CMDU_TYPE_INTERFACE_POWER_CHANGE_REQUEST) = {
	[0] = {
		.type = TLV_TYPE_INTERFACE_POWER_CHANGE_INFORMATION,
		.present = TLV_PRESENT_MORE,
	},
};

DEFINE_POLICY(CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE) = {
	[0] = {
		.type = TLV_TYPE_INTERFACE_POWER_CHANGE_STATUS,
		.present = TLV_PRESENT_MORE,
	},
};

DEFINE_POLICY(CMDU_TYPE_GENERIC_PHY_QUERY) = {
	/* no tlvs */
};

DEFINE_POLICY(CMDU_TYPE_GENERIC_PHY_RESPONSE) = {
	[0] = {
		.type = TLV_TYPE_GENERIC_PHY_DEVICE_INFORMATION,
		.present = TLV_PRESENT_ONE,
	},
};

static struct cmdu_tlv_policy i1905_policy[] = {
	P(CMDU_TYPE_TOPOLOGY_DISCOVERY),
	P(CMDU_TYPE_TOPOLOGY_NOTIFICATION),
	P(CMDU_TYPE_TOPOLOGY_QUERY),
	P(CMDU_TYPE_TOPOLOGY_RESPONSE),
	P(CMDU_TYPE_VENDOR_SPECIFIC),
	P(CMDU_TYPE_LINK_METRIC_QUERY),	/* 0x0005 */
	P(CMDU_TYPE_LINK_METRIC_RESPONSE),
	P(CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH),
	P(CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE),
	P(CMDU_TYPE_AP_AUTOCONFIGURATION_WSC),
	P(CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW), /* 0x000a */
	P(CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION),
	P(CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION),
	P(CMDU_TYPE_HIGHER_LAYER_QUERY),
	P(CMDU_TYPE_HIGHER_LAYER_RESPONSE),
	P(CMDU_TYPE_INTERFACE_POWER_CHANGE_REQUEST), /* 0x000f */
	P(CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE),
	P(CMDU_TYPE_GENERIC_PHY_QUERY),
	P(CMDU_TYPE_GENERIC_PHY_RESPONSE),	/* 0x0012 */
};

int i1905_cmdu_parse_tlvs(struct cmdu_buff *cmdu, struct tlv *tv[][16], int num_tv)
{
	uint16_t type;


	if (!cmdu)
		return -1;

	type = cmdu_get_type(cmdu);
	if (type > CMDU_TYPE_1905_END)
		return -1;

	if (i1905_policy[type].num == 0)
		return 0;

	if (num_tv < i1905_policy[type].num) {
		fprintf(stderr, "%s: minimum %zu tv needed!\n", __func__, i1905_policy[type].num);
		return -1;
	}

	return cmdu_parse_tlvs(cmdu, tv, i1905_policy[type].pol, num_tv);
}
