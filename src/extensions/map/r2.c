/*
 * r2.c - Easymesh-R2 TLV policy
 *
 * Copyright (C) 2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 * See LICENSE file for license related information.
 *
 */

#if (EASYMESH_VERSION >= 2)

#define DEFINE_POLICY(t)	static struct tlv_policy map_policy_r2_ ## t[]
#define P(t)			{ .num = ARRAY_SIZE(map_policy_r2_ ## t), .pol = map_policy_r2_ ## t }


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
	{
		.type = MAP_TLV_CLIENT_ASSOCIATION_EVENT,
		.present = TLV_PRESENT_OPTIONAL_ONE,
		.len = sizeof(struct tlv_client_assoc_event)
	},
};

DEFINE_POLICY(CMDU_TYPE_TOPOLOGY_QUERY) = {
	{
		.type = MAP_TLV_MULTIAP_PROFILE,
		.present = TLV_PRESENT_ONE,
		.len = 1,
	},
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
	{	.type = MAP_TLV_SUPPORTED_SERVICE,
		.present = TLV_PRESENT_OPTIONAL_ONE,
		.minlen = 1	/* when num_services is 0 */
	},
	{	.type = MAP_TLV_AP_OPERATIONAL_BSS,
		.present = TLV_PRESENT_ONE,
		.minlen = 1	/* sizeof(struct tlv_ap_oper_bss) */
	},
	{	.type = MAP_TLV_ASSOCIATED_CLIENTS,
		.present = TLV_PRESENT_OPTIONAL_ONE,
		.minlen = 1	/* sizeof(struct tlv_assoc_client) */
	},
	{	.type = MAP_TLV_MULTIAP_PROFILE,
		.present = TLV_PRESENT_ONE,
		.len = 1	/* sizeof(struct tlv_map_profile) */
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
	[0] = { .type = TLV_TYPE_AL_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6, /* macaddr */
	},
	[1] = { .type = TLV_TYPE_SEARCHED_ROLE,
		.present = TLV_PRESENT_ONE,
		.len = 1, /* tlv_searched_role */
	},
	[2] = { .type = TLV_TYPE_AUTOCONFIG_FREQ_BAND,
		.present = TLV_PRESENT_ONE,
		.len = 1, /* tlv_autoconfig_band */
	},
	[3] = { .type = MAP_TLV_SUPPORTED_SERVICE,
		.present = TLV_PRESENT_OPTIONAL_ONE,
		.minlen = 1, /* num of services */
	},
	[4] = { .type = MAP_TLV_SEARCHED_SERVICE,
		.present = TLV_PRESENT_OPTIONAL_ONE,
		.minlen = 1, /* num of services */
	},
	[5] = { .type = MAP_TLV_MULTIAP_PROFILE,
		.present = TLV_PRESENT_ONE,
		.len = 1, /* tlv_map_profile */
	},
};


DEFINE_POLICY(CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE) = {
	[0] = { .type = TLV_TYPE_SUPPORTED_ROLE,
		.present = TLV_PRESENT_ONE,
		.len = 1, /* tlv_supported_role */
	},
	[1] = { .type = TLV_TYPE_SUPPORTED_FREQ_BAND,
		.present = TLV_PRESENT_ONE,
		.len = 1, /* tlv_supported_band */
	},
	[2] = { .type = MAP_TLV_SUPPORTED_SERVICE,
		.present = TLV_PRESENT_OPTIONAL_ONE,
		.minlen = 1, /* num of services */
	},
	[3] = { .type = MAP_TLV_MULTIAP_PROFILE,
		.present = TLV_PRESENT_ONE,
		.len = 1, /* tlv_map_profile */
	},
};

/* WSC-M1 */
DEFINE_POLICY(CMDU_TYPE_AP_AUTOCONFIGURATION_WSC) = {
	[0] = { .type = MAP_TLV_AP_RADIO_BASIC_CAPABILITIES,
		.present = TLV_PRESENT_ONE,
		.minlen = 8, /* tlv_ap_radio_basic_cap */
	},
	[1] = { .type = TLV_TYPE_WSC,
		.present = TLV_PRESENT_ONE
	},
	[2] = { .type = MAP_TLV_PROFILE2_AP_CAPABILITY,
		.present = TLV_PRESENT_ONE,
		.len = 4, /* tlv_profile2_ap_cap */
	},
	[3] = { .type = MAP_TLV_AP_RADIO_ADV_CAPABILITY,
		.present = TLV_PRESENT_ONE,
		.len = 7, /* tlv_ap_radio_adv_cap */
	},
};

#if 0
/* WSC-M2 */
DEFINE_POLICY(CMDU_TYPE_AP_AUTOCONFIGURATION_WSC_M2) = {
	[0] = { .type = MAP_TLV_AP_RADIO_IDENTIFIER,
		.present = TLV_PRESENT_ONE,
	},
	[1] = { .type = TLV_TYPE_WSC,
		.present = TLV_PRESENT_MORE,
	},
	[2] = { .type = MAP_TLV_DEFAULT_8021Q_SETTINGS,
		.present = TLV_PRESENT_OPTIONAL_ONE,
	},
	[3] = { .type = MAP_TLV_TRAFFIC_SEPARATION_POLICY,
		.present = TLV_PRESENT_OPTIONAL_ONE
	}
};
#endif

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



/* Easymesh CMDUs */

DEFINE_POLICY(CMDU_1905_ACK) = {
	[0] = {
		.type = MAP_TLV_ERROR_CODE,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
};

DEFINE_POLICY(CMDU_AP_CAPABILITY_QUERY) = {
	/* empty */
};

DEFINE_POLICY(CMDU_AP_CAPABILITY_REPORT) = {
	[0] = {
		.type = MAP_TLV_AP_CAPABILITY,
		.present = TLV_PRESENT_ONE
	},
	[1] = {
		.type = MAP_TLV_AP_RADIO_BASIC_CAPABILITIES,
		.present = TLV_PRESENT_MORE
	},
	[2] = {
		.type = MAP_TLV_AP_HT_CAPABILITIES,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	[3] = {
		.type = MAP_TLV_AP_VHT_CAPABILITIES,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	[4] = {
		.type = MAP_TLV_AP_HE_CAPABILITIES,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	[5] = {
		.type = MAP_TLV_CHANNEL_SCAN_CAPABILITY,
		.present = TLV_PRESENT_ONE
	},
	[6] = {
		.type = MAP_TLV_CAC_CAPABILITY,
		.present = TLV_PRESENT_ONE
	},
	[7] = {
		.type = MAP_TLV_PROFILE2_AP_CAPABILITY,
		.present = TLV_PRESENT_ONE
	},
	[8] = {
		.type = MAP_TLV_METRIC_COLLECTION_INTERVAL,
		.present = TLV_PRESENT_ONE
	},
};

DEFINE_POLICY(CMDU_POLICY_CONFIG_REQ) = {
	[0] = {
		.type = MAP_TLV_STEERING_POLICY,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
	[1] = {
		.type = MAP_TLV_METRIC_REPORTING_POLICY,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
	[2] = {
		.type = MAP_TLV_DEFAULT_8021Q_SETTINGS,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
	[3] = {
		.type = MAP_TLV_TRAFFIC_SEPARATION_POLICY,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
	[4] = {
		.type = MAP_TLV_CHANNEL_SCAN_REPORTING_POLICY,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
	[5] = {
		.type = MAP_TLV_UNSUCCESS_ASSOCIATION_POLICY,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
	[6] = {
		.type = MAP_TLV_BACKHAUL_BSS_CONFIG,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
};

DEFINE_POLICY(CMDU_CHANNEL_PREFERENCE_QUERY) = {
	/* empty */
};

DEFINE_POLICY(CMDU_CHANNEL_PREFERENCE_REPORT) = {
	[0] = {
		.type = MAP_TLV_CHANNEL_PREFERENCE,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	[1] = {
		.type = MAP_TLV_RADIO_OPERATION_RESTRICTION,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	[2] = {
		.type = MAP_TLV_CAC_COMPLETION_REPORT,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
	[3] = {
		.type = MAP_TLV_CAC_STATUS_REPORT,
		.present = TLV_PRESENT_ONE
	},
};

DEFINE_POLICY(CMDU_CHANNEL_SELECTION_REQ) = {
	[0] = {
		.type = MAP_TLV_CHANNEL_PREFERENCE,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	[1] = {
		.type = MAP_TLV_TRANSMIT_POWER_LIMIT,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
};

DEFINE_POLICY(CMDU_CHANNEL_SELECTION_RESPONSE) = {
	[0] = {
		.type = MAP_TLV_CHANNEL_SELECTION_RESPONSE,
		.present = TLV_PRESENT_MORE,
	},
};

DEFINE_POLICY(CMDU_OPERATING_CHANNEL_REPORT) = {
	[0] = {
		.type = MAP_TLV_OPERATING_CHANNEL_REPORT,
		.present = TLV_PRESENT_MORE
	},
};

DEFINE_POLICY(CMDU_CLIENT_CAPABILITY_QUERY) = {
	[0] = {
		.type = MAP_TLV_CLIENT_INFO,
		.present = TLV_PRESENT_ONE
	}
};

DEFINE_POLICY(CMDU_CLIENT_CAPABILITY_REPORT) = {
	[0] = {
		.type = MAP_TLV_CLIENT_INFO,
		.present = TLV_PRESENT_ONE
	},
	[1] = {
		.type = MAP_TLV_CLIENT_CAPABILITY_REPORT,
		.present = TLV_PRESENT_ONE
	},
	[2] = {
		.type = MAP_TLV_ERROR_CODE,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
};

DEFINE_POLICY(CMDU_AP_METRICS_QUERY) = {
	[0] = {
		.type = MAP_TLV_AP_METRIC_QUERY,
		.present = TLV_PRESENT_ONE
	},
	[1] = {
		.type = MAP_TLV_AP_RADIO_IDENTIFIER,
		.present = TLV_PRESENT_OPTIONAL_MORE
	}
};

DEFINE_POLICY(CMDU_AP_METRICS_RESPONSE) = {
	[0] = {
		.type = MAP_TLV_AP_METRICS,
		.present = TLV_PRESENT_MORE,
	},
	[1] = {
		.type = MAP_TLV_ASSOCIATED_STA_TRAFFIC_STATS,
		.present = TLV_PRESENT_OPTIONAL_MORE,
	},
	[2] = {
		.type = MAP_TLV_ASSOCIATED_STA_LINK_METRICS,
		.present = TLV_PRESENT_OPTIONAL_MORE,
	},
	[3] = {
		.type = MAP_TLV_AP_EXTENDED_METRICS,
		.present = TLV_PRESENT_MORE,
	},
	[4] = {
		.type = MAP_TLV_RADIO_METRICS,
		.present = TLV_PRESENT_OPTIONAL_MORE,
	},
	[5] = {
		.type = MAP_TLV_ASSOCIATED_STA_EXT_LINK_METRICS,
		.present = TLV_PRESENT_OPTIONAL_MORE,
	},
};

DEFINE_POLICY(CMDU_ASSOC_STA_LINK_METRICS_QUERY) = {
	[0] = {
		.type = MAP_TLV_STA_MAC_ADDRESS,
		.present = TLV_PRESENT_ONE
	}
};

DEFINE_POLICY(CMDU_ASSOC_STA_LINK_METRICS_RESPONSE) = {
	[0] = {
		.type = MAP_TLV_ASSOCIATED_STA_LINK_METRICS,
		.present = TLV_PRESENT_MORE
	},
	[1] = {
		.type = MAP_TLV_ERROR_CODE,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
	[2] = {
		.type = MAP_TLV_ASSOCIATED_STA_EXT_LINK_METRICS,
		.present = TLV_PRESENT_MORE
	}
};

DEFINE_POLICY(CMDU_UNASSOC_STA_LINK_METRIC_QUERY) = {
	[0] = {
		.type = MAP_TLV_UNASSOCIATED_STA_LINK_METRICS_QUERY,
		.present = TLV_PRESENT_ONE
	}
};

DEFINE_POLICY(CMDU_UNASSOC_STA_LINK_METRIC_RESPONSE) = {
	[0] = {
		.type = MAP_TLV_UNASSOCIATED_STA_LINK_METRICS_RESPONSE,
		.present = TLV_PRESENT_ONE
	},
};

DEFINE_POLICY(CMDU_BEACON_METRICS_QUERY) = {
	[0] = {
		.type = MAP_TLV_BEACON_METRICS_QUERY,
		.present = TLV_PRESENT_ONE
	}
};

DEFINE_POLICY(CMDU_BEACON_METRICS_RESPONSE) = {
	[0] = {
		.type = MAP_TLV_BEACON_METRICS_RESPONSE,
		.present = TLV_PRESENT_ONE
	},
};

DEFINE_POLICY(CMDU_COMBINED_INFRA_METRICS) = {
	[0] = {
		.type = MAP_TLV_AP_METRICS,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	[1] = {
		.type = TLV_TYPE_TRANSMITTER_LINK_METRIC,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	[2] = {
		.type = TLV_TYPE_RECEIVER_LINK_METRIC,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
};

DEFINE_POLICY(CMDU_CLIENT_STEERING_REQUEST) = {
	[0] = {
		.type = MAP_TLV_STEERING_REQUEST,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
	[1] = {
		.type = MAP_TLV_PROFILE2_STEERING_REQ,
		.present = TLV_PRESENT_OPTIONAL_ONE
	}
};

DEFINE_POLICY(CMDU_CLIENT_STEERING_BTM_REPORT) = {
	[0] = {
		.type = MAP_TLV_STEERING_BTM_REPORT,
		.present = TLV_PRESENT_ONE
	},
};

DEFINE_POLICY(CMDU_CLIENT_ASSOC_CONTROL_REQUEST) = {
	[0] = {
		.type = MAP_TLV_CLIENT_ASSOCIATION_CONTROL_REQUEST,
		.present = TLV_PRESENT_MORE
	}
};

DEFINE_POLICY(CMDU_STEERING_COMPLETED) = {
	/* empty */
};

DEFINE_POLICY(CMDU_HIGHER_LAYER_DATA) = {
	[0] = {
		.type = MAP_TLV_HIGHER_LAYER_DATA,
		.present = TLV_PRESENT_ONE
	},
};

DEFINE_POLICY(CMDU_BACKHAUL_STEER_REQUEST) = {
	[0] = {
		.type = MAP_TLV_BACKHAUL_STEERING_REQUEST,
		.present = TLV_PRESENT_ONE
	},
};

DEFINE_POLICY(CMDU_BACKHAUL_STEER_RESPONSE) = {
	[0] = {
		.type = MAP_TLV_BACKHAUL_STEERING_RESPONSE,
		.present = TLV_PRESENT_ONE
	},
	[1] = {
		.type = MAP_TLV_ERROR_CODE,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
};

DEFINE_POLICY(CMDU_CHANNEL_SCAN_REQUEST) = {
	[0] = {
		.type = MAP_TLV_CHANNEL_SCAN_REQ,
		.present = TLV_PRESENT_ONE,
		.minlen = 2,
	}
};

DEFINE_POLICY(CMDU_CHANNEL_SCAN_REPORT) = {
	[0] = {
		.type = MAP_TLV_TIMESTAMP,
		.present = TLV_PRESENT_ONE,
	},
	[1] = {
		.type = MAP_TLV_CHANNEL_SCAN_RES,
		.present = TLV_PRESENT_MORE,
	}
};

DEFINE_POLICY(CMDU_CAC_REQUEST) = {
	[0] = {
		.type = MAP_TLV_CAC_REQ,
		.present = TLV_PRESENT_ONE
	}
};

DEFINE_POLICY(CMDU_CAC_TERMINATION) = {
	[0] = {
		.type = MAP_TLV_CAC_TERMINATION,
		.present = TLV_PRESENT_ONE
	}
};

DEFINE_POLICY(CMDU_CLIENT_DISASSOCIATION_STATS) = {
	[0] = {
		.type = MAP_TLV_STA_MAC_ADDRESS,
		.present = TLV_PRESENT_ONE
	},
	[1] = {
		.type = MAP_TLV_REASON_CODE,
		.present = TLV_PRESENT_ONE
	},
	[2] = {
		.type = MAP_TLV_ASSOCIATED_STA_TRAFFIC_STATS,
		.present = TLV_PRESENT_ONE
	},
};

DEFINE_POLICY(CMDU_ERROR_RESPONSE) = {
	[0] = {
		.type = MAP_TLV_PROFILE2_ERR_CODE,
		.present = TLV_PRESENT_MORE
	}
};

DEFINE_POLICY(CMDU_ASSOCIATION_STATUS_NOTIFICATION) = {
	[0] = {
		.type = MAP_TLV_ASSOCIATION_STATUS_NOTIF,
		.present = TLV_PRESENT_ONE
	}
};

DEFINE_POLICY(CMDU_TUNNELED) = {
	[0] = {
		.type = MAP_TLV_SOURCE_INFO,
		.present = TLV_PRESENT_ONE
	},
	[1] = {
		.type = MAP_TLV_TUNNELED_MSG_TYPE,
		.present = TLV_PRESENT_ONE
	},
	[2] = {
		.type = MAP_TLV_TUNNELED,
		.present = TLV_PRESENT_MORE
	}
};

DEFINE_POLICY(CMDU_BACKHAUL_STA_CAPABILITY_QUERY) = {
	/* empty */
};

DEFINE_POLICY(CMDU_BACKHAUL_STA_CAPABILITY_REPORT) = {
	[0] = {
		.type = MAP_TLV_BACKHAUL_STA_RADIO_CAPABILITY,
		.present = TLV_PRESENT_OPTIONAL_MORE
	}
};

DEFINE_POLICY(CMDU_FAILED_CONNECTION) = {
	[0] = {
		.type = MAP_TLV_STA_MAC_ADDRESS,
		.present = TLV_PRESENT_ONE
	},
	[1] = {
		.type = MAP_TLV_STATUS_CODE,
		.present = TLV_PRESENT_ONE
	},
	[2] = {
		.type = MAP_TLV_REASON_CODE,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
};

static struct cmdu_tlv_policy easymesh_policy_r2[] = {
	P(CMDU_TYPE_TOPOLOGY_DISCOVERY),
	P(CMDU_TYPE_TOPOLOGY_NOTIFICATION),
	P(CMDU_TYPE_TOPOLOGY_QUERY),
	P(CMDU_TYPE_TOPOLOGY_RESPONSE),
	P(CMDU_TYPE_VENDOR_SPECIFIC),
	P(CMDU_TYPE_LINK_METRIC_QUERY),	/* 0x0005 */
	P(CMDU_TYPE_LINK_METRIC_RESPONSE),
	P(CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH),
	P(CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE),
	P(CMDU_TYPE_AP_AUTOCONFIGURATION_WSC),	/* 0x0009 */
	/* P_ALT(CMDU_TYPE_AP_AUTOCONFIGURATION_WSC, 1), */
	P(CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW),
	P(CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION),
	P(CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION),
	P(CMDU_TYPE_HIGHER_LAYER_QUERY),
	P(CMDU_TYPE_HIGHER_LAYER_RESPONSE),
	P(CMDU_TYPE_INTERFACE_POWER_CHANGE_REQUEST),
	P(CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE),
	P(CMDU_TYPE_GENERIC_PHY_QUERY),
	P(CMDU_TYPE_GENERIC_PHY_RESPONSE),	/* 0x0012 */

	P(CMDU_1905_ACK),	/* 0x8000 */
	P(CMDU_AP_CAPABILITY_QUERY),
	P(CMDU_AP_CAPABILITY_REPORT),
	P(CMDU_POLICY_CONFIG_REQ),
	P(CMDU_CHANNEL_PREFERENCE_QUERY),
	P(CMDU_CHANNEL_PREFERENCE_REPORT),
	P(CMDU_CHANNEL_SELECTION_REQ),
	P(CMDU_CHANNEL_SELECTION_RESPONSE),
	P(CMDU_OPERATING_CHANNEL_REPORT),
	P(CMDU_CLIENT_CAPABILITY_QUERY),
	P(CMDU_CLIENT_CAPABILITY_REPORT),
	P(CMDU_AP_METRICS_QUERY),
	P(CMDU_AP_METRICS_RESPONSE),
	P(CMDU_ASSOC_STA_LINK_METRICS_QUERY),
	P(CMDU_ASSOC_STA_LINK_METRICS_RESPONSE),
	P(CMDU_UNASSOC_STA_LINK_METRIC_QUERY),
	P(CMDU_UNASSOC_STA_LINK_METRIC_RESPONSE),	/* 0x8010 */
	P(CMDU_BEACON_METRICS_QUERY),
	P(CMDU_BEACON_METRICS_RESPONSE),
	P(CMDU_COMBINED_INFRA_METRICS),
	P(CMDU_CLIENT_STEERING_REQUEST),
	P(CMDU_CLIENT_STEERING_BTM_REPORT),
	P(CMDU_CLIENT_ASSOC_CONTROL_REQUEST),
	P(CMDU_STEERING_COMPLETED),
	P(CMDU_HIGHER_LAYER_DATA),
	P(CMDU_BACKHAUL_STEER_REQUEST),
	P(CMDU_BACKHAUL_STEER_RESPONSE),
	P(CMDU_CHANNEL_SCAN_REQUEST),
	P(CMDU_CHANNEL_SCAN_REPORT),	/* 0x801C */
	{ 0, NULL },
	{ 0, NULL },
	{ 0, NULL },
	P(CMDU_CAC_REQUEST),		/* 0x8020 */
	P(CMDU_CAC_TERMINATION),
	P(CMDU_CLIENT_DISASSOCIATION_STATS),
	{ 0, NULL },
	P(CMDU_ERROR_RESPONSE),
	P(CMDU_ASSOCIATION_STATUS_NOTIFICATION),
	P(CMDU_TUNNELED),
	P(CMDU_BACKHAUL_STA_CAPABILITY_QUERY),
	P(CMDU_BACKHAUL_STA_CAPABILITY_REPORT),	/* 0x8028 */
	{ 0, NULL },
	{ 0, NULL },
	{ 0, NULL },
	{ 0, NULL },
	{ 0, NULL },
	{ 0, NULL },
	{ 0, NULL },
	{ 0, NULL },
	{ 0, NULL },
	{ 0, NULL },
	P(CMDU_FAILED_CONNECTION),	/* 0x8033 */
};

#undef P
#undef DEFINE_POLICY

#endif /* EASYMESH_VERSION >= 2 */
