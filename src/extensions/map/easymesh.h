/*
 * easymesh.h - WFA Easymesh CMDUs and TLVs definition in flat format.
 *
 * Copyright (C) 2021-2022 IOPSYS Software Solutions AB.
 * All rights reserved.
 *
 * See LICENSE file for license related information.
 *
 */
#ifndef EASYMESH_H
#define EASYMESH_H


#include <stdint.h>


#define CMDU_1905_ACK                                  0x8000
#define CMDU_AP_CAPABILITY_QUERY                       0x8001
#define CMDU_AP_CAPABILITY_REPORT                      0x8002
#define CMDU_POLICY_CONFIG_REQ                         0x8003
#define CMDU_CHANNEL_PREFERENCE_QUERY                  0x8004
#define CMDU_CHANNEL_PREFERENCE_REPORT                 0x8005
#define CMDU_CHANNEL_SELECTION_REQ                     0x8006
#define CMDU_CHANNEL_SELECTION_RESPONSE                0x8007
#define CMDU_OPERATING_CHANNEL_REPORT                  0x8008
#define CMDU_CLIENT_CAPABILITY_QUERY                   0x8009
#define CMDU_CLIENT_CAPABILITY_REPORT                  0x800a
#define CMDU_AP_METRICS_QUERY                          0x800b
#define CMDU_AP_METRICS_RESPONSE                       0x800c
#define CMDU_ASSOC_STA_LINK_METRICS_QUERY              0x800d
#define CMDU_ASSOC_STA_LINK_METRICS_RESPONSE           0x800e
#define CMDU_UNASSOC_STA_LINK_METRIC_QUERY             0x800f
#define CMDU_UNASSOC_STA_LINK_METRIC_RESPONSE          0x8010
#define CMDU_BEACON_METRICS_QUERY                      0x8011
#define CMDU_BEACON_METRICS_RESPONSE                   0x8012
#define CMDU_COMBINED_INFRA_METRICS                    0x8013
#define CMDU_CLIENT_STEERING_REQUEST                   0x8014
#define CMDU_CLIENT_STEERING_BTM_REPORT                0x8015
#define CMDU_CLIENT_ASSOC_CONTROL_REQUEST              0x8016
#define CMDU_STEERING_COMPLETED                        0x8017
#define CMDU_HIGHER_LAYER_DATA                         0x8018
#define CMDU_BACKHAUL_STEER_REQUEST                    0x8019
#define CMDU_BACKHAUL_STEER_RESPONSE                   0x801a

#if (EASYMESH_VERSION >= 2)
#define CMDU_CHANNEL_SCAN_REQUEST                      0x801b
#define CMDU_CHANNEL_SCAN_REPORT                       0x801c

#if (EASYMESH_VERSION >= 3)
#define CMDU_DPP_CCE_INDICATION                        0x801d
#define CMDU_1905_REKEY_REQUEST                        0x801e
#define CMDU_1905_DECRYPT_FAIL                         0x801f
#endif /* >= R3 */

#define CMDU_CAC_REQUEST                               0x8020
#define CMDU_CAC_TERMINATION                           0x8021
#define CMDU_CLIENT_DISASSOCIATION_STATS               0x8022

#if (EASYMESH_VERSION >= 3)
#define CMDU_SERVICE_PRIORITIZATION_REQUEST            0x8023
#endif /* >= R3 */

#define CMDU_ERROR_RESPONSE                            0x8024
#define CMDU_ASSOCIATION_STATUS_NOTIFICATION           0x8025
#define CMDU_TUNNELED                                  0x8026
#define CMDU_BACKHAUL_STA_CAPABILITY_QUERY             0x8027
#define CMDU_BACKHAUL_STA_CAPABILITY_REPORT            0x8028

#if (EASYMESH_VERSION >= 3)
#define CMDU_PROXIED_ENCAP_DPP                         0x8029
#define CMDU_DIRECT_ENCAP_DPP                          0x802a
#define CMDU_RECONFIG_TRIGGER                          0x802b
#define CMDU_BSS_CONFIG_REQUEST                        0x802c
#define CMDU_BSS_CONFIG_RESPONSE                       0x802d
#define CMDU_BSS_CONFIG_RESULT                         0x802e
#define CMDU_CHIRP_NOTIFICATION                        0x802f
#define CMDU_1905_ENCAP_EAPOL                          0x8030
#define CMDU_DPP_BOOTSTRAPING_URI                      0x8031

#if (EASYMESH_VERSION >= 4)
#define CMDU_ANTICIPATED_CHANNEL_PREFERENCE            0x8032
#endif /* >= R4 */
#endif /* >= R3 */

#define CMDU_FAILED_CONNECTION                         0x8033
#endif /* >= R2 */

#if (EASYMESH_VERSION >= 3)
#define CMDU_AGENT_LIST                                0x8035
#endif /* >= R3 */

#if (EASYMESH_VERSION >= 4)
#define CMDU_ANTICIPATED_CHANNEL_USAGE                 0x8036
#define CMDU_QOS_MANAGEMENT_NOTIFICATION               0x8037
#endif /* >= R4 */


#if (EASYMESH_VERSION >= 4)
#define LAST_MAP_CMDU                                  CMDU_QOS_MANAGEMENT_NOTIFICATION
#elif (EASYMESH_VERSION == 3)
#define LAST_MAP_CMDU                                  CMDU_AGENT_LIST
#elif (EASYMESH_VERSION == 2)
#define LAST_MAP_CMDU                                  CMDU_FAILED_CONNECTION
#else
#define LAST_MAP_CMDU                                  CMDU_BACKHAUL_STEER_RESPONSE
#endif

#define MAP_CMDU_TYPE_MAX                              LAST_MAP_CMDU


#define MAP_TLV_SUPPORTED_SERVICE                      0x80
#define MAP_TLV_SEARCHED_SERVICE                       0x81
#define MAP_TLV_AP_RADIO_IDENTIFIER                    0x82
#define MAP_TLV_AP_OPERATIONAL_BSS                     0x83
#define MAP_TLV_ASSOCIATED_CLIENTS                     0x84
#define MAP_TLV_AP_CAPABILITY                          0xA1
#define MAP_TLV_AP_RADIO_BASIC_CAPABILITIES            0x85
#define MAP_TLV_AP_HT_CAPABILITIES                     0x86
#define MAP_TLV_AP_VHT_CAPABILITIES                    0x87
#define MAP_TLV_AP_HE_CAPABILITIES                     0x88
#define MAP_TLV_STEERING_POLICY                        0x89
#define MAP_TLV_METRIC_REPORTING_POLICY                0x8A
#define MAP_TLV_CHANNEL_PREFERENCE                     0x8B
#define MAP_TLV_RADIO_OPERATION_RESTRICTION            0x8C
#define MAP_TLV_TRANSMIT_POWER_LIMIT                   0x8D
#define MAP_TLV_CHANNEL_SELECTION_RESPONSE             0x8E
#define MAP_TLV_OPERATING_CHANNEL_REPORT               0x8F
#define MAP_TLV_CLIENT_INFO                            0x90
#define MAP_TLV_CLIENT_CAPABILITY_REPORT               0x91
#define MAP_TLV_CLIENT_ASSOCIATION_EVENT               0x92
#define MAP_TLV_AP_METRIC_QUERY                        0x93
#define MAP_TLV_AP_METRICS                             0x94
#define MAP_TLV_STA_MAC_ADDRESS                        0x95
#define MAP_TLV_ASSOCIATED_STA_LINK_METRICS            0x96
#define MAP_TLV_UNASSOCIATED_STA_LINK_METRICS_QUERY    0x97
#define MAP_TLV_UNASSOCIATED_STA_LINK_METRICS_RESPONSE 0x98
#define MAP_TLV_BEACON_METRICS_QUERY                   0x99
#define MAP_TLV_BEACON_METRICS_RESPONSE                0x9A
#define MAP_TLV_STEERING_REQUEST                       0x9B
#define MAP_TLV_STEERING_BTM_REPORT                    0x9C
#define MAP_TLV_CLIENT_ASSOCIATION_CONTROL_REQUEST     0x9D
#define MAP_TLV_BACKHAUL_STEERING_REQUEST              0x9E
#define MAP_TLV_BACKHAUL_STEERING_RESPONSE             0x9F
#define MAP_TLV_HIGHER_LAYER_DATA                      0xA0
#define MAP_TLV_ASSOCIATED_STA_TRAFFIC_STATS           0xA2
#define MAP_TLV_ERROR_CODE                             0xA3
#define MAP_TLV_CHANNEL_SCAN_REPORTING_POLICY          0xA4
#define MAP_TLV_CHANNEL_SCAN_CAPABILITY                0xA5
#define MAP_TLV_CHANNEL_SCAN_REQ                       0xA6
#define MAP_TLV_CHANNEL_SCAN_RES                       0xA7
#define MAP_TLV_TIMESTAMP                              0xA8

#if (EASYMESH_VERSION >= 3)
#define MAP_TLV_1905_SECURITY_CAPS                     0xA9
#define MAP_TLV_AP_WIFI6_CAPS                          0xAA
#define MAP_TLV_MIC                                    0xAB
#define MAP_TLV_ENCRYPTED_PAYLOAD                      0xAC
#endif /* >= 3 */

#define MAP_TLV_CAC_REQ                                0xAD
#define MAP_TLV_CAC_TERMINATION                        0xAE
#define MAP_TLV_CAC_COMPLETION_REPORT                  0xAF

#if (EASYMESH_VERSION >= 3)
#define MAP_TLV_ASSOCIATED_WIFI6_STA_STATUS            0xB0
#endif /* >= 3 */

#define MAP_TLV_CAC_STATUS_REPORT                      0xB1
#define MAP_TLV_CAC_CAPABILITY                         0xB2
#define MAP_TLV_MULTIAP_PROFILE                        0xB3
#define MAP_TLV_PROFILE2_AP_CAPABILITY                 0xB4
#define MAP_TLV_DEFAULT_8021Q_SETTINGS                 0xB5
#define MAP_TLV_TRAFFIC_SEPARATION_POLICY              0xB6
#if (EASYMESH_VERSION >= 3)
#define MAP_TLV_BSS_CONFIGURATION_REPORT               0xB7
#define MAP_TLV_BSSID                                  0xB8
#define MAP_TLV_SERVICE_PRIORITIZATION_RULE            0xB9
#define MAP_TLV_DSCP_MAPPING_TABLE                     0xBA
#define MAP_TLV_BSS_CONFIGURATION_REQUEST              0xBB
#endif /* >= 3 */

#define MAP_TLV_PROFILE2_ERR_CODE                      0xBC

#if (EASYMESH_VERSION >= 3)
#define MAP_TLV_BSS_CONFIGURATION_RESPONSE             0xBD
#endif /* >= 3 */

#define MAP_TLV_AP_RADIO_ADV_CAPABILITY                0xBE
#define MAP_TLV_ASSOCIATION_STATUS_NOTIF               0xBF
#define MAP_TLV_SOURCE_INFO                            0xC0
#define MAP_TLV_TUNNELED_MSG_TYPE                      0xC1
#define MAP_TLV_TUNNELED                               0xC2
#define MAP_TLV_PROFILE2_STEERING_REQ                  0xC3
#define MAP_TLV_UNSUCCESS_ASSOCIATION_POLICY           0xC4
#define MAP_TLV_METRIC_COLLECTION_INTERVAL             0xC5
#define MAP_TLV_RADIO_METRICS                          0xC6
#define MAP_TLV_AP_EXTENDED_METRICS                    0xC7
#define MAP_TLV_ASSOCIATED_STA_EXT_LINK_METRICS        0xC8
#define MAP_TLV_STATUS_CODE                            0xC9
#define MAP_TLV_REASON_CODE                            0xCA
#define MAP_TLV_BACKHAUL_STA_RADIO_CAPABILITY          0xCB

#if (EASYMESH_VERSION >= 3)
#define MAP_TLV_AKM_SUITE_CAPS                         0xCC
#define MAP_TLV_1905_ENCAP_DPP                         0xCD
#define MAP_TLV_1905_ENCAP_EAPOL                       0xCE
#define MAP_TLV_DPP_BOOTSTRAP_URI_NOTIFICATION         0xCF
#endif /* >= 3 */

#define MAP_TLV_BACKHAUL_BSS_CONFIG                    0xD0

#if (EASYMESH_VERSION >= 3)
#define MAP_TLV_DPP_MESSAGE                            0xD1
#define MAP_TLV_DPP_CCE_INDICATION                     0xD2
#define MAP_TLV_DPP_CHIRP_VALUE                        0xD3
#define MAP_TLV_DEVICE_INVENTORY                       0xD4
#define MAP_TLV_AGENT_LIST                             0xD5
#endif /* >= 3 */

#if (EASYMESH_VERSION >= 4)
#define MAP_TLV_ANTICIPATED_CHANNEL_PREF               0xD6
#define MAP_TLV_ANTICIPATED_CHANNEL_USAGE              0xD7
#define MAP_TLV_SPATIAL_REUSE_REQUEST                  0xD8
#define MAP_TLV_SPATIAL_REUSE_REPORT                   0xD9
#define MAP_TLV_SPATIAL_REUSE_CONFIG_RESPONSE          0xDA
#define MAP_TLV_QOS_MANAGEMENT_POLICY                  0xDB
#define MAP_TLV_QOS_MANAGEMENT_DESCRIPTOR              0xDC
#define MAP_TLV_CONTROLLER_CAPS                        0xDD
#endif /* >= 4 */


#define MULTIAP_PROFILE_1                              0x01
#define MULTIAP_PROFILE_2                              0x02
#if (EASYMESH_VERSION >= 3)
#define MULTIAP_PROFILE_3                              0x03
#endif

#define SUPPORTED_SERVICE_MULTIAP_CONTROLLER           0x00
#define SUPPORTED_SERVICE_MULTIAP_AGENT                0x01

#define SEARCHED_SERVICE_MULTIAP_CONTROLLER            0x00



#define IEEE1905_OBJECT_MULTIAP			"ieee1905.map"



typedef uint8_t macaddr_t[6];


/** TLV: Supported Service */
struct tlv_supported_service {
	uint8_t num_services;
	uint8_t services[];
} __attribute__((packed));

/** TLV: Searched Service */
struct tlv_searched_service {
	uint8_t num_services;
	uint8_t services[];
} __attribute__((packed));

/** TLV: AP Radio Identifier */
struct tlv_ap_radio_identifier {
	uint8_t radio[6];
} __attribute__((packed));


/** TLV: AP Operational BSS */
struct tlv_ap_oper_bss {
	uint8_t num_radio;
	struct ap_oper_bss_radiolist {
		uint8_t radio[6];
		uint8_t num_bss;
		struct ap_oper_bss_bss {
			uint8_t bssid[6];
			uint8_t ssidlen;
			char ssid[];
		} bss[];
	} radiolist[];
} __attribute__((packed));


/** TLV: Associated Clients */
struct tlv_assoc_client {
	uint8_t num_bss;
	struct assoc_client_bss {
		uint8_t bssid[6];
		uint16_t num_client;
		struct assoc_client_sta {
			uint8_t macaddr[6];
			uint16_t conntime;
		} sta[];
	} bss[];
} __attribute__((packed));


/** TLV: AP Capability */
struct tlv_ap_cap {
#define UNASSOC_STA_REPORTING_ONCHAN	0x80
#define UNASSOC_STA_REPORTING_OFFCHAN	0x40
#define AGENT_SUPPORTS_RCPI_STEER       0x20
	uint8_t cap;
} __attribute__((packed));

/** TLV: AP Radio Basic Capabilities */
struct tlv_ap_radio_basic_cap {
	uint8_t radio[6];
	uint8_t max_bssnum;
	uint8_t num_opclass;
	struct ap_radio_basic_cap_opclass {
		uint8_t classid;
		uint8_t max_txpower;
		uint8_t num_nonop_channel;
		uint8_t nonop_channel[];
	} __attribute__((packed)) opclass[];
} __attribute__((packed));

/** TLV: AP HT Capabilities */
struct tlv_ap_ht_cap {
	uint8_t radio[6];
	uint8_t cap;
#define HT_MAX_TX_STREAM_MASK	0xc0
#define HT_MAX_RX_STREAM_MASK	0x30
#define HT_SGI20_MASK		0x08
#define HT_SGI40_MASK		0x04
#define HT_HT40_MASK		0x02
} __attribute__((packed));

/** TLV: AP VHT Capabilities */
struct tlv_ap_vht_cap {
	uint8_t radio[6];
	uint16_t tx_mcs_supported;
	uint16_t rx_mcs_supported;
	uint8_t cap[2];
	/* cap[0] bitflags */
#define VHT_MAX_TX_STREAM_MASK	0xe0
#define VHT_MAX_RX_STREAM_MASK	0x1c
#define VHT_SGI80_MASK		0x02
#define VHT_SGI160_8080_MASK	0x01
	/* cap[1] bitflags */
#define VHT_8080_MASK		0x80
#define VHT_160_MASK		0x40
#define VHT_SU_BFR		0x20
#define VHT_MU_BFR		0x10
};

/** TLV: AP HE Capabilities */
struct ap_he_cap_mcs {
	uint8_t len;
	uint8_t mcs[];
} __attribute__((packed));

struct tlv_ap_he_cap {
	uint8_t radio[6];
	struct ap_he_cap_mcs hemcs;
	uint8_t cap[2];
	/* cap[0] bitflags */
#define HE_MAX_TX_STREAM_MASK	0xe0
#define HE_MAX_RX_STREAM_MASK	0x1c
#define HE_8080_MASK		0x02
#define HE_160_MASK		0x01
	/* cap[1] bitflags */
#define HE_SU_BFR		0x80
#define HE_MU_BFR		0x40
#define HE_UL_MUMIMO		0x20
#define HE_UL_MUMIMO_OFDMA	0x10
#define HE_DL_MUMIMO_OFDMA	0x08
#define HE_UL_OFDMA		0x04
#define HE_DL_OFDMA		0x02
} __attribute__((packed));


/** TLV: Steering Policy */
struct sta_macaddr {
	uint8_t num;
	uint8_t macaddr[][6];
} __attribute__((packed));

struct tlv_steering_policy {
	struct sta_macaddr nosteer;
	struct sta_macaddr nobtmsteer;
	uint8_t num_radio;
	struct {
		uint8_t radio[6];
		uint8_t steer_policy;
#define STEER_DISALLOW	0x00
#define STEER_MANDATE	0x01
#define STEER_ALLOW	0x02
		uint8_t util_threshold;
		uint8_t rcpi_threshold;
	} policy[];
} __attribute__((packed));


/** TLV: Metric Reporting Policy */
struct tlv_metric_report_policy {
	uint8_t interval;
	uint8_t num_radio;
	struct {
		uint8_t radio[6];
		uint8_t rcpi_threshold;
		uint8_t rcpi_hysteresis;
		uint8_t util_threshold;
#define INCLUDE_STA_STATS		0x80
#define INCLUDE_STA_LINK_METRICS	0x40
#define INCLUDE_STA_STATUS_REPORT	0x20
		uint8_t include;
	} policy[];
} __attribute__((packed));


/** TLV: Channel Preference */
struct channel_preflist {
	uint8_t num_channel;
	uint8_t channel[];
} __attribute__((packed));

struct tlv_channel_pref {
	uint8_t radio[6];
	uint8_t num_opclass;
	struct channel_pref_opclass {
		uint8_t classid;
		struct channel_preflist chs;
#define CHANNEL_PREF_MASK	0xf0
#define CHANNEL_PREF_REASON	0x0f
#define CHANNEL_PREF_REASON_UNSPEC			0x0	/* 0000 */
#define CHANNEL_PREF_REASON_NON11_INTERFERENCE		0x1	/* 0001 */
#define CHANNEL_PREF_REASON_INT_OBSS_INTERFERENCE	0x2	/* 0010 */
#define CHANNEL_PREF_REASON_EXT_OBSS_INTERFERENCE	0x3	/* 0011 */
#define CHANNEL_PREF_REASON_REDUCED_COVERAGE		0x4	/* 0100 */
#define CHANNEL_PREF_REASON_REDUCED_THROUGHPUT		0x5	/* 0101 */
#define CHANNEL_PREF_REASON_IN_DEVICE_INTERFERENCE	0x6	/* 0110 */
#define CHANNEL_PREF_REASON_DFS_NOP			0x7	/* 0111 */
#define CHANNEL_PREF_REASON_SHARED_BHAUL_PREVENT	0x8	/* 1000 */
#define CHANNEL_PREF_REASON_DFS_AVAILABLE		0x9	/* 1001 */
#define CHANNEL_PREF_REASON_DFS_USABLE			0xa	/* 1010 */
#define CHANNEL_PREF_REASON_DFS_CLEAR_INDICATION	0xb	/* 1011 */
#define CHANNEL_PREF_REASON_REG_DISALLOWED		0xc	/* 1100 */
		uint8_t preference;
	} opclass[];
} __attribute__((packed));


/** TLV: Radio Operation Restriction */
struct channel_restrictlist {
	uint8_t num_channel;
	struct {
		uint8_t channel;
		uint8_t min_freq_sep;
	} channels[];
} __attribute__((packed));

struct tlv_radio_oper_restrict {
	uint8_t radio[6];
	uint8_t num_opclass;
	struct {
		uint8_t classid;
		struct channel_restrictlist chs;
	} opclass[];
} __attribute__((packed));


/** TLV: Transmit Power Limit */
struct tlv_txpower_limit {
	uint8_t radio[6];
	uint8_t limit;
} __attribute__((packed));

/** TLV: Channel Selection Response */
struct tlv_channel_selection_resp {
	uint8_t radio[6];
	uint8_t response;
} __attribute__((packed));


/** TLV: Operating Channel Report */
struct oper_channel_report {
	uint8_t num_opclass;
	struct {
		uint8_t classid;
		uint8_t channel;
	} opclass[];
} __attribute__((packed));

struct tlv_oper_channel_report {
	uint8_t radio[6];
	struct oper_channel_report report;
	uint8_t curr_txpower;
} __attribute__((packed));

/** TLV: Client Info */
struct tlv_client_info {
	uint8_t bssid[6];
	uint8_t macaddr[6];
} __attribute__((packed));

/** TLV: Client Capability Report */
struct tlv_client_cap_report {
	uint8_t result;
	uint8_t frame[];
} __attribute__((packed));


/** TLV: Client Association Event */
struct tlv_client_assoc_event {
	uint8_t macaddr[6];
	uint8_t bssid[6];
#define CLIENT_EVENT_MASK	0x80
	uint8_t event;
} __attribute__((packed));


/** TLV: AP Metric Query */
struct tlv_ap_metric_query {
	uint8_t num_bss;
	struct {
		uint8_t bssid[6];
	} bss[];
} __attribute__((packed));


/** TLV: AP Metrics TLV */
struct tlv_ap_metrics {
	uint8_t bssid[6];
	uint8_t channel_utilization;
	uint16_t num_station;
#define ESP_AC_BE	0x80
#define ESP_AC_BK	0x40
#define ESP_AC_VO	0x20
#define ESP_AC_VI	0x10
	uint8_t esp_ac;
	uint8_t esp_be[3];
	uint8_t esp[];
} __attribute__((packed));


/** TLV: STA MAC Address Type */
struct tlv_sta_mac {
	uint8_t macaddr[6];
} __attribute__((packed));


/** TLV: Associated STA Link Metrics */
struct assoc_sta_link_metrics_bss {
	uint8_t bssid[6];
	uint32_t time_delta;
	uint32_t dl_thput;
	uint32_t ul_thput;
	uint8_t ul_rcpi;
} __attribute__((packed));

struct tlv_assoc_sta_link_metrics {
	uint8_t macaddr[6];
	uint8_t num_bss;
	struct assoc_sta_link_metrics_bss bss[];
} __attribute__((packed));

/** TLV: Unssociated STA Link Metrics Query */
struct tlv_unassoc_sta_link_metrics_query {
	uint8_t opclass;
	uint8_t num_channel;
	struct {
		uint8_t channel;
		uint8_t num_sta;
		struct {
			uint8_t macaddr[6];
		} sta[];
	} ch[];
} __attribute__((packed));

/** TLV: Unssociated STA Link Metrics Response */
struct unassoc_sta_link_metrics_sta {
	uint8_t macaddr[6];
	uint8_t channel;
	uint32_t time_delta;
	uint8_t ul_rcpi;
} __attribute__((packed));

struct tlv_unassoc_sta_link_metrics_resp {
	uint8_t opclass;
	uint8_t num_sta;
	struct unassoc_sta_link_metrics_sta sta[];
} __attribute__((packed));


/** TLV: Beacon Metrics Query */
struct ssid_query {
	uint8_t ssidlen;
	char ssid[];
} __attribute__((packed));

struct ap_channel_report {
	uint8_t len;
	uint8_t opclass;
	uint8_t channel[];
} __attribute__((packed));

struct tlv_beacon_metrics_query {
	uint8_t sta_macaddr[6];
	uint8_t opclass;
	uint8_t channel;
	uint8_t bssid[6];
	uint8_t reporting_detail;
	struct ssid_query ssid;
	uint8_t num_report;
	struct ap_channel_report report;
	uint8_t num_element;
	uint8_t element[];
} __attribute__((packed));


/** TLV: Beacon Metrics Response */
struct tlv_beacon_metrics_resp {
	uint8_t sta_macaddr[6];
	uint8_t reserved;
	uint8_t num_element;
	uint8_t element[];
} __attribute__((packed));

/** TLV: Steering Request */
struct steer_target_bss {
	uint8_t num;
	struct {
		uint8_t bssid[6];
		uint8_t opclass;
		uint8_t channel;
	} bss[];
} __attribute__((packed));

struct steer_sta_request {
	uint8_t num;
	struct {
		uint8_t macaddr[6];
	} sta[];
} __attribute__((packed));

struct tlv_steer_request {
	uint8_t bssid[6];
	uint8_t mode;
#define STEER_REQUEST_MODE		0x80
#define STEER_REQUEST_BTM_DISASSOC_IMM	0x40
#define STEER_REQUEST_BTM_ABRIDGED	0x20
	uint16_t op_window;
	uint16_t btm_disassoc_timer;
	struct steer_sta_request sta;
	struct steer_target_bss target;
} __attribute__((packed));


/** TLV: Steering BTM Report */
struct tlv_steer_btm_report {
	uint8_t bssid[6];
	uint8_t sta_macaddr[6];
	uint8_t status;
	macaddr_t target_bssid[];
} __attribute__((packed));


/** TLV: Client Association Control Request */
struct tlv_client_assoc_ctrl_request {
	uint8_t bssid[6];
	uint8_t control;
#define ASSOC_CTRL_BLOCK	0x00
#define ASSOC_CTRL_UNBLOCK	0x01
	uint16_t validity_period;
	uint8_t num_sta;
	struct {
		uint8_t macaddr[6];
	} sta[];
} __attribute__((packed));


/** TLV: Backhaul Steering Request */
struct tlv_backhaul_steer_request {
	uint8_t macaddr[6];
	uint8_t target_bssid[6];
	uint8_t target_opclass;
	uint8_t target_channel;
} __attribute__((packed));

/** TLV: Backhaul Steering Response */
struct tlv_backhaul_steer_resp {
	uint8_t macaddr[6];
	uint8_t target_bssid[6];
	uint8_t result;
} __attribute__((packed));


/** TLV: Higher Layer Data */
struct tlv_higher_layer_data {
	uint8_t protocol;
	uint8_t payload[];
} __attribute__((packed));


/** TLV: Associated STA Traffic Stats */
struct tlv_assoc_sta_traffic_stats {
	uint8_t macaddr[6];
	uint32_t tx_bytes;
	uint32_t rx_bytes;
	uint32_t tx_packets;
	uint32_t rx_packets;
	uint32_t tx_err_packets;
	uint32_t rx_err_packets;
	uint32_t rtx_packets;
} __attribute__((packed));


/** TLV: Error code */
struct tlv_error_code {
	uint8_t reason;
	uint8_t macaddr[6];
} __attribute__((packed));


/** TLV: Channel scan reporting policy */
struct tlv_channel_scan_report_policy {
	uint8_t report;
#define REPORT_CHANNEL_SCANS	0x80
} __attribute__((packed));


/** TLV: Channel scan capabilities */
struct channel_scan_capability_opclass {
	uint8_t classid;
	uint8_t num_channel;
	uint8_t channel[];
} __attribute__((packed));

struct channel_scan_capability_radio {
	uint8_t radio[6];
	uint8_t cap;
#define SCAN_CAP_ON_BOOT_ONLY	0x80
#define SCAN_CAP_IMPACT		0x60
	uint32_t min_scan_interval;
	uint8_t num_opclass;
	struct channel_scan_capability_opclass opclass[];
} __attribute__((packed));

struct tlv_channel_scan_capability {
	uint8_t num_radio;
	struct channel_scan_capability_radio radio[];
} __attribute__((packed));


/** TLV: Channel scan request */
struct tlv_channel_scan_request {
	uint8_t mode;
#define SCAN_REQUEST_FRESH_SCAN	0x80
	uint8_t num_radio;
	struct channel_scan_request_radio {
		uint8_t radio[6];
		uint8_t num_opclass;
		struct channel_scan_request_opclass {
			uint8_t classid;
			uint8_t num_channel;
			uint8_t channel[];
		} opclass[];
	} radio[];
} __attribute__((packed));


/** TLV: Channel scan result */
struct scan_result_timestamp {
	uint8_t len;
	char timestamp[];
} __attribute__((packed));

struct scan_result_ssid {
	uint8_t len;
	uint8_t ssid[];
} __attribute__((packed));

struct scan_result_bandwidth {
	uint8_t len;
	char bwstr[];		/* weird definition! */
} __attribute__((packed));

struct scan_result_bssload_data {
	uint8_t ch_util;
	uint16_t sta_count;
} __attribute__((packed));

struct scan_result_bssload {
	uint8_t info;
#define CH_SCAN_RESULT_BSSLOAD_PRESENT		0x80
	struct scan_result_bssload_data data[];
} __attribute__((packed));

struct scan_result_neighbor {
	uint16_t num_neighbor;
	struct {
		uint8_t bssid[6];
		struct scan_result_ssid ssid;
		uint8_t rcpi;
		struct scan_result_bandwidth bw;
		struct scan_result_bssload bssload;
	} neighbor[];
} __attribute__((packed));

struct scan_result_detail {
	struct scan_result_timestamp tsp;
	uint8_t utilization;
	uint8_t noise;
	struct scan_result_neighbor nbr;
	uint32_t total_scan_duration;
#define SCAN_RESULT_SCAN_TYPE	0x80
	uint8_t type;
} __attribute__((packed));

struct tlv_channel_scan_result {
	uint8_t radio[6];
	uint8_t opclass;
	uint8_t channel;
#define CH_SCAN_STATUS_SUCCESS                  0x00
#define CH_SCAN_STATUS_SCAN_NOT_SUPPORTED       0x01
#define CH_SCAN_STATUS_TOO_SOON                 0x02
#define CH_SCAN_STATUS_TOO_BUSY                 0x03
#define CH_SCAN_STATUS_SCAN_NOT_COMPLETED       0x04
#define CH_SCAN_STATUS_SCAN_ABORTED             0x05
#define CH_SCAN_STATUS_BOOT_SCAN_ONLY           0x06
	uint8_t status;
	struct scan_result_detail detail[];	/* present when satus = 0 */
} __attribute__((packed));


/** TLV: Timestamp */
struct tlv_timestamp {
	uint8_t len;
	uint8_t timestamp[];
} __attribute__((packed));


/** TLV: CAC request */
struct tlv_cac_request {
	uint8_t num_radio;
	struct {
		uint8_t radio[6];
		uint8_t opclass;
		uint8_t channel;
#define CAC_REQUEST_METHOD		0xe0
#define CAC_REQUEST_COMPLETE_ACTION	0x18
		uint8_t mode;
	} radio[];
} __attribute__((packed));


/** TLV: CAC termination */
struct tlv_cac_termination {
	uint8_t num_radio;
	struct {
		uint8_t radio[6];
		uint8_t opclass;
		uint8_t channel;
	} radio[];
} __attribute__((packed));


/** TLV: CAC completion report */
struct tlv_cac_complete_report {
	uint8_t num_radio;
	struct {
		uint8_t radio[6];
		uint8_t opclass;
		uint8_t channel;
#define CAC_COMP_REPORT_STATUS_SUCCESSFUL                       0x00
#define CAC_COMP_REPORT_STATUS_RADAR_DETECTED                   0x01
#define CAC_COMP_REPORT_STATUS_CAC_NOT_SUPPORTED                0x02
#define CAC_COMP_REPORT_STATUS_TOO_BUSY                         0x03
#define CAC_COMP_REPORT_STATUS_NON_CONFORMANT                   0x04
#define CAC_COMP_REPORT_STATUS_OTHER                            0x05
		uint8_t status;
		uint8_t num_pairs;	/* radars detected in pairs */
		struct {
			uint8_t opclass;
			uint8_t channel;
		} pair[];
	} radio[];
} __attribute__((packed));


/** TLV: CAC status report */
struct cac_status_available {
	uint8_t num_channel;
	struct {
		uint8_t opclass;
		uint8_t channel;
		uint16_t since;		/* in minutes */
	} ch[];
} __attribute__((packed));

struct cac_status_noop {
	uint8_t num_channel;
	struct {
		uint8_t opclass;
		uint8_t channel;
		uint16_t remain;	/* in seconds */
	} ch[];
} __attribute__((packed));

struct cac_status_cac {
	uint8_t num_channel;
	struct {
		uint8_t opclass;
		uint8_t channel;
		uint16_t remain;	/* in seconds */
	} ch[];
} __attribute__((packed));

struct tlv_cac_status_report {
	struct cac_status_available available;
	struct cac_status_noop noop;
	struct cac_status_cac cac;
} __attribute__((packed));


/** TLV: CAC capability */
struct tlv_cac_cap {
	uint8_t country[2];
	uint8_t num_radio;
	struct cac_cap_radio {
		uint8_t radio[6];
		uint8_t num_cac;
		struct cac_cap_cac {
#define CAC_METHOD_CONTINUOUS_CAC	0x00
#define CAC_METHOD_DEDICATED_RADIO	0x01
#define CAC_METHOD_MIMO_DIM_REDUCED     0x02
#define CAC_METHOD_TIME_SLICED		0x03
			uint8_t supp_method;
			uint8_t duration[3];
			uint8_t num_opclass;
			struct cac_cap_opclass {
				uint8_t classid;
				uint8_t num_channel;
				uint8_t channel[];
			} __attribute__((packed)) opclass[];
		} __attribute__((packed)) cac[];
	} __attribute__((packed)) radio[];
} __attribute__((packed));


/** TLV: Multi-AP profile */
struct tlv_map_profile {
	uint8_t profile;
} __attribute__((packed));


/** TLV: Profile-2 AP capability */
struct tlv_profile2_ap_cap {
#if (EASYMESH_VERSION > 2)
	uint8_t max_prio_rules;
	uint8_t reserved;
	uint8_t caps;
#else
	uint16_t reserved;
	uint8_t unit;
#endif /* EASYMESH_VERSION */

#define STATS_UNIT_MASK              0xC0
#define STATS_UNIT_MB                0x80
#define STATS_UNIT_KB                0x40
#define STATS_UNIT_BYTE              0x00

#if (EASYMESH_VERSION > 2)
#define PRIORITIZATION_SUPPORTED     0x20
#define DPP_ONBOARDING_SUPPORTED     0x10
#define TRAFFIC_SEPARATION_SUPPORTED 0x08
#endif /* EASYMESH_VERSION */

	uint8_t max_vids;
} __attribute__((packed));


/** TLV: Default 802.1Q settings */
struct tlv_default_8021q_settings {
	uint16_t pvid;
	uint8_t pcp;
#define PCP_MASK  0xe0
} __attribute__((packed));

/** TLV: Traffic separation policy */
struct ssid_info {
	uint8_t len;
	uint8_t ssid[];
} __attribute__((packed));

struct tlv_traffic_sep_policy {
	uint8_t num_ssid;
	struct {
		struct ssid_info info;
		uint16_t vid;
	} __attribute__((packed)) ssid[];
} __attribute__((packed));


/** TLV: Profile-2 error code */
struct tlv_profile2_error_code {
	uint8_t reason;
	macaddr_t bssid[];
} __attribute__((packed));


/** TLV: AP radio advanced capability */
struct tlv_ap_radio_adv_cap {
	uint8_t radio[6];
	uint8_t cap;
#define RADIO_CAP_COMBINED_FHBK      0x80
#define RADIO_CAP_COMBINED_P1P2      0x40
#if (EASYMESH_VERSION > 2)
#define RADIO_CAP_MSCS_AND_EM        0x20
#define RADIO_CAP_SCS_AND_EM         0x10
#define RADIO_CAP_DSCP_TO_UP_MAPPING 0x08
#define RADIO_CAP_DSCP_POLICY        0x04
#endif /* EASYMESH_VERSION */
} __attribute__((packed));


/** TLV: Association status notification */
struct tlv_assoc_status_notif {
	uint8_t num_bss;
	struct {
		uint8_t bssid[6];
		uint8_t allowance;
#define STA_ASSOC_NOT_ALLOWED	0x00
#define STA_ASSOC_ALLOWED	0x01
	} bss[];
} __attribute__((packed));


/** TLV: Source info */
struct tlv_source_info {
	uint8_t macaddr[6];
} __attribute__((packed));

/** TLV: Tunneled message type */
struct tlv_tunnel_msg_type {
#define TUN_MSG_ASSOC_REQ	0x00
#define TUN_MSG_REASSOC_REQ	0x01
#define TUN_MSG_BTM_QUERY	0x02
#define TUN_MSG_WNM_REQ		0x03
#define TUN_MSG_ANQP_NBR_RPT	0x04
	uint8_t type;
} __attribute__((packed));


/** TLV: Tunneled message */
struct tlv_tunneled {
	uint8_t frame[0];
} __attribute__((packed));


/** TLV: Profile-2 steering request */
struct profile2_sta_steer {
	uint8_t num_sta;
	struct {
		uint8_t macaddr[6];
	} sta[];
} __attribute__((packed));

struct tlv_profile2_steer_request {
	uint8_t bssid[6];
	uint8_t mode;
#define STEER_MODE		0x80
#define STEER_BTM_DISASSOC_IMM	0x40
#define STEER_BTM_ABRIDGED	0x20
	uint16_t op_window;
	uint16_t btm_disassoc_timer;
	struct profile2_sta_steer steer;
	uint8_t num_target;
	struct {
		uint8_t bssid[6];
		uint8_t opclass;
		uint8_t channel;
		uint8_t reason;
	} target[];
} __attribute__((packed));

/** TLV: Unsuccessful association policy */
struct tlv_unsuccess_assoc_policy {
	uint8_t report;
#define UNSUCCESSFUL_ASSOC_REPORT  0x80
	uint32_t max_report_rate;
} __attribute__((packed));

/** TLV: Metric collection interval */
struct tlv_metric_collection_int {
	uint32_t interval;
} __attribute__((packed));


/** TLV: Radio metrics */
struct tlv_radio_metrics {
	uint8_t radio[6];
	uint8_t noise;
	uint8_t transmit;
	uint8_t receive_self;
	uint8_t receive_other;
} __attribute__((packed));


/** TLV: AP extended metrics */
struct tlv_ap_ext_metrics {
	uint8_t bssid[6];
	uint32_t tx_bytes_ucast;
	uint32_t rx_bytes_ucast;
	uint32_t tx_bytes_mcast;
	uint32_t rx_bytes_mcast;
	uint32_t tx_bytes_bcast;
	uint32_t rx_bytes_bcast;
} __attribute__((packed));


/** TLV: Associated STA extended link metrics */
struct sta_ext_link_metric_bss {
	uint8_t bssid[6];
	uint32_t dl_rate;
	uint32_t ul_rate;
	uint32_t rx_util;
	uint32_t tx_util;
} __attribute__((packed));

struct tlv_sta_ext_link_metric {
	uint8_t macaddr[6];
	uint8_t num_bss;
	struct sta_ext_link_metric_bss bss[];
} __attribute__((packed));

/** TLV: Status code */
struct tlv_status_code {
	uint16_t code;
} __attribute__((packed));

/** TLV: Reason code */
struct tlv_reason_code {
	uint16_t code;
} __attribute__((packed));


/** TLV: Backhaul STA radio capabilities */
struct tlv_bsta_radio_cap {
	uint8_t radio[6];
	uint8_t macaddr_included;
#define BSTA_MACADDRESS_INCLUDED	0x80
	macaddr_t macaddr[];
} __attribute__((packed));


/** TLV: Backhaul BSS config */
struct tlv_bbss_config {
	uint8_t bssid[6];
	uint8_t config;
#define BBSS_CONFIG_P1_BSTA_DISALLOWED	0x80
#define BBSS_CONFIG_P2_BSTA_DISALLOWED	0x40
} __attribute__((packed));


#if (EASYMESH_VERSION >= 3)

/** TLV: 1905 layer security capability */
#define SECURITY_PROTOCOL_DPP		0x00
#define SECURITY_MIC_HMAC_SHA256	0x00
#define SECURITY_ENC_AES_SIV		0x00

struct tlv_1905_security_cap {
	uint8_t protocol;
	uint8_t mic;
	uint8_t enc;
} __attribute__ ((packed));


/** TLV: AP Wi-Fi 6 capabilities */
struct tlv_ap_wifi6_caps {
	uint8_t ruid[6];
	uint8_t num_roles;
	struct wifi6_agent_role {
#define AGENT_ROLE_MASK                     0xC0
#define AGENT_ROLE_AP                       0
#define AGENT_ROLE_BH_STA                   1
#define H160_SUPPORTED                      0x20
#define HE8080_SUPPORTED                    0x10
#define MCS_NSS_LEN_MASK                    0x0F
		uint8_t caps;
		union {
			uint8_t mcs_nss_4[4];
			uint8_t mcs_nss_8[8];
			uint8_t mcs_nss_12[12];
		} __attribute__((packed));
		struct wifi6_agent_role_other_caps {
#define SU_BEAMFORMER_SUPPORTED             0x80
#define SU_BEAMFORMEE_SUPPORTED             0x40
#define MU_B_FORMER_STATUS_SUPPORTED        0x20
#define B_FORMEE_STS_LE_80_SUPPORTED        0x10
#define B_FORMEE_STS_GT_80_SUPPORTED        0x08
#define UL_MU_MIMO_SUPPORTED                0x04
#define UL_OFDMA_SUPPORTED                  0x02
#define DL_OFDMA_SUPPORTED                  0x01
			uint8_t beamform_caps;
#define MAX_NUM_USRS_DL_MU_MIMO_MASK        0xF0
#define MAX_NUM_USRS_UL_MU_MIMO_MASK        0x0F
			uint8_t max_mu_mimo_users;
			uint8_t max_dl_ofdma_users;
			uint8_t max_ul_ofdma_users;
#define RTS_SUPPORTED                       0x80
#define MU_RTS_SUPPORTED                    0x40
#define MULTI_BSSID_SUPPORTED               0x20
#define MU_EDCA_SUPPORTED                   0x10
#define TWT_REQUESTER_SUPPORTED             0x08
#define TWT_RESPONDER_SUPPORTED             0x04
#define SPATIAL_REUSE_SUPPORTED             0x02
#define ACU_SUPPORTED                       0x01
			uint8_t other_caps;
		} __attribute__((packed)) agent_role_other_caps;
	} __attribute__((packed)) roles[];
} __attribute__ ((packed));

/** TLV: MIC */
struct tlv_mic {
	uint8_t flag;
	uint8_t	itc[6];
	uint8_t src[6];
	uint16_t len;
	uint8_t mic[];
} __attribute__ ((packed));


/** TLV: Encrypted Payload */
struct tlv_enc_payload {
	uint8_t etc[6];
	uint8_t	src[6];
	uint8_t dst[6];
	uint16_t len;
	uint8_t enc[];
} __attribute__ ((packed));


/** TLV: 1905 Encap EAPOL */
struct tlv_1905_encap_eapol {
	uint8_t eapol[0];
} __attribute__ ((packed));



/** TLV: DPP Chirp */
#define DPP_CHIRP_ENROLLEE_MAC_PRESENT  BIT(7)
#define DPP_CHIRP_HASH_VALIDITY         BIT(6)

struct dpp_chirp_enrollee {
	uint8_t flag;
	macaddr_t addr[];
} __attribute__ ((packed));

struct tlv_dpp_chirp {
	struct dpp_chirp_enrollee dst;
	uint8_t hashlen;
	uint8_t hash[];
} __attribute__ ((packed));


/** TLV: Associated Wi-Fi 6 STA Status Report */
struct tlv_assoc_wifi6_sta_status_report {
	uint8_t macaddr[6];
	uint8_t num_queue;
	struct assoc_sta_status_report_queue {
		uint8_t tid;
		uint8_t qsize;
	} __attribute__ ((packed)) queue[];
} __attribute__ ((packed));


/** TLV: BSS configuration report */
struct tlv_bss_configuration_report {
	uint8_t num_radio;
	struct bss_configuration_report_radio {
		uint8_t ruid[6];
		uint8_t num_bss;
		struct bss_configuration_report_bss {
			uint8_t bssid[6];
#define BSS_CONFIG_BBSS                 BIT(7)
#define BSS_CONFIG_FBSS                 BIT(6)
#define BSS_CONFIG_R1_DISALLOWED        BIT(5)
#define BSS_CONFIG_R2_DISALLOWED        BIT(4)
#define BSS_CONFIG_MBSSID               BIT(3)
#define BSS_CONFIG_TX_MBSSID            BIT(2)
			uint8_t flag;
			uint8_t rsvd;
			uint8_t ssidlen;
			uint8_t ssid[];
		} __attribute__ ((packed)) bss[];
	} __attribute__ ((packed)) radio[];
} __attribute__ ((packed));


/** TLV: Device inventory */
struct device_inventory_sn {
	uint8_t lsn;
	uint8_t sn[];		/* serial number (<= 64 octets) */
} __attribute__ ((packed));

struct device_inventory_sv {
	uint8_t lsv;
	uint8_t sv[];		/* software version (<= 64 octets) */
} __attribute__ ((packed));

struct device_inventory_ee {
	uint8_t lee;
	uint8_t ee[];		/* execution env (<= 64 octets) */
} __attribute__ ((packed));

struct device_inventory_radio {
	uint8_t ruid[6];
	uint8_t lcv;
	uint8_t cv[];		/* chipset vendor (<= 64 octets) */
} __attribute__ ((packed));

struct tlv_device_inventory {
	struct device_inventory_sn slnum;
	struct device_inventory_sv swver;
	struct device_inventory_ee exenv;
	uint8_t num_radio;
	struct device_inventory_radio radio[];
} __attribute__ ((packed));


/** TLV: Agent list */
struct tlv_agent_list {
	uint8_t num_agent;
	struct agent_list_info {
		uint8_t aladdr[6];
		uint8_t profile;
		uint8_t security;
	} __attribute__ ((packed)) agent[];
} __attribute__ ((packed));


/** TLV: AKM suite capabilities */
struct akm_suite {
	uint8_t oui[3];
	uint8_t type;
} __attribute__ ((packed));

struct bbss_akm_suite {
	uint8_t num;
	struct akm_suite suite[];
} __attribute__ ((packed));

struct fbss_akm_suite {
	uint8_t num;
	struct akm_suite suite[];
} __attribute__ ((packed));

struct tlv_akm_suite_caps {
	struct bbss_akm_suite bbss;
	struct fbss_akm_suite fbss;
} __attribute__ ((packed));


/** TLV: 1905 Encap DPP */
#define ENCAP_DPP_ENROLLEE_MAC_PRESENT		BIT(7)
#define ENCAP_DPP_FRAME_INDICATOR		BIT(5)

struct encap_dpp_enrollee {
	uint8_t flag;
	macaddr_t addr[];
} __attribute__ ((packed));

struct encap_dpp_frame {
	uint8_t type;		/* DPP public action type, or 255 for GAS */
	uint16_t len;
	uint8_t frame[];
} __attribute__ ((packed));

struct tlv_1905_encap_dpp {
	struct encap_dpp_enrollee dst;
	struct encap_dpp_frame frame;
} __attribute__ ((packed));


/** TLV: DPP bootstrapping URI notification */
struct tlv_dpp_uri_bootstrap {
	uint8_t ruid[6];
	uint8_t bssid[6];
	uint8_t bsta[6];
	uint8_t uri[];
} __attribute__ ((packed));


/** TLV: DPP CCE indication */
struct tlv_dpp_cce {
	uint8_t enable;
} __attribute__ ((packed));


/** TLV: BSS configuration request/response */
struct tlv_bss_configuration {
	uint8_t data[1];
} __attribute__ ((packed));


/** TLV: DPP message */
struct tlv_dpp_message {
	uint8_t frame[1];
} __attribute__ ((packed));


#if (EASYMESH_VERSION >= 4)

/** TLV: Anticipated channel preference */
struct channel_list {
	uint8_t num_channel;
	uint8_t channel[];
} __attribute__((packed));

struct opclass_channel {
	uint8_t opclass;
	struct channel_list chlist;
	uint8_t rsvd[4];
} __attribute__((packed));

struct tlv_anticipated_channel_pref {
	uint8_t num_opclass;
	struct opclass_channel och[];
} __attribute__ ((packed));


/** TLV: Anticipated channel usage */
struct ru_bitmask {
	uint8_t len;
	uint8_t mask[];
} __attribute__((packed));

struct tlv_anticipated_channel_usage {
	uint8_t opclass;
	uint8_t channel;
	uint8_t bssid[6];
	uint8_t num_usage;
	struct anticipated_channel_usage_entry {
		uint32_t burst_start_time;
		uint32_t burst_len;
		uint32_t burst_rep;
		uint32_t burst_int;
		struct ru_bitmask bitmask;
		uint8_t txid[6];
		uint8_t pwrlevel;
		uint8_t reason;
		uint8_t rsvd[4];
	} __attribute__ ((packed)) usage[];
} __attribute__ ((packed));


/** TLV: Spatial reuse request */
#define SR_BSSCOLOR_MASK			0x3f
#define SR_PBSSCOLOR				BIT(6)

#define SR_FLAG_HESIGA_VALUE15_ALLOWED		BIT(4)
#define SR_FLAG_SRG_VALID			BIT(3)
#define SR_FLAG_NON_SRG_OFFSET_VALID		BIT(2)
#define SR_FLAG_PSR_DISALLOWED			BIT(0)

struct tlv_sr_request {
	uint8_t ruid[6];
	uint8_t bsscolor;
	uint8_t flag;
	uint8_t non_srg_obss_pd_max_offset;
	uint8_t srg_obss_pd_min_offset;
	uint8_t srg_obss_pd_max_offset;
	uint8_t srg_bsscolor_bmp[8];
	uint8_t srg_pbssid_bmp[8];
	uint8_t rsvd[2];
} __attribute__((packed));


/** TLV: Spatial reuse report */
struct tlv_sr_report {
	uint8_t ruid[6];
	uint8_t bsscolor;
	uint8_t flag;
	uint8_t non_srg_obss_pd_max_offset;
	uint8_t srg_obss_pd_min_offset;
	uint8_t srg_obss_pd_max_offset;
	uint8_t srg_bsscolor_bmp[8];
	uint8_t srg_pbssid_bmp[8];
	uint8_t nbr_bsscolor_bmp[8];
	uint8_t rsvd[2];
} __attribute__((packed));


/** TLV: Spatial reuse config response */
struct tlv_sr_config_response {
	uint8_t ruid[6];
	uint8_t code;
} __attribute__((packed));


/** TLV: QoS management policy */
struct tlv_qos_management_policy {
	uint8_t num_mscs_disallowed;
	struct sta_macaddr mscs_disallowed;
	uint8_t num_scs_disallowed;
	struct sta_macaddr scs_disallowed;
} __attribute__((packed));


/** TLV: QoS management descriptor */
struct tlv_qos_management_desc {
	uint16_t qmid;
	uint8_t bssid[6];
	uint8_t sta[6];
	uint8_t desc[];
} __attribute__((packed));


/** TLV: Controller capability */
struct tlv_controller_cap {
#define CONTROLLER_KIBMIB_COUNTER_SUPPORTED	BIT(7)
	uint8_t flag;
	uint8_t rsvd[];
} __attribute__ ((packed));

#endif /* >= 4 */
#endif /* >= 3 */

#endif /* EASYMESH_H */
