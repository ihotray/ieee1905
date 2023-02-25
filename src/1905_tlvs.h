/*
 * 1905_tlvs.h: 1905 tlvs definition in flat format.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef _1905_TLVS_H_
#define _1905_TLVS_H_

#include <stdint.h>


#define ETHERTYPE_1905		0x893a
#define ETHERTYPE_LLDP		0x88cc

#define MCAST_1905	(uint8_t *)"\x01\x80\xC2\x00\x00\x13"
#define MCAST_LLDP	(uint8_t *)"\x01\x80\xC2\x00\x00\x0E"


/* 1905 CMDU types */
#define CMDU_TYPE_TOPOLOGY_DISCOVERY               0x0000
#define CMDU_TYPE_TOPOLOGY_NOTIFICATION            0x0001
#define CMDU_TYPE_TOPOLOGY_QUERY                   0x0002
#define CMDU_TYPE_TOPOLOGY_RESPONSE                0x0003
#define CMDU_TYPE_VENDOR_SPECIFIC                  0x0004
#define CMDU_TYPE_LINK_METRIC_QUERY                0x0005
#define CMDU_TYPE_LINK_METRIC_RESPONSE             0x0006
#define CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH      0x0007
#define CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE    0x0008
#define CMDU_TYPE_AP_AUTOCONFIGURATION_WSC         0x0009
#define CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW       0x000a
#define CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION   0x000b
#define CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION    0x000c
#define CMDU_TYPE_HIGHER_LAYER_QUERY               0x000d
#define CMDU_TYPE_HIGHER_LAYER_RESPONSE            0x000e
#define CMDU_TYPE_INTERFACE_POWER_CHANGE_REQUEST   0x000f
#define CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE  0x0010
#define CMDU_TYPE_GENERIC_PHY_QUERY                0x0011
#define CMDU_TYPE_GENERIC_PHY_RESPONSE             0x0012
#define LAST_1905_CMDU                             CMDU_TYPE_GENERIC_PHY_RESPONSE

#define CMDU_TYPE_MAX                              LAST_1905_CMDU
#define CMDU_TYPE_NONE                             0xffff

#define CMDU_TYPE_1905_START                       0x0000
#define CMDU_TYPE_1905_END                         CMDU_TYPE_MAX

/* 1905 CMDU version */
#define CMDU_MESSAGE_VERSION_1905_1_2013           0x00



/* 1905 TLV types */
#define TLV_TYPE_END_OF_MESSAGE                      (0)
#define TLV_TYPE_AL_MAC_ADDRESS_TYPE                 (1)
#define TLV_TYPE_MAC_ADDRESS_TYPE                    (2)
#define TLV_TYPE_DEVICE_INFORMATION_TYPE             (3)
#define TLV_TYPE_DEVICE_BRIDGING_CAPABILITIES        (4)
#define TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST       (6)
#define TLV_TYPE_NEIGHBOR_DEVICE_LIST                (7)
#define TLV_TYPE_LINK_METRIC_QUERY                   (8)
#define TLV_TYPE_TRANSMITTER_LINK_METRIC             (9)
#define TLV_TYPE_RECEIVER_LINK_METRIC                (10)
#define TLV_TYPE_VENDOR_SPECIFIC                     (11)
#define TLV_TYPE_LINK_METRIC_RESULT_CODE             (12)
#define TLV_TYPE_SEARCHED_ROLE                       (13)
#define TLV_TYPE_AUTOCONFIG_FREQ_BAND                (14)
#define TLV_TYPE_SUPPORTED_ROLE                      (15)
#define TLV_TYPE_SUPPORTED_FREQ_BAND                 (16)
#define TLV_TYPE_WSC                                 (17)
#define TLV_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION      (18)
#define TLV_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION       (19)
#define TLV_TYPE_GENERIC_PHY_DEVICE_INFORMATION      (20)
#define TLV_TYPE_DEVICE_IDENTIFICATION               (21)
#define TLV_TYPE_CONTROL_URL                         (22)
#define TLV_TYPE_IPV4                                (23)
#define TLV_TYPE_IPV6                                (24)
#define TLV_TYPE_GENERIC_PHY_EVENT_NOTIFICATION      (25)
#define TLV_TYPE_1905_PROFILE_VERSION                (26)
#define TLV_TYPE_POWER_OFF_INTERFACE                 (27)
#define TLV_TYPE_INTERFACE_POWER_CHANGE_INFORMATION  (28)
#define TLV_TYPE_INTERFACE_POWER_CHANGE_STATUS       (29)
#define TLV_TYPE_L2_NEIGHBOR_DEVICE                  (30)

#define TLV_TYPE_LAST                                (30)


/* Media types */
#define MEDIA_TYPE_IEEE_802_3U_FAST_ETHERNET       (0x0000)
#define MEDIA_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET   (0x0001)
#define MEDIA_TYPE_IEEE_802_11B_2_4_GHZ            (0x0100)
#define MEDIA_TYPE_IEEE_802_11G_2_4_GHZ            (0x0101)
#define MEDIA_TYPE_IEEE_802_11A_5_GHZ              (0x0102)
#define MEDIA_TYPE_IEEE_802_11N_2_4_GHZ            (0x0103)
#define MEDIA_TYPE_IEEE_802_11N_5_GHZ              (0x0104)
#define MEDIA_TYPE_IEEE_802_11AC_5_GHZ             (0x0105)
#define MEDIA_TYPE_IEEE_802_11AD_60_GHZ            (0x0106)
#define MEDIA_TYPE_IEEE_802_11AF_GHZ               (0x0107)
#define MEDIA_TYPE_IEEE_1901_WAVELET               (0x0200)
#define MEDIA_TYPE_IEEE_1901_FFT                   (0x0201)
#define MEDIA_TYPE_MOCA_V1_1                       (0x0300)
#define MEDIA_TYPE_UNKNOWN                         (0xFFFF)


/* IEEE802.11 frequency bands */
#define IEEE80211_FREQUENCY_BAND_2_4_GHZ           (0x00)
#define IEEE80211_FREQUENCY_BAND_5_GHZ             (0x01)
#define IEEE80211_FREQUENCY_BAND_60_GHZ            (0x02)
#define IEEE80211_FREQUENCY_BAND_UNKNOWN           (0xff)

#define IEEE80211_FREQUENCY_BAND_NUM                4

/* IEEE80211 roles */
#define IEEE80211_ROLE_REGISTRAR                   (0x00)

#define IEEE80211_ROLE_AP                          (0x00)
#define IEEE80211_ROLE_STA                         (0x40)
#define IEEE80211_ROLE_P2P_CLIENT                  (0x80)
#define IEEE80211_ROLE_P2P_GO                      (0x90)
#define IEEE80211_ROLE_AD_PCP                      (0xa0)
#define IEEE80211_ROLE_UNKNOWN                     (0xff)



typedef uint8_t macaddr_t[6];



/* TLV: End of message */
struct tlv_eom {
} __attribute__((packed));

/* TLV: Vendor specific info */
struct tlv_vendor_specific {
	uint8_t oui[3];
	uint8_t bytes[];
} __attribute__((packed));


/* TLV: AL mac-address */
struct tlv_aladdr {
	uint8_t macaddr[6];
} __attribute__ ((packed));


/* TLV: mac-address */
struct tlv_macaddr {
	uint8_t macaddr[6];
} __attribute__((packed));


/* IEEE 802.11 media specific info */
struct ieee80211_info {
	uint8_t bssid[6];
	uint8_t role;
	uint8_t ap_bandwidth;
	uint8_t ap_channel_seg0_idx;
	uint8_t ap_channel_seg1_idx;
} __attribute__ ((packed));

/* IEEE 1901 media specific info */
struct ieee1901_info {
	uint8_t netid[7];
} __attribute__((packed));

struct local_interface {
	uint8_t macaddr[6];
	uint16_t mediatype;	/* One of the MEDIA_TYPE_* values */
	uint8_t sizeof_mediainfo;
	uint8_t mediainfo[];	/* ieee80211_info, ieee1901_info etc. */
}__attribute__((packed));

/* TLV: device information */
struct tlv_device_info {
	uint8_t aladdr[6];
	uint8_t num_interface;
	struct local_interface interface[];
} __attribute__((packed));


struct device_bridge_tuple_macaddr {
	uint8_t macaddr[6];
} __attribute__ ((packed));

struct device_bridge_tuple {
	uint8_t num_macaddrs;
	struct device_bridge_tuple_macaddr addr[];
} __attribute__ ((packed));

/* TLV: Device bridging capability */
struct tlv_device_bridge_caps {
	uint8_t num_tuples;
	struct device_bridge_tuple tuple[];
} __attribute__((packed));


struct non1905_neighbor {
	uint8_t macaddr[6];
} __attribute__((packed));

/* TLV: non-1905 neighbor devices */
struct tlv_non1905_neighbor {
	uint8_t local_macaddr[6];
	struct non1905_neighbor non1905_nbr[];
} __attribute__((packed));


struct i1905_neighbor {
	uint8_t aladdr[6];
	uint8_t has_bridge;
} __attribute__((packed));

/* TLV: 1905 neighbor devices */
struct tlv_1905neighbor {
	uint8_t local_macaddr[6];
	struct i1905_neighbor nbr[];
} __attribute__((packed));



#define LINKMETRIC_QUERY_NEIGHBOR_ALL		(0x00)
#define LINKMETRIC_QUERY_NEIGHBOR_SPECIFIC	(0x01)

#define LINKMETRIC_QUERY_TYPE_TX		(0x00)
#define LINKMETRIC_QUERY_TYPE_RX		(0x01)
#define LINKMETRIC_QUERY_TYPE_BOTH		(0x02)

/* TLV: link metric query */
struct tlv_linkmetric_query {
	uint8_t nbr_type;
	uint8_t nbr_macaddr[6];
	uint8_t query_type;
} __attribute__((packed));

struct tx_link_info {
	uint8_t local_macaddr[6];
	uint8_t neighbor_macaddr[6];
	uint16_t mediatype;		/* one of MEDIA_TYPE_* */
	uint8_t has_bridge;
	uint32_t errors;
	uint32_t packets;
	uint16_t max_throughput;	/* estimated mac thput in Mbps */
	uint16_t availability;		/* in %age */
	uint16_t phyrate;		/* estimated phy rate in Mbps */
} __attribute__((packed));

/* TLV: transmitter link metric */
struct tlv_tx_linkmetric {
	uint8_t aladdr[6];
	uint8_t neighbor_aladdr[6];

	struct tx_link_info link[];
} __attribute__((packed));



struct rx_link_info {
	uint8_t local_macaddr[6];
	uint8_t neighbor_macaddr[6];
	uint16_t mediatype;
	uint32_t errors;
	uint32_t packets;
	int8_t rssi;			/* in dBm */
} __attribute__((packed));

/* TLV: receiver link metric */
struct tlv_rx_linkmetric {
	uint8_t aladdr[6];
	uint8_t neighbor_aladdr[6];
	struct rx_link_info link[];
} __attribute__((packed));


#define LINKMETRIC_RESULT_INVALID_NEIGHBOR  (0x00)

/* TLV: link metric result code */
struct tlv_linkmetric_result {
	uint8_t code;
} __attribute__((packed));

/* TLV: searched role */
struct tlv_searched_role {
	uint8_t role;		/* one of IEEE80211_ROLE_* */
} __attribute__((packed));

/* TLV: autoconfig frequency band */
struct tlv_autoconfig_band {
	uint8_t band;		/* one of IEEE80211_FREQUENCY_BAND_* */
} __attribute__((packed));

/* TLV: supported role */
struct tlv_supported_role {
	uint8_t role;		/* one of IEEE80211_ROLE_* */
} __attribute__((packed));

/* TLV: supported frequency band */
struct tlv_supported_band {
	uint8_t band;		/* one of IEEE80211_FREQUENCY_BAND_* */
} __attribute__((packed));


/* TLV: wsc */
struct tlv_wsc {
	uint8_t frame[0];
} __attribute__((packed));


struct media_info {
	uint16_t type;
	uint8_t sizeof_info;
	uint8_t info[];		/* ieee80211_info, ieee1901_info etc. */
} __attribute__((packed));

/* TLV: push button event notification */
struct tlv_pbc_notification {
	uint8_t num_media;
	struct media_info media[];
} __attribute__((packed));


/* TLV: push button join notification */
struct tlv_pbc_join_notification {
	uint8_t aladdr[6];
	uint16_t mid;
	uint8_t macaddr[6];
	uint8_t new_macaddr[6];
} __attribute__((packed));



/* TLV: generic phy device information */
struct generic_phy_data {
	uint8_t oui[3];
	uint8_t variant_index;
	uint8_t variant_name[32];
	uint8_t sizeof_url;
	uint8_t sizeof_mediainfo;
	uint8_t url_plus_mediainfo[];
} __attribute__((packed));

struct generic_phy_interface {
	uint8_t macaddr[6];
	struct generic_phy_data data;
} __attribute__((packed));

struct tlv_generic_phy_devinfo {
	uint8_t aladdr[6];
	uint8_t num_interfaces;
	struct generic_phy_interface interface[];
} __attribute__((packed));


/* TLV: device identification */
struct tlv_device_identification {
	uint8_t name[64];
	uint8_t manufacturer[64];
	uint8_t model[64];
} __attribute__((packed));


/* TLV: control URL */
struct tlv_control_url {
	uint8_t url[0];
} __attribute__((packed));



#define IPV4_TYPE_UNKNOWN	0
#define IPV4_TYPE_DHCP		1
#define IPV4_TYPE_STATIC	2
#define IPV4_TYPE_AUTOIP	3

struct ipv4_entry {
	uint8_t type;
	uint8_t address[4];
	uint8_t dhcpserver[4];
} __attribute__((packed));

struct ipv4_interface {
	uint8_t macaddr[6];
	uint8_t num_ipv4;
	struct ipv4_entry ipv4[];
} __attribute__((packed));

/* TLV: IPv4 TLV */
struct tlv_ipv4 {
	uint8_t num_interfaces;
	struct ipv4_interface interface[];
} __attribute__((packed));




#define IPV6_TYPE_UNKNOWN	0
#define IPV6_TYPE_DHCP		1
#define IPV6_TYPE_STATIC	2
#define IPV6_TYPE_SLAAC		3

struct ipv6_entry {
	uint8_t type;
	uint8_t address[16];
	uint8_t origin[16];
} __attribute__((packed));

struct ipv6_interface {
	uint8_t macaddr[6];
	uint8_t link_local_address[16];
	uint8_t num_ipv6;
	struct ipv6_entry ipv6[];
} __attribute__((packed));

/* TLV: IPv6 TLV */
struct tlv_ipv6 {
	uint8_t num_interfaces;
	struct ipv6_interface interface[];
} __attribute__((packed));



/* TLV: Push button generic PHY event notification */
struct tlv_pbc_generic_phy_notification {
	uint8_t num_genphys;
	struct {
		uint8_t oui[3];
		uint8_t variant_index;
		uint8_t sizeof_mediainfo;
		uint8_t mediainfo[];
	} genphy[];
} __attribute__((packed));


#define PROFILE_1905_1   (0x00)
#define PROFILE_1905_1A  (0x01)

/* TLV: 1905 profile version */
struct tlv_1905_profile {
	uint8_t version;
} __attribute__((packed));


/* TLV: Power off interface */
struct tlv_power_off {
	uint8_t num_interfaces;
	struct {
		uint8_t macaddr[6];
		uint16_t media_type;
		uint8_t oui[3];
		uint8_t variant_index;
		uint8_t sizeof_mediainfo;
		uint8_t mediainfo[];
	} interface[];
} __attribute__((packed));


#define POWER_REQUEST_OFF	0x00
#define POWER_REQUEST_ON	0x01
#define POWER_REQUEST_SAVE	0x02

/* TLV: interface power change information */
struct tlv_powerchange_request {
	uint8_t num_interfaces;
	struct {
		uint8_t macaddr[6];
		uint8_t power;
	} interface[];
} __attribute__((packed));



#define POWER_CHANGE_OK		0x00
#define POWER_CHANGE_NOK	0x01
#define POWER_CHANGE_ALT	0x02

/* TLV: interface power change status */
struct tlv_powerchange_status {
	uint8_t num_interfaces;
	struct {
		uint8_t macaddr[6];
		uint8_t status;
	} interface[];
} __attribute__((packed));


/* TLV: L2 neighbor device */
struct l2_interface_neighbor {
	uint8_t macaddr[6];
	uint16_t num_behind_macs;
	uint8_t behind_macaddrs[];
} __attribute__((packed));

struct l2_interface {
	uint8_t macaddr[6];
	uint16_t num_l2_neighbors;
	struct l2_interface_neighbor l2_nbr[];
} __attribute__((packed));

struct tlv_l2_neighbor {
	uint8_t num_interfaces;
	struct l2_interface interface[];
} __attribute__((packed));


/* LLDP tlvs definition */
/* Tlv types */
#define LLDP_TLV_EOL			0
#define LLDP_TLV_CHASSIS_ID		1
#define LLDP_TLV_PORT_ID		2
#define LLDP_TLV_TTL			3


/* TLV: end of LLDPPDU */
struct tlv_eol {
} __attribute__((packed));


#define LLDP_CHASSIS_ID_SUBTYPE_CHASSIS_COMPONENT	1
#define LLDP_CHASSIS_ID_SUBTYPE_INTERFACE_ALIAS		2
#define LLDP_CHASSIS_ID_SUBTYPE_PORT_COMPONENT		3
#define LLDP_CHASSIS_ID_SUBTYPE_MAC_ADDRESS		4
#define LLDP_CHASSIS_ID_SUBTYPE_NETWORK_ADDRESS		5
#define LLDP_CHASSIS_ID_SUBTYPE_INTERFACE_NAME		6
#define LLDP_CHASSIS_ID_SUBTYPE_LOGICALLY_ASSIGNED	7

/* TLV: chassis-id */
struct tlv_chassis_id {
	uint8_t subtype;
	uint8_t id[256];
} __attribute__((packed));



#define LLDP_PORT_ID_SUBTYPE_INTERFACE_ALIAS		1
#define LLDP_PORT_ID_SUBTYPE_PORT_COMPONENT		2
#define LLDP_PORT_ID_SUBTYPE_MAC_ADDRESS		3
#define LLDP_PORT_ID_SUBTYPE_NETWORK_ADDRESS		4
#define LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME		5
#define LLDP_PORT_ID_SUBTYPE_AGENT_CIRCUIT_ID		6
#define LLDP_PORT_ID_SUBTYPE_LOGICALLY_ASSIGNED		7

/* TLV: port-id */
struct tlv_port_id {
	uint8_t subtype;
	uint8_t id[256];
} __attribute__((packed));



#define LLDP_TTL_1905_DEFAULT_VALUE	180	/* in secs */

/* TLV: ttl */
struct tlv_ttl {
	uint16_t ttl;	/* in secs */
} __attribute__((packed));

#endif	/* _1905_TLVS_H_ */
