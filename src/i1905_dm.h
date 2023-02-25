/*
 * 1905_dm.h
 * IEEE-1905 data model definitions as per TR-181.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef I1905_DM_H
#define I1905_DM_H


#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include <netinet/in.h>
#include <arpa/inet.h>


enum i1905_version {
	I1905_VERSION_DOT_1,
	I1905_VERSION_DOT_1A,
	I1905_VERSION_INVALID,
};

enum i1905_registrar_type {
	I1905_REGISTRAR_NONE,
	I1905_REGISTRAR_2G    = 1 << 0,
	I1905_REGISTRAR_5G    = 1 << 1,
	I1905_REGISTRAR_60G   = 1 << 2,

	//_I1905_REGISTRAR_MAX,
	//I1905_NUM_REGISTRAR = _I1905_REGISTRAR_MAX,
};

enum i1905_security_method {
	I1905_SECURITY_UNKNOWN,
	I1905_SECURITY_UCPK,
	I1905_SECURITY_PBC,
	I1905_SECURITY_NFC,
	I1905_SECURITY_INVALID,
};

enum i1905_ifpowerstate {
	I1905_IFPOWER_ON,
	I1905_IFPOWER_PS,
	I1905_IFPOWER_OFF,
	I1905_IFPOWER_NOTSUPP,
	I1905_IFPOWER_INVALID,
};


struct i1905_registrar {
	uint8_t type;
	uint8_t macaddr[6];
	struct list_head list;
};

struct i1905_metric {
	bool br_present;
	uint32_t tx_errors;
	uint32_t rx_errors;
	uint32_t tx_packets;
	uint32_t rx_packets;
	uint32_t available;		/* in percentage */
	uint32_t max_rate;		/* max throughput at MAC layer */
	uint32_t max_phyrate;
	uint8_t rssi;			/* rcpi (0..255) */
};

/**
 * @brief Defines non-1905 neighbors reported by a 1905 device in Topology Response.
 */
struct i1905_net_non1905_neighbor {
	//uint8_t local_macaddr[6];
	uint8_t macaddr[6];		/**< macaddress of the non-1905 device */
	struct list_head list;
};

struct i1905_genphy {
	uint8_t oui[3];
	uint8_t variant;
	char *url;
};

struct i1905_vendor_info {
	uint8_t oui[3];
	uint8_t *data;
	struct list_head list;
};


enum i1905_fwdrule_mask {
	I1905_FWDRULE_SRC     = 1 << 0,
	I1905_FWDRULE_DST     = 1 << 1,
	I1905_FWDRULE_TYPE    = 1 << 2,
	I1905_FWDRULE_VID     = 1 << 3,
	I1905_FWDRULE_PCP     = 1 << 4,
	I1905_FWDRULE_UNVALID = 1 << 5,
};

enum i1905_mediatype {
	I1905_802_3U_FAST_ETHERNET       = (0x0000),
	I1905_802_3AB_GIGABIT_ETHERNET   = (0x0001),
	I1905_802_11B_2_4_GHZ            = (0x0100),
	I1905_802_11G_2_4_GHZ            = (0x0101),
	I1905_802_11A_5_GHZ              = (0x0102),
	I1905_802_11N_2_4_GHZ            = (0x0103),
	I1905_802_11N_5_GHZ              = (0x0104),
	I1905_802_11AC_5_GHZ             = (0x0105),
	I1905_802_11AD_60_GHZ            = (0x0106),
	I1905_802_11AF_GHZ               = (0x0107),
#ifdef WIFI_EASYMESH
	I1905_802_11AX                   = (0x0108),  /* 11ax */
	I1905_802_11BE                   = (0x0109),  /* 11be */
#endif
	I1905_1901_WAVELET               = (0x0200),
	I1905_1901_FFT                   = (0x0201),
	I1905_MOCA_V1_1                  = (0x0300),
	I1905_MEDIA_UNKNOWN              = (0xFFFF),
};


#define IS_MEDIA_1901(m)	\
	((m) == I1905_1901_WAVELET || (m) == I1905_1901_FFT)


#define IS_MEDIA_WIFI(m)	\
	((m) >= I1905_802_11B_2_4_GHZ && (m) < I1905_1901_WAVELET)


#define IS_MEDIA_WIFI_5GHZ(m)			\
	((m) == I1905_802_11A_5_GHZ ||		\
	 (m) == I1905_802_11N_5_GHZ ||		\
	 (m) == I1905_802_11AC_5_GHZ)

#define IS_MEDIA_WIFI_2GHZ(m)			\
	((m) == I1905_802_11B_2_4_GHZ ||	\
	 (m) == I1905_802_11G_2_4_GHZ ||	\
	 (m) == I1905_802_11N_2_4_GHZ)

struct i1905_fwdrule {
	struct list_head iflist;	/* list of ifnames/macaddres FIXME */
	uint32_t mask;			/* bitmap of I1905_FWDRULE_* */
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t ethtype;
	uint16_t vid;
	uint8_t pcp;
	struct list_head list;
};


struct i1905_fwdtable {
	bool allow;
	struct list_head rulelist;
};

/**
 * @brief Defines a 1905 link, i.e. interface on the immediate neighbor device's
 * side.
 *
 * This structure defines interface information of the 1905 immediate neighbor
 * device that has a linkage with this 1905 device.
 * A 1905 link is defined by the tuple -
 *	{i1905_interface, i1905_neighbor_interface}.
 * TODO: rename to 'struct i1905_iflink'.
 */
struct i1905_neighbor_interface {
	uint8_t macaddr[6];		/**< macaddress of the neighbor interface */
	uint8_t aladdr[6];		/**< ALID or AL-macaddress of the neighbor device */
	bool has_bridge;		/**< has atleast one L2 bridge in the link path */
	enum i1905_mediatype media;	/**< media information of the interface from neighbor's Topology response */
	struct i1905_genphy genphy;	/**< generic phy information of the interface, if available */
	struct i1905_metric metric;	/**< link metric of the link */
	struct list_head list;
	bool direct;			/**< whether direct link exists with this neighbor */
	time_t tsp;			/**< timestamp when this link was last updated */
	atimer_t staletimer;		/**< free the link when not updated for too long */
	struct i1905_interface *iface;	/**< reference back to the i1905_interface this link connects to */
	bool invalid;
};

/**
 * @brief Defines a non-1905 device in the network.
 *
 * The non-1905 devices are identified through any implementation specific manner,
 * outside of the scope of the 1905 protocol.
 */
struct i1905_non1905_neighbor {
	uint8_t macaddr[6];		/**< macaddress of the non-1905 device */
	struct list_head list;
};

/**
 * @brief Defines a 1905 interface.
 *
 * This structure is used to represent an IEEE1905 interface belonging to either
 * struct i1905_selfdevice or struct i1905_device.
 * Depending on which type of the parent structure this belongs to, few members
 * may be available or not available.
 */
struct i1905_interface {
	char ifname[16];		/**< interface name */
	uint32_t ifindex;		/**< interface index; valid only it belongs to i1905_selfdevice */
	uint8_t macaddr[6];		/**< macaddress of the interface */
	uint8_t aladdr[6];		/**< 1905 ALID or AL-macaddress or the device this interface belongs to */
	uint32_t ifstatus;		/**< interface status */
	uint16_t vid;                   /**< outgoing cmdus will be tagged if non-zero */
	bool authenticated;		/**< whether 1905 authenticated or not */
	bool pbc_supported;		/**< whether WPS PBC is supported by this interface of not */
	bool pbc_ongoing;		/**< whether PBC is ongoing or not */
	bool is_registrar;
	bool upstream;			/**< true when points towards the registrar */

	bool lo;			/** for cmdu loopback to localhost */
	bool invalid;
	bool is_brif;			/**< whether a bridged (slave) interface */
	uint32_t brport;		/**< bridge port number when is_brif = true */
	uint32_t br_ifindex;		/**< bridge (master) interface index when is_brif = true */

	void *device;			/**< points to struct 1905_device it belongs to */

	int band;			/**< freq-band in GHz */
	enum i1905_mediatype media;	/**< media type of this interface */
	uint8_t *mediainfo;		/**< ieee80211_info, ieee1901_info etc. depending on media type */

	struct i1905_genphy genphy;	/**< generic phy information when no defined mediatype is identified */

	bool allow_ifpower;		/**< whether allows setting interface power state */
	enum i1905_ifpowerstate power;	/**< one of I1905_IFPOWER_ */

	uint32_t num_vendor;		/**< number of vendor properties */
	struct list_head vendorlist;	/**< list of vendor properties */

	uint32_t num_ipaddrs;		/**< number of IP-addresses this interface has */
	struct ip_address *ipaddrs;	/**< array of IP-addresses */

	uint32_t num_links;		/**< number of i1905_neighbor_interface to the neighbor 1905 device */
	//struct list_head iflinklist;	/* i1905_iflink (or i1905_neighbor_interface) */

	uint32_t num_neighbor_non1905;	/**< number of non-1905 neighbor devices reachable through this interface */
	struct list_head non1905_nbrlist; /**< list of i1905_non1905_neighbor devices */
	struct list_head nbriflist;	/**< list of i1905_neighbor_interface */

	struct list_head list;
	void *priv;			/**< interface private data */
};

struct i1905_security {
	enum i1905_security_method method;
	uint8_t password[64];
};


enum ip4addr_type {
	IP4_TYPE_UNKNOWN,
	IP4_TYPE_DHCP,
	IP4_TYPE_STATIC,
	IP4_TYPE_AUTOIP,
};

struct i1905_ipv4 {
	uint8_t macaddr[6];
	struct in_addr addr;
	enum ip4addr_type type;
	struct in_addr dhcpserver;
	struct list_head list;
};

enum ip6addr_type {
	IP6_TYPE_UNKNOWN,
	IP6_TYPE_LINKLOCAL,
	IP6_TYPE_DHCP,
	IP6_TYPE_STATIC,
	IP6_TYPE_SLAAC,
};

struct i1905_ipv6 {
	uint8_t macaddr[6];
	struct in6_addr addr;
	enum ip6addr_type type;
	struct in6_addr origin;
	struct list_head list;
};

struct i1905_bridge_tuple {
	uint8_t num_macs;
	uint8_t *macaddrs;	/* array of interface macaddress */
	struct list_head list;
};

struct i1905_selfdevice;

/**
 * @brief Defines a 1905 device in the network.
 *
 * This structure is used to represent another 1905 device in the network.
 * It includes only the 1905 devices that are immediate neighbors, i.e. they
 * have been identified through the 1905 Topology discovery multicast CMDUs.
 */
struct i1905_device {
	time_t tsp;
	atimer_t agetimer;
	atimer_t immediate_nbr_agetimer;
	int is_immediate_neighbor;	/**< whether this 1905 device is our immediate neighbor */
	//bool changed;			/* flag topo change notification */
	bool upstream;                  /**< true when this deivce is on our upstream path */
	bool enabled;
	uint8_t aladdr[6];		/**< ALID or AL-macaddress of the device */
	enum i1905_version version;	/**< version, one of I1905_VERSION_ */
	uint8_t regband;		/**< bitmap of i1905_registrar_type */

	char name[65];			/**< friendly device name */
	char manufacturer[65];		/**< manufacturer name */
	char model[65];			/**< model name */
	char *url;			/**< control url of the device */

	uint32_t num_vendor;		/**< number of vendor properties */
	uint32_t num_ipv4;		/**< number of IPv4 addresses this device has */
	uint32_t num_ipv6;		/**< number of IPv6 addresses this device has */
	uint32_t num_interface;		/**< number of 1905 interfaces */
	uint32_t num_neighbor_non1905;	/**< number of non-1905 neighbors reported by it through Topology response */
	uint32_t num_neighbor_1905;	/**< number of 1905 neighbors reported by it through Topology response */
	uint32_t num_neighbor_l2;	/**< number of L2 neighbors reported by it through Topology response */
	uint32_t num_brtuple;		/**< number of L2 bridge tuples reported by it through Topology response */

	struct list_head ipv4list;	/**< list of struct i1905_ipv4 */
	struct list_head ipv6list;	/**< list of struct i1905_ipv6 */
	struct list_head vendorlist;	/**< list of struct i1905_vendor_info */
	struct list_head iflist;	/**< list of struct i1905_interface */
	struct list_head non1905_nbrlist;
	struct list_head l2_nbrlist;
	struct list_head brlist;	/**< list of struct i1905_bridge_tuple */

	uint8_t *non1905_macaddrs;      /* non1905-neighbors' macaddresses */

	struct i1905_security security;	/**< 1905 security type */
	//struct list_head reglist;	/* list of i1905_registrar in network */

	struct i1905_selfdevice *dev;	/**< reference back to self device */
	struct list_head list;
};


/**
 * @brief Represents the network topology.
 *
 * Defines the network topology that is built using 1905 Topology discovery,
 * 1905 Topology request/response and 1905 Topology notifications.
 */
struct i1905_topology {
	bool enable;
	uint8_t status;			/**< whether available or incomplete */
	//TODO: changelog table
	uint32_t num_devices;		/**< number of 1905 devices in the network */
	struct list_head devlist;	/**< list of struct i1905_device in the network excluding self device*/
};


struct i1905_master_interface {
	char ifname[16];
	uint32_t ifindex;
	uint8_t macaddr[6];
	uint32_t ifstatus;
	uint32_t num_ipaddrs;
	struct ip_address *ipaddrs;
	struct list_head list;
};

/**
 * @brief Represents the own device that is running IEEE1905 protocol.
 */
struct i1905_selfdevice {
	uint32_t tsp;
	bool enabled;
	uint8_t aladdr[6];		/**< ALID or AL-macaddress */
	enum i1905_version version;	/**< version, one of I1905_VERSION_ */
	uint8_t regband;		/**< bitmap of i1905_registrar_type */

	char name[65];                  /**< friendly device name */
	char manufacturer[65];          /**< manufacturer name */
	char model[65];                 /**< model name */
	char *url;			/**< control URL */

	uint32_t num_interface;		/**< number of 1905 interfaces */
	struct list_head iflist;	/**< list of struct i1905_interface */

	uint32_t num_master_interface;	/**< number of master interfaces */
	struct list_head miflist;	/**< list of struct i1905_master_interface */

	int num_non1905_neighbor;

	struct i1905_fwdtable fwd;
	struct i1905_topology topology;	/**< network topology */

	struct i1905_security security;	/**< 1905 security */
	uint8_t netregistrar[3][6];	/**< macaddress of WSC registrars in the network */
};


/**
 * @brief Structure representing IEEE1905 data model.
 *
 * This structure defines the data model for an IEEE1905 device object.
 */
struct i1905_dm {
	struct i1905_selfdevice self;	/**< represents self device */
};


#endif /* I1905_DM_H */
