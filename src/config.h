/*
 * config.h
 * IEEE-1905 configuration structs and functions.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */


#ifndef CONFIG_H
#define CONFIG_H


struct i1905_extension_config {
	char name[32];
	struct list_head ovrrlist;
	struct list_head newlist;
	struct list_head list;
};

struct i1905_iface_config {
	char ifname[16];
	bool is_bridge;			/* whether a bridged interface */
	struct list_head list;
};

enum i1905_apband_config {
	I1905_CONFIG_REGISTRAR_2G,
	I1905_CONFIG_REGISTRAR_5G,
	I1905_CONFIG_REGISTRAR_60G,
	I1905_CONFIG_REGISTRAR_NUM,
};

#define I1905_CONFIG_REGISTRAR_NONE	0
#define I1905_CONFIG_REGISTRAR_ALL	0xff

struct i1905_apconfig {
	uint32_t band;
	size_t ssidlen;
	uint8_t ssid[32];
	size_t keylen;
	uint8_t key[64];
	uint8_t macaddr[6];

	/* wsc attributes */
	uint8_t apband;
	uint8_t uuid[16];
	uint16_t auth_type;
	uint16_t enc_type;
	char manufacturer[65];		/* with terminating '\0' */
	char model_name[33];
	char device_name[33];
	char model_number[33];
	char serial_number[33];
	uint8_t device_type[8];		/* category-0050F204-subcategory */
	uint32_t os_version;
	struct list_head list;
};

struct i1905_config {
	const char *objname;
	bool enabled;
	uint16_t primary_vid;           /* primary vlanid; default = 0 (untagged) */
	uint32_t registrar;		/* bitmap of I1905_CONFIG_REGISTRAR_* */
	bool extensions;		/* allow extensions ? */
	struct list_head extlist;	/* list of i1905_extension_config */
	uint8_t macaddr[6];		/* AL macaddress */
	struct list_head iflist;	/* list of i1905_iface_config */
	struct list_head reglist;	/* list of i1905_apconfig */
	bool update_config;

	/* following three for device identification tlv */
	char manufacturer[65];
	char model_name[33];
	char device_name[33];
	char *url;			/**< url to control or webui */

	/* global wsc attributes follow -
	 * can be overridden by ap specific ones
	 * from struct i1905_apconfig.
	 */
	uint8_t uuid[16];
	char model_number[33];
	char serial_number[33];
	uint8_t device_type[8];		/* category-0050F204-subcategory */
	uint32_t os_version;
};



int i1905_reconfig(struct i1905_config *cfg, const char *path, const char *file);
int i1905_config_defaults(struct i1905_config *cfg);
int i1905_dump_config(struct i1905_config *cfg);
void i1905_config_free(struct i1905_config *cfg);

int i1905_config_update_ap(struct i1905_config *cfg, struct i1905_apconfig *ap);

int i1905_config_add_interface(struct i1905_config *cfg, const char *ifname);


#endif /* CONFIG_H */
