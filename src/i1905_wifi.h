/*
 * i1905_wifi.h - WiFi HAL API wrappers
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef I1905_PLATFORM_H
#define I1905_PLATFORM_H

enum I1905_WPS_STATUS {
	I1905_WPS_STATUS_IDLE,
	I1905_WPS_STATUS_PROCESSING,
	I1905_WPS_STATUS_SUCCESS,
	I1905_WPS_STATUS_FAIL,
	I1905_WPS_STATUS_TIMEOUT,
	I1905_WPS_STATUS_UNKNOWN,
};

#ifdef HAS_WIFI
int is_wifi_interface(const char *ifname);
int platform_wifi_get_assoc_sta_metric(const char *ifname, uint8_t *sta_macaddr, struct i1905_metric *metric);
int platform_wifi_get_interface_metric(const char *ifname, struct i1905_metric *metric);
int platform_wifi_get_standard(const char *ifname, enum i1905_mediatype *std);
int platform_wifi_get_channel(const char *ifname, uint32_t *ch, uint32_t *bw, uint32_t *cf0, uint32_t *cf1);
int platform_wifi_get_freqband(const char *ifname, uint32_t *band);
int platform_wifi_get_bssid(const char *ifname, uint8_t *bssid);
int platform_wifi_get_wps_status(const char *ifname, enum I1905_WPS_STATUS *status);
int platform_wifi_get_role(const char *ifname, uint32_t *role);
int platform_wifi_get_assoclist(const char *ifname, uint8_t *sta_macaddrs, int *num);
int platform_wifi_get_4addr_parent(const char *ifname, char *parent);

#else
static inline int is_wifi_interface(const char *ifname)
{
	return -1;
}

static inline int platform_wifi_get_assoc_sta_metric(const char *ifname, uint8_t *sta_macaddr, struct i1905_metric *metric)
{
	return -1;
}

static inline int platform_wifi_get_interface_metric(const char *ifname, struct i1905_metric *metric)
{
	return -1;
}

static inline int platform_wifi_get_standard(const char *ifname, enum i1905_mediatype *std)
{
	return -1;
}

static inline int platform_wifi_get_channel(const char *ifname, uint32_t *ch, uint32_t *bw, uint32_t *cf0, uint32_t *cf1)
{
	return -1;
}

static inline int platform_wifi_get_freqband(const char *ifname, uint32_t *band)
{
	return -1;
}

static inline int platform_wifi_get_bssid(const char *ifname, uint8_t *bssid)
{
	return -1;
}

static inline int platform_wifi_get_wps_status(const char *ifname, enum I1905_WPS_STATUS *status)
{
	return -1;
}

static inline int platform_wifi_get_role(const char *ifname, uint32_t *role)
{
	return -1;
}

static inline int platform_wifi_get_assoclist(const char *ifname, uint8_t *sta_macaddrs, int *num)
{
	return -1;
}

static inline int platform_wifi_get_4addr_parent(const char *ifname, char *parent)
{
	return -1;
}

#endif /* HAS_WIFI */

#endif /* I1905_PLATFORM_H */
