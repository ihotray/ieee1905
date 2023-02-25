/*
 * i1905_wifi.c - WiFi HAL API wrapper implementation for Easy-soc-libs libwifi.so
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <easy/easy.h>
#include <wifi.h>

#include "debug.h"
#include "bufutil.h"
#include "util.h"
#include "timer.h"
#include "i1905_dm.h"
#include "i1905_wifi.h"

#include "1905_tlvs.h"

uint8_t wifi_rssi_to_rcpi(int rssi)
{
	if (!rssi)
		return 255;

	if (rssi < -110)
		return 0;

	if (rssi > 0)
		return 220;

	return (rssi + 110) * 2;
}

int is_wifi_interface(const char *ifname)
{
	char parent[16] = {0};
	char path[512] = {0};
	char rpath[PATH_MAX] = {0};
	struct stat s;

	memset(&s, 0, sizeof(struct stat));
	snprintf(path, 512, "/sys/class/net/%s/phy80211", ifname);
	realpath(path, rpath);
	if (lstat(rpath, &s) != -1) {
		if (S_ISDIR(s.st_mode)) {
			return 1;
		}
	}

	/* WDS interface also has WiFi mediatype */
	if (platform_wifi_get_4addr_parent(ifname, parent) == 0 &&
	    strlen(parent)) {
		return 1;
	}

	return 0;
}

int platform_wifi_get_assoc_sta_metric(const char *ifname, uint8_t *sta_macaddr,
				       struct i1905_metric *metric)
{
	struct wifi_sta sta = {0};
	int ret = -1;


	ret = wifi_get_sta_info(ifname, sta_macaddr, &sta);
#ifdef WIFI_EASYMESH
	if (ret) {
		char parent[16] = {0};

		if (!wifi_get_4addr_parent(ifname, parent))
			ret = wifi_get_sta_info(parent, sta_macaddr, &sta);
	}
#endif
	if (!ret) {
		metric->tx_errors = sta.stats.tx_err_pkts;
		metric->rx_errors = sta.stats.rx_fail_pkts;
		metric->tx_packets = sta.stats.tx_pkts;
		metric->rx_packets = sta.stats.rx_pkts;
		metric->available = 100;
		metric->max_rate = sta.maxrate;
		metric->max_phyrate = sta.rate.rate;
		metric->rssi = wifi_rssi_to_rcpi(sta.rssi[0]);
	}

	return ret;
}

int platform_wifi_get_interface_metric(const char *ifname, struct i1905_metric *metric)
{
	struct wifi_sta sta = {0};
	int ret = -1;


	ret = wifi_sta_info(ifname, &sta);
	if (!ret) {
		metric->tx_errors = sta.stats.tx_err_pkts;
		metric->rx_errors = sta.stats.rx_fail_pkts;
		metric->tx_packets = sta.stats.tx_pkts;
		metric->rx_packets = sta.stats.rx_pkts;
		metric->available = 100;
		metric->max_rate = sta.maxrate;
		metric->max_phyrate = sta.rate.rate;
		metric->rssi = wifi_rssi_to_rcpi(sta.rssi[0]);
	}

	return ret;
}

int platform_wifi_get_channel(const char *ifname, uint32_t *channel,
			      uint32_t *bandwidth, uint32_t *channel_seg0_idx,
			      uint32_t *channel_seg1_idx)
{
	enum wifi_bw bw;
	int ret;


	ret = wifi_get_channel(ifname, channel, &bw);
	if (!ret) {
		switch (bw) {
		case BW20:
			*bandwidth = 20;
			*channel_seg0_idx = *channel;
			break;
		case BW40:
			*bandwidth = 40;
			*channel_seg0_idx = *channel;
			break;
		case BW80:
			*bandwidth = 80;
			*channel_seg0_idx = *channel;
			break;
		case BW160:
			*bandwidth = 160;
			*channel_seg0_idx = *channel;
			break;
		case BW8080:
			*bandwidth = 160;
			*channel_seg0_idx = *channel;
			//*channel_seg1_idx =		//TODO
			break;
		default:
			break;
		}
	}

	return ret;
}

int platform_wifi_get_freqband(const char *ifname, uint32_t *band)
{
	enum wifi_band b;
	int ret;

	*band = 0;
	ret = wifi_get_oper_band(ifname, &b);
	if (ret)
		return -1;

	info("Oper-band: %d\n", b);
	switch (b) {
	case BAND_2:
		*band = 2;
		break;
	case BAND_5:
		*band = 5;
		break;
	case BAND_60:
		*band = 60;
		break;
	case BAND_6:
		*band = 6;
		break;
	default:
		ret = -1;
		break;
	}

	return ret;
}

int platform_wifi_get_standard(const char *ifname, enum i1905_mediatype *std)
{
	int ret;
	uint8_t s = 0;
	uint32_t channel;
	enum wifi_bw bw;
	enum wifi_band band;


	ret = wifi_get_channel(ifname, &channel, &bw);
	if (ret)
		return -1;

	ret = wifi_get_oper_band(ifname, &band);
	if (ret)
		return -1;

	info("Oper-band: %d\n", band);
	ret = wifi_get_oper_stds(ifname, &s);
	if (ret)
		return -1;

	info("Oper-Standards: %d\n", s);

#ifdef WIFI_EASYMESH
	if (!!(s & WIFI_AX)) {
		info("802.11ax\n");
		*std = I1905_802_11AX;
	} else if (!!(s & WIFI_BE)) {
		info("802.11be\n");
		*std = I1905_802_11BE;
	} else
#endif
	if (!!(s & WIFI_AC)) {
		*std = I1905_802_11AC_5_GHZ;
		info("802.11ac\n");
	} else if (!!(s & WIFI_N)) {
		*std = band == BAND_2 ?
				I1905_802_11N_2_4_GHZ :
				I1905_802_11N_5_GHZ;
		info("802.11n\n");
	} else if (!!(s & WIFI_A)) {
		*std = I1905_802_11A_5_GHZ;
		info("802.11a\n");
	} else if (!!(s & WIFI_G)) {
		*std = I1905_802_11G_2_4_GHZ;
		info("802.11g\n");
	} else {
		*std = I1905_802_11B_2_4_GHZ;
		info("802.11b\n");
	}

	return 0;
}

int platform_wifi_get_role(const char *ifname, uint32_t *role)
{
	enum wifi_mode mode;
	int ret;


	ret = wifi_get_mode(ifname, &mode);
	if (!ret) {
		if (mode == WIFI_MODE_AP || mode == WIFI_MODE_AP_VLAN)
			*role = IEEE80211_ROLE_AP;
		else if (mode == WIFI_MODE_STA)
			*role = IEEE80211_ROLE_STA;
		else
			*role = IEEE80211_ROLE_UNKNOWN;
	}

	return ret;
}

int platform_wifi_get_assoclist(const char *ifname, uint8_t *sta_macaddrs, int *num)
{
	return wifi_get_assoclist(ifname, sta_macaddrs, num);
}

int platform_wifi_get_bssid(const char *ifname, uint8_t *bssid)
{
	return wifi_get_bssid(ifname, bssid);
}

int platform_wifi_get_wps_status(const char *ifname, enum I1905_WPS_STATUS *status)
{
	enum wps_status wpsstatus = WPS_STATUS_IDLE;

	return wifi_get_wps_status(ifname, &wpsstatus);
}

int platform_wifi_get_4addr_parent(const char *ifname, char *parent)
{
	return wifi_get_4addr_parent(ifname, parent);
}
