/*
 * i1905_al.c - IEEE-1905 AL functions
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>

#include <easy/easy.h>

#include "debug.h"
#include "bufutil.h"
#include "util.h"
#include "timer.h"
#include "config.h"
#include "cmdu.h"
#include "cmdu_ackq.h"
#include "cmdufrag.h"
#include "i1905_dm.h"
#include "i1905.h"
#include "1905_tlvs.h"
#include "i1905_wifi.h"



#if 0
static struct i1905_ipv4 *alloc_ipv4(void)
{
	struct i1905_ipv4 *ip;

	ip = calloc(1, sizeof(*ip));
	return ip;
}

static struct i1905_ipv6 *alloc_ipv6(void)
{
	struct i1905_ipv6 *ip;

	ip = calloc(1, sizeof(*ip));
	return ip;
}
#endif


int i1905_get_link_info(struct i1905_interface *iface, uint8_t *peer_macaddr)
{

	return 0;
}

int i1905_dm_update_interface_linkmetrics(struct i1905_private *priv,
					  struct i1905_interface *iface)
{
	struct i1905_neighbor_interface *nif;
	struct if_stats s = {0};
	int ret;


	if (!iface)
		return -1;


	if (!IS_MEDIA_WIFI(iface->media)) {
		ret = if_getstats(iface->ifname, &s);
		if (ret)
			return -1;
	}

	list_for_each_entry(nif, &iface->nbriflist, list) {
		if (nif->media == I1905_MEDIA_UNKNOWN)
			nif->media = iface->media;

		if (!IS_MEDIA_WIFI(iface->media)) {
			nif->metric.br_present = iface->is_brif ? true : false;
			nif->metric.tx_errors = s.tx_errors;
			nif->metric.rx_errors = s.rx_errors;
			nif->metric.tx_packets = s.tx_packets;
			nif->metric.rx_packets = s.rx_packets;
			nif->metric.available = 100;
			//nif->metric.max_rate;
			//nif->metric.max_phyrate;
			nif->metric.rssi = 255;
		} else {
			struct ieee80211_info *wifi =
				(struct ieee80211_info *)iface->mediainfo;
			struct i1905_metric metric = {0};
			int res = -1;

			memset(&metric, 0, sizeof(struct i1905_metric));
			if (wifi->role == IEEE80211_ROLE_AP)
				res = platform_wifi_get_assoc_sta_metric(iface->ifname, nif->macaddr, &metric);
			else if (wifi->role == IEEE80211_ROLE_STA)
				res = platform_wifi_get_interface_metric(iface->ifname, &metric);

			if (!res) {
				memcpy(&nif->metric, &metric, sizeof(struct i1905_metric));
				nif->metric.br_present = iface->is_brif ? true : false;
			}
		}
	}

	return 0;
}

int i1905_dm_update_interface_non1905_nbrs(struct i1905_private *p,
					   struct i1905_interface *iface)
{
	struct neigh_queue *q = (struct neigh_queue *)&p->neigh_q;
	//struct i1905_device *rdevs[NEIGH_ENTRIES_MAX] = {0};
	struct i1905_selfdevice *self = &p->dm.self;
	struct i1905_device *rdev = NULL;
	struct neigh_entry *e = NULL;
	uint8_t stas[768] = {0};
	//int num_rdevs = 0;
	int numb = 128;
	int idx = 0;
	int i, k;


	/* delete current non1905-neighbors through this interface */
	list_flush(&iface->non1905_nbrlist, struct i1905_non1905_neighbor, list);
	iface->num_neighbor_non1905 = 0;

	if (iface->invalid)
		return 0;

	/* get associated STAs */
	platform_wifi_get_assoclist(iface->ifname, stas, &numb);

	for (idx = 0; idx < NEIGH_ENTRIES_MAX; idx++) {
		hlist_for_each_entry(e, &q->table[idx], hlist) {
			if (e->is1905) {
				/*
				struct i1905_device *rdev = NULL;

				rdev = i1905_get_neigh_device(iface, e->macaddr);
				if (rdev)
					rdevs[num_rdevs++] = rdev;
				*/
				continue;
			}

			if (e->is1905_slave)
				continue;

			if ((iface->brport && e->brport == iface->brport) ||
			    !strncmp(e->ifname, iface->ifname, 16)) {
				struct i1905_non1905_neighbor *nnbr;

				if (e->type != NEIGH_TYPE_WIFI) {
					nnbr = calloc(1, sizeof(*nnbr));
					if (nnbr) {
						memcpy(nnbr->macaddr, e->macaddr, 6);
						list_add_tail(&nnbr->list, &iface->non1905_nbrlist);
						iface->num_neighbor_non1905++;
					}
				} else {
					for (i = 0; i < numb; i++) {
						if (!memcmp(&stas[i*6], e->macaddr, 6)) {
							nnbr = calloc(1, sizeof(*nnbr));
							if (nnbr) {
								memcpy(nnbr->macaddr, e->macaddr, 6);
								list_add_tail(&nnbr->list, &iface->non1905_nbrlist);
								iface->num_neighbor_non1905++;
								break;
							}
						}
					}
				}
			}
		}
	}


	/* discard non1905-neighbors reported by our downstream neighbors */
	list_for_each_entry(rdev, &self->topology.devlist, list) {
		if (rdev->upstream)
			continue;

		for (k = 0; k < rdev->num_neighbor_non1905; k++) {
			struct i1905_non1905_neighbor *xn, *tmp;

			list_for_each_entry_safe(xn, tmp, &iface->non1905_nbrlist, list) {
				if (hwaddr_equal(&rdev->non1905_macaddrs[k*6], xn->macaddr)) {
					list_del(&xn->list);
					iface->num_neighbor_non1905--;
					free(xn);
				}
			}
		}
	}

	return 0;
}

int i1905_dm_update_interface_self(struct i1905_private *p,
				   struct i1905_interface *iface)
{
	struct ip_address ips[32] = {0};
	enum if_mediatype mtype;
	int num = 32;
	int ret;
	int ifindex;


	if (!iface)
		return -1;

	dbg("%s: %s\n", __func__, iface->ifname);

	ifindex = if_nametoindex(iface->ifname);
	if (!ifindex) {
		err("%s: %s not found\n", __func__, iface->ifname);
		return -1;
	}

	if_getflags(iface->ifname, &iface->ifstatus);
	if (!(iface->ifstatus & IFF_UP)) {
		err("%s: %s not up\n", __func__, iface->ifname);
		return 0;
	}

	if (ifindex != iface->ifindex) {
		err("%s: %s ifindex mismatch (old = %d, new = %d) rebinding\n",
			__func__, iface->ifname, iface->ifindex, ifindex);

		i1905_rebind_interface(p, iface->priv);
	}

	if (!strncmp(iface->ifname, "lo", 2))
		return 0;

	ret = if_isbridge_interface(iface->ifname);
	if (ret > 0) {
		iface->is_brif = true;
		iface->br_ifindex = ret;
	} else {
		iface->is_brif = false;
		iface->br_ifindex = 0;
	}


	ret = if_getaddrs(iface->ifname, ips, &num);
	if (!ret) {
		if (iface->ipaddrs) {
			free(iface->ipaddrs);
			iface->ipaddrs = NULL;
			iface->num_ipaddrs = 0;
		}

		if (num > 0) {
			iface->ipaddrs = calloc(num, sizeof(struct ip_address));
			if (!iface->ipaddrs) {
				fprintf(stderr, "-ENOMEM!\n");
				return -1;
			}

			iface->num_ipaddrs = num;
			memcpy(iface->ipaddrs, ips, num * sizeof(struct ip_address));
#if 1	//debug
			for (int i = 0; i < num; i++) {
				char buf[256] = {0};
				size_t sz = 256;

				if (ips[i].family == AF_INET)
					inet_ntop(AF_INET, &ips[i].addr.ip4, buf, sz);
				else
					inet_ntop(AF_INET6, &ips[i].addr.ip6, buf, sz);

				printf("%s: ip = %s\n", iface->ifname, buf);
			}
#endif	//debug
		}
	}

	/* consider downstream-only non1905 neighbors */
	if (!iface->upstream)
		i1905_dm_update_interface_non1905_nbrs(p, iface);

	//fprintf(stderr, "Updating mediainfo for '%s'\n", iface->ifname);
	if_getmediatype(iface->ifname, &mtype);
	if (mtype == IF_MEDIA_WIFI) {
		struct ieee80211_info *wifi;
		enum i1905_mediatype std = I1905_MEDIA_UNKNOWN;
		uint32_t role = IEEE80211_ROLE_UNKNOWN;
		uint32_t seg0_idx, seg1_idx;
		uint32_t bandwidth;
		uint32_t channel;
		uint8_t band = 5;


		if (iface->mediainfo) {
			free(iface->mediainfo);
			iface->mediainfo = NULL;
			iface->media = I1905_MEDIA_UNKNOWN;
		}

		iface->mediainfo = calloc(1, sizeof(struct ieee80211_info));
		if (!iface->mediainfo) {
			fprintf(stderr, "-ENOMEM\n");
			return -1;
		}

		wifi = (struct ieee80211_info *)iface->mediainfo;

		/* get channel and bandwidth */
		ret = platform_wifi_get_channel(iface->ifname, &channel,
						&bandwidth,
						&seg0_idx,
						&seg1_idx);
		if (!ret) {
			wifi->ap_channel_seg0_idx = seg0_idx;
			wifi->ap_channel_seg1_idx = seg1_idx;
			wifi->ap_bandwidth = bandwidth;

			if (channel > 0 && channel <= 14)
				band = 2;
			else if (channel >= 36 && channel < 200)
				band = 5;
		}

		/* get standard */
		ret = platform_wifi_get_standard(iface->ifname, &std);
		if (!ret)
			iface->media = std;

		/* if cannot determine media, assume based on band */
		if (iface->media == I1905_MEDIA_UNKNOWN) {
			iface->media = band == 2 ?
				I1905_802_11G_2_4_GHZ : I1905_802_11AC_5_GHZ;
		}

		/* get bssid */
		ret = platform_wifi_get_bssid(iface->ifname, wifi->bssid);
		if (ret)
			warn("error platform_wifi_get_bssid()\n");

		/* get role */
		ret = platform_wifi_get_role(iface->ifname, &role);
		if (!ret)
			wifi->role = role;

	} else {

		if (iface->mediainfo) {
			free(iface->mediainfo);
			iface->mediainfo = NULL;
		}

		iface->media = MEDIA_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET; //FIXME
		iface->mediainfo = NULL;
	}

	i1905_dm_update_interface_linkmetrics(p, iface);


	return 0;
}

int i1905_dm_update_master_interfaces(struct i1905_private *p)
{
	struct i1905_master_interface *m, *tmp;
	struct ip_address ips[32] = {0};
	int num = 32;
	int ifindex;
	int ret;

	list_for_each_entry_safe(m, tmp, &p->dm.self.miflist, list) {
		ifindex = if_nametoindex(m->ifname);
		if (!ifindex) {
			err("%s: %s vanished!\n", __func__, m->ifname);
			continue;
		}

		m->ifindex = ifindex;
		if_getflags(m->ifname, &m->ifstatus);
		if (!(m->ifstatus & IFF_UP)) {
			dbg("%s: %s not up\n", __func__, m->ifname);
			continue;
		}

		dbg("%s: %s\n", __func__, m->ifname);
		ret = if_getaddrs(m->ifname, ips, &num);
		if (!ret) {
			if (m->num_ipaddrs > 0) {
				free(m->ipaddrs);
				m->num_ipaddrs = 0;
			}

			if (num > 0) {
				m->ipaddrs = calloc(num, sizeof(struct ip_address));
				if (m->ipaddrs) {
					m->num_ipaddrs = num;
					memcpy(m->ipaddrs, ips, num * sizeof(struct ip_address));
				} else {
					dbg("%s: -ENOMEM!\n", __func__);
				}
			}
		}
	}

	return 0;
}

int i1905_dm_refresh_self(struct i1905_private *p)
{
	struct i1905_interface *iface, *tmp;
	int ifindex;
	int ret;


	list_for_each_entry_safe(iface, tmp, &p->dm.self.iflist, list) {
		ifindex = if_nametoindex(iface->ifname);
		if (!ifindex) {
			err("%s: %s vanished! Removing object....\n", __func__, iface->ifname);
			ret = i1905_remove_interface_object(p, iface->ifname);

			i1905_teardown_interface(p, iface->ifname);
			err("%s: %s\n", __func__, !ret ? "SUCCESS" : "FAILED");
			continue;
		}

		i1905_dm_update_interface_self(p, iface);
	}

	i1905_dm_update_master_interfaces(p);


	return 0;
}

