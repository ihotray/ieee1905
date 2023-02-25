/*
 * i1905_ubus.c - implements IEEE-1905 UBUS APIs.
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
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
#include "util.h"
#include "timer.h"
#include "config.h"
#include "cmdu.h"
#include "cmdu_ackq.h"
#include "cmdufrag.h"
#include "i1905_dm.h"
#include "i1905.h"
#include "neigh.h"
#include "i1905_extension.h"

#include "1905_tlvs.h"
#include "i1905_wifi.h"


static const char *ubus_object_to_ifname(struct ubus_object *obj)
{
	if (strstr(obj->name, IEEE1905_OBJECT".al."))
		return obj->name + strlen(IEEE1905_OBJECT".al.");

	return NULL;
}

static const char *media_type2str(enum i1905_mediatype m)
{
#define C2S(x)	case I1905_ ## x: return "IEEE " #x;

	switch (m) {
	C2S(802_3U_FAST_ETHERNET)
	C2S(802_3AB_GIGABIT_ETHERNET)
	C2S(802_11B_2_4_GHZ)
	C2S(802_11G_2_4_GHZ)
	C2S(802_11A_5_GHZ)
	C2S(802_11N_2_4_GHZ)
	C2S(802_11N_5_GHZ)
	C2S(802_11AC_5_GHZ)
	C2S(802_11AD_60_GHZ)
	C2S(802_11AF_GHZ)
#ifdef WIFI_EASYMESH
	C2S(802_11AX)
	C2S(802_11BE)
#endif
	C2S(1901_WAVELET)
	C2S(1901_FFT)
	C2S(MOCA_V1_1)
	case I1905_MEDIA_UNKNOWN:
		break;
	}

	return "Unknown";

#undef C2S
}

static const char *ipv4_type2str(enum ip4addr_type t)
{
#define C2S(x)	case IP4_TYPE_ ## x: return #x;

	switch (t) {
	C2S(DHCP)
	C2S(STATIC)
	C2S(AUTOIP)
	case IP4_TYPE_UNKNOWN:
		break;
	}

	return "Unknown";

#undef C2S
}

static const char *ipv6_type2str(enum ip6addr_type t)
{
#define C2S(x)	case IP6_TYPE_ ## x: return #x;

	switch (t) {
	C2S(LINKLOCAL)
	C2S(DHCP)
	C2S(STATIC)
	C2S(SLAAC)
	case IP6_TYPE_UNKNOWN:
		break;
	}

	return "Unknown";

#undef C2S
}

static const char *role_type2str(uint8_t r)
{
	if (r == IEEE80211_ROLE_AP)
		return "ap";
	else if (r == IEEE80211_ROLE_STA)
		return "sta";
	else if (r == IEEE80211_ROLE_P2P_CLIENT)
		return "p2p_client";
	else if (r == IEEE80211_ROLE_P2P_GO)
		return "p2p_go";
	else if (r == IEEE80211_ROLE_AD_PCP)
		return "pcp";

	return "Unknown";
}

static int i1905_ubus_dump_neighbors(struct i1905_private *priv, struct blob_buf *bb)
{
	struct i1905_selfdevice *self = &priv->dm.self;
	struct i1905_device *nbr;
	void *a, *aa;


	a = blobmsg_open_array(bb, "neighbors");
	list_for_each_entry(nbr, &self->topology.devlist, list) {
		char nbr_almacstr[18] = {0};

		aa = blobmsg_open_table(bb, "");
		hwaddr_ntoa(nbr->aladdr, nbr_almacstr);
		blobmsg_add_string(bb, "ieee1905id", nbr_almacstr);
		blobmsg_add_u8(bb, "immediate", nbr->is_immediate_neighbor ? true : false);
		blobmsg_add_u32(bb, "ageout", timer_remaining_ms(&nbr->agetimer));
		blobmsg_add_u32(bb, "ageout_immediate", timer_remaining_ms(&nbr->immediate_nbr_agetimer));
		blobmsg_close_table(bb, aa);
	}
	blobmsg_close_array(bb, a);

	return 0;
}

static int i1905_ubus_dump_links(struct i1905_private *priv, struct blob_buf *bb)
{
	struct i1905_selfdevice *self = &priv->dm.self;
	struct i1905_neighbor_interface *link = NULL;
	struct i1905_interface *iface;
	void *a, *aa;
	void *t, *tt;


	a = blobmsg_open_array(bb, "interfaces");
	list_for_each_entry(iface, &self->iflist, list) {
		char ifstr[18] = {0};
		char alstr[18] = {0};

		t = blobmsg_open_table(bb, "");
		hwaddr_ntoa(iface->aladdr, alstr);
		hwaddr_ntoa(iface->macaddr, ifstr);
		blobmsg_add_string(bb, "ifname", iface->ifname);
		blobmsg_add_u8(bb, "upstream", iface->upstream ? true : false);
		blobmsg_add_string(bb, "ieee1905id", alstr);
		blobmsg_add_string(bb, "macaddress", ifstr);

		aa = blobmsg_open_array(bb, "links");
		list_for_each_entry(link, &iface->nbriflist, list) {
			char nalstr[18] = {0};
			char nifstr[18] = {0};

			tt = blobmsg_open_table(bb, "");
			hwaddr_ntoa(link->aladdr, nalstr);
			hwaddr_ntoa(link->macaddr, nifstr);
			blobmsg_add_string(bb, "nbr_ieee1905id", nalstr);
			blobmsg_add_string(bb, "nbr_macaddress", nifstr);
			blobmsg_add_u8(bb, "direct", link->direct ? true : false);
			blobmsg_add_u32(bb, "ageout", timer_remaining_ms(&link->staletimer));
			blobmsg_close_table(bb, tt);
		}
		blobmsg_close_array(bb, aa);
		blobmsg_close_table(bb, t);
	}
	blobmsg_close_array(bb, a);

	return 0;
}

static int i1905_ubus_dump_non1905neighbors(struct i1905_private *priv,
					    struct blob_buf *bb)
{
	struct i1905_selfdevice *self = &priv->dm.self;
	struct i1905_interface *lif;
	void *a, *aa, *aaa;


	a = blobmsg_open_array(bb, "non1905_neighbors");
	list_for_each_entry(lif, &self->iflist, list) {
		struct i1905_non1905_neighbor *nnbr;
		char xnbr[18] = {0};

		if (lif->invalid)
			continue;

		aa = blobmsg_open_table(bb, "");
		blobmsg_add_string(bb, "ifname", lif->ifname);
		blobmsg_add_u8(bb, "upstream", lif->upstream ? true : false);

		aaa = blobmsg_open_array(bb, lif->ifname);
		list_for_each_entry(nnbr, &lif->non1905_nbrlist, list) {
			hwaddr_ntoa(nnbr->macaddr, xnbr);
			blobmsg_add_string(bb, "", xnbr);
		}
		blobmsg_close_array(bb, aaa);
		blobmsg_close_table(bb, aa);
	}
	blobmsg_close_array(bb, a);

	return 0;
}

static int i1905_ubus_dump_info(struct i1905_private *priv, struct blob_buf *bb)
{
	struct i1905_selfdevice *self = &priv->dm.self;
	struct i1905_config *cfg = &priv->cfg;
	//struct i1905_registrar_config *r;
	int num_immediate_neighbors = 0;
	struct i1905_interface *iface;
	struct i1905_vendor_info *ven;
	struct i1905_bridge_tuple *br;
	//struct i1905_registrar *reg;
	struct i1905_interface *rif;
	struct i1905_device *nbr;
	void *a, *aa, *aaa, *aaaa;
	char almacstr[18] = {0};



	blobmsg_add_string(bb, "version", self->version == I1905_VERSION_DOT_1 ?
			   "1905.1" : "1905.1a");

	hwaddr_ntoa(self->aladdr, almacstr);
	blobmsg_add_string(bb, "ieee1905id", almacstr);
	blobmsg_add_string(bb, "status", "enabled");

	if (cfg->registrar) {
		blobmsg_add_u8(bb, "registrar", true);
		a = blobmsg_open_array(bb, "registrar_band");
		if (!!(cfg->registrar & I1905_REGISTRAR_5G))
			blobmsg_add_string(bb, "", "5GHz");

		if (!!(cfg->registrar & I1905_REGISTRAR_2G))
			blobmsg_add_string(bb, "", "2.4GHz");

		if (!!(cfg->registrar & I1905_REGISTRAR_60G))
			blobmsg_add_string(bb, "", "60GHz");

		blobmsg_close_array(bb, a);
	} else {
		blobmsg_add_u8(bb, "registrar", false);
	}

	/* skip 'lo' as valid interface */
	blobmsg_add_u32(bb, "num_interfaces", self->num_interface - 1);

	aa = blobmsg_open_array(bb, "interface");
	list_for_each_entry(iface, &self->iflist, list) {
		char ifmacstr[18] = {0};
		struct i1905_vendor_info *v;
		struct i1905_neighbor_interface *link;
		char ouistring[7] = {0};
		char parent[16] = {0};

		if (iface->invalid || iface->lo)
			continue;

		aaa = blobmsg_open_table(bb, "");
		blobmsg_add_string(bb, "ifname", iface->ifname);
		if (!platform_wifi_get_4addr_parent(iface->ifname, parent))
			blobmsg_add_string(bb, "parent_ifname", parent);
		else
			blobmsg_add_string(bb, "parent_ifname", "");

		hwaddr_ntoa(iface->macaddr, ifmacstr);
		blobmsg_add_string(bb, "macaddress", ifmacstr);
		/* blobmsg_add_u32(bb, "ifindex", iface->ifindex); */
		blobmsg_add_string(bb, "status", !!(iface->ifstatus & IFF_UP) ?
				   "up" : "down");

		blobmsg_add_string(bb, "media", media_type2str(iface->media));
		blobmsg_add_u32(bb, "band", iface->band);

		sprintf(ouistring, "%02x%02x%02x", iface->genphy.oui[0],
			iface->genphy.oui[1], iface->genphy.oui[2]);
		blobmsg_add_string(bb, "genphy_oui", ouistring);
		if (iface->genphy.variant) {
			char varstr[3] = {0};

			sprintf(varstr, "%02x", iface->genphy.variant);
			blobmsg_add_string(bb, "genphy_variant", varstr);
		} else {
			blobmsg_add_string(bb, "genphy_variant", "");
		}

		blobmsg_add_string(bb, "genphy_url", iface->genphy.url ?
				   iface->genphy.url : "");

		blobmsg_add_string(bb, "power", !!(iface->ifstatus & IFF_UP) ?
				   "on" : "off");	//FIXME

		blobmsg_add_u32(bb, "num_vendor_properties", iface->num_vendor);
		a = blobmsg_open_array(bb, "properties");
		list_for_each_entry(v, &iface->vendorlist, list) {
			blobmsg_add_string(bb, "oui", "");
			blobmsg_add_string(bb, "data", "");
		}
		blobmsg_close_array(bb, a);

		blobmsg_add_u32(bb, "num_links", iface->num_links);

		a = blobmsg_open_array(bb, "links");
		list_for_each_entry(link, &iface->nbriflist, list) {
			char peer_macstr[18] = {0};
			char peer_almacstr[18] = {0};
			struct i1905_device *rdev;
			void *t, *tt;

			t = blobmsg_open_table(bb, "");
			hwaddr_ntoa(link->macaddr, peer_macstr);
			blobmsg_add_string(bb, "macaddress", peer_macstr);
			hwaddr_ntoa(link->aladdr, peer_almacstr);
			blobmsg_add_string(bb, "ieee1905id", peer_almacstr);
			blobmsg_add_u8(bb, "direct", link->direct ? true : false);

			blobmsg_add_string(bb, "media", media_type2str(link->media));

			rdev = i1905_dm_neighbor_lookup(iface, link->aladdr);
			if (rdev && rdev->version == I1905_VERSION_DOT_1A) {
				blobmsg_add_string(bb, "genphy_oui", "");
				blobmsg_add_string(bb, "genphy_variant", "");
				blobmsg_add_string(bb, "genphy_url", "");
			}

			tt = blobmsg_open_table(bb, "metric");
			blobmsg_add_u8(bb, "has_bridge",
				       link->metric.br_present ? true : false);

			blobmsg_add_u32(bb, "tx_errors", link->metric.tx_errors);
			blobmsg_add_u32(bb, "rx_errors", link->metric.rx_errors);
			blobmsg_add_u32(bb, "tx_packets", link->metric.tx_packets);
			blobmsg_add_u32(bb, "rx_packets", link->metric.rx_packets);

			blobmsg_add_u32(bb, "max_macrate", link->metric.max_rate);
			blobmsg_add_u32(bb, "max_phyrate", link->metric.max_phyrate);
			blobmsg_add_u32(bb, "rssi", link->metric.rssi);
			blobmsg_close_table(bb, tt);


			blobmsg_close_table(bb, t);
		}
		blobmsg_close_array(bb, a);
		blobmsg_close_table(bb, aaa);
	}
	blobmsg_close_array(bb, aa);


	a = blobmsg_open_table(bb, "topology");
	blobmsg_add_u8(bb, "enabled", self->topology.enable ? true : false);
	blobmsg_add_string(bb, "status", "available");
	blobmsg_add_u32(bb, "max_changelog", 100);
	blobmsg_add_u32(bb, "num_changelog", 0);
	blobmsg_add_string(bb, "last_change", "");
	//TODO: changelog table

	/* skip showing non-immediate 1905 neighbors from topology */
	list_for_each_entry(nbr, &self->topology.devlist, list) {
		if (nbr->is_immediate_neighbor)
			num_immediate_neighbors++;
	}

	blobmsg_add_u32(bb, "num_device", num_immediate_neighbors);
	aa = blobmsg_open_array(bb, "device");
	list_for_each_entry(nbr, &self->topology.devlist, list) {
		struct i1905_net_non1905_neighbor *non;
		char nbr_almacstr[18] = {0};
		struct i1905_ipv4 *ipv4;
		struct i1905_ipv6 *ipv6;
		void *t, *tt;


		if (!nbr->is_immediate_neighbor)
			continue;

		t = blobmsg_open_table(bb, "");
		hwaddr_ntoa(nbr->aladdr, nbr_almacstr);
		blobmsg_add_string(bb, "ieee1905id", nbr_almacstr);
		blobmsg_add_string(bb, "version", nbr->version == I1905_VERSION_DOT_1 ?
				   "1905.1" : "1905.1a");


		blobmsg_add_string(bb, "name", nbr->name);
		blobmsg_add_string(bb, "manufacturer", nbr->manufacturer);
		blobmsg_add_string(bb, "model", nbr->model);
		blobmsg_add_string(bb, "url", nbr->url ? nbr->url : "");

		blobmsg_add_u32(bb, "num_vendor_properties", nbr->num_vendor);
		blobmsg_add_u32(bb, "num_ipv4", nbr->num_ipv4);
		blobmsg_add_u32(bb, "num_ipv6", nbr->num_ipv6);
		blobmsg_add_u32(bb, "num_interface", nbr->num_interface);
		blobmsg_add_u32(bb, "num_neighbor_non1905", nbr->num_neighbor_non1905);
		blobmsg_add_u32(bb, "num_neighbor_1905", nbr->num_neighbor_1905);
		blobmsg_add_u32(bb, "num_neighbor_l2", nbr->num_neighbor_l2);
		blobmsg_add_u32(bb, "num_bridge_tuple", nbr->num_brtuple);

		aaa = blobmsg_open_array(bb, "ipv4_address");
		list_for_each_entry(ipv4, &nbr->ipv4list, list) {
			char ipv4_ifmacstr[18] = {0};
			char ipbuf[256] = {0};
			char dhcpsbuf[256] = {0};

			tt = blobmsg_open_table(bb, "");
			hwaddr_ntoa(ipv4->macaddr, ipv4_ifmacstr);
			inet_ntop(AF_INET, &ipv4->addr, ipbuf, sizeof(ipbuf));
			inet_ntop(AF_INET, &ipv4->dhcpserver, dhcpsbuf, sizeof(dhcpsbuf));
			blobmsg_add_string(bb, "macaddress", ipv4_ifmacstr);
			blobmsg_add_string(bb, "ip", ipbuf);
			blobmsg_add_string(bb, "type", ipv4_type2str(ipv4->type));
			blobmsg_add_string(bb, "dhcpserver", dhcpsbuf);
			blobmsg_close_table(bb, tt);
		}
		blobmsg_close_array(bb, aaa);

		aaa = blobmsg_open_array(bb, "ipv6_address");
		list_for_each_entry(ipv6, &nbr->ipv6list, list) {
			char ipv6_ifmacstr[18] = {0};
			char ipbuf[256] = {0};
			char dhcpsbuf[256] = {0};

			tt = blobmsg_open_table(bb, "");
			hwaddr_ntoa(ipv6->macaddr, ipv6_ifmacstr);
			inet_ntop(AF_INET6, &ipv6->addr, ipbuf, sizeof(ipbuf));
			inet_ntop(AF_INET6, &ipv6->origin, dhcpsbuf, sizeof(dhcpsbuf));
			blobmsg_add_string(bb, "macaddress", ipv6_ifmacstr);
			blobmsg_add_string(bb, "ip", ipbuf);
			blobmsg_add_string(bb, "type", ipv6_type2str(ipv6->type));
			blobmsg_add_string(bb, "dhcpserver", dhcpsbuf);
			blobmsg_close_table(bb, tt);
		}
		blobmsg_close_array(bb, aaa);

		aaa = blobmsg_open_array(bb, "vendor_properties");
		list_for_each_entry(ven, &nbr->vendorlist, list) {
			tt = blobmsg_open_table(bb, "");
			blobmsg_add_string(bb, "oui", "");
			blobmsg_add_string(bb, "data", "");
			blobmsg_close_table(bb, tt);
		}
		blobmsg_close_array(bb, aaa);


		aaa = blobmsg_open_array(bb, "interface");
		list_for_each_entry(rif, &nbr->iflist, list) {
			char rifmacstr[18] = {0};

			tt = blobmsg_open_table(bb, "");
			hwaddr_ntoa(rif->macaddr, rifmacstr);
			blobmsg_add_string(bb, "macaddress", rifmacstr);
			dbg("%s: rif = %s\n", __func__, rifmacstr);
			blobmsg_add_string(bb, "media", media_type2str(rif->media));
			blobmsg_add_string(bb, "power", "on");	//TODO
			if (nbr->version == I1905_VERSION_DOT_1A) {
				blobmsg_add_string(bb, "genphy_oui", "");
				blobmsg_add_string(bb, "genphy_variant", "");
				blobmsg_add_string(bb, "genphy_url", "");
			}

			if (IS_MEDIA_WIFI(rif->media)) {
				struct ieee80211_info *winfo;
				char rif_bssidstr[18] = {0};

				winfo = (struct ieee80211_info *)rif->mediainfo;
				if (winfo) {
					hwaddr_ntoa(winfo->bssid, rif_bssidstr);
					blobmsg_add_string(bb, "bssid", rif_bssidstr);
					blobmsg_add_string(bb, "role", role_type2str(winfo->role));
					blobmsg_add_u32(bb, "bandwidth", winfo->ap_bandwidth);
					blobmsg_add_u32(bb, "freq_seg0_idx", winfo->ap_channel_seg0_idx);
					blobmsg_add_u32(bb, "freq_seg1_idx", winfo->ap_channel_seg1_idx);
				} else {
					dbg("%s: WiFi rif missing mediainfo!\n", __func__);
				}
			}
			blobmsg_close_table(bb, tt);
		}
		blobmsg_close_array(bb, aaa);


		aaa = blobmsg_open_array(bb, "non1905_neighbors");
		list_for_each_entry(rif, &nbr->iflist, list) {
			char rif_macstr[18] = {0};

			aaaa = blobmsg_open_table(bb, "");
			hwaddr_ntoa(rif->macaddr, rif_macstr);
			blobmsg_add_string(bb, "interface_macaddress", rif_macstr);

			tt = blobmsg_open_array(bb, "neighbors");
			list_for_each_entry(non, &rif->non1905_nbrlist, list) {
				char non_macstr[18] = {0};

				hwaddr_ntoa(non->macaddr, non_macstr);
				blobmsg_add_string(bb, "macaddress", non_macstr);
			}
			blobmsg_close_array(bb, tt);
			blobmsg_close_table(bb, aaaa);
		}
		blobmsg_close_array(bb, aaa);

		/*
		aaa = blobmsg_open_array(bb, "l2_neighbors");
		list_for_each_entry(l2, &nbr->l2_nbrlist, list) {

			tt = blobmsg_open_table(bb, "");
			blobmsg_add_string(bb, "macaddress", "TODO");
			blobmsg_add_string(bb, "behind_macs", "TODO");
			blobmsg_close_table(bb, tt);
		}
		blobmsg_close_array(bb, aaa);
		*/


		aaa = blobmsg_open_array(bb, "ieee1905_neighbors");
		list_for_each_entry(rif, &nbr->iflist, list) {
			struct i1905_neighbor_interface *nnlink = NULL;

			list_for_each_entry(nnlink, &rif->nbriflist, list) {
				char macstr[18] = {0};
				char alstr[18] = {0};
				char mmacstr[18] = {0};
				void *ttt;


				tt = blobmsg_open_table(bb, "");
				hwaddr_ntoa(rif->macaddr, macstr);
				hwaddr_ntoa(nnlink->aladdr, alstr);
				blobmsg_add_string(bb, "macaddress", macstr);
				blobmsg_add_string(bb, "neighbor_device_id", alstr);
				blobmsg_add_u32(bb, "num_metrics", 1);	/* always latest one */

				aaaa = blobmsg_open_array(bb, "metric");
				ttt = blobmsg_open_table(bb, "");
				hwaddr_ntoa(nnlink->macaddr, mmacstr);
				blobmsg_add_string(bb, "neighbor_macaddress", mmacstr);
				blobmsg_add_u8(bb, "has_bridge", nnlink->has_bridge ? true : false);
				blobmsg_add_u32(bb, "tx_errors", nnlink->metric.tx_errors);
				blobmsg_add_u32(bb, "rx_errors", nnlink->metric.rx_errors);
				blobmsg_add_u32(bb, "tx_packets", nnlink->metric.tx_packets);
				blobmsg_add_u32(bb, "rx_packets", nnlink->metric.rx_packets);
				blobmsg_add_u32(bb, "max_macrate", nnlink->metric.max_rate);
				blobmsg_add_u32(bb, "max_phyrate", nnlink->metric.max_phyrate);
				blobmsg_add_u32(bb, "link_available", nnlink->metric.available);
				blobmsg_add_u32(bb, "rssi", nnlink->metric.rssi);
				blobmsg_close_table(bb, ttt);
				blobmsg_close_array(bb, aaaa);
				blobmsg_close_table(bb, tt);
			}
		}
		blobmsg_close_array(bb, aaa);

		aaa = blobmsg_open_array(bb, "bridge_tuples");
		list_for_each_entry(br, &nbr->brlist, list) {
			int i;

			tt = blobmsg_open_table(bb, "");
			aaaa = blobmsg_open_array(bb, "tuple");
			for (i = 0; i < br->num_macs; i++) {
				char macstr[18] = {0};

				hwaddr_ntoa(&br->macaddrs[i*6], macstr);
				blobmsg_add_string(bb, "", macstr);
			}
			blobmsg_close_array(bb, aaaa);
			blobmsg_close_table(bb, tt);
		}
		blobmsg_close_array(bb, aaa);

		blobmsg_close_table(bb, t);
	}
	blobmsg_close_array(bb, aa);
	blobmsg_close_table(bb, a);


	a = blobmsg_open_table(bb, "network_registrars");
	{
		char macstr[18] = {0};

		hwaddr_ntoa(self->netregistrar[IEEE80211_FREQUENCY_BAND_2_4_GHZ], macstr);
		blobmsg_add_string(bb, "registrar_2", macstr);

		hwaddr_ntoa(self->netregistrar[IEEE80211_FREQUENCY_BAND_5_GHZ], macstr);
		blobmsg_add_string(bb, "registrar_5", macstr);

		hwaddr_ntoa(self->netregistrar[IEEE80211_FREQUENCY_BAND_60_GHZ], macstr);
		blobmsg_add_string(bb, "registrar_60", macstr);
	}
	blobmsg_close_table(bb, a);

	return 0;
}

int i1905_ubus_info(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_buf bb;
	struct i1905_private *p = container_of(obj, struct i1905_private, obj);

	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);

	i1905_ubus_dump_info(p, &bb);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

int i1905_ubus_neighbors(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_buf bb;
	struct i1905_private *p = container_of(obj, struct i1905_private, obj);

	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);

	i1905_ubus_dump_neighbors(p, &bb);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

int i1905_ubus_links(struct ubus_context *ctx, struct ubus_object *obj,
		     struct ubus_request_data *req, const char *method,
		     struct blob_attr *msg)
{
	struct blob_buf bb;
	struct i1905_private *p = container_of(obj, struct i1905_private, obj);

	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);

	i1905_ubus_dump_links(p, &bb);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

int i1905_ubus_non1905neighbors(struct ubus_context *ctx, struct ubus_object *obj,
				struct ubus_request_data *req, const char *method,
				struct blob_attr *msg)
{
	struct blob_buf bb;
	struct i1905_private *p = container_of(obj, struct i1905_private, obj);

	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);

	i1905_ubus_dump_non1905neighbors(p, &bb);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

int i1905_ubus_show_arptable(struct ubus_context *ctx, struct ubus_object *obj,
			     struct ubus_request_data *req, const char *method,
			     struct blob_attr *msg)
{
	struct i1905_private *p = container_of(obj, struct i1905_private, obj);
	struct neigh_queue *q = &p->neigh_q;
	struct blob_buf bb;
	void *a, *aa;
	int i;

	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);

	a = blobmsg_open_array(&bb, "arptable");
	for (i = 0; i < NEIGH_ENTRIES_MAX; i++) {
		struct neigh_entry *e = NULL;
		char macstr[18] = {0};

		if (hlist_empty(&q->table[i]))
			continue;

		hlist_for_each_entry(e, &q->table[i], hlist) {
			aa = blobmsg_open_table(&bb, "");
			uint16_t brport;
			char *ifname = NULL;

			hwaddr_ntoa(e->macaddr, macstr);
			blobmsg_add_string(&bb, "macaddr", macstr);
			blobmsg_add_u8(&bb, "is1905", e->is1905 ? true : false);
			blobmsg_add_u8(&bb, "is1905_slave", e->is1905_slave ? true : false);
			blobmsg_add_u32(&bb, "state", e->state);

			brport = neigh_get_brport(q, e->macaddr);
			if (brport != 0xffff) {
				ifname = i1905_brport_to_ifname(p, brport);
				if (ifname)
					blobmsg_add_string(&bb, "ifname", ifname);
			}

			blobmsg_close_table(&bb, aa);
		}
	}
	blobmsg_close_array(&bb, a);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

enum {
	I1905_APCONFIG_IFNAME,
	I1905_APCONFIG_BAND,
	I1905_APCONFIG_ACTION,
	NUM_I1905_APCONFIG_POLICY,
};

static const struct blobmsg_policy apconfig_policy[NUM_I1905_APCONFIG_POLICY] = {
	[I1905_APCONFIG_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[I1905_APCONFIG_BAND] = { .name = "band", .type = BLOBMSG_TYPE_INT32 },
	[I1905_APCONFIG_ACTION] = { .name = "action", .type = BLOBMSG_TYPE_STRING },
};

int i1905_ubus_apconfig(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct i1905_private *p = container_of(obj, struct i1905_private, obj);
	struct blob_attr *tb[NUM_I1905_APCONFIG_POLICY];
	char ifname[16] = { 0 };
	char action[64] = { 0 };
	uint8_t band = 0xff;
	int ret = UBUS_STATUS_INVALID_ARGUMENT;


	blobmsg_parse(apconfig_policy, NUM_I1905_APCONFIG_POLICY, tb,
		      blob_data(msg), blob_len(msg));


	if (tb[I1905_APCONFIG_IFNAME]) {
		strncpy(ifname, blobmsg_data(tb[I1905_APCONFIG_IFNAME]), 16);
		ifname[15] = '\0';
	}


	if (tb[I1905_APCONFIG_BAND]) {
		band = blobmsg_get_u32(tb[I1905_APCONFIG_BAND]);
		if (band != 2 && band != 5 && band != 6)
			return ret;
	}

	if (tb[I1905_APCONFIG_ACTION]) {
		size_t len = blobmsg_data_len(tb[I1905_APCONFIG_ACTION]);

		strncpy(action, blobmsg_data(tb[I1905_APCONFIG_ACTION]), len);
		action[63] = '\0';
	}

	if (!strcmp(action, "renew"))
		ret = i1905_apconfig_renew(p, band);
	else if (!strcmp(action, "search"))
		ret = i1905_apconfig_request(p, band);
	else {
		p->start_apconfig = 1;
		ret = i1905_apconfig_request(p, band);
	}

	return ret;
}

int i1905_ubus_refresh(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	//struct i1905_private *p = container_of(obj, struct i1905_private, obj);
	int ret = 0;

	//ret = i1905_refresh(p);		//TODO

	return ret;
}

int i1905_ubus_start(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct i1905_private *p = container_of(obj, struct i1905_private, obj);
	int ret = 0;

	ret = i1905_start(p);

	return ret;
}

int i1905_ubus_stop(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct i1905_private *p = container_of(obj, struct i1905_private, obj);
	int ret = 0;

	ret = i1905_stop(p);

	return ret;
}

int i1905_ubus_status(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	//struct i1905_private *p = container_of(obj, struct i1905_private, obj);
	int ret = 0;

	//ret = i1905_get_status(p);	// TODO

	return ret;
}

int i1905_ubus_iface_status(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req, const char *method,
			    struct blob_attr *msg)
{
	//struct i1905_interface_private *ifp =
	//		container_of(obj, struct i1905_interface_private, obj);
	int ret = 0;

	//ret = i1905_get_interface_status(ifp);	// TODO

	return ret;
}

int i1905_ubus_iface_neighbors(struct ubus_context *ctx, struct ubus_object *obj,
			       struct ubus_request_data *req, const char *method,
			       struct blob_attr *msg)
{
	struct i1905_interface_private *ifp =
			container_of(obj, struct i1905_interface_private, obj);
	struct i1905_interface *iface = i1905_interface_priv(ifp);
	//struct i1905_selfdevice *self = (struct i1905_selfdevice *)iface->device;
	//struct i1905_device *rdev = NULL;
	char almacstr[18] = {0};
	struct blob_buf bb;
	void *a, *b;


	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);
	a = blobmsg_open_array(&bb, "neighbors");

#if 0
	list_for_each_entry(rdev, &self->topology.devlist, list) {
		struct i1905_interface *rif;
		char ifmacstr[18] = {0};

		b = blobmsg_open_table(&bb, "");
		hwaddr_ntoa(rdev->aladdr, almacstr);
		blobmsg_add_string(&bb, "aladdr", almacstr);
		list_for_each_entry(rif, &rdev->iflist, list) {
			hwaddr_ntoa(rif->macaddr, ifmacstr);
			blobmsg_add_string(&bb, "macaddress", ifmacstr);
			blobmsg_add_string(&bb, "media", IS_MEDIA_WIFI(rif->media) ?
					   "wifi" : "ethernet");
		}
		blobmsg_close_table(&bb, b);
	}
#endif
	struct i1905_neighbor_interface *nif;
	list_for_each_entry(nif, &iface->nbriflist, list) {
		char ifmacstr[18] = {0};

		b = blobmsg_open_table(&bb, "");
		hwaddr_ntoa(nif->aladdr, almacstr);
		hwaddr_ntoa(nif->macaddr, ifmacstr);
		blobmsg_add_string(&bb, "aladdr", almacstr);
		blobmsg_add_string(&bb, "macaddress", ifmacstr);
		blobmsg_add_string(&bb, "media", IS_MEDIA_WIFI(nif->media) ?
				   "wifi" : "ethernet");
		blobmsg_add_u8(&bb, "direct", nif->direct ? true : false);
		blobmsg_close_table(&bb, b);
	}



	blobmsg_close_array(&bb, a);
	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}


/* cmdu tx policy */
enum {
	CMDU_TX_DST,		/* dest macaddress */
	CMDU_TX_SRC,		/* optional; interface's macaddress */
	CMDU_TX_TYPE,		/* can be in hex '0xaaaa' or int */
	CMDU_TX_MID,		/* optional; otherwise autogenerated */
	CMDU_TX_VID,		/* optional; vlanid for tagging frames */
	CMDU_TX_DATA,		/* tlv data in hexstring format */
	CMDU_TX_IFNAME,		/* use as outgoing interface if provided */
	NUM_CMDU_TX_POLICY,
};

static const struct blobmsg_policy cmdu_tx_policy[NUM_CMDU_TX_POLICY] = {
	[CMDU_TX_DST] = { .name = "dst", .type = BLOBMSG_TYPE_STRING },
	[CMDU_TX_SRC] = { .name = "src", .type = BLOBMSG_TYPE_STRING },
	[CMDU_TX_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_INT32 },
	[CMDU_TX_MID] = { .name = "mid", .type = BLOBMSG_TYPE_INT32 },
	[CMDU_TX_VID] = { .name = "vid", .type = BLOBMSG_TYPE_INT32 },
	[CMDU_TX_DATA] = { .name = "data", .type = BLOBMSG_TYPE_STRING },
	[CMDU_TX_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
};

int i1905_ubus_iface_cmdu_tx(struct ubus_context *ctx, struct ubus_object *obj,
			     struct ubus_request_data *req, const char *method,
			     struct blob_attr *msg)
{
	struct i1905_interface_private *ifp =
			container_of(obj, struct i1905_interface_private, obj);
	struct blob_attr *tb[NUM_CMDU_TX_POLICY];
	struct blob_buf bb = {};
	char dst_macstr[18] = {0};
	char src_macstr[18] = {0};
	uint8_t dst[6] = {0};
	uint8_t src[6] = {0};
	char *data_str = NULL;
	uint8_t *data = NULL;
	const char *ifname;
	uint16_t type = 0;
	uint16_t mid = 0;
	uint16_t vid = 0;
	int data_len = 0;
	int ret;


	ifname = ubus_object_to_ifname(obj);
	UNUSED(ifname);

	blobmsg_parse(cmdu_tx_policy, NUM_CMDU_TX_POLICY, tb,
					blob_data(msg), blob_len(msg));

	/* cmdu type and destination macaddress are mandatory */
	if (!tb[CMDU_TX_DST] || !tb[CMDU_TX_TYPE])
		return UBUS_STATUS_INVALID_ARGUMENT;


	if (tb[CMDU_TX_DST]) {
		strncpy(dst_macstr, blobmsg_data(tb[CMDU_TX_DST]),
			sizeof(dst_macstr)-1);

		if (hwaddr_aton(dst_macstr, dst) == NULL)
			return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (tb[CMDU_TX_SRC]) {
		strncpy(src_macstr, blobmsg_data(tb[CMDU_TX_SRC]),
			sizeof(src_macstr)-1);

		if (hwaddr_aton(src_macstr, src) == NULL)
			return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (tb[CMDU_TX_TYPE])
		type = blobmsg_get_u32(tb[CMDU_TX_TYPE]);

	if (tb[CMDU_TX_MID])
		mid = blobmsg_get_u32(tb[CMDU_TX_MID]);

	if (tb[CMDU_TX_VID]) {
		vid = (uint16_t)blobmsg_get_u32(tb[CMDU_TX_VID]);
		if (vid > 4094)
			vid = 0;
	}

	if (tb[CMDU_TX_DATA]) {
		int data_strlen;

		data_strlen = blobmsg_data_len(tb[CMDU_TX_DATA]);
		data_len = (data_strlen - 1) / 2;
		data_str = calloc(1, data_strlen * sizeof(char));
		data = calloc(1, data_len * sizeof(uint8_t));

		if (data_str && data) {
			strncpy(data_str, blobmsg_data(tb[CMDU_TX_DATA]), data_strlen);
			strtob(data_str, data_len, data);
		}
	}

	ret = i1905_cmdu_tx(ifp, vid, dst, src, type, &mid, data, data_len, false);

	if (data_str)
		free(data_str);

	if (data)
		free(data);


	/* reply with mid and status of cmdu tx */
	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "status", ret == 0 ? "ok" : "fail");
	if (!ret)
		blobmsg_add_u32(&bb, "mid", mid);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

int i1905_ubus_cmdu_tx(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{
	struct i1905_private *p = container_of(obj, struct i1905_private, obj);
	struct blob_attr *tb[NUM_CMDU_TX_POLICY];
	struct i1905_interface_private *ifpriv;
	struct i1905_interface *iface = NULL;
	char dst_macstr[18] = {0};
	char src_macstr[18] = {0};
	char outifname[16] = {0};
	struct blob_buf bb = {};
	uint8_t dst[6] = {0};
	uint8_t src[6] = {0};
	uint8_t *data = NULL;
	uint16_t type = 0;
	uint16_t mid = 0;
	uint16_t vid = 0;
	int data_len = 0;
	int ret = 0;



	blobmsg_parse(cmdu_tx_policy, NUM_CMDU_TX_POLICY, tb,
		      blob_data(msg), blob_len(msg));

	/* cmdu type and destination macaddress are mandatory */
	if (!tb[CMDU_TX_DST] || !tb[CMDU_TX_TYPE])
		return UBUS_STATUS_INVALID_ARGUMENT;


	if (tb[CMDU_TX_DST]) {
		strncpy(dst_macstr, blobmsg_data(tb[CMDU_TX_DST]),
			sizeof(dst_macstr)-1);

		if (hwaddr_aton(dst_macstr, dst) == NULL)
			return UBUS_STATUS_INVALID_ARGUMENT;

		if (hwaddr_is_zero(dst))
			return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (tb[CMDU_TX_SRC]) {
		strncpy(src_macstr, blobmsg_data(tb[CMDU_TX_SRC]),
			sizeof(src_macstr)-1);

		if (hwaddr_aton(src_macstr, src) == NULL)
			return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (tb[CMDU_TX_TYPE])
		type = blobmsg_get_u32(tb[CMDU_TX_TYPE]);

	if (tb[CMDU_TX_MID])
		mid = blobmsg_get_u32(tb[CMDU_TX_MID]);

	if (tb[CMDU_TX_VID]) {
		vid = (uint16_t)blobmsg_get_u32(tb[CMDU_TX_VID]);
		if (vid > 4094)
			vid = 0;
	}

	if (tb[CMDU_TX_DATA]) {
		int data_strlen = 0;
		char *data_str = NULL;

		data_strlen = blobmsg_data_len(tb[CMDU_TX_DATA]);
		data_len = (data_strlen - 1) / 2;
		data_str = calloc(1, data_strlen * sizeof(char));
		data = calloc(1, data_len * sizeof(uint8_t));

		if (data_str && data) {
			strncpy(data_str, blobmsg_data(tb[CMDU_TX_DATA]), data_strlen);
			strtob(data_str, data_len, data);
		}

		if (data_str)
			free(data_str);
	}

	if (tb[CMDU_TX_IFNAME]) {
		strncpy(outifname, blobmsg_data(tb[CMDU_TX_IFNAME]), 16);
		outifname[15] = '\0';
		iface = i1905_ifname_to_interface(p, outifname);
		if (!iface) {
			dbg("%s: %s is not a 1905 interface\n", __func__, outifname);
			return UBUS_STATUS_INVALID_ARGUMENT;
		}
	}

	if (hwaddr_is_mcast(dst) || hwaddr_is_bcast(dst)) {
		bool lo = true;

		if (!mid)
			mid = cmdu_get_next_mid();

		/* send out through all interfaces */
		list_for_each_entry(iface, &p->dm.self.iflist, list) {
			ifpriv = iface->priv;
			ret &= i1905_cmdu_tx(ifpriv, vid, dst, src, type, &mid,
					     data, data_len, lo);
			lo = false;
			/* if any ret = 0, return success */
		}
	} else if (hwaddr_equal(dst, p->dm.self.aladdr)) {

		if (list_empty(&p->dm.self.iflist)) {
			if (data)
				free(data);
			return UBUS_STATUS_INVALID_ARGUMENT;
		}

		iface = i1905_lookup_interface(p, "lo");
		if (!iface) {
			if (data)
				free(data);
			return UBUS_STATUS_INVALID_ARGUMENT;
		}

		ifpriv = iface->priv;
		ret = i1905_cmdu_tx(ifpriv, vid, dst, src, type, &mid,
				    data, data_len, true);
	} else {
		struct i1905_neighbor_interface *nif;
		struct neigh_entry *ent = NULL;
		bool sent = false;

		ret = -1;

		if (iface) {
			ret = i1905_cmdu_tx(iface->priv, vid, dst, src, type, &mid,
					    data, data_len, false);

			goto done;
		}

		list_for_each_entry(iface, &p->dm.self.iflist, list) {
			list_for_each_entry(nif, &iface->nbriflist, list) {
				if (hwaddr_equal(nif->aladdr, dst)) {
					ret = i1905_cmdu_tx(iface->priv, vid, dst,
							    src, type, &mid,
							    data, data_len, true);
					sent = true;
					break;
				}
			}

			if (sent)
				break;
		}

		/* last resort neigh cache */
		if (!sent) {
			ent = neigh_lookup(&p->neigh_q, dst);
			if (ent) {
				char *ifname = ent->ifname;

				if (if_isbridge(ifname))
					ifname = i1905_brport_to_ifname(p, ent->brport);

				if (ifname) {
					iface = i1905_ifname_to_interface(p, ifname);
					ret = i1905_cmdu_tx(iface->priv, vid, dst,
							    src, type, &mid,
							    data, data_len, true);
					sent = true;
				}
			}
		}
	}

done:
	if (data)
		free(data);


	/* reply with mid and status of cmdu tx */
	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "status", ret == 0 ? "ok" : "fail");
	if (!ret)
		blobmsg_add_u32(&bb, "mid", mid);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}


/* cmdu rx policy */
enum {
	CMDU_RX_SRC,		/* sender's macaddress */
	CMDU_RX_IFNAME,		/* receiving interface's name */
	CMDU_RX_TYPE,		/* in hex "0xaaaa" or int */
	CMDU_RX_MID,		/* optional; default is 0 */
	CMDU_RX_DATA,		/* data in hexstring representing tlvs */
	NUM_CMDU_RX_POLICY,
};

static const struct blobmsg_policy cmdu_rx_policy[NUM_CMDU_RX_POLICY] = {
	[CMDU_RX_SRC] = { .name = "src", .type = BLOBMSG_TYPE_STRING },
	[CMDU_RX_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[CMDU_RX_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
	[CMDU_RX_MID] = { .name = "mid", .type = BLOBMSG_TYPE_INT32 },
	[CMDU_RX_DATA] = { .name = "data", .type = BLOBMSG_TYPE_STRING },
};

int i1905_ubus_cmdu_rx(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{
	struct i1905_private *p = container_of(obj, struct i1905_private, obj);
	struct blob_attr *tb[NUM_CMDU_RX_POLICY];
	struct i1905_interface *iface;
	struct cmdu_buff *rxf = NULL;
	char src_macstr[18] = {0};
	char ifname[16] = {0};
	uint8_t src[6] = {0};
	char *data_str = NULL;
	uint8_t *data = NULL;
	uint16_t type = 0;
	uint16_t mid = 0;
	int data_len = 0;
	int ret = 0;



	blobmsg_parse(cmdu_rx_policy, NUM_CMDU_RX_POLICY, tb,
		      blob_data(msg), blob_len(msg));

	if (!tb[CMDU_RX_IFNAME]) {
		dbg("%s: interface name is mandatory\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	strncpy(ifname, blobmsg_data(tb[CMDU_RX_IFNAME]), 16);
	ifname[15] = '\0';
	iface = i1905_ifname_to_interface(p, ifname);
	if (!iface) {
		dbg("%s: %s is not a 1905 interface\n", __func__, ifname);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (tb[CMDU_RX_SRC]) {
		strncpy(src_macstr, blobmsg_data(tb[CMDU_RX_SRC]),
			sizeof(src_macstr)-1);

		if (hwaddr_aton(src_macstr, src) == NULL)
			return UBUS_STATUS_INVALID_ARGUMENT;

		if (hwaddr_is_zero(src))
			return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (tb[CMDU_RX_DATA]) {
		int data_strlen = 0;

		data_strlen = blobmsg_data_len(tb[CMDU_RX_DATA]);
		data_len = (data_strlen - 1) / 2;
		data_str = calloc(1, data_strlen * sizeof(char));
		if (!data_str) {
			err("%s: -ENOMEM\n", __func__);
			return -1;
		}

		data = calloc(1, data_len * sizeof(uint8_t));
		if (!data) {
			free (data_str);
			err("%s: -ENOMEM\n", __func__);
			return -1;
		}

		strncpy(data_str, blobmsg_data(tb[CMDU_RX_DATA]), data_strlen);
		strtob(data_str, data_len, data);
		free(data_str);
	}

	/* start building the cmdu */
	rxf = cmdu_alloc_frame(data_len);
	if (!rxf) {
		err("%s: -ENOMEM\n", __func__);
		if (data_len)
			free(data);

		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	memcpy(rxf->dev_macaddr, iface->macaddr, 6);
	strncpy(rxf->dev_ifname, ifname, 15);
	memcpy(rxf->origin, src, 6);
	CMDU_SET_LAST_FRAGMENT(rxf->cdata);

	if (tb[CMDU_RX_TYPE]) {
		const char *typestr = blobmsg_data(tb[CMDU_RX_TYPE]);

		type = strtoul(typestr, NULL, 16);
		cmdu_set_type(rxf, type);
	}

	if (tb[CMDU_RX_MID]) {
		mid = blobmsg_get_u32(tb[CMDU_RX_MID]);
		cmdu_set_mid(rxf, mid);
	}

	if (data_len) {
		cmdu_put(rxf, data, data_len);
		free(data);
	}

	ret = i1905_process_cmdu(p, rxf);
	cmdu_free(rxf);
	return ret;
}

/* cmdu prepare policy */
enum {
	CMDU_PREP_TYPE,		/* cmdu type */
	CMDU_PREP_IFNAME,	/* interface name (optional) */
	CMDU_PREP_ARGS,		/* cmdu specific argument list */
	NUM_CMDU_PREP_POLICY,
};

static const struct blobmsg_policy cmdu_prep_policy[NUM_CMDU_PREP_POLICY] = {
	[CMDU_PREP_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_INT32 },
	[CMDU_PREP_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[CMDU_PREP_ARGS] = { .name = "args", .type = BLOBMSG_TYPE_ARRAY },
};

int i1905_ubus_cmdu_prepare(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req, const char *method,
			    struct blob_attr *msg)
{
	struct i1905_private *p = container_of(obj, struct i1905_private, obj);
	struct blob_attr *tb[NUM_CMDU_PREP_POLICY];
	struct i1905_interface *iface = NULL;
	struct cmdu_buff *cmdu = NULL;
	struct blob_buf bb = {};
	struct blob_attr *attr;
	char ifname[16] = {0};
	char *datastr = NULL;
	uint16_t type = 0;
	int rem;
	int i = 0;
#define ARGS_MAX 8
	char *argv[ARGS_MAX] = {0};
	int argc = 0;
	int ret = UBUS_STATUS_OK;


	if (list_empty(&p->dm.self.iflist))
		return UBUS_STATUS_INVALID_ARGUMENT;

	blobmsg_parse(cmdu_prep_policy, NUM_CMDU_PREP_POLICY, tb,
		      blob_data(msg), blob_len(msg));

	/* cmdu type is mandatory */
	if (!tb[CMDU_PREP_TYPE])
		return UBUS_STATUS_INVALID_ARGUMENT;


	type = blobmsg_get_u32(tb[CMDU_PREP_TYPE]);
	if (type > CMDU_TYPE_1905_END)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[CMDU_PREP_IFNAME]) {
		strncpy(ifname, blobmsg_data(tb[CMDU_PREP_IFNAME]), 16);
		ifname[15] = '\0';

		iface = i1905_ifname_to_interface(p, ifname);
	} else {
		if (list_empty(&p->dm.self.iflist))
			return UBUS_STATUS_INVALID_ARGUMENT;

		/* assume first interface in the iflist */
		iface = list_first_entry(&p->dm.self.iflist, struct i1905_interface, list);
	}

	if (!iface)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[CMDU_PREP_ARGS]) {
		blobmsg_for_each_attr(attr, tb[CMDU_PREP_ARGS], rem) {
			int len = blobmsg_data_len(attr);

			if (blobmsg_type(attr) != BLOBMSG_TYPE_STRING)
				continue;

			if (i >= ARGS_MAX) {
				argc = ARGS_MAX;
				ret = UBUS_STATUS_INVALID_ARGUMENT;
				goto out;
			}

			argv[i] = calloc(1, len * sizeof(char));
			if (argv[i])
				strncpy(argv[i], blobmsg_data(attr), len);

			i++;
		}
	}

	argc = i;

	if (!is_cmdu_tlv_required(type)) {
		blob_buf_init(&bb, 0);
		blobmsg_add_u32(&bb, "type", type);
		blobmsg_add_string(&bb, "data", "");
		ubus_send_reply(ctx, req, bb.head);
		blob_buf_free(&bb);

		goto out;
	}

	switch (type) {
	case CMDU_TYPE_TOPOLOGY_DISCOVERY:
		cmdu = i1905_build_topology_discovery(iface);
		break;
	case CMDU_TYPE_TOPOLOGY_NOTIFICATION:
		cmdu = i1905_build_topology_notification(iface);
		break;
	case CMDU_TYPE_TOPOLOGY_RESPONSE:
		cmdu = i1905_build_topology_response(iface);
		break;
	case CMDU_TYPE_VENDOR_SPECIFIC:
		cmdu = i1905_build_vendor_specific(iface, argc, argv);
		break;
	case CMDU_TYPE_LINK_METRIC_QUERY:
		cmdu = i1905_build_link_metric_query(iface);
		break;
	case CMDU_TYPE_LINK_METRIC_RESPONSE:
		cmdu = i1905_build_link_metric_response(iface, NULL,
					LINKMETRIC_QUERY_TYPE_BOTH); //FIXME
		break;
	case CMDU_TYPE_HIGHER_LAYER_RESPONSE:
		cmdu = i1905_build_higher_layer_response(iface);
		break;
	case CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH:
		cmdu = i1905_build_ap_autoconfig_search(iface,
					IEEE80211_FREQUENCY_BAND_5_GHZ); //FIXME:
		break;
	case CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE:
		cmdu = i1905_build_ap_autoconfig_response(iface,
					IEEE80211_FREQUENCY_BAND_5_GHZ); //FIXME
		break;
	case CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW:
		cmdu = i1905_build_ap_autoconfig_renew(iface,
					IEEE80211_FREQUENCY_BAND_5_GHZ); //FIXME:
		break;
	case CMDU_TYPE_AP_AUTOCONFIGURATION_WSC:
	case CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION:
	case CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION:
	case CMDU_TYPE_INTERFACE_POWER_CHANGE_REQUEST:
	case CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE:
	case CMDU_TYPE_GENERIC_PHY_RESPONSE:
	default:
		ret = UBUS_STATUS_NOT_SUPPORTED;
		goto out;
	}

	if (!cmdu) {
		ret = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}


	datastr = calloc(1, 2 * cmdu->datalen * sizeof(char) + 1);
	if (!datastr) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		cmdu_free(cmdu);
		ret = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}

	btostr(cmdu->data, cmdu->datalen, datastr);
	//fprintf(stderr, "datastr: '%s'\n", datastr);

	/* reply with type and tlv data */
	blob_buf_init(&bb, 0);
	blobmsg_add_u32(&bb, "type", type);
	blobmsg_add_string(&bb, "data", datastr);
	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	free(datastr);
	cmdu_free(cmdu);

out:
	for (i = 0; i < argc; i++)
		free(argv[i]);

	return ret;
}

/* add/del interface policy */
enum {
	I1905_INTERFACE_IFNAME,		/* interface name */
	NUM_I1905_INTERFACE_POLICY,
};

static const struct blobmsg_policy interface_policy[NUM_I1905_INTERFACE_POLICY] = {
	[I1905_INTERFACE_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
};

int i1905_ubus_interface_add(struct ubus_context *ctx, struct ubus_object *obj,
			     struct ubus_request_data *req, const char *method,
			     struct blob_attr *msg)
{
	struct i1905_private *p = container_of(obj, struct i1905_private, obj);
	struct blob_attr *tb[NUM_I1905_INTERFACE_POLICY];
	struct i1905_interface *iface;
	char ifname[16] = {0};
	int ret;


	blobmsg_parse(interface_policy, NUM_I1905_INTERFACE_POLICY, tb,
		      blob_data(msg), blob_len(msg));

	if (!tb[I1905_INTERFACE_IFNAME])
		return UBUS_STATUS_INVALID_ARGUMENT;

	strncpy(ifname, blobmsg_data(tb[I1905_INTERFACE_IFNAME]), 16);
	ifname[15] = '\0';

	iface = i1905_ifname_to_interface(p, ifname);
	if (iface) {
		dbg("%s: %s is already a 1905 interface\n", __func__, ifname);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	iface = i1905_setup_interface(p, ifname);
	if (!iface) {
		dbg("%s: %s: error setup interface\n", __func__, ifname);
		return -1;
	}

	ret = i1905_publish_interface_object(p, ifname);

	return ret;
}

int i1905_ubus_interface_del(struct ubus_context *ctx, struct ubus_object *obj,
			     struct ubus_request_data *req, const char *method,
			     struct blob_attr *msg)
{
	struct i1905_private *p = container_of(obj, struct i1905_private, obj);
	struct blob_attr *tb[NUM_I1905_INTERFACE_POLICY];
	char ifname[16] = {0};
	int ret;


	blobmsg_parse(interface_policy, NUM_I1905_INTERFACE_POLICY, tb,
		      blob_data(msg), blob_len(msg));

	if (!tb[I1905_INTERFACE_IFNAME])
		return UBUS_STATUS_INVALID_ARGUMENT;

	strncpy(ifname, blobmsg_data(tb[I1905_INTERFACE_IFNAME]), 16);
	ifname[15] = '\0';

	ret = i1905_remove_interface_object(p, ifname);
	i1905_teardown_interface(p, ifname);
	return ret;
}

#define MAX_IFACE_METHODS	8
static int add_iface_methods(struct ubus_object *iface_obj)
{
	struct ubus_method *iface_methods;
	int n_methods = 0;

	iface_methods = calloc(MAX_IFACE_METHODS, sizeof(struct ubus_method));
	if (!iface_methods)
		return -ENOMEM;

#define UBUS_METHOD_ADD(_tab, iter, __m)				\
do {									\
	struct ubus_method ___m = __m;					\
	memcpy(&_tab[iter++], &___m, sizeof(struct ubus_method));	\
} while(0)


	UBUS_METHOD_ADD(iface_methods, n_methods,
			UBUS_METHOD_NOARG("status", i1905_ubus_iface_status));

	UBUS_METHOD_ADD(iface_methods, n_methods,
			UBUS_METHOD_NOARG("neighbors", i1905_ubus_iface_neighbors));

	UBUS_METHOD_ADD(iface_methods, n_methods,
			UBUS_METHOD("cmdu", i1905_ubus_iface_cmdu_tx, cmdu_tx_policy));

#undef UBUS_METHOD_ADD

	iface_obj->methods = iface_methods;
	iface_obj->n_methods = n_methods;

	return 0;
}

static void free_iface_methods(struct ubus_object *iface_obj)
{
	if (iface_obj && iface_obj->methods)
		free((void *)iface_obj->methods);
}

int i1905_remove_interface_objects(struct i1905_private *priv)
{
	struct i1905_interface *iface;
	struct i1905_interface_private *ifpriv;
	int ret = 0;

	if (!priv)
		return -1;

	list_for_each_entry(iface, &priv->dm.self.iflist, list) {
		ifpriv = (struct i1905_interface_private *)iface->priv;

		if (ifpriv->obj.id != OBJECT_INVALID) {
			free_iface_methods(&ifpriv->obj);
			ret = ubus_remove_object(priv->ctx, &ifpriv->obj);
			if (ret) {
				fprintf(stderr, "Failed to delete; err = %s\n",
					ubus_strerror(ret));
			}
			ifpriv->obj.id = OBJECT_INVALID;
			free((void *)ifpriv->obj.name);
		}
	}

	return ret;
}

int i1905_publish_interface_objects(struct i1905_private *p)
{
	struct i1905_interface *iface;
	struct i1905_interface_private *priv;
	char objname[64] = {0};
	int ret = 0;


	list_for_each_entry(iface, &p->dm.self.iflist, list) {

		priv = (struct i1905_interface_private *)iface->priv;
		snprintf(objname, 63, "%s.al.%s", IEEE1905_OBJECT, iface->ifname);
		add_iface_methods(&priv->obj);

		priv->obj.name = strdup(objname);
		priv->obj_type.name = priv->obj.name;
		priv->obj_type.n_methods = priv->obj.n_methods;
		priv->obj_type.methods = priv->obj.methods;
		priv->obj.type = &priv->obj_type;

		ret = ubus_add_object(p->ctx, &priv->obj);
		if (ret) {
			fprintf(stderr, "Failed to add '%s' err = %s\n",
				objname, ubus_strerror(ret));
			goto out_rollback;
		}

		fprintf(stderr, "Added object '%s'\n", objname);
	}

	return ret;

out_rollback:
	//TODO: i1905_remove_interface_objects(p);
	return ret;
}

/* vlan policy */
enum {
	I1905_VLAN_ID,		/* vlan id for tagging */
	NUM_I1905_VLAN_POLICY,
};

static const struct blobmsg_policy vlan_policy[NUM_I1905_VLAN_POLICY] = {
	[I1905_VLAN_ID] = { .name = "vid", .type = BLOBMSG_TYPE_INT32 },
};

int i1905_ubus_vlan(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct i1905_private *p = container_of(obj, struct i1905_private, obj);
	struct blob_attr *tb[NUM_I1905_VLAN_POLICY];
	struct i1905_config *cfg = &p->cfg;
	int ret = 0;


	blobmsg_parse(vlan_policy, NUM_I1905_VLAN_POLICY, tb,
		      blob_data(msg), blob_len(msg));

	if (!tb[I1905_VLAN_ID]) {
		struct blob_buf bb;
		void *a;

		memset(&bb, 0, sizeof(bb));
		blob_buf_init(&bb, 0);
		a = blobmsg_open_table(&bb, "vlan");
		blobmsg_add_u32(&bb, "vid", cfg->primary_vid);
		blobmsg_close_table(&bb, a);

		ubus_send_reply(ctx, req, bb.head);
		blob_buf_free(&bb);
	} else {
		uint16_t vid;

		vid = (uint16_t)blobmsg_get_u32(tb[I1905_VLAN_ID]);
		if (vid > 4094) {
			ret = -1;
		} else {
			struct i1905_selfdevice *self = &p->dm.self;
			struct i1905_interface *iface;

			cfg->primary_vid = vid;
			list_for_each_entry(iface, &self->iflist, list) {
				iface->vid = vid;
			}
		}
	}

	return ret;
}

enum {
	I1905_EXT_NAME,
	NUM_I1905_EXT_POLICY,
};

static const struct blobmsg_policy extension_policy[NUM_I1905_EXT_POLICY] = {
	[I1905_EXT_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
};

int i1905_ubus_extension_cmd(struct ubus_context *ctx, struct ubus_object *obj,
			     struct ubus_request_data *req, const char *method,
			     struct blob_attr *msg)
{
	struct i1905_private *p = container_of(obj, struct i1905_private, objext);
	struct blob_attr *tb[NUM_I1905_EXT_POLICY];
	int ret = UBUS_STATUS_INVALID_ARGUMENT;
	char extname[64] = { 0 };


	blobmsg_parse(extension_policy, NUM_I1905_EXT_POLICY, tb,
			blob_data(msg), blob_len(msg));


	if (!tb[I1905_EXT_NAME]) {
		if (!strcmp(method, "list")) {
			struct i1905_extmodule *m;
			struct blob_buf bb;
			void *a, *b;

			memset(&bb, 0, sizeof(bb));
			blob_buf_init(&bb, 0);
			a = blobmsg_open_array(&bb, "extensions");

			list_for_each_entry(m, &p->extlist, list) {
				char tmpstr[8] = {0};

				b = blobmsg_open_table(&bb, "");
				blobmsg_add_string(&bb, "name", m->name);
				blobmsg_add_string(&bb, "status", m->paused ?
						   "paused" : "active");
				blobmsg_add_u8(&bb, "extends",
					       m->num_ext > 0 ? true : false);
				sprintf(tmpstr, "0x%04x", m->from_newtype);
				blobmsg_add_string(&bb, "newcmdu_from", tmpstr);
				sprintf(tmpstr, "0x%04x", m->to_newtype);
				blobmsg_add_string(&bb, "newcmdu_upto", tmpstr);
				blobmsg_close_table(&bb, b);
			}

			blobmsg_close_array(&bb, a);
			ubus_send_reply(ctx, req, bb.head);
			blob_buf_free(&bb);
			ret = 0;
		}

		return ret;
	}

	strncpy(extname, blobmsg_data(tb[I1905_EXT_NAME]), 63);

	if (!strcmp(method, "load"))
		ret = i1905_extension_register(p, extname);
	else if (!strcmp(method, "unload"))
		ret = i1905_extension_unregister(p, extname);
	else if (!strcmp(method, "start"))
		ret = i1905_extension_start(p, extname);
	else if (!strcmp(method, "stop"))
		ret = i1905_extension_stop(p, extname);

	return ret;
}

int i1905_publish_extension_object(struct i1905_private *p, const char *objname)
{
	struct ubus_object *obj;
	struct ubus_object_type *obj_type;
	struct ubus_method *obj_methods;
	struct ubus_method m[5] = {
		UBUS_METHOD("load", i1905_ubus_extension_cmd, extension_policy),
		UBUS_METHOD("unload", i1905_ubus_extension_cmd, extension_policy),
		UBUS_METHOD("start", i1905_ubus_extension_cmd, extension_policy),
		UBUS_METHOD("stop", i1905_ubus_extension_cmd, extension_policy),
		UBUS_METHOD_NOARG("list", i1905_ubus_extension_cmd),
	};
	int num_methods = ARRAY_SIZE(m);
	int ret;


	obj = &p->objext;
	memset(obj, 0, sizeof(*obj));

	obj_type = calloc(1, sizeof(struct ubus_object_type));
	if (!obj_type)
		return -1;

	obj_methods = calloc(num_methods, sizeof(struct ubus_method));
	if (!obj_methods) {
		free(obj_type);
		return -1;
	}

	obj->name = strdup(objname);
	memcpy(obj_methods, m, num_methods * sizeof(struct ubus_method));


	obj->methods = obj_methods;
	obj->n_methods = num_methods;

	obj_type->name = obj->name;
	obj_type->n_methods = obj->n_methods;
	obj_type->methods = obj->methods;
	obj->type = obj_type;

	ret = ubus_add_object(p->ctx, obj);
	if (ret) {
		fprintf(stderr, "Failed to add '%s' err = %s\n",
			ubus_strerror(ret), objname);
		free(obj_methods);
		free(obj_type);

		return ret;
	}

	fprintf(stderr, "Added object '%s'\n", objname);

	return 0;
}

int i1905_publish_object(struct i1905_private *p, const char *objname)
{
	struct ubus_object *obj;
	struct ubus_object_type *obj_type;
	struct ubus_method *obj_methods;
	int ret;
	struct ubus_method m[16] = {
		UBUS_METHOD_NOARG("start", i1905_ubus_start),
		UBUS_METHOD_NOARG("stop", i1905_ubus_stop),
		UBUS_METHOD_NOARG("status", i1905_ubus_status),
		UBUS_METHOD_NOARG("info", i1905_ubus_info),
		UBUS_METHOD_NOARG("neighbors", i1905_ubus_neighbors),
		UBUS_METHOD_NOARG("links", i1905_ubus_links),
		UBUS_METHOD_NOARG("others", i1905_ubus_non1905neighbors),
		UBUS_METHOD_NOARG("arptable", i1905_ubus_show_arptable),
		UBUS_METHOD("apconfig", i1905_ubus_apconfig, apconfig_policy),
		UBUS_METHOD_NOARG("refresh", i1905_ubus_refresh),
		UBUS_METHOD("cmdu", i1905_ubus_cmdu_tx, cmdu_tx_policy),
		UBUS_METHOD("buildcmdu", i1905_ubus_cmdu_prepare, cmdu_prep_policy),
		UBUS_METHOD("rxcmdu", i1905_ubus_cmdu_rx, cmdu_rx_policy),
		UBUS_METHOD("add_interface", i1905_ubus_interface_add, interface_policy),
		UBUS_METHOD("del_interface", i1905_ubus_interface_del, interface_policy),
		UBUS_METHOD("vlan", i1905_ubus_vlan, vlan_policy),
	};
	int num_methods = ARRAY_SIZE(m);

	if (!p->ctx) {
		fprintf(stderr, "%s: connect to ubus!\n", __func__);
		p->ctx = ubus_connect(NULL);
		if (!p->ctx) {
			fprintf(stderr, "Failed to connect to ubus\n");
			return -1;
		}
		ubus_add_uloop(p->ctx);
	}

	obj = &p->obj;
	memset(obj, 0, sizeof(*obj));

	obj_type = calloc(1, sizeof(struct ubus_object_type));
	if (!obj_type)
		return -1;

	obj_methods = calloc(num_methods, sizeof(struct ubus_method));
	if (!obj_methods) {
		free(obj_type);
		return -1;
	}

	obj->name = strdup(objname);
	memcpy(obj_methods, m, num_methods * sizeof(struct ubus_method));


	obj->methods = obj_methods;
	obj->n_methods = num_methods;

	obj_type->name = obj->name;
	obj_type->n_methods = obj->n_methods;
	obj_type->methods = obj->methods;
	obj->type = obj_type;

	ret = ubus_add_object(p->ctx, obj);
	if (ret) {
		fprintf(stderr, "Failed to add '%s' err = %s\n",
			objname, ubus_strerror(ret));
		free(obj_methods);
		free(obj_type);

		return ret;
	}

	fprintf(stderr, "Added object '%s'\n", objname);

	i1905_publish_interface_objects(p);
	i1905_publish_extension_object(p, IEEE1905_OBJECT_EXT);
	return 0;
}

int i1905_publish_interface_object(struct i1905_private *priv, const char *ifname)
{
	struct i1905_interface_private *ifpriv;
	struct i1905_interface *iface;
	char objname[64] = {0};
	int ret = 0;


	if (!priv || !ifname)
		return -1;

	list_for_each_entry(iface, &priv->dm.self.iflist, list) {
		if (memcmp(iface->ifname, ifname, 16))
			continue;

		iface->invalid = false;
		ifpriv = (struct i1905_interface_private *)iface->priv;
		snprintf(objname, 63, "%s.al.%s", IEEE1905_OBJECT, iface->ifname);
		add_iface_methods(&ifpriv->obj);
		ifpriv->obj.name = strdup(objname);
		ifpriv->obj_type.name = ifpriv->obj.name;
		ifpriv->obj_type.n_methods = ifpriv->obj.n_methods;
		ifpriv->obj_type.methods = ifpriv->obj.methods;
		ifpriv->obj.type = &ifpriv->obj_type;

		ret = ubus_add_object(priv->ctx, &ifpriv->obj);
		if (ret) {
			fprintf(stderr, "Failed to publish '%s', err = %s\n",
				objname, ubus_strerror(ret));
		} else {
			fprintf(stderr, "Added object '%s'\n", objname);
		}
		break;
	}

	return ret;
}

int i1905_remove_interface_object(struct i1905_private *priv, const char *ifname)
{
	struct i1905_interface_private *ifpriv;
	struct i1905_interface *iface;
	int ret = -1;


	if (!priv)
		return -1;

	list_for_each_entry(iface, &priv->dm.self.iflist, list) {
		if (memcmp(iface->ifname, ifname, 16))
			continue;

		iface->invalid = true;
		ifpriv = (struct i1905_interface_private *)iface->priv;
		if (ifpriv->obj.id != OBJECT_INVALID) {
			free_iface_methods(&ifpriv->obj);
			ret = ubus_remove_object(priv->ctx, &ifpriv->obj);
			if (ret) {
				fprintf(stderr, "Failed to delete; err = %s\n",
					ubus_strerror(ret));
			}
			dbg("%s: Removed %s\n", __func__, ifpriv->obj.name);
			ifpriv->obj.id = OBJECT_INVALID;
			free((void *)ifpriv->obj.name);
			break;
		}
	}

	return ret;
}

int i1905_remove_object(struct i1905_private *p)
{
	i1905_remove_interface_objects(p);

	if (p->ctx) {
		if (p->objext.id != OBJECT_INVALID) {
			ubus_remove_object(p->ctx, &p->objext);
			free(p->objext.type);
			free((void *)p->objext.methods);
			free((void *)p->objext.name);
		}

		if (p->obj.id != OBJECT_INVALID) {
			ubus_remove_object(p->ctx, &p->obj);
			free(p->obj.type);
			free((void *)p->obj.methods);
			free((void *)p->obj.name);
		}
	}

	return 0;
}

static void i1905_wifi_sta_event_handler(struct i1905_private *p,
					 struct blob_attr *msg)
{
	char ifname[16] = {0}, event[16] = {0};
	struct blob_attr *tb[3];
	static const struct blobmsg_policy ev_attr[3] = {
		[0] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "event", .type = BLOBMSG_TYPE_STRING },
		[2] = { .name = "data", .type = BLOBMSG_TYPE_TABLE },
	};
	bool add = false, del = false;


	blobmsg_parse(ev_attr, 3, tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[1] || !tb[2])
		return;

	strncpy(ifname,	blobmsg_data(tb[0]), sizeof(ifname) - 1);
	strncpy(event, blobmsg_data(tb[1]), sizeof(event) - 1);

	add = !strcmp(event, "connected");
	del = !strcmp(event, "disconnected");

	if (add || del) {
		struct blob_attr *data[1];
		static const struct blobmsg_policy data_attr[1] = {
			[0] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
		};
		char mac_str[18] = {0};
		uint8_t mac[6] = {0};

		blobmsg_parse(data_attr, 1, data, blobmsg_data(tb[2]),
			      blobmsg_data_len(tb[2]));

		if (!data[0])
			return;

		strncpy(mac_str, blobmsg_data(data[0]), sizeof(mac_str) - 1);
		if (!hwaddr_aton(mac_str, mac))
			return;

		if (add) {
			neigh_enqueue(&p->neigh_q, mac,
				      NEIGH_STATE_REACHABLE,
				      ifname,
				      NEIGH_TYPE_WIFI,
				      NULL,
				      NEIGH_AGEOUT_DEFAULT,
				      NULL);
		} else if (del) {
			neigh_dequeue(&p->neigh_q, mac, NULL);
		}

		i1905_send_topology_notification(p, ifname);
	}
}

static void i1905_ethport_event_handler(struct i1905_private *p,
					struct blob_attr *msg)
{
	static const struct blobmsg_policy ev_attr[4] = {
		[0] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
		[1] = { .name = "link", .type = BLOBMSG_TYPE_STRING },
		[2] = { .name = "speed", .type = BLOBMSG_TYPE_TABLE },
		[3] = { .name = "duplex", .type = BLOBMSG_TYPE_TABLE },
	};
	char ifname[16] = {0}, link[8] = {0};
	struct blob_attr *tb[4];
	bool up, down;


	blobmsg_parse(ev_attr, 4, tb, blob_data(msg), blob_len(msg));
	if (!tb[0] || !tb[1])
		return;

	strncpy(ifname,	blobmsg_data(tb[0]), sizeof(ifname) - 1);
	strncpy(link, blobmsg_data(tb[1]), sizeof(link) - 1);

	up = !strcmp(link, "up");
	down = !strcmp(link, "down");

	//TODO
	UNUSED(up);
	UNUSED(down);

	return;
}

static void i1905_wifi_event_handler(struct ubus_context *ctx,
				     struct ubus_event_handler *e,
				     const char *type, struct blob_attr *msg)
{
	struct i1905_private *p = container_of(e, struct i1905_private, evh);
	struct wifi_ev_handler {
		const char *type;
		void (*handler)(struct i1905_private *, struct blob_attr *);
	} evs[] = {
		{ "wifi.sta", i1905_wifi_sta_event_handler },
		{ "ethport", i1905_ethport_event_handler },
	};
	char *str;
	int i;


	str = blobmsg_format_json(msg, true);
	if (!str)
		return;

	//info("Received event: [%s] event = '%s'\n", type, str);
	free(str);

	for (i = 0; i < ARRAY_SIZE(evs); i++) {
		if (!strcmp(type, evs[i].type)) {
			evs[i].handler(p, msg);
			break;
		}
	}
}

int i1905_register_misc_events(struct i1905_private *p)
{
	if (!p || !p->ctx)
		return -1;

	p->evh.cb = i1905_wifi_event_handler;
	return ubus_register_event_handler(p->ctx, &p->evh, "wifi.*");
}

int i1905_unregister_misc_events(struct i1905_private *p)
{
	if (p)
		ubus_unregister_event_handler(p->ctx, &p->evh);

	return 0;
}
