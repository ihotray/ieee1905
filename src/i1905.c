/*
 * i1905.c - IEEE-1905 core functions.
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
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
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
#include "i1905_extension.h"


#include "1905_tlvs.h"

#include "i1905_wifi.h"


static int signal_pending;

static void i1905_sighandler(int sig)
{
	signal_pending = sig;
}

struct i1905_private *i1905_selfdevice_to_context(struct i1905_selfdevice *dev)
{
	struct i1905_dm *dm = container_of(dev, struct i1905_dm, self);

	return container_of(dm, struct i1905_private, dm);
}

int if_getmediatype(const char *ifname, enum if_mediatype *mtype)
{
	*mtype = IF_MEDIA_ETH;

	if (is_wifi_interface(ifname))
		*mtype = IF_MEDIA_WIFI;

	/* TODO: other media types */
	return 0;
}

static struct i1905_extmodule *i1905_lookup_extension(struct i1905_private *p,
						      const char *name)
{
	struct i1905_extmodule *m;

	list_for_each_entry(m, &p->extlist, list) {
		if (!strncmp(m->name, name, strlen(m->name)))
			return m;
	}

	return NULL;
}

static void i1905_load_extensions(struct i1905_private *p)
{
	struct i1905_extension_config *e;


	if (!p->cfg.extensions)
		return;

	list_for_each_entry(e, &p->cfg.extlist, list) {
		struct i1905_extmodule *mod = NULL;

		if (i1905_lookup_extension(p, e->name))
			continue;

		dbg("load extension '%s'\n", e->name);
		mod = i1905_load_extmodule(p, e->name);
		if (mod)
			list_add_tail(&mod->list, &p->extlist);
	}
}

static void i1905_unload_extensions(struct i1905_private *p)
{
	if (!p)
		return;

	extmodules_unload(&p->extlist);
}

int i1905_extension_register(struct i1905_private *p, char *name)
{
	struct i1905_extmodule *m;


	if (i1905_lookup_extension(p, name)) {
		info("extension '%s' already registered\n", name);
		return 0;
	}

	m = i1905_load_extmodule(p, name);
	if (m) {
		list_add_tail(&m->list, &p->extlist);
		return 0;
	}

	return -1;
}

int i1905_extension_unregister(struct i1905_private *p, char *name)
{
	struct i1905_extmodule *m;


	m = i1905_lookup_extension(p, name);
	if (!m)
		return -1;

	if (!m->paused && m->stop) {
		m->stop(m->priv);
		m->paused = 1;
	}

	return i1905_unload_extmodule(m);
}

int i1905_extension_start(struct i1905_private *p, char *name)
{
	struct i1905_extmodule *m;


	m = i1905_lookup_extension(p, name);
	if (!m)
		return -1;


	if (m->paused && m->start) {
		m->paused = 0;
		return m->start(m->priv);
	}

	return 0;
}

int i1905_extension_stop(struct i1905_private *p, char *name)
{
	struct i1905_extmodule *m;


	m = i1905_lookup_extension(p, name);
	if (!m)
		return -1;

	if (!m->paused && m->stop) {
		m->stop(m->priv);
		m->paused = 1;
	}

	return 0;
}

int i1905_start(struct i1905_private *p)
{
	fprintf(stderr, "TODO\n");
	return 0;
}

int i1905_stop(struct i1905_private *p)
{
	fprintf(stderr, "TODO\n");
	return 0;
}

static void i1905_set_ebtable_rules(uint8_t *if_macaddr, uint8_t *aladdr)
{
	char cmd[512] = {0};
	const char *fmt =
		"ebtables -t broute -I BROUTING 1 -d " MACFMT " -p 0x893a -j DROP;"\
		"ebtables -t broute -I BROUTING 1 -d " MACFMT " -p 0x8100 -j DROP --vlan-encap 0x893a";

	/* bypass bridge flow for 1905 unicast to interface */
	snprintf(cmd, 511, fmt, MAC2STR(if_macaddr), MAC2STR(if_macaddr)); /* Flawfinder: ignore */
	dbg("%s\n", cmd);
	system(cmd); /* Flawfinder: ignore */

	/* bypass bridge flow for CMDUs to our AL-address */
	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, 511, fmt, MAC2STR(aladdr), MAC2STR(aladdr)); /* Flawfinder: ignore */
	dbg("%s\n", cmd);
	system(cmd); /* Flawfinder: ignore */

	/* bypass bridge flow for 1905 multicast CMDUs */
	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, 511, fmt, MAC2STR(MCAST_1905), MAC2STR(MCAST_1905)); /* Flawfinder: ignore */
	dbg("%s\n", cmd);
	system(cmd); /* Flawfinder: ignore */
}

static void i1905_clear_ebtable_rules(uint8_t *if_macaddr, uint8_t *aladdr)
{
	char cmd[512] = {0};
	const char *fmt =
		"ebtables -t broute -D BROUTING -d " MACFMT " -p 0x893a -j DROP;"\
		"ebtables -t broute -D BROUTING -d " MACFMT " -p 0x8100 -j DROP --vlan-encap 0x893a";


	snprintf(cmd, 511, fmt, MAC2STR(if_macaddr), MAC2STR(if_macaddr)); /* Flawfinder: ignore */
	dbg("%s\n", cmd);
	system(cmd); /* Flawfinder: ignore */

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, 511, fmt, MAC2STR(aladdr), MAC2STR(aladdr)); /* Flawfinder: ignore */
	dbg("%s\n", cmd);
	system(cmd); /* Flawfinder: ignore */

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, 511, fmt, MAC2STR(MCAST_1905), MAC2STR(MCAST_1905)); /* Flawfinder: ignore */
	dbg("%s\n", cmd);
	system(cmd); /* Flawfinder: ignore */
}

static void i1905_bypass_bridge_flow(uint8_t *macaddr)
{
	char cmd[512] = {0};
	const char *clr =
		"ebtables -t broute -D BROUTING -d " MACFMT " -p 0x893a -j DROP;\
		 ebtables -t broute -D BROUTING -d " MACFMT " -p 0x8100 -j DROP --vlan-encap 0x893a";
	const char *set =
		"ebtables -t broute -I BROUTING 1 -d " MACFMT " -p 0x893a -j DROP;"\
		"ebtables -t broute -I BROUTING 1 -d " MACFMT " -p 0x8100 -j DROP --vlan-encap 0x893a";


	snprintf(cmd, 511, clr, MAC2STR(macaddr), MAC2STR(macaddr)); /* Flawfinder: ignore */
	dbg("%s\n", cmd);
	system(cmd); /* Flawfinder: ignore */

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, 511, set, MAC2STR(macaddr), MAC2STR(macaddr)); /* Flawfinder: ignore */
	dbg("%s\n", cmd);
	system(cmd); /* Flawfinder: ignore */
}

static struct i1905_interface *i1905_alloc_interface(struct i1905_private *priv,
						     const char *ifname,
						     int sizeof_ifpriv)
{
	struct i1905_interface *n = NULL;
	enum if_mediatype mtype;

	n = calloc(1, sizeof(struct i1905_interface) + sizeof_ifpriv);
	if (!n)
		return NULL;

	snprintf(n->ifname, 16, "%s", ifname);
	n->ifindex = if_nametoindex(ifname);
	dbg("%s: %s: ifindex = %d\n", __func__, n->ifname, n->ifindex);
	if_gethwaddr(ifname, n->macaddr);
	if_getflags(ifname, &n->ifstatus);
	if (!strncmp(ifname, "lo", 2)) {
		n->lo = true;
		goto done;
	}

	if_getmediatype(ifname, &mtype);
	if (mtype == IF_MEDIA_WIFI) {
		struct ieee80211_info *wifi;
		uint32_t role = IEEE80211_ROLE_UNKNOWN;
		enum i1905_mediatype std = I1905_MEDIA_UNKNOWN;
		enum I1905_WPS_STATUS wpsstatus = I1905_WPS_STATUS_IDLE;
		uint32_t seg0_idx, seg1_idx;
		uint32_t bandwidth;
		uint32_t channel;
		uint32_t band = 0;
		int ret;

		info("%s: is WiFi ", ifname);

		n->mediainfo = calloc(1, sizeof(struct ieee80211_info));
		if (!n->mediainfo) {
			err("-ENOMEM\n");
			free(n);
			return NULL;
		}
		n->media = I1905_MEDIA_UNKNOWN;

		wifi = (struct ieee80211_info *)n->mediainfo;

		/* get operating band */
		ret = platform_wifi_get_freqband(ifname, &band);
		if (!ret)
			n->band = band;

		/* get channel and bandwidth */
		ret = platform_wifi_get_channel(ifname, &channel, &bandwidth,
						&seg0_idx, &seg1_idx);
		if (!ret) {
			wifi->ap_channel_seg0_idx = seg0_idx;
			wifi->ap_channel_seg1_idx = seg1_idx;
			wifi->ap_bandwidth = bandwidth;

			if (band == 0) {
				if (channel > 0 && channel <= 14)
					band = 2;
				else if (channel >= 36 && channel < 200)
					band = 5;

				n->band = band;
			}
		}

		/* get standard */
		ret = platform_wifi_get_standard(ifname, &std);
		if (!ret)
			n->media = std;

		/* if cannot determine media, assume based on band */
		if (n->media == I1905_MEDIA_UNKNOWN) {
			n->media = band == 2 ?
				I1905_802_11G_2_4_GHZ : I1905_802_11AC_5_GHZ;
		}

		/* get role */
		ret = platform_wifi_get_role(ifname, &role);
		if (!ret)
			wifi->role = role;

		/* get associated STAs */
		if (wifi->role == IEEE80211_ROLE_AP) {
			uint8_t stas[768] = {0};
			int num = 128;

			ret = platform_wifi_get_assoclist(ifname, stas, &num);
			if (!ret) {
				int i;

				for (i = 0; i < num; i++) {
					neigh_enqueue(&priv->neigh_q,
						      &stas[i*6],
						      NEIGH_STATE_UNKNOWN,
						      ifname,
						      NEIGH_TYPE_WIFI,
						      NULL,
						      NEIGH_AGEOUT_DEFAULT,
						      NULL);
				}
			}
		}

		/* get bssid */
		ret = platform_wifi_get_bssid(ifname, wifi->bssid);
		if (ret)
			warn("error platform_wifi_get_bssid()\n");

		if (wifi->role == IEEE80211_ROLE_AP ||
		    (wifi->role == IEEE80211_ROLE_STA && !hwaddr_is_zero(wifi->bssid)))
			n->authenticated = true;

		fprintf(stderr, "%s: %s is %sauthenticated\n", __func__, ifname,
			n->authenticated ? "": "not-");

		if (wifi->role == IEEE80211_ROLE_AP) {
			if (i1905_is_registrar(priv)) {
				n->is_registrar = true;
			} else if (IS_MEDIA_WIFI_2GHZ(n->media) &&
				   i1905_has_registrar(priv, IEEE80211_FREQUENCY_BAND_2_4_GHZ)) {
				n->is_registrar = true;
			} else if (IS_MEDIA_WIFI_5GHZ(n->media) &&
				   i1905_has_registrar(priv, IEEE80211_FREQUENCY_BAND_5_GHZ)) {
				n->is_registrar = true;
			}
		}

		n->pbc_supported = true;
		n->pbc_ongoing = false;
		platform_wifi_get_wps_status(ifname, &wpsstatus);
		if (wpsstatus == I1905_WPS_STATUS_PROCESSING)
			n->pbc_ongoing = true;
	} else {
		info("%s: is Ethernet\n", ifname);
		n->media = MEDIA_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET;	//FIXME
		n->mediainfo = NULL;
		n->authenticated = true;
		n->pbc_supported = false;
		n->pbc_ongoing = false;
	}

done:
	n->allow_ifpower = true;
	n->power = I1905_IFPOWER_ON;	// TODO: if_get_powerstate()

	//n->genphy.	// TODO

	INIT_LIST_HEAD(&n->vendorlist);
	INIT_LIST_HEAD(&n->nbriflist);		/* interface.link[] */
	INIT_LIST_HEAD(&n->non1905_nbrlist);
	//INIT_LIST_HEAD(&n->iflinklist);	/* list of 1905 nbr devices */

	n->priv = (void *)(n + 1);
	dbg("%s: ifpriv = %p\n", __func__, n->priv);

	return n;
}

static void i1905_free_interface(struct i1905_private *priv,
				 struct i1905_interface *iface,
				 void (*free_ifpriv)(struct i1905_private *priv,
						     struct i1905_interface *iface))
{
	if (!priv || !iface)
		return;


	if (free_ifpriv)
		free_ifpriv(priv, iface);

	if (iface->lo) {
		free(iface);
		return;
	}

	if (IS_MEDIA_WIFI(iface->media) && iface->mediainfo) {
		free(iface->mediainfo);
		iface->mediainfo = NULL;
	}

	if (iface->num_ipaddrs && iface->ipaddrs)
		free(iface->ipaddrs);

	list_flush(&iface->vendorlist, struct i1905_vendor_info, list);
	list_flush(&iface->non1905_nbrlist, struct i1905_non1905_neighbor, list);

	//i1905_free_interface_neighbors
	//i1905_free_interface_links
	//i1905_free_interface_vendors


#if 1	//Testing
	struct i1905_neighbor_interface *ifpeer = NULL;
	struct i1905_device *rdev, *tmp;

	list_for_each_entry(ifpeer, &iface->nbriflist, list) {
		list_for_each_entry_safe(rdev, tmp, &priv->dm.self.topology.devlist, list) {
			if (!hwaddr_equal(ifpeer->aladdr, rdev->aladdr))
				continue;

			if (timer_pending(&rdev->agetimer))
				timer_del(&rdev->agetimer);

			if (timer_pending(&rdev->immediate_nbr_agetimer))
				timer_del(&rdev->immediate_nbr_agetimer);

			list_del(&rdev->list);
			i1905_dm_neighbor_free(rdev);
		}
	}
#endif

	i1905_free_interface_links(iface);

	free(iface);
}

struct i1905_interface *i1905_ifname_to_interface(struct i1905_private *priv,
						  const char *ifname)
{
	struct i1905_interface *ifs;
	struct i1905_selfdevice *self;


	if (!ifname || !priv)
		return NULL;

	self = &priv->dm.self;

	list_for_each_entry(ifs, &self->iflist, list) {
		if (!strncmp(ifs->ifname, ifname, 16))
			return ifs;
	}

	return NULL;
}

int i1905_send_cmdu(struct i1905_interface_private *ifpriv, uint16_t vid,
		    uint8_t *dst, uint8_t *src, uint16_t ethtype,
		    struct cmdu_buff *frm)
{
	struct i1905_interface *iface = i1905_interface_priv(ifpriv);
	int ifindex = iface->ifindex;
	struct ether_header *eh;
	struct sockaddr_ll sa;
	int ret;


	if (!frm)
		return -1;

	if (frm->cdata && frm->cdata->hdr.mid == 0)
		frm->cdata->hdr.mid = cmdu_get_next_mid();

	/* prepare ethhdr */
	frm->len = frm->datalen + sizeof(struct ether_header) + sizeof(struct cmdu_header);
	if (vid > 0)
		frm->len += 4;
	else
		frm->head += 4;

	eh = (struct ether_header *)frm->head;
	if (hwaddr_is_zero(src)) {
#ifdef CMDU_SA_IS_ALMAC
		memcpy(eh->ether_shost, iface->aladdr, 6);
#else
		if (hwaddr_is_zero(iface->macaddr))
			memcpy(eh->ether_shost, iface->aladdr, 6);
		else
			memcpy(eh->ether_shost, iface->macaddr, 6);
#endif
	} else {
		memcpy(eh->ether_shost, src, 6);
	}

	if (hwaddr_is_zero(dst)) {
		/* if dst = 0, assume selfdevice */
		memcpy(eh->ether_dhost, iface->aladdr, 6);
	} else {
		memcpy(eh->ether_dhost, dst, 6);
	}

	eh->ether_type = vid > 0 ? htons(0x8100) : htons(ethtype);
	if (vid > 0) {
		buf_put_be16(frm->head + ETH_HLEN, vid);
		buf_put_be16(frm->head + ETH_HLEN + 2, ethtype);
	}

	sa.sll_ifindex = ifindex;
	sa.sll_halen = ETH_ALEN;
	memcpy(sa.sll_addr, dst, 6);

	if (frm->len < ETH_ZLEN) {
		memset(frm->head + frm->len, 0, ETH_ZLEN - frm->len);
		frm->len = ETH_ZLEN;
	}

	ret = sendto(ifpriv->sock_1905, frm->head, frm->len, 0, (struct sockaddr*)&sa,
		     sizeof(struct sockaddr_ll));
	if (ret < 0) {
		dbg("%s: %s (%d) failed to send!!! (err = %d, %s)\n", __func__,
		    iface->ifname, iface->ifindex, errno, strerror(errno));
		return -1;
	}

	logcmdu(frm->head, frm->len, iface->ifname, 0);
	return 0;
}

int i1905_send_cmdu_relay_mcast(struct i1905_private *priv, const char *ifname,
				uint8_t *dst, uint8_t *src, uint16_t ethtype,
				struct cmdu_buff *frm)
{
	struct i1905_selfdevice *self;
	struct i1905_interface *ifs;
	uint16_t mid = 0;
	bool lo = true;
	uint16_t type;
	int ret;


	if (!priv || !frm || !frm->cdata)
		return -1;

	if (!IS_CMDU_RELAY_MCAST(frm->cdata))
		return -1;

	self = &priv->dm.self;
	type = cmdu_get_type(frm);
	mid = cmdu_get_mid(frm);

	UNUSED(ethtype);

	list_for_each_entry(ifs, &self->iflist, list) {
		struct i1905_interface_private *ifpriv = ifs->priv;

		/* skip sending out of the receiving interface */
		if (ifname && !strncmp(ifname, ifs->ifname, 16))
			continue;

		ret = i1905_cmdu_tx(ifpriv, ifs->vid, dst, src, type, &mid,
				     frm->data, frm->datalen, lo);
		lo = false;
		if (ret < 0) {
			dbg("Error relay mcast through '%s' (err = %d, %s)\n",
			    ifs->ifname, errno, strerror(errno));
		}
	}

	return 0;
}

int i1905_relay_cmdu(struct i1905_private *priv, const char *ifname,
		     uint8_t *dst, uint8_t *src, uint16_t ethtype,
		     struct cmdu_buff *frm)
{
	struct i1905_selfdevice *self;
	struct i1905_interface *ifs;
	uint16_t mid = 0;
	uint16_t type;
	int ret;
	bool dup;
	int i;


	if (!priv || !frm || !frm->cdata)
		return -1;

	if (!IS_CMDU_RELAY_MCAST(frm->cdata))
		return -1;

	self = &priv->dm.self;
	type = cmdu_get_type(frm);
	mid = cmdu_get_mid(frm);

	UNUSED(ethtype);

	list_for_each_entry(ifs, &self->iflist, list) {
		struct i1905_interface_private *ifpriv = ifs->priv;

		if (ifs->lo)
			continue;

		/* skip sending out through the receiving interface */
		if (ifname && !strncmp(ifname, ifs->ifname, 16))
			continue;

#if 1	//TODO: improve
		dup = false;
		for (i = 0; i < I1905_MID_LOOKBACK_MAX; i++) {
			if (ifpriv->lastmid[i] == mid) {
				dup = true;
				break;
			}
		}

		if (dup)
			continue;

		ifpriv->lastmid[ifpriv->lastmid_idx] = mid;
		ifpriv->lastmid_idx = (ifpriv->lastmid_idx + 1) % 4;
#endif
		ret = i1905_cmdu_tx(ifpriv, ifs->vid, dst, src, type, &mid,
				     frm->data, frm->datalen, false);
		if (ret < 0) {
			dbg("Error relay mcast through '%s' (err = %d, %s)\n",
			    ifs->ifname, errno, strerror(errno));
		}
	}

	return 0;
}

int i1905_cmdu_fragment_and_tx(struct i1905_interface_private *ifpriv, uint16_t vid,
			       uint8_t *dst, uint8_t *src, uint16_t type,
			       uint16_t *mid, uint8_t *data, int datalen,
			       bool loopback)
{
	struct i1905_interface *iface;
	struct cmdu_buff *frm = NULL;
	struct cmdu_frag *frag = NULL;
	struct i1905_private *priv;
	uint16_t resp_type;
	int ret = 0;
	int i = 0;


	priv = (struct i1905_private *)ifpriv->i1905private;
	iface = i1905_interface_priv(ifpriv);

#if 0
	/* re-enqueue for receive if dst = self */
	if (hwaddr_equal(dst, iface->aladdr)) {
		frm = cmdu_alloc_frame(datalen + 3);
		if (!frm) {
			err("%s: -ENOMEM\n", __func__);
			return -1;
		}

		memcpy(frm->aladdr, iface->aladdr, 6);
		cmdu_set_type(frm, type);
		if (*mid == 0)
			*mid = cmdu_get_next_mid();

		cmdu_set_mid(frm, *mid);
		CMDU_SET_LAST_FRAGMENT(frm->cdata);

		ret = cmdu_put(frm, data, datalen) ||
		      cmdu_put_eom(frm);

		if (ret) {
			cmdu_free(frm);
			return ret;
		}
	}
#endif

	frm = cmdu_fragment(data, datalen);
	if (!frm) {
		err("%s: -ENOMEM\n", __func__);
		return -1;
	}

	if (*mid == 0)
		*mid = cmdu_get_next_mid();

	cmdu_set_mid(frm, *mid);
	cmdu_set_type(frm, type);

	/* when dst = selfdevice, i.e. cmdu is loopedback */
	if (hwaddr_equal(dst, iface->aladdr))
		memcpy(frm->aladdr, iface->aladdr, 6);

	err("TX Frag %d (datalen = %d) -->\n", i, frm->datalen);
	ret = i1905_send_cmdu(ifpriv, vid, dst, src, ETHERTYPE_1905, frm);
	if (ret < 0) {
		err("%s: failed!\n", __func__);
		goto out;
	}

	list_for_each_entry(frag, &frm->fraglist, list) {
		struct cmdu_buff *ffrm = NULL;
		size_t sz = frag->len + 3;

		bufprintf(frag->data, frag->len, "CMDU Fragment:");

		if (sz < ETH_ZLEN)
			sz = ETH_ZLEN;

		ffrm = cmdu_alloc_frame(sz);
		if (!ffrm) {
			err("%s: -ENOMEM\n", __func__);
			goto out;
		}

		ret = cmdu_put(ffrm, frag->data, frag->len);
		if (!ret) {
			cmdu_set_mid(ffrm, *mid);
			cmdu_set_type(ffrm, type);
			cmdu_set_fid(ffrm, ++i);
			if (i == frm->num_frags) {
				CMDU_SET_LAST_FRAGMENT(ffrm->cdata);
				cmdu_put_eom(ffrm);
			}

			err("TX Frag-%d (datalen = %d) -->\n", i, ffrm->datalen);
			ret = i1905_send_cmdu(ifpriv, vid, dst, src, ETHERTYPE_1905, ffrm);
			if (ret < 0) {
				err("%s: failed!\n", __func__);
				cmdu_free(ffrm);
				goto out;
			}
		}

		cmdu_free(ffrm);
	}

	//TODO: when dst = mcast, skip matching dst on recv'd cmdu in DEQ
	resp_type = cmdu_expect_response(type);
	if (resp_type != CMDU_TYPE_NONE) {
		cmdu_ackq_enqueue(&priv->txack_q, resp_type, *mid, dst,
				  CMDU_DEFAULT_TIMEOUT, 0, NULL);
	}

out:
	cmdu_free(frm);
	return ret;
}

int i1905_cmdu_tx(struct i1905_interface_private *ifpriv, uint16_t vid,
		  uint8_t *dst, uint8_t *src, uint16_t type, uint16_t *mid,
		  uint8_t *data, int datalen, bool loopback)
{
	struct i1905_interface *iface;
	struct cmdu_buff *frm = NULL;
	struct i1905_private *priv;
	uint16_t resp_type;
	int ret = 0;


	if (!ifpriv)
		return -1;

	iface = i1905_interface_priv(ifpriv);

	if (datalen > FRAG_DATA_SIZE) {
		return i1905_cmdu_fragment_and_tx(ifpriv, vid, dst, src,
						  type, mid, data, datalen,
						  loopback);
	}

	frm = cmdu_alloc_simple(type, mid);
	if (!frm) {
		err("%s: -ENOMEM\n", __func__);
		return -1;
	}

	ret = cmdu_put(frm, data, datalen) || cmdu_put_eom(frm);
	if (ret) {
		cmdu_free(frm);
		return ret;
	}

	/* when dst = selfdevice, i.e. cmdu is loopedback */
	if (hwaddr_equal(dst, iface->aladdr))
		memcpy(frm->aladdr, iface->aladdr, 6);

	ret = i1905_send_cmdu(ifpriv, vid, dst, src, ETHERTYPE_1905, frm);
	if (ret < 0) {
		err("%s: failed!\n", __func__);
		goto out;
	}

	dbg("TX CMDU %s (%d)\n", iface->ifname, iface->ifindex);
	//TODO: when dst = mcast, skip matching dst on recv'd cmdu in DEQ
	resp_type = cmdu_expect_response(type);
	if (resp_type != CMDU_TYPE_NONE) {
		priv = (struct i1905_private *)ifpriv->i1905private;
		cmdu_ackq_enqueue(&priv->txack_q, resp_type, *mid, dst,
				  CMDU_DEFAULT_TIMEOUT, 0, NULL);
	}

out:
	cmdu_free(frm);
	return ret;
}

static void i1905_recv_1905(struct uloop_fd *fd, unsigned int events)
{
	struct i1905_interface_private *ifpriv =
		container_of(fd, struct i1905_interface_private, uloop_1905);
	struct i1905_interface *iface = i1905_interface_priv(ifpriv);
	struct i1905_private *priv = (struct i1905_private *)ifpriv->i1905private;
	int res;


	for (;;) {
		struct cmdu_buff *rxf = NULL;
		int eth_hdrsize = 14;


		ifpriv->rxcmdu = cmdu_alloc_default();
		rxf = ifpriv->rxcmdu;
		if (!rxf) {
			err("%s: -ENOMEM\n", __func__);
			return;
		}
		res = recvfrom(ifpriv->sock_1905, rxf->head, 1518,
			       0, NULL, NULL);
		if (res == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				cmdu_free(rxf);
				ifpriv->rxcmdu = NULL;
				return;
			}

			break;
		}

		dbg("%s: Rx 1905 CMDU ifname = %s (len = %d)\n", __func__, iface->ifname, res);
		logcmdu(rxf->head, res, iface->ifname, 1);

		if (*(rxf->head + 12) == 0x81 && *(rxf->head + 13) == 0x00) {
			/* vlan tagged */
			eth_hdrsize += 4;
		}
		rxf->len = res;
		rxf->cdata = (struct cmdu_linear *)(rxf->head + eth_hdrsize);
		rxf->data = (uint8_t *)(rxf->cdata + 1);
		rxf->datalen = res - eth_hdrsize - sizeof(struct cmdu_header);
		rxf->tail = rxf->data + rxf->datalen;
		memcpy(rxf->dev_macaddr, iface->macaddr, 6);
		strncpy(rxf->dev_ifname, iface->ifname, 15);
		memcpy(rxf->origin, rxf->head + 6, 6);

		if (!IS_CMDU_LAST_FRAGMENT(rxf->cdata)) {
			cmdufrag_queue_enqueue(&ifpriv->rxfrag_queue, rxf,
						3 * CMDU_DEFAULT_TIMEOUT);
		} else {
			if (rxf->cdata->hdr.fid == 0) {
				i1905_process_cmdu(priv, rxf);
				cmdu_free(rxf);
				ifpriv->rxcmdu = NULL;
			} else {
				struct cmdu_buff *rxff;

				cmdufrag_queue_enqueue(&ifpriv->rxfrag_queue,
						       rxf, 3 * CMDU_DEFAULT_TIMEOUT);
				rxff = cmdu_defrag(&ifpriv->rxfrag_queue, rxf);
				if (rxff) {
					i1905_process_cmdu(priv, rxff);
					cmdu_free(rxff);
				}
			}
		}
	}

	dbg("%s: 1905 recv error (err = %d, %s)\n", iface->ifname, errno, strerror(errno));
	if (!ifpriv->uloop_1905.registered) {
		dbg("%s: uloop re-registering...\n", iface->ifname);
		uloop_fd_delete(&ifpriv->uloop_1905);
		uloop_fd_add(&ifpriv->uloop_1905, ULOOP_READ | ULOOP_EDGE_TRIGGER);
	}
}

static int i1905_init_interface_socket_1905(struct i1905_interface *n,
					    struct i1905_interface_private *priv)
{
	unsigned int ifindex = 0;
	struct sockaddr_ll sa;
	struct packet_mreq mr;
	int reuse = 1;
	int flags;
	int ret;
	int sk;


	sk = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_1905));
	if (sk < 0) {
		fprintf(stderr, "packet socket err\n");
		return -1;
	}

	flags = fcntl(sk, F_GETFL, 0);
	if (flags != -1) {
		fcntl(sk, F_SETFL, flags | O_NONBLOCK);
	}

	if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
		fprintf(stderr, "reuseaddr err\n");
		close(sk);
		return -1;
	}

	ifindex = if_nametoindex(n->ifname);
	sa.sll_family = PF_PACKET;
	sa.sll_protocol = htons(ETHERTYPE_1905);
	sa.sll_halen = ETH_ALEN;
	sa.sll_ifindex = ifindex;
	if ((bind(sk, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll))) != 0) {
		fprintf(stderr, "bind() error\n");
		close(sk);
		return -1;
	}

	/* subscribe to 1905 multicast */
	memset(&mr,0,sizeof(mr));
	mr.mr_ifindex = sa.sll_ifindex;
	mr.mr_type = PACKET_MR_MULTICAST;
	mr.mr_alen = 6;
	memcpy(mr.mr_address, "\x01\x80\xC2\x00\x00\x13", 6);
	if (setsockopt(sk, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
		fprintf(stderr, "%s: setsockopt error (%s)\n", __func__,
			strerror(errno));
		close(sk);
		return -1;
	}

	priv->sock_1905 = sk;
	priv->uloop_1905.fd = sk;
	priv->uloop_1905.cb = i1905_recv_1905;
	ret = uloop_fd_add(&priv->uloop_1905, ULOOP_READ | ULOOP_EDGE_TRIGGER);
	if (ret) {
		close(sk);
		priv->sock_1905 = -1;
		return -1;
	}

	return 0;
}

static void i1905_free_interface_socket_1905(struct i1905_interface *iface,
					     struct i1905_interface_private *ifpriv)
{
	struct packet_mreq mr;


	memset(&mr,0,sizeof(mr));
	mr.mr_ifindex = iface->ifindex;
	mr.mr_type = PACKET_MR_MULTICAST;
	mr.mr_alen = 6;
	memcpy(mr.mr_address, "\x01\x80\xC2\x00\x00\x13", 6);
	setsockopt(ifpriv->sock_1905, SOL_PACKET, PACKET_DROP_MEMBERSHIP,
		   &mr, sizeof(mr));

	uloop_fd_delete(&ifpriv->uloop_1905);
	close(ifpriv->sock_1905);
	ifpriv->sock_1905 = -1;
}

static void i1905_recv_lldp(struct uloop_fd *fd, unsigned int events)
{
	struct i1905_interface_private *ifpriv =
		container_of(fd, struct i1905_interface_private, uloop_lldp);
	struct i1905_interface *iface = i1905_interface_priv(ifpriv);
	struct i1905_private *priv = (struct i1905_private *)ifpriv->i1905private;
	int res;


	for (;;) {
		struct cmdu_buff *rxf = NULL;
		int eth_hdrsize = 14;


		ifpriv->rxlldp = cmdu_alloc_default();
		rxf = ifpriv->rxlldp;
		if (!rxf) {
			fprintf(stderr, "%s: -ENOMEM\n", __func__);
			return;
		}

		res = recvfrom(ifpriv->sock_lldp, rxf->head, 1518,
				0, NULL, NULL);
		if (res == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				cmdu_free(rxf);
				ifpriv->rxlldp = NULL;
				return;
			}

			break;
		}

		//bufprintf(rxf->head, res, "Received lldp data");
		if (*(rxf->head + 12) == 0x81 && *(rxf->head + 13) == 0x00) {
			/* vlan tagged */
			eth_hdrsize += 4;
		}
		rxf->len = res;
		rxf->data = rxf->head + eth_hdrsize;
		rxf->cdata = NULL;
		rxf->datalen = res - eth_hdrsize;
		rxf->tail = rxf->data + rxf->datalen;
		memcpy(rxf->dev_macaddr, iface->macaddr, 6);
		strncpy(rxf->dev_ifname, iface->ifname, 15);
		memcpy(rxf->origin, rxf->head + 6, 6);

		i1905_process_lldp(priv, rxf);
		cmdu_free(rxf);
		ifpriv->rxlldp = NULL;
	}

	dbg("%s: lldp recv error (err = %d, %s)\n", iface->ifname, errno, strerror(errno));
	if (!ifpriv->uloop_lldp.registered) {
		dbg("%s: ULOOP re-registering...\n", iface->ifname);
		uloop_fd_delete(&ifpriv->uloop_lldp);
		uloop_fd_add(&ifpriv->uloop_lldp, ULOOP_READ | ULOOP_EDGE_TRIGGER);
	}
}

static int i1905_init_interface_socket_lldp(struct i1905_interface *n,
					    struct i1905_interface_private *priv)
{
	unsigned int ifindex = 0;
	struct sockaddr_ll sa;
	struct packet_mreq mr;
	int reuse = 1;
	int flags;
	int ret;
	int sk;


	sk = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_LLDP));
	if (sk < 0) {
		fprintf(stderr, "socket err\n");
		return -1;
	}

	flags = fcntl(sk, F_GETFL, 0);
	if (flags != -1) {
		fcntl(sk, F_SETFL, flags | O_NONBLOCK);
	}

	if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
		fprintf(stderr, "reuseaddr err\n");
		close(sk);
		return -1;
	}

	ifindex = if_nametoindex(n->ifname);
	sa.sll_family = PF_PACKET;
	sa.sll_protocol = htons(ETHERTYPE_LLDP);
	sa.sll_halen = ETH_ALEN;
	sa.sll_ifindex = ifindex;
	if ((bind(sk, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll))) != 0) {
		fprintf(stderr, "bind() error\n");
		close(sk);
		return -1;
	}

	/* subscribe to lldp multicast */
	memset(&mr,0,sizeof(mr));
	mr.mr_ifindex = sa.sll_ifindex;
	mr.mr_type = PACKET_MR_MULTICAST;
	mr.mr_alen = ETH_ALEN;
	memcpy(mr.mr_address, "\x01\x80\xC2\x00\x00\x0E", ETH_ALEN);
	if (setsockopt(sk, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
		fprintf(stderr, "%s: setsockopt error (%s)\n", __func__,
			strerror(errno));
		close(sk);
		return -1;
	}

	priv->sock_lldp = sk;
	priv->uloop_lldp.fd = sk;
	priv->uloop_lldp.cb = i1905_recv_lldp;
	ret = uloop_fd_add(&priv->uloop_lldp, ULOOP_READ | ULOOP_EDGE_TRIGGER);
	if (ret) {
		close(sk);
		priv->sock_lldp = -1;
		return -1;
	}

	return 0;
}

static void i1905_free_interface_socket_lldp(struct i1905_interface *iface,
					     struct i1905_interface_private *ifpriv)
{
	struct packet_mreq mr;


	memset(&mr,0,sizeof(mr));
	mr.mr_ifindex = iface->ifindex;
	mr.mr_type = PACKET_MR_MULTICAST;
	mr.mr_alen = ETH_ALEN;
	memcpy(mr.mr_address, "\x01\x80\xC2\x00\x00\x0E", ETH_ALEN);
	setsockopt(ifpriv->sock_lldp, SOL_PACKET, PACKET_DROP_MEMBERSHIP,
		   &mr, sizeof(mr));

	uloop_fd_delete(&ifpriv->uloop_lldp);
	close(ifpriv->sock_lldp);
	ifpriv->sock_lldp = -1;
}


#if 0
static int i1905_create_al_interface(struct i1905_private *p)
{
	//TODO

	return 0;
}

static int i1905_destroy_al_interface(struct i1905_private *p)
{
	//TODO

	return 0;
}
#endif

static int i1905_init_interface_private_wsc(struct i1905_interface *n)
{
	struct i1905_interface_private *p =
			(struct i1905_interface_private *)n->priv;
	struct i1905_private *priv= (struct i1905_private *)p->i1905private;
	struct i1905_interface_private_wsc *wsc;
	int band = 0;
	int ret = 0;


	wsc = calloc(1, sizeof(*wsc));
	if (!wsc) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return -ENOMEM;
	}

	p->wsc = wsc;
	wsc->last_msg = NULL;
	wsc->last_msglen = 0;
	wsc->key = NULL;

	// TODO: get 'enum wps_state' and decide
	p->configured = false;

	//wifi_get_supp_security(n->ifname, &auth, &enc);
	//wifi_get_wps_device_info(n->ifname, struct wps_device *info);

	if (n->band == 2)
		band = WPS_RF_24GHZ;
	else if (n->band == 5)
		band = WPS_RF_50GHZ;
	else if (n->band == 60)
		band = WPS_RF_60GHZ;
	else
		band = n->band;


	ret = i1905_get_apsettings_for_band(priv, band, &wsc->cred);
	if (ret) {
		i1905_init_apsettings_for_band(priv, band, &wsc->cred);
	}

	dbg("[%s]   WSC band = %d  manufacturer = %s\n", n->ifname,
	    p->wsc->cred.band, p->wsc->cred.manufacturer);

	return 0;
}

static void i1905_free_interface_private_wsc(struct i1905_interface *iface)
{
	struct i1905_interface_private *ifpriv =
			(struct i1905_interface_private *)iface->priv;

	if (ifpriv->wsc) {
		ifpriv->wsc->last_msg = NULL;
		ifpriv->wsc->last_msglen = 0;
		ifpriv->wsc->key = NULL;
		free(ifpriv->wsc);
	}
}

static int i1905_setup_interface_priv(struct i1905_private *priv,
				      struct i1905_interface *iface)
{
	struct i1905_interface_private *p =
			(struct i1905_interface_private *)iface->priv;

	int ret;


	p->iface = iface;
	p->i1905private = priv;
	p->sock_1905 = -1;
	p->sock_lldp = -1;

	cmdufrag_queue_init(&p->rxfrag_queue);

	if (IS_MEDIA_WIFI(iface->media))
		i1905_init_interface_private_wsc(iface);

	ret = i1905_init_interface_socket_1905(iface, p);
	ret |= i1905_init_interface_socket_lldp(iface, p);

	fprintf(stderr, "%s: returned %d\n", __func__, ret);

	return ret;
}

static void i1905_free_interface_priv(struct i1905_private *priv,
				      struct i1905_interface *iface)
{
	struct i1905_interface_private *p =
			(struct i1905_interface_private *)iface->priv;


	i1905_free_interface_socket_1905(iface, p);
	i1905_free_interface_socket_lldp(iface, p);
	p->i1905private = NULL;

	if (p->rxcmdu) {
		free(p->rxcmdu);
		p->rxcmdu = NULL;
	}

	if (p->rxlldp) {
		free(p->rxlldp);
		p->rxlldp = NULL;
	}

	if (IS_MEDIA_WIFI(iface->media))
		i1905_free_interface_private_wsc(iface);

	cmdufrag_queue_free(&p->rxfrag_queue);
}

static int i1905_init_interface(struct i1905_private *priv,
				struct i1905_interface *iface,
				int (*setup_ifpriv)(struct i1905_private *priv,
						    struct i1905_interface *iface))
{
	struct i1905_config *cfg = &priv->cfg;
	int ret = 0;


	iface->device = &priv->dm.self;
	memcpy(iface->aladdr, cfg->macaddr, 6);
	iface->vid = cfg->primary_vid;

	if (setup_ifpriv)
		ret = setup_ifpriv(priv, iface);

	return ret;
}

struct i1905_interface *i1905_lookup_interface(struct i1905_private *p,
					       char *ifname)
{
	struct i1905_interface *iface = NULL;


	list_for_each_entry(iface, &p->dm.self.iflist, list) {
		if (!strncmp(iface->ifname, ifname, 15))
			return iface;
	}

	return NULL;
}

bool i1905_lookup_interface_in_config(struct i1905_private *priv, char *ifname)
{
	struct i1905_iface_config *f;

	if (!priv)
		return false;

	list_for_each_entry(f, &priv->cfg.iflist, list) {
		if (!strncmp(f->ifname, ifname, 15))
			return true;
	}

	return false;
}

char *i1905_brport_to_ifname(struct i1905_private *priv, uint16_t port)
{
	struct i1905_interface *iface;

	list_for_each_entry(iface, &priv->dm.self.iflist, list) {
		if (iface->is_brif && iface->brport == port)
			return iface->ifname;
	}

	return NULL;
}

void i1905_teardown_interface(struct i1905_private *priv, const char *ifname)
{
	struct i1905_selfdevice *self = &priv->dm.self;
	struct i1905_interface *iface;


	iface = i1905_ifname_to_interface(priv, ifname);
	if (iface) {
		list_del(&iface->list);
		self->num_interface--;
		i1905_free_interface(priv, iface, i1905_free_interface_priv);
	}
}

struct i1905_interface *i1905_setup_interface(struct i1905_private *priv,
					      const char *ifname)
{
	struct i1905_interface *iface;
	int br_ifindex = 0;
	int ret = 0;


	iface = i1905_alloc_interface(priv, ifname,
				      sizeof(struct i1905_interface_private));

	if (!iface)
		return NULL;

	ret = i1905_init_interface(priv, iface, i1905_setup_interface_priv);
	if (ret) {
		fprintf(stderr, "ERROR init interface %s\n", ifname);
		//TODO: free
		return NULL;
	}

	list_add_tail(&iface->list, &priv->dm.self.iflist);
	priv->dm.self.num_interface++;

	br_ifindex = if_isbridge_interface(ifname);
	if (br_ifindex > 0) {
		iface->is_brif = true;
		iface->brport = if_brportnum(ifname);
		iface->br_ifindex = br_ifindex;
		fprintf(stderr, "%s: allow cmdus to %s through bridge\n",
			__func__, ifname);

		i1905_clear_ebtable_rules(iface->macaddr, iface->aladdr);
		i1905_set_ebtable_rules(iface->macaddr, iface->aladdr);
	}

	i1905_get_known_neighbors(priv, (char *)ifname);

	return iface;
}

static int i1905_add_master_interface(struct i1905_private *priv, const char *ifname)
{
	struct i1905_master_interface *m;
	int ret;


	m = calloc(1, sizeof(*m));
	if (m) {
		struct ip_address ips[32] = {0};
		int num = 32;

		snprintf(m->ifname, 16, "%s", ifname);
		m->ifindex = if_nametoindex(ifname);
		dbg("%s: %s: ifindex = %d\n", __func__, m->ifname, m->ifindex);
		if_gethwaddr(ifname, m->macaddr);
		if_getflags(ifname, &m->ifstatus);

		ret = if_getaddrs(ifname, ips, &num);
		if (!ret && num > 0) {
			m->ipaddrs = calloc(num, sizeof(struct ip_address));
			if (m->ipaddrs) {
				m->num_ipaddrs = num;
				memcpy(m->ipaddrs, ips, num * sizeof(struct ip_address));
			} else {
				dbg("%s: -ENOMEM!\n", __func__);
			}
		}

		list_add_tail(&m->list, &priv->dm.self.miflist);
		priv->dm.self.num_master_interface++;
		return 0;
	}

	return -1;
}

static void i1905_free_master_interfaces(struct i1905_private *priv)
{
	struct i1905_selfdevice *self = &priv->dm.self;
	struct i1905_master_interface *m, *tmp;


	list_for_each_entry_safe(m, tmp, &self->miflist, list) {
		list_del(&m->list);
		self->num_master_interface--;
		if (m->num_ipaddrs > 0) {
			free(m->ipaddrs);
			m->num_ipaddrs = 0;
		}
		free(m);
	}
}

static int i1905_init_interfaces(struct i1905_private *p)
{
	struct i1905_config *cfg = &p->cfg;
	struct i1905_iface_config *f;

	list_for_each_entry(f, &cfg->iflist, list) {
		struct i1905_interface *iface;


		dbg("%s: ifname = %s\n", __func__, f->ifname);

		if (f->is_bridge && if_isbridge(f->ifname)) {
			char ifnames[32][16] = {0};
			uint32_t br_ifindex = 0;
			int n = 32;
			int ret;
			int i;

			dbg("%s: %s is bridge\n", __func__, f->ifname);
			i1905_add_master_interface(p, f->ifname);

			br_ifindex = if_nametoindex(f->ifname);
			ret = br_get_iflist(f->ifname, &n, ifnames);
			if (ret)
				return -1;

			for (i = 0; i < n; i++) {
				iface = i1905_alloc_interface(p, ifnames[i],
						sizeof(struct i1905_interface_private));

				i1905_init_interface(p, iface, i1905_setup_interface_priv);
				iface->is_brif = true;
				iface->brport = if_brportnum(ifnames[i]);
				iface->br_ifindex = br_ifindex;
				/* fprintf(stderr, "%s: aladdr = " MACFMT "\n",
					__func__, MAC2STR(cfg->macaddr)); */

				list_add_tail(&iface->list, &p->dm.self.iflist);
				p->dm.self.num_interface++;

				i1905_bypass_bridge_flow(iface->macaddr);
			}

			i1905_bypass_bridge_flow(cfg->macaddr);
			i1905_bypass_bridge_flow(MCAST_1905);

			i1905_get_known_neighbors(p, f->ifname);
		} else {
			/* config cannot be trusted; ensure that ifname is not added
			 * more than ones.
			 */
			if (i1905_lookup_interface(p, f->ifname) != NULL)
				continue;

			iface = i1905_alloc_interface(p, f->ifname,
					sizeof(struct i1905_interface_private));
			if (iface) {
				i1905_init_interface(p, iface, i1905_setup_interface_priv);
				iface->is_brif = false;
				iface->brport = 0xffffffff;
				info("%s: aladdr = " MACFMT "\n", __func__,
				     MAC2STR(cfg->macaddr));

				list_add_tail(&iface->list, &p->dm.self.iflist);
				p->dm.self.num_interface++;

				if (iface->lo)
					continue;

#if 0	//TODO: only if almac interface is unique
				if (!p->al_ifindex) {
					int res;

					res = macvlan_addif(f->ifname,
							    p->al_ifname,
							    cfg->macaddr,
							    NULL);
					if (!res) {
						p->al_ifindex = if_nametoindex(p->al_ifname);
						dbg("Bringing up AL interface ifindex = %d\n",
						    p->al_ifindex);
						res = if_setflags(p->al_ifname, IFF_UP);
						if (res) {
							err("Failed to bring up al-interface!!!!!\n");
						}
					}
				}
				i1905_get_known_neighbors(p, f->ifname);
#endif
			}
		}
	}

	return 0;
}

void i1905_free_interfaces(struct i1905_private *priv)
{
	struct i1905_interface *iface, *tmp;


	list_for_each_entry_safe(iface, tmp, &priv->dm.self.iflist, list) {
		list_del(&iface->list);
		i1905_clear_ebtable_rules(iface->macaddr, iface->aladdr);
		i1905_free_interface(priv, iface, i1905_free_interface_priv);
	}
}

int i1905_handle_iflink_change(struct i1905_private *priv, const char *ifname,
			       bool is_brif, int br_ifindex, bool dellink)
{
	struct i1905_interface *iface;
	uint8_t macaddr[6] = {0};
	int ifindex;
	int ret = 0;



	if (!priv || !ifname)
		return -1;


	trace("%s: --->\n", __func__);

	iface = i1905_ifname_to_interface(priv, ifname);
	if (!iface) {
		if (dellink) {
			return 0;
		}

		dbg("%s: num_interfaces = %d\n", __func__, priv->dm.self.num_interface);
		iface = i1905_setup_interface(priv, ifname);
		if (!iface)
			return -1;

		dbg("%s: num_interfaces = %d\n", __func__, priv->dm.self.num_interface);
		ret = i1905_publish_interface_object(priv, ifname);

		/* speedup discovery by neighbor nodes */
		i1905_send_topology_discovery(iface);

		return ret;
	}

	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		err("%s: %s ifindex = 0!\n", __func__, ifname);
		return 0;
	}

	ret = if_gethwaddr(iface->ifname, macaddr);
	if (ret || hwaddr_is_zero(macaddr)) {
		err("%s: %s hwaddr = 0!\n", __func__, ifname);
		return -1;
	}

	if (!hwaddr_equal(iface->macaddr, macaddr)) {
		dbg("%s: %s updating macaddr\n", __func__, iface->ifname);

		i1905_clear_ebtable_rules(iface->macaddr, iface->aladdr);
		memcpy(iface->macaddr, macaddr, 6);
		i1905_set_ebtable_rules(iface->macaddr, iface->aladdr);
	}

	if (ifindex != iface->ifindex) {
		dbg("%s: ifpriv = %p  ifindex mismatch, rebinding\n",
		    __func__, iface->priv);

		i1905_remove_interface_object(priv, ifname);

		ret = i1905_rebind_interface(priv, iface);
		if (ret) {
			err("%s: %s failed to rebind\n", __func__, iface->ifname);
			return -1;
		}

		i1905_clear_ebtable_rules(iface->macaddr, iface->aladdr);
		iface->ifindex = ifindex;
		i1905_set_ebtable_rules(iface->macaddr, iface->aladdr);

		ret = i1905_publish_interface_object(priv, ifname);

		/* allow for quicker re-discovery by neighbors */
		i1905_send_topology_discovery(iface);
	}

	return ret;
}

int i1905_rebind_interface(struct i1905_private *priv, struct i1905_interface *iface)
{
	int ret;


	if (!priv || !iface || !iface->priv) {
		err("%s: rebind error\n", __func__);
		return -1;
	}

	i1905_free_interface_socket_1905(iface, iface->priv);
	i1905_free_interface_socket_lldp(iface, iface->priv);

	ret = i1905_init_interface_socket_1905(iface, iface->priv);
	ret |= i1905_init_interface_socket_lldp(iface, iface->priv);
	if (ret)
		err("%s: Failed to rebind\n", __func__);

	return ret;
}

static void i1905_periodic_refresh_self(atimer_t *t)
{
	struct i1905_private *p = container_of(t, struct i1905_private, refreshtimer);

	i1905_dm_refresh_self(p);

	timer_set(t, 5000);
}

static int i1905_init_al(struct i1905_private *p)
{
	int ret;

	i1905_dm_init(&p->dm, &p->cfg);
	cmdu_midgen_init();
	cmdu_ackq_init(&p->txack_q);
	neigh_queue_init(&p->neigh_q);

	ret = i1905_init_interfaces(p);
	if (ret)
		return -1;

	i1905_periodic_refresh_self(&p->refreshtimer);
	return 0;
}

static void i1905_exit_al(struct i1905_private *p)
{
	if (!p)
		return;

	i1905_free_interfaces(p);
	i1905_free_master_interfaces(p);
	neigh_queue_free(&p->neigh_q);
	cmdu_ackq_free(&p->txack_q);
	cmdu_midgen_exit();
	i1905_dm_free(&p->dm);
}

void heartbeat_timer_cb(atimer_t *t)
{
	struct i1905_private *p = container_of(t, struct i1905_private, hbtimer);

	UNUSED(p);
	switch (signal_pending) {
	case SIGUSR2:
		signal_pending = 0;
		err("%s", "Received SIGUSR2\n");
		break;
	default:
		break;
	}

	timer_set(t, 1000);
}

int i1905_run_bridge_discovery(struct i1905_private *p)
{
	struct i1905_interface *iface;


	list_for_each_entry(iface, &p->dm.self.iflist, list) {
		i1905_send_bridge_discovery(iface);
	}

	return 0;
}

int i1905_run_topology_discovery(struct i1905_private *p)
{
	struct i1905_interface *iface;


	list_for_each_entry(iface, &p->dm.self.iflist, list) {
		i1905_send_topology_discovery(iface);
	}

	return 0;
}

void topology_timer_cb(atimer_t *t)
{
	struct i1905_private *p = container_of(t, struct i1905_private, topotimer);

	i1905_run_topology_discovery(p);
	i1905_run_bridge_discovery(p);

	timer_set(t, 60000);
}

bool i1905_has_registrar(void *priv, uint8_t freqband)
{
	struct i1905_private *p = priv;

	if (!p)
		return false;

	switch (freqband) {
	case IEEE80211_FREQUENCY_BAND_2_4_GHZ:
	case IEEE80211_FREQUENCY_BAND_5_GHZ:
	case IEEE80211_FREQUENCY_BAND_60_GHZ:
		return !!(p->cfg.registrar & BIT(freqband));
	default:
		break;
	}

	return false;
}

bool i1905_is_registrar(void *priv)
{
	struct i1905_private *p = priv;

	if (p && p->cfg.registrar == I1905_CONFIG_REGISTRAR_ALL)
		return true;

	return false;
}

int i1905_init_apsettings_for_band(void *priv, uint8_t band,
				   struct wps_credential *ap)
{
	dbg("%s: init apconfig for wsc band = %u\n", __func__, band);

	ap->band = band;
	ap->ssidlen = 0;
	ap->keylen = 0;
	ap->auth_type = WPS_AUTH_WPA2PSK;
	ap->enc_type = WPS_ENCR_AES;
	strcpy(ap->manufacturer, WPS_DEFAULT_MANUFACTURER);
	strcpy(ap->model_name, WPS_DEFAULT_MODEL_NAME);
	strcpy(ap->device_name, WPS_DEFAULT_DEVICE_NAME);
	memcpy(ap->device_type, WPS_DEFAULT_DEVICE_TYPE, 8);
	strcpy(ap->model_number, WPS_DEFAULT_MODEL_NUM);
	strcpy(ap->serial_number, WPS_DEFAULT_SERIAL_NUM);
	memcpy(ap->uuid, WPS_DEFAULT_UUID, 16);
	ap->os_version = strtoul(WPS_DEFAULT_OS_VERSION, NULL, 0);

	return 0;
}

int i1905_get_apsettings_for_band(void *priv, uint8_t band,
				  struct wps_credential *cred)
{
	struct i1905_apconfig *ap;
	struct i1905_private *p = priv;


	if (!p) {
		dbg("priv is NULL\n");
		return -1;
	}

	list_for_each_entry(ap, &p->cfg.reglist, list) {
		if (band == ap->band) {
			cred->band = ap->band;
		} else {
			if (!(BIT(ap->band) & band))
				continue;

			if (!!(band & WPS_RF_24GHZ))
				cred->band = WPS_RF_24GHZ;
			else if (!!(band & WPS_RF_50GHZ))
				cred->band = WPS_RF_50GHZ;
			else if (!!(band & WPS_RF_60GHZ))
				cred->band = WPS_RF_60GHZ;
			else
				continue;
		}

		memcpy(cred->ssid, ap->ssid, ap->ssidlen);
		cred->ssidlen = ap->ssidlen;
		cred->auth_type = ap->auth_type;
		cred->enc_type = ap->enc_type;
		memcpy(cred->key, ap->key, ap->keylen);
		cred->keylen = ap->keylen;

		memcpy(cred->uuid, ap->uuid, 16);
		strncpy(cred->manufacturer, ap->manufacturer, 63);
		strncpy(cred->model_name, ap->model_name, 33);
		strncpy(cred->device_name, ap->device_name, 33);
		strncpy(cred->model_number, ap->model_number, 33);
		strncpy(cred->serial_number, ap->serial_number, 33);
		memcpy(cred->device_type, ap->device_type, 8);
		cred->os_version = ap->os_version;

		return 0;
	}

	dbg("%s: apconfig not found for band = %u\n", __func__, band);
	return -1;
}

int i1905_apconfig_request(void *priv, uint8_t band)
{
	uint8_t freqband = IEEE80211_FREQUENCY_BAND_UNKNOWN;
	//struct i1905_private *p = priv;
	bool forall_radios = false;
	int ret = 0;
	int i;
	uint8_t bands[] = { IEEE80211_FREQUENCY_BAND_2_4_GHZ,
			  IEEE80211_FREQUENCY_BAND_5_GHZ,
			  IEEE80211_FREQUENCY_BAND_60_GHZ };


	switch (band) {
	case 0:
	case 0xff:
		forall_radios = true;
		break;
	case 2:
		freqband = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
		break;
	case 5:
		freqband = IEEE80211_FREQUENCY_BAND_5_GHZ;
		break;
	case 60:
		freqband = IEEE80211_FREQUENCY_BAND_60_GHZ;
		break;
	default:
		return -EINVAL;
	}

	if (!forall_radios) {
#if 0
		if (i1905_has_registrar(p, freqband) && p->start_apconfig == 1) {
			fprintf(stderr, "Self is registrar on band %d\n", band);
			p->start_apconfig = 0;
			return -EINVAL;
		}
#endif

		return i1905_send_ap_autoconfig_search(priv, freqband);
	}

	/* for all wifi bands */
	for (i = 0; i < ARRAY_SIZE(bands); i++)
		ret |= i1905_send_ap_autoconfig_search(priv, freqband);

	return ret;
}

int i1905_apconfig_renew(void *priv, uint8_t band)
{
	uint8_t freqband = IEEE80211_FREQUENCY_BAND_UNKNOWN;
	uint8_t bands[] = { IEEE80211_FREQUENCY_BAND_2_4_GHZ,
			  IEEE80211_FREQUENCY_BAND_5_GHZ,
			  IEEE80211_FREQUENCY_BAND_60_GHZ };
	bool forall_radios = false;
	int ret = 0;
	int i;


	switch (band) {
	case 0:
	case 0xff:
		forall_radios = true;
		break;
	case 2:
		freqband = IEEE80211_FREQUENCY_BAND_2_4_GHZ;
		break;
	case 5:
		freqband = IEEE80211_FREQUENCY_BAND_5_GHZ;
		break;
	case 60:
		freqband = IEEE80211_FREQUENCY_BAND_60_GHZ;
		break;
	default:
		return -EINVAL;
	}

	if (!forall_radios) {
		if (!i1905_has_registrar(priv, freqband))
			return -EINVAL;

		return i1905_send_ap_autoconfig_renew(priv, freqband);
	}

	for (i = 0; i < ARRAY_SIZE(bands); i++) {
		if (!i1905_has_registrar(priv, freqband))
			continue;

		ret |= i1905_send_ap_autoconfig_renew(priv, freqband);
	}

	return ret;
}


int i1905_init(void **priv, void *opts)
{
	struct i1905_useropts *uopts = (struct i1905_useropts *)opts;
	struct i1905_private *p;
	int ret;


	set_sighandler(SIGUSR2, i1905_sighandler);
	set_sighandler(SIGPIPE, SIG_IGN);
	/* and SIGINT/SIGTERM handlers from uloop cancel uloop */

	*priv = NULL;
	p = calloc(1, sizeof(struct i1905_private));
	if (!p)
		return -1;


	INIT_LIST_HEAD(&p->extlist);
	snprintf(p->al_ifname, 16, "%s", "i1905");	//TODO:

	uloop_init();
	p->ctx = ubus_connect(uopts->ubus_sockpath);
	if (!p->ctx) {
		err("Failed to connect to ubus\n");
		goto out_err;
	}
	ubus_add_uloop(p->ctx);

	/* read from config */
	i1905_config_defaults(&p->cfg);
	ret = i1905_reconfig(&p->cfg, uopts->confpath, uopts->conffile);
	if (ret) {
		err("Invalid config\n");
		goto out_err;
	}

	i1905_dump_config(&p->cfg);

	dbg("%s:  priv = %p  mode = %s )\n", __func__, p,
			p->cfg.registrar ? "registrar" : "enrollee");

	if (uopts->lo) {
		ret = i1905_config_add_interface(&p->cfg, "lo");
		if (ret)
			dbg("%s: failed to add 'lo' to config iflist\n", __func__);
	}

	ret = i1905_init_al(p);
	if (ret)
		goto out_err;


	ret = i1905_publish_object(p, uopts->objname);
	if (ret)
		goto out_err;

	ret = i1905_register_misc_events(p);
	if (ret)
		goto out_err;

	ret = i1905_register_nlevents(p);
	if (ret)
		goto out_err;

	i1905_load_extensions(p);


	timer_init(&p->hbtimer, heartbeat_timer_cb);
	timer_init(&p->topotimer, topology_timer_cb);
	timer_init(&p->refreshtimer, i1905_periodic_refresh_self);

	timer_set(&p->hbtimer, 1000);
	timer_set(&p->topotimer, 1500);


	*priv = p;
	return 0;

out_err:
	uloop_done();
	cmdu_midgen_exit();
	free(p);
	return -1;
}

void i1905_run(void *handle)
{
	UNUSED(handle);

	uloop_run();
}

int i1905_exit(void *handle)
{
	struct i1905_private *priv = (struct i1905_private *)handle;

	if (!priv)
		return 0;


	timer_del(&priv->topotimer);
	timer_del(&priv->hbtimer);
	timer_del(&priv->refreshtimer);

	i1905_unregister_misc_events(priv);
	i1905_unregister_nlevents(priv);

	i1905_remove_object(priv);

	i1905_unload_extensions(priv);

	i1905_exit_al(priv);

	i1905_config_free(&priv->cfg);

	ubus_free(priv->ctx);

	uloop_done();

	free(priv);

	fprintf(stderr, "i1905_exit\n");
	return 0;
}

int i1905_main(void *user_options)
{
	struct i1905_useropts *opts = (struct i1905_useropts *)user_options;
	uint8_t aladdr[6] = {0};
	void *i1905_handle;
	int ret;


	if (opts->alid && !hwaddr_aton(opts->alid, aladdr)) {
		err("Invalid ALID format; use ':' separated macaddress\n");
		return -1;
	}

	if (opts->daemonize)
		do_daemonize(opts->pidfile);

	start_logging(opts);

	ret = i1905_init(&i1905_handle, opts);
	if (ret) {
		err("%s : Failed to init.\n", IEEE1905_OBJECT);
		return -1;
	}

	i1905_run(i1905_handle);

	i1905_exit(i1905_handle);

	stop_logging();

	return 0;
}
