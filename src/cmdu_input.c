/*
 * cmdu_input.c - received CMDU and TLV handling
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

#include "i1905_extension.h"




int i1905_handle_topology_discovery(const char *ifname, uint8_t *from,
				    struct cmdu_buff *rxf, void *priv,
				    void *cookie)
{
	struct tlv *tv[2][16];
	uint8_t aladdr_origin[6] = {0};
	uint8_t macaddr_origin[6] = {0};
	struct i1905_interface *iface;
	int ret;


	trace("%s -------------->\n", __func__);

	ret = i1905_cmdu_parse_tlvs(rxf, tv, 2);
	if (ret)
		return -1;

	if (!tv[0][0] || !tv[1][0]) {
		err("Error! missing TLV(s) in topology discovery\n");
		return -1;
	}

	memcpy(aladdr_origin, tv[0][0]->data, tlv_length(tv[0][0]));
	memcpy(macaddr_origin, tv[1][0]->data, tlv_length(tv[1][0]));

	if (hwaddr_is_zero(macaddr_origin) || hwaddr_is_zero(aladdr_origin)) {
		dbg("%s: Invalid topology discovery: tlv-aladdr = " MACFMT ", tlv-macaddr = " MACFMT "\n",
		    __func__, MAC2STR(aladdr_origin), MAC2STR(macaddr_origin));
		/* return -1; */	/* why? see reason below */
	}

	/* some implementations using 'lo' to communicate with collocated 1905
	 * entity within a single device send topology discovery with
	 * macaddress in tlv-src-macaddress field set to '0'.
	 * Do not reject the received discovery frames as invalid from such.
	 */
	if (hwaddr_is_zero(macaddr_origin) && !strncmp(ifname, "lo", 2))
		memcpy(macaddr_origin, aladdr_origin, 6);


	iface = i1905_ifname_to_interface(priv, ifname);
	if (!iface) {
		fprintf(stderr, "Error! ifname_to_interface(%s)\n", ifname);
		return -1;
	}

	if (hwaddr_equal(from, iface->aladdr)) {
		dbg("%s: Ignore topology discovery from self through 'lo'\n", __func__);
		return 0;
	}

	dbg("%s: %s UPDATE 1905 NBR: " MACFMT " rif = " MACFMT"\n",
		__func__, ifname, MAC2STR(aladdr_origin), MAC2STR(macaddr_origin));

	ret = i1905_dm_neighbor_discovered(iface, aladdr_origin, macaddr_origin,
					   CMDU_TYPE_TOPOLOGY_DISCOVERY);
	if (ret) {
		dbg("%s: Error updating DM for discovered neighbor " MACFMT"\n",
		    __func__, MAC2STR(macaddr_origin));

		return -1;
	}

	neigh_set_1905(&((struct i1905_private *)priv)->neigh_q, aladdr_origin);
	neigh_set_1905_slave(&((struct i1905_private *)priv)->neigh_q, macaddr_origin);

	//TODO: processed by extensions; use meaningful flag
	if (rxf->flags == 1)
		return 0;

	//TODO: conditionally send topology query
	ret = i1905_send_topology_query(iface, aladdr_origin);
	ret |= i1905_send_link_metric_query(iface, aladdr_origin);
	ret |= i1905_send_higherlayer_query(iface, aladdr_origin);

	ret |= i1905_send_ap_autoconfig_search(priv, IEEE80211_FREQUENCY_BAND_2_4_GHZ);
	ret |= i1905_send_ap_autoconfig_search(priv, IEEE80211_FREQUENCY_BAND_5_GHZ);

	return ret;
}

int i1905_handle_topology_notification(const char *ifname, uint8_t *from,
				       struct cmdu_buff *rxf, void *priv,
				       void *cookie)
{
	struct tlv *tv[1][16];
	uint8_t aladdr_origin[6] = {0};
	struct i1905_interface *iface;
	int ret;


	trace("%s -------------->\n", __func__);

	ret = i1905_cmdu_parse_tlvs(rxf, tv, 1);
	if (ret)
		return -1;

	if (tv[0][0])
		memcpy(aladdr_origin, tv[0][0]->data, tlv_length(tv[0][0]));


	if (hwaddr_is_zero(aladdr_origin)) {
		fprintf(stderr,
			"%s: Discard topo notification from aladdr = 0!\n",
			__func__);

		return -1;
	}

	iface = i1905_ifname_to_interface(priv, ifname);
	if (!iface) {
		fprintf(stderr, "Error! ifname_to_interface(%s)\n", ifname);
		return -1;
	}

	if (hwaddr_equal(from, iface->aladdr)) {
		dbg("%s: Ignore topology notification from self through 'lo'\n", __func__);
		return 0;
	}

	ret = i1905_dm_neighbor_changed(iface, aladdr_origin);
	if (ret) {
		fprintf(stderr,
			"%s: Error handling neighbor " MACFMT" change notification\n",
			__func__, MAC2STR(aladdr_origin));
	}

	neigh_set_1905(&((struct i1905_private *)priv)->neigh_q, aladdr_origin);

	/* relay mcast the change notification */
	ret = i1905_relay_cmdu(priv, ifname, MCAST_1905, iface->aladdr,
			       ETHERTYPE_1905, rxf);
	if (ret)
		fprintf(stderr, "Error sending relaying TOPOLOGY_CHANGE\n");

	/* query what changed */
	ret = i1905_send_topology_query(iface, aladdr_origin);

	return ret;
}

int i1905_handle_topology_query(const char *ifname, uint8_t *from,
				struct cmdu_buff *rxf, void *priv,
				void *cookie)
{
	struct i1905_interface *iface;


	//TODO: processed by extensions; use meaningful flag
	if (rxf->flags == 1)
		return 0;

	iface = i1905_ifname_to_interface(priv, ifname);
	if (!iface) {
		fprintf(stderr, "Error! ifname_to_interface(%s)\n", ifname);
		return -1;
	}

	return i1905_send_topology_response(iface, rxf->origin, cmdu_get_mid(rxf));
}

int i1905_handle_topology_response(const char *ifname, uint8_t *from,
				   struct cmdu_buff *rxf, void *priv,
				   void *cookie)
{
	struct tlv *tv[6][16];
	struct tlv_device_info *devinfo;
	uint8_t aladdr_origin[6] = {0};
	struct i1905_interface *iface;
	uint8_t num_interface = 0;
	int ret;


	trace("%s -------------->\n", __func__);

	iface = i1905_ifname_to_interface(priv, ifname);
	if (!iface) {
		fprintf(stderr, "Error! ifname_to_interface(%s)\n", ifname);
		return -1;
	}

	if (hwaddr_equal(from, iface->aladdr)) {
		dbg("%s: Discard topology response from localhost\n", __func__);
		return 0;
	}

	ret = i1905_cmdu_parse_tlvs(rxf, tv, 6);
	if (ret)
		return -1;

	if (!tv[0][0]) {
		dbg("%s: Discard topology response - missing TLV DEVICE_INFORMATION_TYPE\n", __func__);
		return -1;
	}

	devinfo = (struct tlv_device_info *)tv[0][0]->data;
	if (hwaddr_is_zero(devinfo->aladdr)) {
		dbg("%s: Discard topology response from aladdr = 00:00..\n", __func__);
		return -1;
	}

	if (hwaddr_equal(iface->aladdr, devinfo->aladdr)) {
		dbg("%s: Ignore topology response from self\n", __func__);
		return 0;
	}

	memcpy(aladdr_origin, devinfo->aladdr, 6);
	num_interface = devinfo->num_interface;
	if (num_interface > 1 && !tv[1][0]) {
		dbg("%s: Discard topology response - missing TLV DEVICE_BRIDGING_CAPABILITIES\n", __func__);
		return -1;
	}

	ret = i1905_dm_neighbor_update(iface, aladdr_origin, tv[0][0]);
	if (ret == -99) {
		/* topology response from unknown neighbor; add new */
		ret = i1905_dm_neighbor_discovered(iface, aladdr_origin, from,
						   CMDU_TYPE_TOPOLOGY_RESPONSE);
		if (ret) {
			dbg("%s: Error updating DM for discovered neighbor " MACFMT"\n",
			    __func__, MAC2STR(from));

			return -1;
		}

		ret = i1905_dm_neighbor_update(iface, aladdr_origin, tv[0][0]);
		if (ret) {
			dbg("%s: Error updating DM for neighbor " MACFMT"\n",
			    __func__, MAC2STR(from));

			return -1;
		}

		neigh_set_1905(&((struct i1905_private *)priv)->neigh_q, aladdr_origin);
		neigh_set_1905_slave(&((struct i1905_private *)priv)->neigh_q, from);
	}


	/* bridge capabilities */
	if (tv[1][0]) {
		int num = 0;

		while (tv[1][num]) {
			ret = i1905_dm_neighbor_update(iface, aladdr_origin, tv[1][num]);
			if (ret)
				break;
			num++;
		}
	}

	/* non-1905 neighbor list */
	i1905_free_all_non1905_nbrs_of_neighbor(iface, aladdr_origin);
	if (tv[2][0]) {
		int num = 0;

		while (tv[2][num]) {
			ret = i1905_dm_neighbor_update(iface, aladdr_origin, tv[2][num]);
			if (ret)
				break;
			num++;
		}
	}

	/* 1905 neighbor list */
	if (tv[3][0]) {
		int num = 0;

		while (tv[3][num]) {
			ret = i1905_dm_neighbor_update(iface, aladdr_origin, tv[3][num]);
			if (ret)
				break;
			num++;
		}
	}

	i1905_free_all_invalid_links(iface, aladdr_origin);

	i1905_dm_neighbor_update_non1905_neighbors(iface, aladdr_origin);

	//TODO: tv[4], tv[5]

	return 0;
}

int i1905_handle_vendor_request(const char *ifname, uint8_t *from,
				struct cmdu_buff *rxf, void *priv,
				void *cookie)
{
	return 0;
}

int i1905_handle_link_metric_query(const char *ifname, uint8_t *from,
				   struct cmdu_buff *rxf, void *priv,
				   void *cookie)
{
	struct tlv_linkmetric_query *lq;
	struct i1905_interface *iface;
	struct tlv *tv[1][16];
	uint8_t nbr[6] = {0};
	int ret;



	//TODO: processed by extensions; use meaningful flag
	if (rxf->flags == 1)
		return 0;

	ret = i1905_cmdu_parse_tlvs(rxf, tv, 1);
	if (ret)
		return -1;

	if (!tv[0][0]) {
		fprintf(stderr, "%s: Invalid LINK METRIC QUERY!\n", __func__);
		return -1;
	}


	lq = (struct tlv_linkmetric_query *)tv[0][0]->data;

	if (lq->query_type > LINKMETRIC_QUERY_TYPE_BOTH)
		return -1;

	if (lq->nbr_type == LINKMETRIC_QUERY_NEIGHBOR_SPECIFIC) {
		if (tlv_length(tv[0][0]) != sizeof(*lq))
			return -1;

		memcpy(nbr, lq->nbr_macaddr, 6);
		if (hwaddr_is_zero(nbr)) {
			fprintf(stderr, "%s: Discard link query for nbr-aladdr = 0!\n",
				__func__);

			return -1;
		}
	}

	iface = i1905_ifname_to_interface(priv, ifname);
	if (!iface) {
		fprintf(stderr, "Error! ifname_to_interface(%s)\n", ifname);
		return -1;
	}

	ret = i1905_send_link_metric_response(iface, rxf->origin, nbr,
					      lq->query_type,
					      cmdu_get_mid(rxf));

	return ret;
}

int i1905_handle_link_metric_response(const char *ifname, uint8_t *from,
				      struct cmdu_buff *rxf, void *priv,
				      void *cookie)
{
	struct i1905_interface *iface;
	struct tlv *tv[2][16];
	int num = 0;
	int ret;


	iface = i1905_ifname_to_interface(priv, ifname);
	if (!iface) {
		fprintf(stderr, "Error! ifname_to_interface(%s)\n", ifname);
		return -1;
	}

	ret = i1905_cmdu_parse_tlvs(rxf, tv, 2);
	if (ret)
		return -1;

	while (tv[0][num]) {
		struct tlv_tx_linkmetric *txl =
			(struct tlv_tx_linkmetric *)tv[0][num]->data;

		if (hwaddr_is_zero(txl->aladdr) ||
			hwaddr_is_zero(txl->neighbor_aladdr)) {

			fprintf(stderr, "%s: Discard Tx-link response (aladdr = 0!)\n",
				__func__);

			return -1;
		}

		ret = i1905_dm_neighbor_update(iface, txl->aladdr, tv[0][num]);
		if (ret)
			break;
		num++;
	}

	num = 0;
	while (tv[1][num]) {
		struct tlv_rx_linkmetric *rxl =
			(struct tlv_rx_linkmetric *)tv[1][num]->data;

		if (hwaddr_is_zero(rxl->aladdr) ||
			hwaddr_is_zero(rxl->neighbor_aladdr)) {

			fprintf(stderr, "%s: Discard Rx-link response\n",
				__func__);

			return -1;
		}

		ret = i1905_dm_neighbor_update(iface, rxl->aladdr, tv[1][num]);
		if (ret)
			break;
		num++;
	}

	return 0;
}


int i1905_handle_ap_autoconfig_search(const char *ifname, uint8_t *from,
				      struct cmdu_buff *rxf, void *priv,
				      void *cookie)
{
	struct i1905_interface *iface;
	struct tlv_autoconfig_band *freq;
	uint8_t aladdr_origin[6] = {0};
	struct tlv *tv[3][16];
	int ret = 0;



	trace("%s -------------->\n", __func__);

	iface = i1905_ifname_to_interface(priv, ifname);
	if (!iface) {
		fprintf(stderr, "Error! ifname_to_interface(%s)\n", ifname);
		return -1;
	}

	if (hwaddr_equal(from, iface->aladdr)) {
		fprintf(stderr, "Discard ap-autoconfig search from localhost\n");
		return 0;
	}

	ret = i1905_cmdu_parse_tlvs(rxf, tv, 3);
	if (ret)
		return -1;

	if (!tv[0][0] || !tv[1][0] || !tv[2][0])
		return -1;


	memcpy(aladdr_origin, tv[0][0]->data, tlv_length(tv[0][0]));
	if (hwaddr_is_zero(aladdr_origin)) {
		dbg("%s: Discard ap-autoconfig search from aladdr = 00:00..\n", __func__);
		return -1;
	}

	if (hwaddr_equal(iface->aladdr, aladdr_origin)) {
		dbg("%s: Ignore ap-autoconfig search from self\n", __func__);
		return 0;
	}

	/* Allow faster discovery of a new 1905 device.
	 * The new device may not necessarily be an immediate neighbor
	 * to us, because the autoconfig search may have been relay received.
	 * But in strictly star topologies, it can speed up neighbor discovery.
	 */
	dbg("%s: %s UPDATE 1905 NBR: " MACFMT " rif = " MACFMT"\n",
		__func__, ifname, MAC2STR(aladdr_origin), MAC2STR(rxf->origin));

	ret = i1905_dm_neighbor_discovered(iface, aladdr_origin, rxf->origin,
					   CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH);
	if (ret) {
		dbg("%s: Error updating DM for discovered neighbor " MACFMT"\n",
		    __func__, MAC2STR(rxf->origin));
	} else {
		neigh_set_1905(&((struct i1905_private *)priv)->neigh_q, aladdr_origin);
		neigh_set_1905_slave(&((struct i1905_private *)priv)->neigh_q, rxf->origin);
	}

	/* relay mcast the received cmdu */
	ret = i1905_relay_cmdu(priv, ifname, MCAST_1905, rxf->origin,
			       ETHERTYPE_1905, rxf);
	if (ret)
		fprintf(stderr, "Error sending AP_AUTOCONFIG_SEARCH\n");

	/* processed by extensions; don't proceed further */
	if (rxf->flags == 1)
		return 0;

	if (tv[1][0]->data[0] != IEEE80211_ROLE_REGISTRAR) {
		dbg("%s: Discard ap-autoconfig search for role != registrar\n",
		    __func__);
		return -1;
	}

	freq = (struct tlv_autoconfig_band *)tv[2][0]->data;
	if (freq->band > IEEE80211_FREQUENCY_BAND_60_GHZ) {
		dbg("%s: Discard ap-autoconfig search for invalid WiFi band\n",
		    __func__);
		return -1;
	}

	if (i1905_has_registrar(priv, freq->band)) {
		dbg("%s: sending autoconfig response for band = %d\n",
		    __func__, freq->band);
		ret = i1905_send_ap_autoconfig_response(iface, aladdr_origin,
							freq->band,
							cmdu_get_mid(rxf));
		return ret;
	}

	return ret;
}

int i1905_handle_ap_autoconfig_response(const char *ifname, uint8_t *from,
					struct cmdu_buff *rxf, void *priv,
					void *cookie)
{
	struct tlv_supported_band *freq;
	struct i1905_interface *iface;
	struct i1905_selfdevice *self;
	struct i1905_interface *ifs;
	struct tlv *tv[2][16];
	int ret;




	iface = i1905_ifname_to_interface(priv, ifname);
	if (!iface) {
		fprintf(stderr, "Error! ifname_to_interface(%s)\n", ifname);
		return -1;
	}

	if (hwaddr_equal(from, iface->aladdr)) {
		fprintf(stderr, "Discard ap-autoconfig response from localhost\n");
		return 0;
	}

	self = (struct i1905_selfdevice *)iface->device;

	ret = i1905_cmdu_parse_tlvs(rxf, tv, 2);
	if (ret)
		return -1;

	if (!tv[0][0] || !tv[1][0])
		return -1;

	freq = (struct tlv_supported_band *)tv[1][0]->data;
	if (freq->band > IEEE80211_FREQUENCY_BAND_60_GHZ) {
		dbg("%s: Discard ap-autoconfig response for invalid WiFi band\n",
		    __func__);
		return -1;
	}


	if (tv[0][0]->data[0] != IEEE80211_ROLE_REGISTRAR) {
		dbg("%s: Discard ap-autoconfig response for role != registrar\n",
		    __func__);
		return -1;
	}

	if (!hwaddr_is_zero(self->netregistrar[freq->band]) &&
	    !hwaddr_equal(self->netregistrar[freq->band], from)) {
		//TODO: notify another registrar or duplicate found
		fprintf(stderr, "WARN! Multiple registrars for band = %d detected!\n",
			freq->band);
	} else {
		memcpy(self->netregistrar[freq->band], from, 6);
		//TODO: ubus notify discovered registrar
		fprintf(stderr, "INFO! Registrar for band = %d detected!\n",
			freq->band);

		/* (re)set upstream interface */
		list_for_each_entry(ifs, &self->iflist, list) {
			if (iface == ifs)
				continue;

			if (ifs->upstream)
				ifs->upstream = false;
		}

		iface->upstream = true;
	}

	/* return from here if apconfig is not requested */
	if (((struct i1905_private *)priv)->start_apconfig != 1)
		return 0;


	//TODO: processed by extensions; use meaningful flag
	if (rxf->flags == 1)
		return 0;


	trace("%s -------------->\n", __func__);

	/* Send WSC-M1 for each unconfigured 1905 WiFi radios */
	list_for_each_entry(ifs, &self->iflist, list) {
		if (!IS_MEDIA_WIFI(ifs->media)) {
			dbg("Skip sending WSC-M1 for non-wifi interface %s\n", ifs->ifname);
			continue;
		}

		dbg("WiFi interface %s  media = %u\n", ifs->ifname, ifs->media);

		if ((IS_MEDIA_WIFI_2GHZ(ifs->media) && freq->band == IEEE80211_FREQUENCY_BAND_2_4_GHZ) ||
		    (IS_MEDIA_WIFI_5GHZ(ifs->media) && freq->band == IEEE80211_FREQUENCY_BAND_5_GHZ)) {

			if (!((struct i1905_interface_private *)ifs->priv)->configured) {
				ret = i1905_send_ap_autoconfig_wsc_m1(iface->priv, ifs->priv, from);
				if (ret) {
					fprintf(stderr, "Error sending AP_AUTOCONFIG_WSC_M1\n");
					break;
				}
				dbg("Sending WSC-M1 for %s\n", ifs->ifname);
			} else {
				dbg("Skip sending WSC-M1 for %s. Already configured\n",
				    ifs->ifname);
			}
		}
	}

	((struct i1905_private *)priv)->start_apconfig = 0;

	return ret;
}

int i1905_handle_ap_autoconfig_renew(const char *ifname, uint8_t *from,
				     struct cmdu_buff *rxf, void *priv,
				     void *cookie)
{
	struct tlv_supported_band *freq;
	uint8_t aladdr_origin[6] = {0};
	struct i1905_interface *iface;
	struct i1905_selfdevice *self;
	struct i1905_interface *ifs;
	struct tlv *tv[3][16];
	int ret;



	trace("%s -------------->\n", __func__);

	iface = i1905_ifname_to_interface(priv, ifname);
	if (!iface) {
		fprintf(stderr, "Error! ifname_to_interface(%s)\n", ifname);
		return -1;
	}

	if (hwaddr_equal(from, iface->aladdr)) {
		fprintf(stderr, "Discard ap-autoconfig renew from localhost\n");
		return 0;
	}

	self = (struct i1905_selfdevice *)iface->device;

	ret = i1905_cmdu_parse_tlvs(rxf, tv, 3);
	if (ret)
		return -1;

	if (!tv[0][0] || !tv[1][0] || !tv[2][0])
		return -1;

	//TODO: ignore this renew if not from the already established registrar

	memcpy(aladdr_origin, tv[0][0]->data, tlv_length(tv[0][0]));
	if (hwaddr_is_zero(aladdr_origin)) {
		dbg("%s: Discard ap-autoconfig renew from aladdr = 0!\n",
		    __func__);

		return -1;
	}

	/* relay mcast the received cmdu */
	ret = i1905_relay_cmdu(priv, ifname, MCAST_1905, rxf->origin,
			       ETHERTYPE_1905, rxf);
	if (ret)
		fprintf(stderr, "Error relaying AP_AUTOCONFIG_RENEW\n");


	//TODO: processed by extensions; use meaningful flag
	if (rxf->flags == 1)
		return 0;


	if (tv[1][0]->data[0] != IEEE80211_ROLE_REGISTRAR) {
		fprintf(stderr,
			"%s: Discard ap-autoconfig renew for role != registrar\n",
			__func__);
		return -1;
	}

	freq = (struct tlv_supported_band *)tv[2][0]->data;
	if (freq->band > IEEE80211_FREQUENCY_BAND_60_GHZ) {
		fprintf(stderr,
			"%s: Discard ap-autoconfig renew for invalid WiFi band\n",
			__func__);
		return -1;
	}

	list_for_each_entry(ifs, &self->iflist, list) {
		if (IS_MEDIA_WIFI(ifs->media)) {
			//TODO: check band in supported-bands
			ret = i1905_send_ap_autoconfig_wsc_m1(iface->priv, ifs->priv, from); //FIXME priv
			if (ret) {
				fprintf(stderr, "Error sending AP_AUTOCONFIG_WSC_M1\n");
				break;
			}
		}
	}

	return ret;
}

static int i1905_wsc_process_m1(struct i1905_interface_private *pif,
				uint8_t *msg, uint16_t msglen, uint16_t mid,
				uint8_t *from)
{
	struct i1905_private *priv = pif->i1905private;
	struct wps_credential cred = {0};
	uint16_t attrlen = 1;
	uint8_t band = 0;
	int ret;


	ret = wsc_msg_get_attr(msg, msglen, ATTR_RF_BANDS, &band, &attrlen);
	if (ret) {
		fprintf(stderr, "Error getting band from wsc msg\n");
		return ret;
	}

	ret = i1905_get_apsettings_for_band(priv, band, &cred);
	if (ret) {
		fprintf(stderr, "No registrar config for band %u found\n", band);
		return -1;
	}

	ret = i1905_send_ap_autoconfig_wsc_m2(pif, &cred, mid, from, msg, msglen);

	return ret;
}

static int i1905_wsc_process_m2(struct i1905_interface_private *pif,
				uint8_t *msg, uint16_t msglen, uint16_t mid,
				uint8_t *from, void *cookie)
{
	struct i1905_private *priv = (struct i1905_private *)pif->i1905private;
	struct i1905_interface *iface = i1905_interface_priv(pif);
	struct i1905_interface_private *ifpriv;
	struct i1905_interface_private_wsc *wsc;
	struct wps_credential out = {0};
	struct i1905_apconfig ap = {0};
	struct i1905_interface *ifwsc;
	char *ifname = cookie;
	int ret;


	trace("%s: Process M2. ingress ifname = %s (cookie = %s)\n",
	      __func__, iface->ifname, ifname);

	if (!cookie) {
		dbg("cookie = NULL! Valid cookie expected for WSC-M2\n");
		return 0;
	}


	ifwsc = i1905_ifname_to_interface(priv, ifname);
	if (!ifwsc) {
		dbg("Failed to match interface cookie '%s'\n", ifname);
		return -1;
	}

	ifpriv = ifwsc->priv;
	wsc = ifpriv->wsc;
	if (!wsc) {
		err("%s: wsc = NULL! Unexpected error!\n", __func__);
		return -1;
	}

	ret = wsc_process_m2(wsc->last_msg, wsc->last_msglen, wsc->key, msg, msglen, &out, NULL, 0);
	if (ret) {
		dbg("Error processing WSC M2 for '%s'\n", ifwsc->ifname);
		return ret;
	}

	/* set interface to configured */
	ifpriv->configured = true;

#if 1	// TESTING
	fprintf(stderr, "####################################################\n");
	fprintf(stderr, "Ssid : %s   (len = %zu)\n", out.ssid, out.ssidlen);
	fprintf(stderr, "Key  : %s   (len = %zu)\n", out.key, out.keylen);
	fprintf(stderr, "Band : %d\n", wsc->cred.band == WPS_RF_24GHZ ? 2 : 5);
	fprintf(stderr, "####################################################\n");
#endif

	/* prepare ap settings and update config */
	memcpy(ap.ssid, out.ssid, out.ssidlen);
	ap.ssidlen = out.ssidlen;
	ap.auth_type = out.auth_type;
	ap.enc_type = out.enc_type;
	memcpy(ap.key, out.key, out.keylen);
	ap.keylen = out.keylen;
	ap.band = wsc->cred.band == WPS_RF_24GHZ ?
			IEEE80211_FREQUENCY_BAND_2_4_GHZ :
			IEEE80211_FREQUENCY_BAND_5_GHZ;

	i1905_config_update_ap(&priv->cfg, &ap);

	return 0;
}

int i1905_handle_ap_autoconfig_wsc(const char *ifname, uint8_t *from,
				   struct cmdu_buff *rxf, void *priv,
				   void *cookie)
{
	struct i1905_interface *iface;
	struct tlv *tv[1][16];
	uint8_t wsc_msgtype;
	uint16_t msglen;
	uint8_t *msg;
	uint16_t mid;
	int ret = 0;
	void *m1_cookie = NULL;
	struct i1905_private *p = (struct i1905_private *)priv;



	//TODO: processed by extensions; use meaningful flag
	if (rxf->flags == 1)
		return 0;


	trace("%s -------------->\n", __func__);

	iface = i1905_ifname_to_interface(priv, ifname);
	if (!iface) {
		fprintf(stderr, "Error! ifname_to_interface(%s)\n", ifname);
		return -1;
	}

	ret = i1905_cmdu_parse_tlvs(rxf, tv, 1);
	if (ret)
		return -1;

	if (!tv[0][0])
		return -1;

	msg = tv[0][0]->data;
	msglen = tlv_length(tv[0][0]);

	mid = cmdu_get_mid(rxf);

	bufprintf(msg, msglen, "Received M1 Buffer");

	wsc_msgtype = wsc_get_message_type(msg, msglen);
	switch (wsc_msgtype) {
	case WPS_M1:
		fprintf(stderr, "Received WPS M1\n");
		ret = i1905_wsc_process_m1(iface->priv, msg, msglen, mid, from);
		break;
	case WPS_M2:
		fprintf(stderr, "Received WPS M2\n");

		ret = cmdu_ackq_dequeue(&p->txack_q,
					CMDU_TYPE_AP_AUTOCONFIGURATION_WSC,
					mid, from, &m1_cookie);
		if (!ret && m1_cookie) {
			ret = i1905_wsc_process_m2(iface->priv, msg, msglen,
						   mid, from, m1_cookie);
			free(m1_cookie);
		} else {
			fprintf(stderr,
				"%s: drop unexpected WSC-M2 CMDU (mid = %d)\n",
				__func__, mid);
			return -1;
		}
		break;
	default:
		fprintf(stderr, "Received WPS msgtype %u\n", wsc_msgtype);
		return -1;
	}

	return ret;
}


int i1905_handle_pbc_notification(const char *ifname, uint8_t *from,
				  struct cmdu_buff *rxf, void *priv,
				  void *cookie)
{
	struct tlv *tv[2][16];
	uint8_t aladdr_origin[6] = {0};
	struct tlv_pbc_notification *pbc;
	struct i1905_selfdevice *self;
	struct i1905_interface *iface, *ifs;
	bool has_wifi_info = false;
	int ret;
	int i;


	ret = i1905_cmdu_parse_tlvs(rxf, tv, 2);
	if (ret)
		return -1;

	if (!tv[0][0] || !tv[1][0])
		return -1;


	memcpy(aladdr_origin, tv[0][0]->data, tlv_length(tv[0][0]));
	if (hwaddr_is_zero(aladdr_origin)) {
		fprintf(stderr,
			"%s: Discard PBC event from aladdr = 0!\n",
			__func__);

		return -1;
	}

	pbc = (struct tlv_pbc_notification *)tv[1][0]->data;
	for (i = 0; i < pbc->num_media; i++) {
		if (IS_MEDIA_WIFI(pbc->media[i].type)) {
			has_wifi_info = true;
			break;
		}
	}

	iface = i1905_ifname_to_interface(priv, ifname);
	if (!iface) {
		fprintf(stderr, "Error! ifname_to_interface(%s)\n", ifname);
		return -1;
	}

	if (hwaddr_equal(from, iface->aladdr)) {
		fprintf(stderr, "Discard pbc notification from localhost\n");
		return 0;
	}

	self = (struct i1905_selfdevice *)iface->device;

	list_for_each_entry(ifs, &self->iflist, list) {
		//TODO: power up interface if down
	}

	list_for_each_entry(ifs, &self->iflist, list) {
		if (strncmp(ifs->ifname, ifname, 16) && ifs->authenticated) {
			/* relay the notification */
			ret = i1905_send_cmdu(ifs->priv, ifs->vid, MCAST_1905, ifs->aladdr,
					      ETHERTYPE_1905, rxf);
			if (ret)
				dbg("%s: err sending PBC notification\n", ifs->ifname);
		}

		if (!ifs->pbc_supported)
			continue;

		if (IS_MEDIA_WIFI(ifs->media)) {
			struct ieee80211_info *wifi =
				(struct ieee80211_info *)ifs->mediainfo;

			if (wifi->role != IEEE80211_ROLE_AP)
				continue;

			if (wifi->role == IEEE80211_ROLE_AP && !ifs->is_registrar)
				continue;

			if (has_wifi_info)
				continue;
		}

		//TODO: platform_start_pbc(ifs->ifname);
	}

	return 0;
}

int i1905_handle_pbc_join_notification(const char *ifname, uint8_t *from,
				       struct cmdu_buff *rxf, void *priv,
				       void *cookie)
{
	struct tlv *tv[2][16];
	uint8_t aladdr_origin[6] = {0};
	struct tlv_pbc_join_notification *join;
	int ret;
	//struct i1905_selfdevice *self;
	//struct i1905_interface *ifs;


	ret = i1905_cmdu_parse_tlvs(rxf, tv, 2);
	if (ret)
		return -1;

	if (!tv[0][0] || !tv[1][0])
		return -1;


	memcpy(aladdr_origin, tv[0][0]->data, tlv_length(tv[0][0]));
	if (hwaddr_is_zero(aladdr_origin)) {
		fprintf(stderr,
			"%s: Discard PBC event from aladdr = 0!\n",
			__func__);

		return -1;
	}

	join = (struct tlv_pbc_join_notification *)tv[1][0]->data;

	//TODO TODO

	UNUSED(join);

	return 0;
}

int i1905_handle_higherlayer_query(const char *ifname, uint8_t *from,
				   struct cmdu_buff *rxf, void *priv,
				   void *cookie)
{
	struct i1905_interface *iface;


	//TODO: processed by extensions; use meaningful flag
	if (rxf->flags == 1)
		return 0;


	trace("%s -------------->\n", __func__);

	iface = i1905_ifname_to_interface(priv, ifname);
	if (!iface) {
		fprintf(stderr, "Error! ifname_to_interface(%s)\n", ifname);
		return -1;
	}

	return i1905_send_higherlayer_response(iface, from, cmdu_get_mid(rxf));
}


int i1905_handle_higherlayer_response(const char *ifname, uint8_t *from,
				      struct cmdu_buff *rxf, void *priv,
				      void *cookie)
{
	struct tlv *tv[6][16];
	uint8_t aladdr_origin[6] = {0};
	struct tlv_1905_profile *profile;
	struct i1905_interface *iface;
	int ret;


	trace("%s -------------->\n", __func__);

	ret = i1905_cmdu_parse_tlvs(rxf, tv, 6);
	if (ret)
		return -1;

	if (!tv[0][0] || !tv[1][0] || !tv[2][0])
		return -1;


	memcpy(aladdr_origin, tv[0][0]->data, tlv_length(tv[0][0]));
	if (hwaddr_is_zero(aladdr_origin)) {
		fprintf(stderr,
			"%s: Discard higherlayer response from aladdr = 0!\n",
			__func__);

		return -1;
	}

	profile = (struct tlv_1905_profile *)tv[1][0]->data;
	if (profile->version != PROFILE_1905_1 &&
	    profile->version != PROFILE_1905_1A) {

		fprintf(stderr,
			"%s: Discard higherlayer response (invalid profile)!\n",
				__func__);
		return -1;
	}

	iface = i1905_ifname_to_interface(priv, ifname);
	if (!iface) {
		fprintf(stderr, "Error! ifname_to_interface(%s)\n", ifname);
		return -1;
	}

	if (hwaddr_equal(from, iface->aladdr)) {
		fprintf(stderr, "Discard higher-layer response from localhost\n");
		return 0;
	}

	ret = i1905_dm_neighbor_update(iface, aladdr_origin, tv[1][0]);
	ret |= i1905_dm_neighbor_update(iface, aladdr_origin, tv[2][0]);

	if (tv[3][0])
		ret |= i1905_dm_neighbor_update(iface, aladdr_origin, tv[3][0]);

	if (tv[4][0])
		ret |= i1905_dm_neighbor_update(iface, aladdr_origin, tv[4][0]);

	if (tv[5][0])
		ret |= i1905_dm_neighbor_update(iface, aladdr_origin, tv[5][0]);


	return ret;
}


int i1905_handle_interface_power_request(const char *ifname, uint8_t *from,
					 struct cmdu_buff *rxf, void *priv,
					 void *cookie)
{
	//TODO
	return 0;
}


int i1905_handle_interface_power_response(const char *ifname, uint8_t *from,
					  struct cmdu_buff *rxf, void *priv,
					  void *cookie)
{
	//TODO
	return 0;
}


int i1905_handle_generic_phy_query(const char *ifname, uint8_t *from,
				   struct cmdu_buff *rxf, void *priv,
				   void *cookie)
{
	//TODO
	return 0;
}


int i1905_handle_generic_phy_response(const char *ifname, uint8_t *from,
				      struct cmdu_buff *rxf, void *priv,
				      void *cookie)
{
	//TODO
	return 0;
}


typedef int (*cmdu_handler_t)(const char *ifname, uint8_t *from,
			      struct cmdu_buff *rxf, void *priv, void *cookie);

static const cmdu_handler_t i1905ftable[] = {
	[0x00] = i1905_handle_topology_discovery,
	[0x01] = i1905_handle_topology_notification,
	[0x02] = i1905_handle_topology_query,
	[0x03] = i1905_handle_topology_response,
	[0x04] = i1905_handle_vendor_request,
	[0x05] = i1905_handle_link_metric_query,
	[0x06] = i1905_handle_link_metric_response,
	[0x07] = i1905_handle_ap_autoconfig_search,
	[0x08] = i1905_handle_ap_autoconfig_response,
	[0x09] = i1905_handle_ap_autoconfig_wsc,
	[0x0a] = i1905_handle_ap_autoconfig_renew,
	[0x0b] = i1905_handle_pbc_notification,
	[0x0c] = i1905_handle_pbc_join_notification,
	[0x0d] = i1905_handle_higherlayer_query,
	[0x0e] = i1905_handle_higherlayer_response,
	[0x0f] = i1905_handle_interface_power_request,
	[0x10] = i1905_handle_interface_power_response,
	[0x11] = i1905_handle_generic_phy_query,
	[0x12] = i1905_handle_generic_phy_response,
};


int i1905_process_cmdu(struct i1905_private *priv, struct cmdu_buff *rxf)
{
	cmdu_res_t res = CMDU_NOP;
	void *cookie = NULL;
	uint16_t type, mid;
	uint8_t *src;
	int ret;


	if (!rxf->cdata) {
		cmdu_free(rxf);
		return -1;
	}

	type = cmdu_get_type(rxf);
	mid = cmdu_get_mid(rxf);
	src = cmdu_get_origin(rxf);

	/* update with origin's aladdr if available */
	if (rxf->dev_ifname[0] != '\0') {
		struct i1905_neighbor_interface *link = NULL;
		struct i1905_interface *iface = NULL;

		iface = i1905_ifname_to_interface(priv, rxf->dev_ifname);
		if (iface && src && !hwaddr_is_zero(src)) {
			/* assume src-macaddr of received cmdu same as
			 * sender's aladdr.
			 */
			memcpy(rxf->aladdr, src, 6);

			/* override with real aladdr of the sender if a
			 * valid link is found with this sender.
			 */
			link = i1905_link_neighbor_lookup(iface, src);
			if (link)
				memcpy(rxf->aladdr, link->aladdr, 6);
		}
	}


	dbg("%s: rx-ifname = %s, src = " MACFMT ", aladdr = " MACFMT " type = %s (mid = %hu)\n",
	    __func__, rxf->dev_ifname, MAC2STR(src), MAC2STR(rxf->aladdr), cmdu_type2str(type), mid);


	res = extmodule_maybe_process_cmdu(&priv->extlist, rxf);
	switch (res) {
	case CMDU_NOK:
		return -1;
	case CMDU_OK:
	case CMDU_DONE:
	case CMDU_DROP:
		rxf->flags = 1;
	default:
		break;
	}

	if (type >= CMDU_TYPE_1905_END) {
		dbg("%s: Unknown cmdu!\n", __func__);
		return -1;
	}

	if (rxf->flags == 0 && is_cmdu_type_response(type)) {
		/* discard responses with no matching request awaiting */
		ret = cmdu_ackq_dequeue(&priv->txack_q, type, mid, src, &cookie);
		if (ret) {
			dbg("%s: drop unexpected CMDU (mid = %d)\n",
			    __func__, mid);
			goto out;
		}
	}

	if (i1905ftable[type])
		ret = i1905ftable[type](rxf->dev_ifname, rxf->origin, rxf, priv, cookie);

out:
	if (cookie)
		free(cookie);

	return ret;
}

int i1905_process_lldp(struct i1905_private *priv, struct cmdu_buff *rxf)
{
	uint8_t *src;

	if (rxf->cdata)
		return -1;

	src = cmdu_get_origin(rxf);

	if (rxf->dev_ifname[0] != '\0') {
		struct i1905_neighbor_interface *link = NULL;
		struct i1905_interface *iface = NULL;

		iface = i1905_ifname_to_interface(priv, rxf->dev_ifname);
		if (iface && src && !hwaddr_is_zero(src)) {
			link = i1905_link_neighbor_lookup(iface, src);
			if (link)
				link->has_bridge = false;
		}

		/* TODO: lldp received with macaddress in PortID-tlv different
		 * than 'link->macaddress' - link has bridge in-between.
		 */
	}

	return 0;
}
