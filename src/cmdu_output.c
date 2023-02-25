/*
 * cmdu_output.c - handle CMDUs for transmit
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


int i1905_send_bridge_discovery(struct i1905_interface *iface)
{
	struct cmdu_buff *frm = NULL;
	uint8_t *lldpbuf;
	int ret = 0;



	trace("%s: [%s] Send BRIDGE DISCOVERY to " MACFMT "\n", __func__,
	      iface->ifname, MAC2STR(MCAST_LLDP));

	frm = cmdu_alloc_default();
	if (!frm) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return -1;
	}

	frm->data = (uint8_t *)(frm->head + 18);
	frm->tail = frm->data;

	/* lldp tlvs are not compatible with 1905's.
	 * So, the same struct tlv cannot be used here.
	 */
	lldpbuf = calloc(1, 256 * sizeof(uint8_t));
	if (!lldpbuf) {
		cmdu_free(frm);
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return -1;
	}

	lldpbuf[0] = (LLDP_TLV_CHASSIS_ID << 1) | ((7 & 0x80) >> 7);
	lldpbuf[1] = 7 & 0x7f;
	lldpbuf[2] = LLDP_CHASSIS_ID_SUBTYPE_MAC_ADDRESS;
	memcpy(&lldpbuf[3], iface->aladdr, 6);

	ret = cmdu_put(frm, lldpbuf, 9);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put()\n", __func__);
		cmdu_free(frm);
		free(lldpbuf);
		return -1;
	}

	memset(lldpbuf, 0, 256);
	lldpbuf[0] = (LLDP_TLV_PORT_ID << 1) | ((7 & 0x80) >> 7);
	lldpbuf[1] = 7 & 0x7f;
	lldpbuf[2] = LLDP_PORT_ID_SUBTYPE_MAC_ADDRESS;
	memcpy(&lldpbuf[3], iface->macaddr, 6);

	ret = cmdu_put(frm, lldpbuf, 9);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put()\n", __func__);
		cmdu_free(frm);
		free(lldpbuf);
		return -1;
	}

	memset(lldpbuf, 0, 256);
	lldpbuf[0] = (LLDP_TLV_TTL << 1) | ((2 & 0x80) >> 7);
	lldpbuf[1] = 2 & 0x7f;
	buf_put_be16(&lldpbuf[2], LLDP_TTL_1905_DEFAULT_VALUE);

	ret = cmdu_put(frm, lldpbuf, 4);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put()\n", __func__);
		cmdu_free(frm);
		free(lldpbuf);
		return -1;
	}

	ret = i1905_send_cmdu(iface->priv, iface->vid, MCAST_LLDP, iface->aladdr,
			      ETHERTYPE_LLDP, frm);
	if (ret) {
		fprintf(stderr, "Error sending BRIDGE DISCOVERY\n");
	}

	free(lldpbuf);
	cmdu_free(frm);

	return 0;
}

struct cmdu_buff *i1905_build_topology_discovery(struct i1905_interface *iface)
{
	struct cmdu_buff *frm = NULL;
	struct tlv *t;
	int ret = 0;
	uint16_t mid = 0x1111;	/* dummy */



	//trace("%s: Build TOPOLOGY DISCOVERY\n", __func__);

	frm = cmdu_alloc_simple(CMDU_TYPE_TOPOLOGY_DISCOVERY, &mid);
	if (!frm) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	/* prepare TLVs */
	t = cmdu_reserve_tlv(frm, 6);
	if (!t) {
		cmdu_free(frm);
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	t->type = TLV_TYPE_AL_MAC_ADDRESS_TYPE;
	t->len = 6;
	memcpy(t->data, iface->aladdr, 6);
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(frm);
		return NULL;
	}

	t = cmdu_reserve_tlv(frm, 6);
	if (!t) {
		cmdu_free(frm);
		return NULL;
	}

	t->type = TLV_TYPE_MAC_ADDRESS_TYPE;
	t->len = 6;
	if (!hwaddr_is_zero(iface->macaddr))
		memcpy(t->data, iface->macaddr, 6);
	else
		memcpy(t->data, iface->aladdr, 6);	/* 'lo' interface has macaddr = 0 */

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(frm);
		return NULL;
	}

	cmdu_put_eom(frm);

	return frm;
}

int i1905_send_topology_discovery(struct i1905_interface *iface)
{
	struct cmdu_buff *frm = NULL;
	int ret = 0;


	trace("%s: [%s] Send TOPOLOGY DISCOVERY to " MACFMT "\n", __func__,
	      iface->ifname, MAC2STR(MCAST_1905));

	frm = i1905_build_topology_discovery(iface);
	if (!frm)
		return -1;

	cmdu_set_mid(frm, cmdu_get_next_mid());

	ret = i1905_send_cmdu(iface->priv, iface->vid, MCAST_1905, iface->aladdr,
			      ETHERTYPE_1905, frm);
	if (ret) {
		fprintf(stderr, "Error sending TOPOLOGY_DISCOVERY\n");
	}

	cmdu_free(frm);

	return 0;
}

int i1905_send_topology_query(struct i1905_interface *iface, uint8_t *dest)
{
	struct i1905_interface_private *ifpriv = iface->priv;
	struct cmdu_buff *frm = NULL;
	struct i1905_private *priv;
	uint16_t mid = 0;
	int ret = 0;


	if (!dest)
		return -1;


	trace("%s: [%s] Send TOPOLOGY_QUERY to " MACFMT "\n", __func__,
	      iface->ifname, MAC2STR(dest));

	frm = cmdu_alloc_simple(CMDU_TYPE_TOPOLOGY_QUERY, &mid);
	if (!frm) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return -1;
	}

	cmdu_put_eom(frm);

	ret = i1905_send_cmdu(iface->priv, iface->vid, dest, iface->aladdr,
			      ETHERTYPE_1905, frm);
	if (ret) {
		fprintf(stderr, "Error sending TOPOLOGY QUERY\n");
	}

	cmdu_free(frm);

	//TODO: move following to i1905_send_cmdu()
	if (ifpriv) {
		uint16_t resp_type;

		priv = (struct i1905_private *)ifpriv->i1905private;

		resp_type = cmdu_expect_response(CMDU_TYPE_TOPOLOGY_QUERY);
		if (resp_type != CMDU_TYPE_NONE) {
			cmdu_ackq_enqueue(&priv->txack_q, resp_type, mid, dest,
					  2 * CMDU_DEFAULT_TIMEOUT, 0, strdup(iface->ifname));
		}
	}

	return 0;
}

struct cmdu_buff *i1905_build_topology_response(struct i1905_interface *iface)
{
	struct i1905_selfdevice *self = (struct i1905_selfdevice *)iface->device;
	struct tlv_device_bridge_caps *brcaps;
	struct tlv_non1905_neighbor *non1905;
	struct i1905_non1905_neighbor *nnbr;
	struct tlv_device_info *devinfo;
	struct tlv_1905neighbor *nbrs;
	struct i1905_interface *ifs;
	struct cmdu_buff *resp;

	struct i1905_neighbor_interface *nif;
	struct i1905_interface *lif;
	uint16_t mid = 0x1111;

	struct tlv *t;
	uint8_t *ptr;
	int ret = 0;
	int i = 0;
	int offset;



	resp = cmdu_alloc_simple(CMDU_TYPE_TOPOLOGY_RESPONSE, &mid);
	if (!resp) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	t = cmdu_reserve_tlv(resp, 256);
	if (!t) {
		cmdu_free(resp);
		return NULL;
	}

	t->type = TLV_TYPE_DEVICE_INFORMATION_TYPE;
	t->len = sizeof(*devinfo);
	devinfo = (struct tlv_device_info *)t->data;
	memcpy(devinfo->aladdr, iface->aladdr, 6);
	ptr = t->data;
	offset = sizeof(struct tlv_device_info);
	i = 0;

	list_for_each_entry(ifs, &self->iflist, list) {
		struct local_interface *liface;

		/* skip reporting for lo */
		if (ifs->lo || hwaddr_is_zero(ifs->macaddr))
			continue;

		ptr += offset;
		liface = (struct local_interface *)ptr;

		memcpy(liface->macaddr, ifs->macaddr, 6);
		BUF_PUT_BE16(liface->mediatype, ifs->media);
		if (IS_MEDIA_WIFI(ifs->media)) {
			liface->sizeof_mediainfo = sizeof(struct ieee80211_info);
#ifdef WIFI_EASYMESH
			if (ifs->media == I1905_802_11AX || ifs->media == I1905_802_11BE)
				liface->sizeof_mediainfo = 0;
#endif
		} else
			liface->sizeof_mediainfo = 0;

		if (liface->sizeof_mediainfo && ifs->mediainfo) {
			memcpy(liface->mediainfo,
			       ifs->mediainfo,
			       liface->sizeof_mediainfo);
		}

		offset = sizeof(struct local_interface) + liface->sizeof_mediainfo;
		t->len += offset;
		i++;
	}
	devinfo->num_interface = i;

	dbg7("%s: TOPOLOGY_RESPONSE num-interfaces = %d\n", __func__,
	     devinfo->num_interface);

	ret = cmdu_put_tlv(resp, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(resp);
		return NULL;
	}

	/* append bridge-caps */
	do {
		if (iface->is_brif) {
			int bridx;


			dbg7("%s: Adding br-tuples\n", __func__);
			t = cmdu_reserve_tlv(resp, 128);
			if (!t) {
				cmdu_free(resp);
				return NULL;
			}

			bridx = if_isbridge_interface(iface->ifname);
			if (bridx > 0) {
				char brname[16] = {0};
				char brifs[32][16] = {0};
				int n = 32;
				struct device_bridge_tuple *tuple;


				if_indextoname(bridx, brname);
				ret = br_get_iflist(brname, &n, brifs);
				if (ret)
					break;

				t->type = TLV_TYPE_DEVICE_BRIDGING_CAPABILITIES;
				t->len = sizeof(*brcaps) + sizeof(*tuple);
				brcaps = (struct tlv_device_bridge_caps *)t->data;
				brcaps->num_tuples = 1;
				tuple = brcaps->tuple;
				tuple->num_macaddrs = n;
				for (i = 0; i < n; i++) {
					uint8_t macaddr[6] = {0};

					if_gethwaddr(brifs[i], macaddr);
					memcpy(tuple->addr[i].macaddr, macaddr, 6);
					t->len += 6;
				}
				ret = cmdu_put_tlv(resp, t);
				if (ret) {
					fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
					cmdu_free(resp);
					return NULL;
				}
			}
		}
	} while (0);


	/* append non-1905 neighbors */
	list_for_each_entry(lif, &self->iflist, list) {
		int rem = 256;

		if (lif->upstream)
			continue;

		if (list_empty(&lif->non1905_nbrlist))
			continue;

		/* skip reporting for lo */
		if (lif->lo || hwaddr_is_zero(lif->macaddr))
			continue;

		dbg7("%s: Adding non-1905nbr for iface %s (" MACFMT ")\n", __func__,
		     lif->ifname, MAC2STR(lif->macaddr));

		t = cmdu_reserve_tlv(resp, rem);
		if (!t) {
			cmdu_free(resp);
			return NULL;
		}

		t->type = TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST;
		t->len = sizeof(*non1905);
		non1905 = (struct tlv_non1905_neighbor *)t->data;
		memcpy(non1905->local_macaddr, lif->macaddr, 6);
		i = 0;
		rem -= 6;

		list_for_each_entry(nnbr, &lif->non1905_nbrlist, list) {
			struct non1905_neighbor *non = &non1905->non1905_nbr[i++];

			if (rem >= sizeof(*non)) {
				t->len += sizeof(*non);
				memcpy(non->macaddr, nnbr->macaddr, 6);
				dbg7(MACFMT"\n", MAC2STR(non->macaddr));
				rem -= sizeof(*non);
			}
		}

		ret = cmdu_put_tlv(resp, t);
		if (ret) {
			fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
			cmdu_free(resp);
			return NULL;
		}
	}

	/* append 1905 neighbors */
	list_for_each_entry(lif, &self->iflist, list) {
		bool has_neighbor = false;
		int rem = 256;


		/* skip reporting for lo */
		if (lif->lo || hwaddr_is_zero(lif->macaddr))
			continue;

		list_for_each_entry(nif, &lif->nbriflist, list) {
			if (nif->direct) {
				has_neighbor = true;
				break;
			}
		}

		if (!has_neighbor)
			continue;

		dbg7("%s: Adding 1905nbr for iface %s (" MACFMT ")\n", __func__,
		     lif->ifname, MAC2STR(lif->macaddr));

		t = cmdu_reserve_tlv(resp, rem);
		if (!t) {
			cmdu_free(resp);
			return NULL;
		}

		t->type = TLV_TYPE_NEIGHBOR_DEVICE_LIST;
		t->len = sizeof(*nbrs);
		nbrs = (struct tlv_1905neighbor *)t->data;
		memcpy(nbrs->local_macaddr, lif->macaddr, 6);
		i = 0;
		rem -= 6;

		list_for_each_entry(nif, &lif->nbriflist, list) {
			struct i1905_neighbor *nbr = &nbrs->nbr[i];

			if (!nif->direct)
				continue;

			if (rem >= sizeof(*nbr)) {
				t->len += sizeof(*nbr);
				memcpy(nbr->aladdr, nif->aladdr, 6);
				nbr->has_bridge = nif->has_bridge ? 0x8 : 0;
				dbg7(MACFMT"\n", MAC2STR(nbr->aladdr));
				rem -= sizeof(*nbr);
				i++;
			}
		}

		ret = cmdu_put_tlv(resp, t);
		if (ret) {
			fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
			cmdu_free(resp);
			return NULL;
		}
	}

	cmdu_put_eom(resp);

	return resp;
}

int i1905_send_topology_response(struct i1905_interface *iface,
				 uint8_t *dest, uint16_t mid)
{
	struct cmdu_buff *resp;
	int ret = 0;


	trace("%s: [%s] Send TOPOLOGY_RESPONSE to " MACFMT "\n", __func__,
	      iface->ifname, MAC2STR(dest));

	resp = i1905_build_topology_response(iface);
	if (!resp)
		return -1;

	cmdu_set_mid(resp, mid);


	ret = i1905_send_cmdu(iface->priv, iface->vid, dest, iface->aladdr,
			      ETHERTYPE_1905, resp);
	if (ret) {
		dbg("Error sending TOPOLOGY_RESPONSE\n");
	}

	cmdu_free(resp);

	return 0;
}

struct cmdu_buff *i1905_build_link_metric_query(struct i1905_interface *iface)
{
	struct tlv_linkmetric_query *lq;
	struct cmdu_buff *frm = NULL;
	uint16_t mid = 0x1111;
	struct tlv *t;
	int ret = 0;


	//trace("%s: Build LINK_METRIC_QUERY\n", __func__);

	frm = cmdu_alloc_simple(CMDU_TYPE_LINK_METRIC_QUERY, &mid);
	if (!frm) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	t = cmdu_reserve_tlv(frm, 256);
	if (!t) {
		cmdu_free(frm);
		return NULL;
	}

	t->type = TLV_TYPE_LINK_METRIC_QUERY;
	t->len = sizeof(*lq);
	lq = (struct tlv_linkmetric_query *)t->data;
	lq->nbr_type = LINKMETRIC_QUERY_NEIGHBOR_ALL;
	lq->query_type = LINKMETRIC_QUERY_TYPE_BOTH;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(frm);
		return NULL;
	}

	cmdu_put_eom(frm);

	return frm;
}

int i1905_send_link_metric_query(struct i1905_interface *iface, uint8_t *dest)
{
	struct i1905_interface_private *ifpriv = iface->priv;
	struct cmdu_buff *frm = NULL;
	struct i1905_private *priv;
	uint16_t mid = 0;
	int ret = 0;


	if (!dest)
		return -1;


	trace("%s: Send LINK_METRIC_QUERY to " MACFMT "\n", __func__,
	      MAC2STR(dest));

	frm = i1905_build_link_metric_query(iface);
	if (!frm)
		return -1;

	mid = cmdu_get_next_mid();
	cmdu_set_mid(frm, mid);

	ret = i1905_send_cmdu(iface->priv, iface->vid, dest, iface->aladdr,
			      ETHERTYPE_1905, frm);
	if (ret) {
		dbg("Error sending TOPOLOGY QUERY\n");
	}

	cmdu_free(frm);

	//TODO: move following to i1905_send_cmdu()
	if (ifpriv) {
		uint16_t resp_type;

		priv = (struct i1905_private *)ifpriv->i1905private;

		resp_type = cmdu_expect_response(CMDU_TYPE_LINK_METRIC_QUERY);
		if (resp_type != CMDU_TYPE_NONE) {
			cmdu_ackq_enqueue(&priv->txack_q, resp_type, mid, dest,
					  2 * CMDU_DEFAULT_TIMEOUT, 0,
					  strdup(iface->ifname));
		}
	}

	return 0;
}

struct cmdu_buff *i1905_build_link_metric_response(struct i1905_interface *iface,
						   uint8_t *neighbor,
						   uint8_t query_type)
{
	struct i1905_selfdevice *self = (struct i1905_selfdevice *)iface->device;
	struct i1905_device *rdev = NULL;
	bool forall_neighbors = false;
	struct cmdu_buff *resp;
	uint16_t mid = 0x1111;
	struct tlv *t;
	int ret;



	//trace("%s: Build LINK_METRIC_RESPONSE\n", __func__);

	resp = cmdu_alloc_simple(CMDU_TYPE_LINK_METRIC_RESPONSE, &mid);
	if (!resp) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	if (!neighbor || hwaddr_is_zero(neighbor))
		forall_neighbors = true;


	if (!forall_neighbors) {
		rdev = i1905_dm_neighbor_lookup(iface, neighbor);
		if (!rdev) {
			struct tlv_linkmetric_result *res;

			t = cmdu_reserve_tlv(resp, 4);
			if (!t) {
				cmdu_free(resp);
				return NULL;
			}

			t->type = TLV_TYPE_LINK_METRIC_RESULT_CODE;
			t->len = sizeof(*res);
			res = (struct tlv_linkmetric_result *)t->data;
			res->code = LINKMETRIC_RESULT_INVALID_NEIGHBOR;

			ret = cmdu_put_tlv(resp, t);
			if (ret) {
				fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
				cmdu_free(resp);
				return NULL;
			}

			goto out_build;
		}
	}


	if (query_type == LINKMETRIC_QUERY_TYPE_TX ||
		query_type == LINKMETRIC_QUERY_TYPE_BOTH) {

		list_for_each_entry(rdev, &self->topology.devlist, list) {
			struct i1905_neighbor_interface *nif;
			struct tlv_tx_linkmetric *txl;
			struct i1905_interface *lif;
			int i = 0;


			if (!forall_neighbors && memcmp(rdev->aladdr, neighbor, 6))
				continue;

			t = cmdu_reserve_tlv(resp, 256);
			if (!t) {
				cmdu_free(resp);
				return NULL;
			}

			t->type = TLV_TYPE_TRANSMITTER_LINK_METRIC;
			t->len = sizeof(*txl);
			txl = (struct tlv_tx_linkmetric *)t->data;

			memcpy(txl->aladdr, iface->aladdr, 6);
			memcpy(txl->neighbor_aladdr, rdev->aladdr, 6);

			list_for_each_entry(lif, &self->iflist, list) {
				/* skip reporting for lo */
				if (lif->lo || hwaddr_is_zero(lif->macaddr))
					continue;

				list_for_each_entry(nif, &lif->nbriflist, list) {
					struct tx_link_info *txlinfo;

					if (!nif->direct)
						continue;

					if (memcmp(nif->aladdr, rdev->aladdr, 6))
						continue;

					txlinfo = (struct tx_link_info *)&txl->link[i];

					memcpy(txlinfo->local_macaddr, lif->macaddr, 6);
					memcpy(txlinfo->neighbor_macaddr, nif->macaddr, 6);
					BUF_PUT_BE16(txlinfo->mediatype, nif->media);
					txlinfo->has_bridge = nif->has_bridge ? 1 : 0;
					BUF_PUT_BE32(txlinfo->errors, nif->metric.tx_errors);
					BUF_PUT_BE32(txlinfo->packets, nif->metric.tx_packets);
					BUF_PUT_BE16(txlinfo->max_throughput, nif->metric.max_rate);
					BUF_PUT_BE16(txlinfo->availability, nif->metric.available);
					BUF_PUT_BE16(txlinfo->phyrate, nif->metric.max_phyrate);
					t->len += sizeof(*txlinfo);
					i++;
				}
			}

			ret = cmdu_put_tlv(resp, t);
			if (ret) {
				fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
				cmdu_free(resp);
				return NULL;
			}
		}
	}


	if (query_type == LINKMETRIC_QUERY_TYPE_RX ||
		query_type == LINKMETRIC_QUERY_TYPE_BOTH) {

		list_for_each_entry(rdev, &self->topology.devlist, list) {
			struct i1905_neighbor_interface *nif;
			struct tlv_rx_linkmetric *rxl;
			struct i1905_interface *lif;
			int i = 0;


			if (!forall_neighbors && memcmp(rdev->aladdr, neighbor, 6))
				continue;


			t = cmdu_reserve_tlv(resp, 256);
			if (!t) {
				cmdu_free(resp);
				return NULL;
			}

			t->type = TLV_TYPE_RECEIVER_LINK_METRIC;
			t->len = sizeof(*rxl);
			rxl = (struct tlv_rx_linkmetric *)t->data;

			memcpy(rxl->aladdr, iface->aladdr, 6);
			memcpy(rxl->neighbor_aladdr, rdev->aladdr, 6);

			list_for_each_entry(lif, &self->iflist, list) {
				/* skip reporting for lo */
				if (lif->lo || hwaddr_is_zero(lif->macaddr))
					continue;

				list_for_each_entry(nif, &lif->nbriflist, list) {
					struct rx_link_info *rxlinfo;

					if (!nif->direct)
						continue;

					if (memcmp(nif->aladdr, rdev->aladdr, 6))
						continue;

					rxlinfo = (struct rx_link_info *)&rxl->link[i];

					memcpy(rxlinfo->local_macaddr, lif->macaddr, 6);
					memcpy(rxlinfo->neighbor_macaddr, nif->macaddr, 6);
					BUF_PUT_BE16(rxlinfo->mediatype, nif->media);
					BUF_PUT_BE32(rxlinfo->errors, nif->metric.rx_errors);
					BUF_PUT_BE32(rxlinfo->packets, nif->metric.rx_packets);
					if (IS_MEDIA_WIFI(nif->media))
						rxlinfo->rssi = nif->metric.rssi;
					else
						rxlinfo->rssi = 0xff;

					t->len += sizeof(*rxlinfo);
					i++;
				}
			}

			ret = cmdu_put_tlv(resp, t);
			if (ret) {
				fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
				cmdu_free(resp);
				return NULL;
			}
		}
	}


out_build:
	cmdu_put_eom(resp);

	return resp;
}

int i1905_send_link_metric_response(struct i1905_interface *iface,
				    uint8_t *dest, uint8_t *neighbor,
				    uint8_t query_type, uint16_t mid)
{
	struct cmdu_buff *resp;
	int ret;


	trace("%s: Send LINK_METRIC_RESPONSE to " MACFMT "\n", __func__,
	      MAC2STR(dest));

	resp = i1905_build_link_metric_response(iface, neighbor, query_type);
	if (!resp)
		return -1;

	cmdu_set_mid(resp, mid);
	ret = i1905_send_cmdu(iface->priv, iface->vid, dest, iface->aladdr, ETHERTYPE_1905, resp);
	if (ret) {
		dbg("Error sending LINK_METRIC_RESPONSE\n");
	}

	cmdu_free(resp);

	return ret;
}

struct cmdu_buff *i1905_build_topology_notification(struct i1905_interface *iface)
{
	struct cmdu_buff *frm = NULL;
	uint16_t mid = 0x1111;
	struct tlv *t;
	int ret = 0;


	//trace("%s: Build TOPOLOGY_NOTIFICATION\n", __func__);

	frm = cmdu_alloc_simple(CMDU_TYPE_TOPOLOGY_NOTIFICATION, &mid);
	if (!frm) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	t = cmdu_reserve_tlv(frm, 256);
	if (!t) {
		cmdu_free(frm);
		return NULL;
	}

	t->type = TLV_TYPE_AL_MAC_ADDRESS_TYPE;
	t->len = 6;
	memcpy(t->data, iface->aladdr, 6);

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(frm);
		return NULL;
	}

	cmdu_put_eom(frm);

	return frm;
}

int i1905_send_topology_notification(struct i1905_private *priv, const char *ifname)
{
	struct i1905_selfdevice *self;
	struct i1905_interface *iface;
	struct cmdu_buff *frm = NULL;
	uint16_t mid = 0;
	int ret = 0;


	if (!priv)
		return -1;


	fprintf(stderr, "%s: Send TOPOLOGY_NOTIFICATION to " MACFMT "\n", __func__,
		MAC2STR(MCAST_1905));

	self = &priv->dm.self;

	/* any interface to get aladdr from will work, so getting first interface */
	if (list_empty(&self->iflist))
		return -1;

	iface = list_first_entry(&self->iflist, struct i1905_interface, list);

	frm = i1905_build_topology_notification(iface);
	if (!frm)
		return -1;

	mid = cmdu_get_next_mid();
	cmdu_set_mid(frm, mid);

	CMDU_SET_RELAY_MCAST(frm->cdata);

	ret = i1905_send_cmdu_relay_mcast(priv, ifname, MCAST_1905, self->aladdr,
					  ETHERTYPE_1905, frm);
	if (ret) {
		fprintf(stderr, "Error sending TOPOLOGY_NOTIFICATION\n");
	}

	cmdu_free(frm);

	return 0;
}

struct cmdu_buff *i1905_build_ap_autoconfig_search(struct i1905_interface *iface,
						   uint8_t freqband)
{
	struct cmdu_buff *frm = NULL;
	uint16_t mid = 0x1111;
	struct tlv *t;
	int ret = 0;



	//trace("%s: Build AP_AUTOCONFIG_SEARCH\n", __func__);

	if (freqband > IEEE80211_FREQUENCY_BAND_60_GHZ) {
		err("Invalid band %u in ap-autoconfig\n", freqband);
		return NULL;
	}

	frm = cmdu_alloc_simple(CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH, &mid);
	if (!frm) {
		err("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	CMDU_SET_RELAY_MCAST(frm->cdata);


	t = cmdu_reserve_tlv(frm, 256);
	if (!t) {
		cmdu_free(frm);
		return NULL;
	}

	t->type = TLV_TYPE_AL_MAC_ADDRESS_TYPE;
	t->len = 6;
	memcpy(t->data, iface->aladdr, 6);

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(frm);
		return NULL;
	}

	t = cmdu_reserve_tlv(frm, 256);
	if (!t) {
		cmdu_free(frm);
		return NULL;
	}

	t->type = TLV_TYPE_SEARCHED_ROLE;
	t->len = 1;
	t->data[0] = 0x00;
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(frm);
		return NULL;
	}

	t = cmdu_reserve_tlv(frm, 256);
	if (!t) {
		cmdu_free(frm);
		return NULL;
	}

	t->type = TLV_TYPE_AUTOCONFIG_FREQ_BAND;
	t->len = 1;
	t->data[0] = freqband;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(frm);
		return NULL;
	}

	cmdu_put_eom(frm);

	return frm;
}

int i1905_send_ap_autoconfig_search(struct i1905_private *priv, uint8_t freqband)
{
	struct i1905_selfdevice *self;
	struct i1905_interface *ifs;
	uint16_t mid = 0;


	if (!priv)
		return -1;


	trace("%s: Send AP_AUTOCONFIG_SEARCH to " MACFMT "\n", __func__,
	      MAC2STR(MCAST_1905));

	if (freqband > IEEE80211_FREQUENCY_BAND_60_GHZ) {
		err("Invalid band %u in ap-autoconfig\n", freqband);
		return -1;
	}

	self = &priv->dm.self;

	list_for_each_entry(ifs, &self->iflist, list) {
		struct cmdu_buff *frm = NULL;
		int ret = 0;

		frm = i1905_build_ap_autoconfig_search(ifs, freqband);
		if (!frm)
			return -1;

		if (!mid)
			mid = cmdu_get_next_mid();

		cmdu_set_mid(frm, mid);
		loud("%s: ifname = %s\n", __func__, ifs->ifname);
		ret = i1905_send_cmdu(ifs->priv, ifs->vid, MCAST_1905, ifs->aladdr,
				      ETHERTYPE_1905, frm);
		if (ret) {
			dbg("Error sending AP_AUTOCONFIG_SEARCH\n");
		}

		cmdu_free(frm);
	}

	return 0;
}

struct cmdu_buff *i1905_build_ap_autoconfig_renew(struct i1905_interface *iface,
						  uint8_t freqband)
{
	struct cmdu_buff *frm = NULL;
	uint16_t mid = 0x1111;
	struct tlv *t;
	int ret = 0;



	//trace("%s: Build AP_AUTOCONFIG_RENEW\n", __func__);

	if (freqband > IEEE80211_FREQUENCY_BAND_60_GHZ) {
		err("Invalid band %u in ap-autoconf renew\n", freqband);
		return NULL;
	}


	frm = cmdu_alloc_simple(CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW, &mid);
	if (!frm) {
		err("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	CMDU_SET_RELAY_MCAST(frm->cdata);

	t = cmdu_reserve_tlv(frm, 256);
	if (!t) {
		cmdu_free(frm);
		return NULL;
	}

	t->type = TLV_TYPE_AL_MAC_ADDRESS_TYPE;
	t->len = 6;
	memcpy(t->data, iface->aladdr, 6);

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(frm);
		return NULL;
	}

	t = cmdu_reserve_tlv(frm, 256);
	if (!t) {
		cmdu_free(frm);
		return NULL;
	}


	t->type = TLV_TYPE_SUPPORTED_ROLE;
	t->len = 1;
	t->data[0] = 0x00;
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(frm);
		return NULL;
	}

	t = cmdu_reserve_tlv(frm, 256);
	if (!t) {
		cmdu_free(frm);
		return NULL;
	}


	t->type = TLV_TYPE_SUPPORTED_FREQ_BAND;
	t->len = 1;
	t->data[0] = freqband;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(frm);
		return NULL;
	}

	cmdu_put_eom(frm);

	return frm;
}

int i1905_send_ap_autoconfig_renew(struct i1905_private *priv, uint8_t freqband)
{
	struct i1905_selfdevice *self;
	struct i1905_interface *ifs;
	uint16_t mid = 0;


	if (!priv)
		return -1;

	trace("%s: Send AP_AUTOCONFIG_RENEW to " MACFMT "\n", __func__,
	      MAC2STR(MCAST_1905));

	if (freqband > IEEE80211_FREQUENCY_BAND_60_GHZ) {
		err("Invalid band %u in ap-autoconf renew\n", freqband);
		return -EINVAL;
	}

	self = &priv->dm.self;

	list_for_each_entry(ifs, &self->iflist, list) {
		struct cmdu_buff *frm = NULL;
		int ret = 0;

		frm = i1905_build_ap_autoconfig_renew(ifs, freqband);
		if (!frm)
			return -1;

		if (!mid)
			mid = cmdu_get_next_mid();

		cmdu_set_mid(frm, mid);
		ret = i1905_send_cmdu(ifs->priv, ifs->vid, MCAST_1905, ifs->aladdr,
				      ETHERTYPE_1905, frm);
		if (ret) {
			dbg("Error sending AP_AUTOCONFIG_RENEW\n");
		}

		cmdu_free(frm);
	}

	return 0;
}

struct cmdu_buff *i1905_build_ap_autoconfig_response(struct i1905_interface *iface,
						     uint8_t freqband)
{
	struct cmdu_buff *resp;
	uint16_t mid = 0x1111;
	struct tlv *t;
	int ret;


	//trace("%s: Build AP_AUTOCONFIG_RESPONSE\n", __func__);

	resp = cmdu_alloc_simple(CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE, &mid);
	if (!resp) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	t = cmdu_reserve_tlv(resp, 256);
	if (!t) {
		cmdu_free(resp);
		return NULL;
	}

	t->type = TLV_TYPE_SUPPORTED_ROLE;
	t->len = 1;
	t->data[0] = 0x00;
	ret = cmdu_put_tlv(resp, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(resp);
		return NULL;
	}

	t = cmdu_reserve_tlv(resp, 256);
	if (!t) {
		cmdu_free(resp);
		return NULL;
	}


	t->type = TLV_TYPE_SUPPORTED_FREQ_BAND;
	t->len = 1;
	t->data[0] = freqband;

	ret = cmdu_put_tlv(resp, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(resp);
		return NULL;
	}

	cmdu_put_eom(resp);

	return resp;
}

int i1905_send_ap_autoconfig_response(struct i1905_interface *iface,
				      uint8_t *dest, uint8_t band, uint16_t mid)
{
	struct cmdu_buff *resp;
	int ret;


	trace("%s: Send AP_AUTOCONFIG_RESPONSE to " MACFMT "\n", __func__,
	      MAC2STR(dest));

	resp = i1905_build_ap_autoconfig_response(iface, band);
	if (!resp)
		return -1;

	cmdu_set_mid(resp, mid);
	ret = i1905_send_cmdu(iface->priv, iface->vid, dest, iface->aladdr, ETHERTYPE_1905, resp);
	if (ret) {
		dbg("Error sending AP_AUTOCONFIG_RESPONSE\n");
	}

	cmdu_free(resp);

	return ret;
}

int i1905_send_ap_autoconfig_wsc_m1(struct i1905_interface_private *out_pif,
				    struct i1905_interface_private *pif,
				    uint8_t *dest)
{
	struct i1905_interface *iface = i1905_interface_priv(pif);
	struct i1905_interface *out_iface = i1905_interface_priv(out_pif);
	//struct i1905_selfdevice *self = (struct i1905_selfdevice *)iface->device;
	struct cmdu_buff *frm;
	struct tlv *t;
	int ret;

	uint8_t *m1;
	uint16_t m1_size = 0;
	void *key;
	uint16_t resp_type;
	uint16_t mid = 0;
	struct i1905_private *p = (struct i1905_private *)out_pif->i1905private;



	ret = wsc_build_m1(&pif->wsc->cred, &m1, &m1_size, &key);
	if (ret) {
		fprintf(stderr, "Failed to build WSC M1 frame!\n");
		return ret;
	}

	//TODO: improve wsc data and state -- maybe move to iface
	/* store wsc m1 context */
	if (pif->wsc) {
		if (pif->wsc->last_msg)
			free(pif->wsc->last_msg);

		if (pif->wsc->key)
			free(pif->wsc->key);

		pif->wsc->last_msg = m1;
		pif->wsc->last_msglen = m1_size;
		pif->wsc->key = key;
	}


	bufprintf(m1, m1_size, "WSC-M1");

	fprintf(stderr, "%s: Send WSC_M1 to " MACFMT "\n", __func__,
		MAC2STR(dest));

	frm = cmdu_alloc_simple(CMDU_TYPE_AP_AUTOCONFIGURATION_WSC, &mid);
	if (!frm) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return -1;
	}

	t = cmdu_reserve_tlv(frm, m1_size + 64);
	if (!t) {
		cmdu_free(frm);
		return -1;
	}

	t->type = TLV_TYPE_WSC;
	t->len = m1_size;
	memcpy(t->data, m1, m1_size);
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(frm);
		return -1;
	}

	cmdu_put_eom(frm);

	dbg("%s: out-ifname = %s    dest = " MACFMT "   mid = %hu\n", __func__,
	    out_iface->ifname, MAC2STR(dest), mid);

	ret = i1905_send_cmdu(out_pif, iface->vid, dest, iface->aladdr, ETHERTYPE_1905, frm);
	if (ret) {
		fprintf(stderr, "Error sending AP_AUTOCONFIG_WSC_M1\n");
	}

	cmdu_free(frm);

	//TODO: move following to i1905_send_cmdu()
	resp_type = cmdu_expect_response(CMDU_TYPE_AP_AUTOCONFIGURATION_WSC);
	if (resp_type != CMDU_TYPE_NONE) {
		cmdu_ackq_enqueue(&p->txack_q, resp_type, mid, dest,
				  5 * CMDU_DEFAULT_TIMEOUT, 0, strdup(iface->ifname));	//FIXME: timeout
	}

	return ret;
}

int i1905_send_ap_autoconfig_wsc_m2(struct i1905_interface_private *out_pif,
				    struct wps_credential *cred,
				    uint16_t mid, uint8_t *dest,
				    uint8_t *m1, uint16_t m1_size)
{
	struct i1905_interface *iface = i1905_interface_priv(out_pif);
	struct cmdu_buff *frm;
	uint16_t m2_size;
	struct tlv *t;
	uint8_t *m2;
	int ret;


	ret = wsc_build_m2(m1, m1_size, cred, NULL, 0, &m2, &m2_size);
	if (ret) {
		fprintf(stderr, "Error building WSC M2 for '%s'\n", iface->ifname);
		return ret;
	}

	fprintf(stderr, "%s: Send WSC_M2 to " MACFMT "\n", __func__,
		MAC2STR(dest));

	frm = cmdu_alloc_simple(CMDU_TYPE_AP_AUTOCONFIGURATION_WSC, &mid);
	if (!frm) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return -1;
	}

	t = cmdu_reserve_tlv(frm, m2_size + 64);
	if (!t) {
		cmdu_free(frm);
		return -1;
	}

	t->type = TLV_TYPE_WSC;
	t->len = m2_size;
	memcpy(t->data, m2, m2_size);
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(frm);
		return -1;
	}

	cmdu_put_eom(frm);

	dbg("%s: out-ifname = %s  dest = " MACFMT "\n", __func__, iface->ifname,
	    MAC2STR(dest));

	ret = i1905_send_cmdu(out_pif, iface->vid, dest, iface->aladdr, ETHERTYPE_1905, frm);
	if (ret) {
		fprintf(stderr, "Error sending AP_AUTOCONFIG_WSC_M2\n");
	}

	cmdu_free(frm);

	return ret;
}

int i1905_send_higherlayer_query(struct i1905_interface *iface, uint8_t *dest)
{
	struct i1905_interface_private *ifpriv = iface->priv;
	struct cmdu_buff *frm = NULL;
	struct i1905_private *priv;
	uint16_t mid = 0;
	int ret = 0;


	if (!dest)
		return -1;


	trace("%s: Send HIGHER_LAYER_QUERY to " MACFMT "\n", __func__,
	      MAC2STR(dest));

	frm = cmdu_alloc_simple(CMDU_TYPE_HIGHER_LAYER_QUERY, &mid);
	if (!frm) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return -1;
	}

	cmdu_put_eom(frm);

	ret = i1905_send_cmdu(iface->priv, iface->vid, dest, iface->aladdr,
			      ETHERTYPE_1905, frm);
	if (ret) {
		fprintf(stderr, "Error sending TOPOLOGY QUERY\n");
	}

	cmdu_free(frm);

	//TODO: move following to i1905_send_cmdu()
	if (ifpriv) {
		uint16_t resp_type;

		priv = (struct i1905_private *)ifpriv->i1905private;

		resp_type = cmdu_expect_response(CMDU_TYPE_HIGHER_LAYER_QUERY);
		if (resp_type != CMDU_TYPE_NONE) {
			cmdu_ackq_enqueue(&priv->txack_q, resp_type, mid, dest,
					  2 * CMDU_DEFAULT_TIMEOUT, 0, strdup(iface->ifname));
		}
	}

	return 0;
}

struct cmdu_buff *i1905_build_higher_layer_response(struct i1905_interface *iface)
{
	struct i1905_selfdevice *self = (struct i1905_selfdevice *)iface->device;
	struct tlv_device_identification *ident;
	struct i1905_master_interface *mif;
	struct i1905_interface *ifs;
	struct cmdu_buff *resp;
	uint16_t mid = 0x1111;
	struct tlv_ipv4 *ip4;
	struct tlv_ipv6 *ip6;
	struct tlv *t;
	uint8_t *ptr;
	int offset;
	int ret = 0;
	int i = 0;
	int j;



	trace("%s: Build HIGHER_LAYER_RESPONSE\n", __func__);

	resp = cmdu_alloc_simple(CMDU_TYPE_HIGHER_LAYER_RESPONSE, &mid);
	if (!resp) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	t = cmdu_reserve_tlv(resp, 256);
	if (!t) {
		cmdu_free(resp);
		return NULL;
	}

	t->type = TLV_TYPE_AL_MAC_ADDRESS_TYPE;
	t->len = 6;
	memcpy(t->data, iface->aladdr, 6);

	ret = cmdu_put_tlv(resp, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(resp);
		return NULL;
	}

	t = cmdu_reserve_tlv(resp, 256);
	if (!t) {
		cmdu_free(resp);
		return NULL;
	}
	t->type = TLV_TYPE_1905_PROFILE_VERSION;
	t->len = 1;
	if (self->version == I1905_VERSION_DOT_1A)
		t->data[0] = PROFILE_1905_1A;
	else
		t->data[0] = PROFILE_1905_1;

	ret = cmdu_put_tlv(resp, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(resp);
		return NULL;
	}

	t = cmdu_reserve_tlv(resp, 256);
	if (!t) {
		cmdu_free(resp);
		return NULL;
	}

	t->type = TLV_TYPE_DEVICE_IDENTIFICATION;
	t->len = sizeof(*ident);
	ident = (struct tlv_device_identification *)t->data;
	memcpy(ident->name, self->name, 64);
	memcpy(ident->manufacturer, self->manufacturer, 64);
	memcpy(ident->model, self->model, 64);

	ret = cmdu_put_tlv(resp, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(resp);
		return NULL;
	}


	if (self->url) {
		size_t url_len;

		url_len = strlen(self->url);
		t = cmdu_reserve_tlv(resp, url_len);
		if (!t) {
			cmdu_free(resp);
			return NULL;
		}
		t->type = TLV_TYPE_CONTROL_URL;
		t->len = url_len;
		memcpy(t->data, self->url, url_len);

		ret = cmdu_put_tlv(resp, t);
		if (ret) {
			fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
			cmdu_free(resp);
			return NULL;
		}
	}


	t = cmdu_reserve_tlv(resp, 384);
	if (!t) {
		cmdu_free(resp);
		return NULL;
	}

	t->type = TLV_TYPE_IPV4;
	ip4 = (struct tlv_ipv4 *)t->data;
	ptr = t->data;
	offset = sizeof(struct tlv_ipv4);
	t->len = offset;
	i = 0;

	list_for_each_entry(ifs, &self->iflist, list) {
		struct ipv4_interface *tif4;

		if (ifs->lo || ifs->num_ipaddrs == 0)
			continue;

		ptr += offset;
		tif4 = (struct ipv4_interface *)ptr;

		offset = sizeof(struct ipv4_interface);
		t->len += offset;

		memcpy(tif4->macaddr, ifs->macaddr, 6);
		tif4->num_ipv4 = 0;

		for (j = 0; j < ifs->num_ipaddrs; j++) {
			struct ipv4_entry *e;

			if (ifs->ipaddrs[j].family != AF_INET)
				continue;

			ptr += offset;
			e = (struct ipv4_entry *)ptr;
			e->type = IPV4_TYPE_UNKNOWN;
			memcpy(e->address, &ifs->ipaddrs[j].addr.ip4, 4);
			//e->dhcpserver =	//TODO
			tif4->num_ipv4 += 1;

			offset = sizeof(struct ipv4_entry);
			t->len += offset;
		}
		dbg("Interface: " MACFMT ", added %d ipv4 addresses\n",
		    MAC2STR(ifs->macaddr), tif4->num_ipv4);
		i++;
	}
	ip4->num_interfaces = i;

	/* consider ip addresses of master interfaces, if present */
	list_for_each_entry(mif, &self->miflist, list) {
		struct ipv4_interface *tif4;

		ptr += offset;
		tif4 = (struct ipv4_interface *)ptr;

		offset = sizeof(struct ipv4_interface);
		t->len += offset;

		memcpy(tif4->macaddr, mif->macaddr, 6);
		tif4->num_ipv4 = 0;

		for (j = 0; j < mif->num_ipaddrs; j++) {
			struct ipv4_entry *e;

			if (mif->ipaddrs[j].family != AF_INET)
				continue;

			ptr += offset;
			e = (struct ipv4_entry *)ptr;
			e->type = IPV4_TYPE_UNKNOWN;
			memcpy(e->address, &mif->ipaddrs[j].addr.ip4, 4);
			//e->dhcpserver =	//TODO
			tif4->num_ipv4 += 1;

			offset = sizeof(struct ipv4_entry);
			t->len += offset;
		}
		dbg("Interface: " MACFMT ", added %d ipv4 addresses\n",
		    MAC2STR(mif->macaddr), tif4->num_ipv4);
		i++;
	}
	ip4->num_interfaces = i;

	ret = cmdu_put_tlv(resp, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(resp);
		return NULL;
	}


	t = cmdu_reserve_tlv(resp, 256);
	if (!t) {
		cmdu_free(resp);
		return NULL;
	}

	t->type = TLV_TYPE_IPV6;
	ip6 = (struct tlv_ipv6 *)t->data;
	ptr = t->data;
	offset = sizeof(struct tlv_ipv6);
	t->len = offset;
	i = 0;

	list_for_each_entry(ifs, &self->iflist, list) {
		struct ipv6_interface *tif6;


		if (ifs->lo || ifs->num_ipaddrs == 0)
			continue;

		ptr += offset;
		tif6 = (struct ipv6_interface *)ptr;

		offset = sizeof(struct ipv6_interface);
		t->len += offset;

		memcpy(tif6->macaddr, ifs->macaddr, 6);
		tif6->num_ipv6 = 0;

		for (j = 0; j < ifs->num_ipaddrs; j++) {
			char buf[256] = {0};
			size_t sz = 256;
			struct ipv6_entry *e;


			if (ifs->ipaddrs[j].family != AF_INET6)
				continue;

			ptr += offset;
			e = (struct ipv6_entry *)ptr;

			//TODO: if address scope = local,
			//memcpy(tif6->link_local_address, ifs->macaddr, 6);
			e->type = IPV6_TYPE_UNKNOWN;
			memcpy(e->address, &ifs->ipaddrs[j].addr.ip6, 16);

			inet_ntop(AF_INET6, &ifs->ipaddrs[j].addr.ip6, buf, sz);
			dbg("adding ipv6 address: %s\n", buf);

			//e->origin =
			tif6->num_ipv6 += 1;

			offset = sizeof(struct ipv6_entry);
			t->len += offset;
		}

		dbg("Interface: " MACFMT ", added %d ipv6 addresses\n",
		    MAC2STR(ifs->macaddr), tif6->num_ipv6);
		i++;
	}
	ip6->num_interfaces = i;

	ret = cmdu_put_tlv(resp, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(resp);
		return NULL;
	}

	cmdu_put_eom(resp);

	return resp;
}

int i1905_send_higherlayer_response(struct i1905_interface *iface,
				    uint8_t *dest, uint16_t mid)
{
	struct cmdu_buff *resp;
	int ret = 0;


	trace("%s: Send HIGHER_LAYER_RESPONSE to " MACFMT "\n", __func__,
	      MAC2STR(dest));

	resp = i1905_build_higher_layer_response(iface);
	if (!resp)
		return -1;

	cmdu_set_mid(resp, mid);
	ret = i1905_send_cmdu(iface->priv, iface->vid, dest, iface->aladdr,
			      ETHERTYPE_1905, resp);
	if (ret) {
		dbg("Error sending HIGHER_LAYER_RESPONSE\n");
	}

	cmdu_free(resp);

	return ret;
}

int i1905_send_pbc_event_notification(struct i1905_private *priv, uint8_t num_media,
				      uint16_t type[], void *info[])
{
	struct i1905_selfdevice *self;
	struct i1905_interface *ifs;



	fprintf(stderr, "%s: Send PBC_EVENT_NOTIFICATION to " MACFMT "\n", __func__,
		MAC2STR(MCAST_1905));

	if (!priv)
		return -1;

	self = &priv->dm.self;
	list_for_each_entry(ifs, &self->iflist, list) {
		struct cmdu_buff *frm = NULL;
		struct tlv_pbc_notification *pbc;
		struct tlv *t;
		int ret = 0;
		uint16_t mid = 0;
		int i;


		frm = cmdu_alloc_simple(CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION, &mid);
		if (!frm) {
			fprintf(stderr, "%s: -ENOMEM\n", __func__);
			return -1;
		}

		CMDU_SET_RELAY_MCAST(frm->cdata);


		t = cmdu_reserve_tlv(frm, 256);
		if (!t) {
			cmdu_free(frm);
			return -1;
		}

		t->type = TLV_TYPE_AL_MAC_ADDRESS_TYPE;
		t->len = 6;
		memcpy(t->data, ifs->aladdr, 6);

		ret = cmdu_put_tlv(frm, t);
		if (ret) {
			fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
			cmdu_free(frm);
			return -1;
		}

		t = cmdu_reserve_tlv(frm, 256);
		if (!t) {
			cmdu_free(frm);
			return -1;
		}

		t->type = TLV_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION;
		t->len = sizeof(*pbc);
		pbc = (struct tlv_pbc_notification *)t->data;
		pbc->num_media = num_media;
		for (i = 0; i < num_media; i++) {
			BUF_PUT_BE16(pbc->media[i].type, type[i]);

			if (IS_MEDIA_WIFI(pbc->media[i].type)) {
				pbc->media[i].sizeof_info = sizeof(struct ieee80211_info);
				memcpy(pbc->media[i].info, info[i], pbc->media[i].sizeof_info);
			} else if (IS_MEDIA_1901(pbc->media[i].type)) {
				pbc->media[i].sizeof_info = sizeof(struct ieee1901_info);
				memcpy(pbc->media[i].info, info[i], pbc->media[i].sizeof_info);
			}
		}

		ret = cmdu_put_tlv(frm, t);
		if (ret) {
			fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
			cmdu_free(frm);
			return -1;
		}

		cmdu_put_eom(frm);

		fprintf(stderr, "%s:%d: ifname = %s\n", __func__, __LINE__, ifs->ifname);
		ret = i1905_send_cmdu(ifs->priv, ifs->vid, MCAST_1905, ifs->aladdr,
				      ETHERTYPE_1905, frm);
		if (ret) {
			fprintf(stderr, "Error sending PBC_EVENT_NOTIFICATION\n");
		}

		cmdu_free(frm);
	}

	return 0;
}

int i1905_send_pbc_join_notification(struct i1905_private *priv, uint8_t *macaddr,
				     uint8_t *new_macaddr)
{
	struct i1905_selfdevice *self;
	struct i1905_interface *ifs;


	if (!priv)
		return -1;


	fprintf(stderr, "%s: Send PBC_JOIN_NOTIFICATION to " MACFMT "\n", __func__,
		MAC2STR(MCAST_1905));

	self = &priv->dm.self;
	list_for_each_entry(ifs, &self->iflist, list) {
		struct cmdu_buff *frm = NULL;
		struct tlv_pbc_join_notification *join;
		struct tlv *t;
		int ret = 0;
		uint16_t mid = 0;


		frm = cmdu_alloc_simple(CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION, &mid);
		if (!frm) {
			fprintf(stderr, "%s: -ENOMEM\n", __func__);
			return -1;
		}

		CMDU_SET_RELAY_MCAST(frm->cdata);


		t = cmdu_reserve_tlv(frm, 256);
		if (!t) {
			cmdu_free(frm);
			return -1;
		}

		t->type = TLV_TYPE_AL_MAC_ADDRESS_TYPE;
		t->len = 6;
		memcpy(t->data, ifs->aladdr, 6);

		ret = cmdu_put_tlv(frm, t);
		if (ret) {
			fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
			cmdu_free(frm);
			return -1;
		}

		t = cmdu_reserve_tlv(frm, 256);
		if (!t) {
			cmdu_free(frm);
			return -1;
		}

		t->type = TLV_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION;
		t->len = sizeof(*join);
		join = (struct tlv_pbc_join_notification *)t->data;
		memcpy(join->aladdr, ifs->aladdr, 6);
		BUF_PUT_BE16(join->mid, mid);
		memcpy(join->macaddr, macaddr, 6);
		memcpy(join->new_macaddr, new_macaddr, 6);
		ret = cmdu_put_tlv(frm, t);
		if (ret) {
			fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
			cmdu_free(frm);
			return -1;
		}

		cmdu_put_eom(frm);

		fprintf(stderr, "%s:%d: ifname = %s\n", __func__, __LINE__, ifs->ifname);
		ret = i1905_send_cmdu(ifs->priv, ifs->vid, MCAST_1905, ifs->aladdr,
				      ETHERTYPE_1905, frm);
		if (ret) {
			fprintf(stderr, "Error sending PBC_JOIN_NOTIFICATION\n");
		}

		cmdu_free(frm);
	}

	return 0;
}

struct cmdu_buff *i1905_build_vendor_specific(struct i1905_interface *iface,
					      int argc, char *argv[])
{
	struct cmdu_buff *frm = NULL;
	struct tlv *t;
	int ret = 0;
	uint16_t mid = 0x1111;	/* dummy */
	struct tlv_vendor_specific *vs;
	size_t datalen = 0;



	fprintf(stderr, "%s: Build VENDOR_SPECIFIC\n", __func__);

	if (argc > 2) {
		fprintf(stderr, "%s: -EINVAL\n", __func__);
		return NULL;
	}

	if (argv[0] && strlen(argv[0]) != 6) {
		fprintf(stderr, "%s: invalid OUI length\n", __func__);
		return NULL;
	}

	if (argv[1])
		datalen = strlen(argv[1]) / 2;

	frm = cmdu_alloc_simple(CMDU_TYPE_VENDOR_SPECIFIC, &mid);
	if (!frm) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	/* prepare TLVs */
	t = cmdu_reserve_tlv(frm, 3 + datalen);
	if (!t) {
		cmdu_free(frm);
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	t->type = TLV_TYPE_VENDOR_SPECIFIC;
	t->len = 3;
	vs = (struct tlv_vendor_specific *)t->data;

	if (argv[0])
		strtob(argv[0], 3, vs->oui);

	if (argv[1]) {
		strtob(argv[1], datalen, vs->bytes);
		t->len += datalen;
	}

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(frm);
		return NULL;
	}

	cmdu_put_eom(frm);

	return frm;
}

int i1905_send_vendor_specific(struct i1905_interface *iface, int argc, char *argv[])
{
	struct cmdu_buff *frm = NULL;
	int ret = 0;


	fprintf(stderr, "%s: Send VENDOR_SPECIFIC to " MACFMT "\n", __func__,
		MAC2STR(MCAST_1905));

	frm = i1905_build_vendor_specific(iface, argc, argv);
	if (!frm)
		return -1;

	cmdu_set_mid(frm, cmdu_get_next_mid());

	ret = i1905_send_cmdu(iface->priv, iface->vid, MCAST_1905, iface->aladdr,
			      ETHERTYPE_1905, frm);
	if (ret) {
		fprintf(stderr, "Error sending VENDOR_SPECIFIC\n");
	}

	cmdu_free(frm);

	return 0;
}
