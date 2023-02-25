/*
 * cmdu.c - IEEE1905 CMDU and TLV handling
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>

#include "util.h"
#include "bufutil.h"
#include "1905_tlvs.h"
#include "cmdu.h"


const char *cmdu_type2str(uint16_t type)
{

#define T2STR(t)	case CMDU_TYPE_ ## t: return #t;

	switch (type) {
	T2STR(TOPOLOGY_DISCOVERY)
	T2STR(TOPOLOGY_NOTIFICATION)
	T2STR(TOPOLOGY_QUERY)
	T2STR(TOPOLOGY_RESPONSE)
	T2STR(VENDOR_SPECIFIC)
	T2STR(LINK_METRIC_QUERY)
	T2STR(LINK_METRIC_RESPONSE)
	T2STR(AP_AUTOCONFIGURATION_SEARCH)
	T2STR(AP_AUTOCONFIGURATION_RESPONSE)
	T2STR(AP_AUTOCONFIGURATION_WSC)
	T2STR(AP_AUTOCONFIGURATION_RENEW)
	T2STR(PUSH_BUTTON_EVENT_NOTIFICATION)
	T2STR(PUSH_BUTTON_JOIN_NOTIFICATION)
	T2STR(HIGHER_LAYER_QUERY)
	T2STR(HIGHER_LAYER_RESPONSE)
	T2STR(INTERFACE_POWER_CHANGE_REQUEST)
	T2STR(INTERFACE_POWER_CHANGE_RESPONSE)
	T2STR(GENERIC_PHY_QUERY)
	T2STR(GENERIC_PHY_RESPONSE)
	}

	return "UNKNOWN";

#undef T2STR
}

const char *tlv_type2str(uint8_t type)
{

#define T2STR(t)	case TLV_TYPE_ ## t: return #t;

	switch (type) {
	T2STR(END_OF_MESSAGE)
	T2STR(AL_MAC_ADDRESS_TYPE)
	T2STR(DEVICE_INFORMATION_TYPE)
	T2STR(DEVICE_BRIDGING_CAPABILITIES)
	T2STR(NON_1905_NEIGHBOR_DEVICE_LIST)
	T2STR(NEIGHBOR_DEVICE_LIST)
	T2STR(TRANSMITTER_LINK_METRIC)
	T2STR(RECEIVER_LINK_METRIC)
	T2STR(SEARCHED_ROLE)
	T2STR(AUTOCONFIG_FREQ_BAND)
	T2STR(SUPPORTED_ROLE)
	T2STR(SUPPORTED_FREQ_BAND)
	T2STR(WSC)
	}

	return "UNKNOWN";

#undef T2STR
}

struct tlv *tlv_alloc(uint16_t datalen)
{
	struct tlv *n = calloc(1, sizeof(*n) + datalen);

	return n;
}

void tlv_zero(struct tlv *t)
{
	if (t)
		memset(t, 0, t->len + sizeof(*t));
}

void tlv_free_linear(struct tlv *t)
{
	if (t)
		free(t);
}

int tlv_ok(struct tlv *t, int rem)
{
	uint16_t l;

	if (rem < sizeof(struct tlv))
		return 0;

	l = buf_get_be16(&((uint8_t *)t)[1]);
	if (l + 3 > rem)
		return 0;

	return 1;
}

struct tlv *tlv_next(struct tlv *t, int *rem)
{
	uint16_t l = buf_get_be16(&((uint8_t *)t)[1]);

	*rem -= (l + 3);
	return (struct tlv *)((uint8_t *)t + l + 3);
}

uint16_t tlv_length(struct tlv *t)
{
	return buf_get_be16(&((uint8_t *)t)[1]);
}

uint16_t tlv_total_length(struct tlv *t)
{
	return tlv_length(t) + 3;
}

static size_t tlv_minsize(struct tlv *t)
{
	size_t sizeof_tlv[] = {
		[TLV_TYPE_END_OF_MESSAGE] =                      sizeof(struct tlv_eom),
		[TLV_TYPE_AL_MAC_ADDRESS_TYPE] =                 sizeof(struct tlv_aladdr),
		[TLV_TYPE_MAC_ADDRESS_TYPE] =                    sizeof(struct tlv_macaddr),
		[TLV_TYPE_DEVICE_INFORMATION_TYPE] =             sizeof(struct tlv_device_info),
		[TLV_TYPE_DEVICE_BRIDGING_CAPABILITIES] =        sizeof(struct tlv_device_bridge_caps),
		[TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST] =       sizeof(struct tlv_non1905_neighbor),
		[TLV_TYPE_NEIGHBOR_DEVICE_LIST] =                sizeof(struct tlv_1905neighbor),
		[TLV_TYPE_LINK_METRIC_QUERY] =                   sizeof(struct tlv_linkmetric_query),
		[TLV_TYPE_TRANSMITTER_LINK_METRIC] =             sizeof(struct tlv_tx_linkmetric),
		[TLV_TYPE_RECEIVER_LINK_METRIC] =                sizeof(struct tlv_rx_linkmetric),
		[TLV_TYPE_VENDOR_SPECIFIC] =                     sizeof(struct tlv_vendor_specific),
		[TLV_TYPE_LINK_METRIC_RESULT_CODE] =             sizeof(struct tlv_linkmetric_result),
		[TLV_TYPE_SEARCHED_ROLE] =                       sizeof(struct tlv_searched_role),
		[TLV_TYPE_AUTOCONFIG_FREQ_BAND] =                sizeof(struct tlv_autoconfig_band),
		[TLV_TYPE_SUPPORTED_ROLE] =                      sizeof(struct tlv_supported_role),
		[TLV_TYPE_SUPPORTED_FREQ_BAND] =                 sizeof(struct tlv_supported_band),
		[TLV_TYPE_WSC] =                                 sizeof(struct tlv_wsc),
		[TLV_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION] =      sizeof(struct tlv_pbc_notification),
		[TLV_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION] =       sizeof(struct tlv_pbc_join_notification),
		[TLV_TYPE_GENERIC_PHY_DEVICE_INFORMATION] =      sizeof(struct tlv_generic_phy_devinfo),
		[TLV_TYPE_DEVICE_IDENTIFICATION] =               sizeof(struct tlv_device_identification),
		[TLV_TYPE_CONTROL_URL] =                         sizeof(struct tlv_control_url),
		[TLV_TYPE_IPV4] =                                sizeof(struct tlv_ipv4),
		[TLV_TYPE_IPV6] =                                sizeof(struct tlv_ipv6),
		[TLV_TYPE_GENERIC_PHY_EVENT_NOTIFICATION] =      sizeof(struct tlv_pbc_generic_phy_notification),
		[TLV_TYPE_1905_PROFILE_VERSION] =                sizeof(struct tlv_1905_profile),
		[TLV_TYPE_POWER_OFF_INTERFACE] =                 sizeof(struct tlv_power_off),
		[TLV_TYPE_INTERFACE_POWER_CHANGE_INFORMATION] =  sizeof(struct tlv_powerchange_request),
		[TLV_TYPE_INTERFACE_POWER_CHANGE_STATUS] =       sizeof(struct tlv_powerchange_status),
		[TLV_TYPE_L2_NEIGHBOR_DEVICE] =                  sizeof(struct tlv_l2_neighbor),
	};

	if (t->type <= TLV_TYPE_L2_NEIGHBOR_DEVICE)
		return sizeof_tlv[t->type];

	return 0;
}

__thread int ieee1905_errval;

int *ieee1905_get_errval(void)
{
	return &ieee1905_errval;
}

#define ieee1905_set_error(v)	(ieee1905_errval = (v))

static const char *ieee1905_errlist[IEEE1905_ERROR_MAXNUM] = {
	[CMDU_STATUS_OK] = "Ok",
	[CMDU_STATUS_ERR_TLV_MALFORMED] = "TLV is malformed",
	[CMDU_STATUS_ERR_TLV_NUM_LESS] = "Number of TLVs less than required",
	[CMDU_STATUS_ERR_TLV_NUM_MORE] = "Number of TLVs more than required",
	[CMDU_STATUS_ERR_TLV_NO_EOM] = "EOM TLV is not present",
	[CMDU_STATUS_ERR_TLV_RESIDUE_DATA] = "Stray non-zero bytes after EOM",
	[CMDU_STATUS_ERR_TLV_LEN_INSUFFICIENT] = "TLV length insufficient",
	[CMDU_STATUS_ERR_TLV_LEN_OVERFLOW] = "TLV length points to beyond CMDU",
	[CMDU_STATUS_ERR_CMDU_MALFORMED] = "CMDU input structure malformed",
	[CMDU_STATUS_ERR_MISC] = "Misc cmdu error",
};

const char *ieee1905_strerror(int err)
{
	int last_err = err;

	if (last_err >= 0 && last_err <= IEEE1905_ERROR_LAST && ieee1905_errlist[last_err])
		return ieee1905_errlist[last_err];

	return "";
}

void cmdu_set_type(struct cmdu_buff *c, uint16_t type)
{
	if (c && c->cdata)
		buf_put_be16((uint8_t *)&c->cdata->hdr.type, type);
}

uint16_t cmdu_get_type(struct cmdu_buff *c)
{
	return (c && c->cdata) ?
		buf_get_be16((uint8_t *)&c->cdata->hdr.type) : 0xffff;
}

void cmdu_set_mid(struct cmdu_buff *c, uint16_t mid)
{
	if (c && c->cdata)
		buf_put_be16((uint8_t *)&c->cdata->hdr.mid, mid);
}

uint16_t cmdu_get_mid(struct cmdu_buff *c)
{
	return (c && c->cdata) ?
		buf_get_be16((uint8_t *)&c->cdata->hdr.mid) : 0xffff;
}

void cmdu_set_fid(struct cmdu_buff *c, uint8_t fid)
{
	if (c && c->cdata)
		c->cdata->hdr.fid = fid;
}

uint8_t cmdu_get_fid(struct cmdu_buff *c)
{
	return (c && c->cdata) ? c->cdata->hdr.fid : 0xff;
}

uint8_t *cmdu_get_origin(struct cmdu_buff *c)
{
	return c ? c->origin : NULL;
}

int is_cmdu_type_valid(uint16_t type)
{
	return type <= CMDU_TYPE_MAX;
}

int is_cmdu_tlv_required(uint16_t type)
{
	return !(type == CMDU_TYPE_TOPOLOGY_QUERY ||
		type == CMDU_TYPE_HIGHER_LAYER_QUERY ||
		type == CMDU_TYPE_GENERIC_PHY_QUERY);
}

int cmdu_should_relay(uint16_t type)
{
	return (type == CMDU_TYPE_TOPOLOGY_NOTIFICATION ||
		type == CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH ||
		type == CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW ||
		type == CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION ||
		type == CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION);
}

/* for unicast request types only */
int is_cmdu_type_response(uint16_t type)
{
	return (type == CMDU_TYPE_TOPOLOGY_RESPONSE ||
		type == CMDU_TYPE_LINK_METRIC_RESPONSE ||
		/* type == CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE || */
		type == CMDU_TYPE_HIGHER_LAYER_RESPONSE ||
		type == CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE);
}

uint16_t cmdu_expect_response(uint16_t req_type)
{
	switch (req_type) {
		case CMDU_TYPE_TOPOLOGY_QUERY:
			return CMDU_TYPE_TOPOLOGY_RESPONSE;
		case CMDU_TYPE_LINK_METRIC_QUERY:
			return CMDU_TYPE_LINK_METRIC_RESPONSE;
		case CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH:
			return CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE;
		case CMDU_TYPE_AP_AUTOCONFIGURATION_WSC:
			return CMDU_TYPE_AP_AUTOCONFIGURATION_WSC;
		case CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW:
			return CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE;
		case CMDU_TYPE_HIGHER_LAYER_QUERY:
			return CMDU_TYPE_HIGHER_LAYER_RESPONSE;
		case CMDU_TYPE_INTERFACE_POWER_CHANGE_REQUEST:
			return CMDU_TYPE_INTERFACE_POWER_CHANGE_RESPONSE;
		case CMDU_TYPE_GENERIC_PHY_QUERY:
			return CMDU_TYPE_GENERIC_PHY_RESPONSE;
		default:
			break;
	}

	return CMDU_TYPE_NONE;
}

struct cmdu_buff *cmdu_alloc(int size)
{
#define CMDU_RESERVE_HEADSPACE	32

	struct cmdu_buff *n;
	uint8_t *p;


	p = calloc(1, sizeof(*n) + size + CMDU_RESERVE_HEADSPACE);
	if (!p)
		return NULL;

	n = (struct cmdu_buff *)p;
	n->head = (uint8_t *)(n + 1) + CMDU_RESERVE_HEADSPACE;
	n->end = n->head + size;
	n->data = n->head;
	n->cdata = NULL;
	//n->cdata = (struct cmdu_linear *)(n->head + 18);
	//n->data = (uint8_t *)(n->cdata + 1);
	n->tail = n->data;
	n->num_frags = 0;
	n->datalen = 0;
	n->len = 0;
	n->head -= 18;
	INIT_LIST_HEAD(&n->fraglist);

	return (struct cmdu_buff *)p;
}

struct cmdu_buff *cmdu_alloc_frame(int size)
{
	struct cmdu_buff *f;

	f = cmdu_alloc(size + sizeof(struct cmdu_header));
	if (!f)
		return NULL;

	f->cdata = (struct cmdu_linear *)(f->head + 18);
	f->data = (uint8_t *)(f->cdata + 1);
	f->tail = f->data;

	return f;
}

struct cmdu_buff *cmdu_alloc_default(void)
{
#define ETH_FRAME_SZ	1500

	return cmdu_alloc(ETH_FRAME_SZ);
}

struct cmdu_buff *cmdu_alloc_nohdr(void)
{
	struct cmdu_buff *f;

	f = cmdu_alloc(ETH_FRAME_SZ);
	if (f) {
		f->cdata = NULL;
		f->data = (uint8_t *)(f->head + 18);
		f->tail = f->data;
	}

	return f;
}

struct cmdu_buff *cmdu_alloc_simple(uint16_t type, uint16_t *mid)
{
	struct cmdu_buff *f;


	f = cmdu_alloc_default();
	if (!f) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	f->cdata = (struct cmdu_linear *)(f->head + 18);
	f->data = (uint8_t *)(f->cdata + 1);
	f->tail = f->data;

	cmdu_set_type(f, type);

	if (*mid == 0)
		*mid = cmdu_get_next_mid();

	cmdu_set_mid(f, *mid);

	if (cmdu_should_relay(type))
		CMDU_SET_RELAY_MCAST(f->cdata);

	CMDU_SET_LAST_FRAGMENT(f->cdata);

	return f;
}

void cmdu_free(struct cmdu_buff *c)
{
	if (c) {
		list_flush(&c->fraglist, struct cmdu_frag, list);
		free(c);
	}
}

int cmdu_size(struct cmdu_buff *c)
{
	return c ? c->datalen + sizeof(struct cmdu_header) : 0;
}

#if 0
int cmdu_reserve(struct cmdu_buff *c, size_t s)
{
	if (!c)
		return -1;

	if (c->head - (uint8_t *)(c + 1) < s)
		return -1;

	c->head -= s;

	return 0;
}
#endif


int cmdu_copy_tlvs_linear(struct cmdu_buff *c, uint8_t *tlvs, uint32_t tlvslen)
{
	if (c->end - c->tail < tlvslen)
		return -1;

	memcpy(c->tail, tlvs, tlvslen);
	c->tail += tlvslen;
	c->datalen += tlvslen;

	return 0;
}

struct cmdu_buff *cmdu_alloc_custom(uint16_t type, uint16_t *mid, char *ifname,
				    uint8_t *origin, uint8_t *tlvs,
				    uint32_t tlvslen)
{
	struct cmdu_buff *f;
	int ret;


	f = cmdu_alloc_frame(tlvslen + 128);
	if (!f) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	cmdu_set_type(f, type);

	if (*mid == 0)
		*mid = cmdu_get_next_mid();

	cmdu_set_mid(f, *mid);

	ret = cmdu_copy_tlvs_linear(f, tlvs, tlvslen);
	if (ret) {
		fprintf(stderr, "%s: tlv-length > max cmdu size!\n", __func__);
		cmdu_free(f);
		return NULL;
	}

	memcpy(f->dev_macaddr, origin, 6);
	if (ifname)
		strncpy(f->dev_ifname, ifname, 15);

	return f;
}

struct cmdu_buff *cmdu_clone(struct cmdu_buff *frm)
{
	struct cmdu_buff *f;
	int len;


	if (!frm || !frm->cdata) {
		fprintf(stderr, "%s: cmdu for cloning is invalid!\n", __func__);
		return NULL;
	}

	len = cmdu_size(frm);
	f = cmdu_alloc(len);
	if (!f) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	f->cdata = (struct cmdu_linear *)(f->head + 18);
	f->data = (uint8_t *)(f->cdata + 1);
	f->datalen = frm->datalen;
	f->tail = f->data + f->datalen;
	memcpy(f->cdata, frm->cdata, len);

	memcpy(f->dev_macaddr, frm->dev_macaddr, 6);
	strncpy(f->dev_ifname, frm->dev_ifname, 15);
	memcpy(f->origin, frm->origin, 6);

	return f;
}

struct cmdu_buff *cmdu_realloc(struct cmdu_buff *c, size_t size)
{
	ptrdiff_t head_off, data_off, cdata_off;
	struct cmdu_buff *f;
	ptrdiff_t origsize;
	uint8_t *n;


	if (!c)
		return NULL;

	origsize = (c->end - (uint8_t *)c);
	if (size < origsize)
		return c;

	head_off = c->head - (uint8_t *)c;
	data_off = c->data - (uint8_t *)c;
	cdata_off = c->cdata ? (uint8_t *)c->cdata - (uint8_t *)c : 0;

	n = realloc((uint8_t *)c, sizeof(*f) + size + CMDU_RESERVE_HEADSPACE);
	if (!n)
		return NULL;

	f = (struct cmdu_buff *)n;
	f->head = n + head_off;
	f->data = n + data_off;
	f->tail = f->data + f->datalen;
	f->cdata = cdata_off ? (struct cmdu_linear *)(n + cdata_off) : NULL;
	f->end = f->head + size;

	/* TODO: reconstruct fraglist */
	INIT_LIST_HEAD(&f->fraglist);

	return f;
}

int cmdu_copy_tlvs(struct cmdu_buff *c, struct tlv *tv[], int tv_arrsize)
{
	uint16_t tlvslen = 0;
	int i;


	for (i = 0; i < tv_arrsize; i++)
		tlvslen += tv[i]->len;


	if (c->end - c->tail < tlvslen)
		return -1;


	for (i = 0; i < tv_arrsize; i++) {
		uint16_t tlen = tv[i]->len;

		*c->tail = tv[i]->type;
		buf_put_be16(c->tail + 1, tlen);
		memcpy(c->tail + 3, tv[i]->data, tlen);
		c->tail += tlen + sizeof(struct tlv);
		c->datalen += tlen + sizeof(struct tlv);
	}

	return 0;
}

int cmdu_put_tlv(struct cmdu_buff *c, struct tlv *t)
{
	uint16_t tlen;


	if (!c || !t)
		return -1;


	tlen = t->len;

	if (c->end - c->tail < tlen) {
		fprintf(stderr, "%s: %d: c->end = %p c->tail = %p\n",
			__func__, __LINE__, c->end, c->tail);

		return -1;
	}

	if ((uint8_t *)t != c->tail) {
		fprintf(stderr, "%s: tlv outside cmdu buffer; use cmdu_copy_tlv() instead\n",
			__func__);
		return -1;
	}


	buf_put_be16(c->tail + 1, tlen);
	c->tail += tlen + sizeof(*t);
	c->datalen += tlen + sizeof(*t);

	return 0;
}

int cmdu_put(struct cmdu_buff *c, uint8_t *bytes, int len)
{
	if (!c)
		return -1;

	if (!bytes)
		return 0;

	if (c->end - c->tail < len) {
		fprintf(stderr, "%s: %d: c->end = %p c->tail = %p\n",
			__func__, __LINE__, c->end, c->tail);

		return -1;
	}

	memcpy(c->tail, bytes, len);
	c->tail += len;
	c->datalen += len;

	return 0;
}

int cmdu_put_eom(struct cmdu_buff *c)
{
	uint8_t eom[3] = {0};

	return cmdu_put(c, eom, sizeof(eom));
}

int cmdu_pull_eom(struct cmdu_buff *c)
{
	if (!c || c->datalen < 3)
		return -1;

	c->tail -= 3;
	c->datalen -= 3;
	return 0;
}

struct tlv *cmdu_reserve_tlv(struct cmdu_buff *c, uint16_t tlv_datalen)
{
	uint16_t len = tlv_datalen + TLV_HLEN;

	if (!c)
		return NULL;

	if (c->end - c->tail < len) {
		fprintf(stderr, "%s: Failed to reserve %hu! Allocate new cmdu fragment\n",
			__func__, tlv_datalen);

		return NULL;
	}

	return (struct tlv *)c->tail;
}

int cmdu_parse_tlv_single(struct cmdu_buff *c, struct tlv *tv[],
			  struct tlv_policy *policy, int *num)
{
	struct tlv *t;
	int i = 0;
	int len;


	if (!c || !c->data || !c->datalen)
		return -1;

	if (*num == 0)
		return 0;

	memset(tv, 0, *num * sizeof(struct tlv *));
	len = c->datalen;

	cmdu_for_each_tlv(t, c->data, len) {
		if (policy->type != t->type)
			continue;

		if (policy->len && tlv_length(t) != policy->len)
			return -1;

		if (policy->minlen > 0 && tlv_length(t) < policy->minlen)
			continue;

		if (policy->maxlen > 0 && tlv_length(t) > policy->maxlen)
			continue;

		if (tlv_length(t) < tlv_minsize(t))
			continue;

		if (tv[0] && policy->present == TLV_PRESENT_ONE)
			return -1;

		if (i >= *num)
			break;

		tv[i++] = t;
	}

	/* malformed cmdu if data remaining */
	if (len) {
		int k = 0;

		while (k < len) {
			if (c->data[c->datalen - len + k++] != 0)
				return -1;
		}
	}

	/* exactly one tlv must be present */
	if (policy->present == TLV_PRESENT_ONE && !tv[0])
		return -1;

	*num = i;
	return 0;
}

int cmdu_parse_tlvs(struct cmdu_buff *c, struct tlv *tv[][16],
		    struct tlv_policy *policy, int policy_len)
{
	int idx[policy_len];
	struct tlv *t;
	int len;
	int i;


	ieee1905_set_error(CMDU_STATUS_OK);
	if (!c || !c->data || !c->datalen) {
		ieee1905_set_error(CMDU_STATUS_ERR_CMDU_MALFORMED);
		return -1;
	}

	for (i = 0; i < policy_len; i++) {
		memset(tv[i], 0, 16 * sizeof(struct tlv *));
		idx[i] = 0;
	}
	len = c->datalen;

	cmdu_for_each_tlv(t, c->data, len) {
		for (i = 0; i < policy_len; i++) {
			if (policy[i].type != t->type)
				continue;

			if (policy[i].len && tlv_length(t) != policy[i].len) {
				ieee1905_set_error(CMDU_STATUS_ERR_TLV_MALFORMED);
				return -1;
			}

			if (policy[i].minlen > 0 &&
			    tlv_length(t) < policy[i].minlen) {
				ieee1905_set_error(CMDU_STATUS_ERR_TLV_LEN_INSUFFICIENT);
				return -1;
			}

			if (policy[i].maxlen > 0 &&
			    tlv_length(t) > policy[i].maxlen) {
				ieee1905_set_error(CMDU_STATUS_ERR_TLV_LEN_OVERFLOW);
				return -1;
			}

			if (tlv_length(t) < tlv_minsize(t))
				continue;

			if (tv[i][0]) {
				if (policy[i].present == TLV_PRESENT_ONE ||
				    policy[i].present == TLV_PRESENT_OPTIONAL_ONE) {
					ieee1905_set_error(CMDU_STATUS_ERR_TLV_NUM_MORE);
					return -1;
				}
			}

			tv[i][idx[i]++] = t;
		}
	}

	/* malformed cmdu if data remaining; only allow zero padding */
	if (len) {
		int k = 0;

		while (k < len) {
			if (c->data[c->datalen - len + k++] != 0) {
				ieee1905_set_error(CMDU_STATUS_ERR_TLV_RESIDUE_DATA);
				return -1;
			}
		}
	}

	/* strictly check against tlv policies */
	for (i = 0; i < policy_len; i++) {
		if ((policy[i].present == TLV_PRESENT_ONE ||
		    policy[i].present == TLV_PRESENT_MORE) && !tv[i][0]) {
			ieee1905_set_error(CMDU_STATUS_ERR_TLV_NUM_LESS);
			return -1;
		}
	}

	return 0;
}

/* Extracts the first matching tlv from tlv-stream.
 * This function is destructive, i.e. it modifies the passed cmdu buffer.
 * Use cmdu_peek_tlv() for the non-destructive version.
 */
struct tlv *cmdu_extract_tlv(struct cmdu_buff *c, uint8_t tlv_type)
{
	struct tlv *t, *tmp;
	int found = 0;
	int inlen;


	if (!c)
		return NULL;

	inlen = c->datalen;

	cmdu_for_each_tlv(t, c->data, inlen) {
		if (t->type == tlv_type) {
			found = 1;
			break;
		}
	}

	if (found) {
		uint16_t tlen = tlv_total_length(t);

		tmp = tlv_alloc(tlv_length(t));
		if (tmp)
			memcpy(tmp, t, tlen);

		inlen -= tlen;
		memmove(t, (uint8_t *)t + tlen, inlen);
		c->datalen -= tlen;
		return tmp;
	}

	return NULL;
}

struct tlv *cmdu_peek_tlv(struct cmdu_buff *c, uint8_t tlv_type)
{
	struct tlv *t;
	int len;

	if (!c)
		return NULL;

	len = c->datalen;

	cmdu_for_each_tlv(t, c->data, len) {
		if (t->type == tlv_type)
			return t;
	}

	return NULL;
}
