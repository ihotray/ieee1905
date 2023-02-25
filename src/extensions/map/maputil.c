/*
 * maputil.c - implements multi-ap helper functions for map applications.
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
#include <stdarg.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>

#include "1905_tlvs.h"
#include "cmdu.h"
#include "easymesh.h"
#include "map_module.h"

static __thread int map_errval;

int *map_get_errval(void)
{
	return &map_errval;
}

static const char *map_status_to_string(enum MAP_STATUS err)
{
	switch (err) {
	case MAP_STATUS_ERR_CMDU_TYPE_NOT_SUPPORTED:
		return "MAP: CMDU type not supported";
	case MAP_STATUS_ERR_MAP_PROFILE_NOT_SUPPORTED:
		return "MAP: Multi-AP Profile not supported";
	case MAP_STATUS_ERR_MAP_POLICY_NOT_FOUND:
		return "MAP: Policy required to parse CMDU not found";
	case MAP_STATUS_ERR_TLVS_OUTPUT_ARRAY_INSUFFICIENT:
		return "MAP: TLVs output array insufficient";

	default:
		return "MAP: error description not provided";
	}
}

const char *map_strerror(int err)
{
	if (err >= MAP_STATUS_ERR_FIRST && err < MAP_STATUS_ERR_AFTER_LAST)
		return map_status_to_string(err);

	return ieee1905_strerror(err);
}

#define cmdu_mask_setbit(m, f)						\
do {									\
	if (f >= 0x8000)						\
		(m[4 + (f - 0x8000) / 8] |= (1 << ((f - 0x8000) % 8)));	\
	else								\
		(m[(f) / 8] |= (1 << ((f) % 8)));			\
} while(0)



int map_prepare_cmdu_mask(uint8_t mask[], ...)
{
	va_list args;
	uint16_t v;

	va_start(args, mask);
	do {
		v = (uint16_t)va_arg(args, int);
		if (v > MAP_CMDU_TYPE_MAX )
			break;

		cmdu_mask_setbit(mask, v);
	} while(1);

	va_end(args);
	return 0;
}

const char *map_cmdu_type2str(uint16_t type)
{
	if (type >= CMDU_TYPE_1905_START && type <= CMDU_TYPE_1905_END)
		return cmdu_type2str(type);

#define T2STR(t)	case CMDU_ ## t: return #t;

	switch (type) {
	T2STR(1905_ACK)
	T2STR(AP_CAPABILITY_QUERY)
	T2STR(AP_CAPABILITY_REPORT)
	T2STR(POLICY_CONFIG_REQ)
	T2STR(CHANNEL_PREFERENCE_QUERY)
	T2STR(CHANNEL_PREFERENCE_REPORT)
	T2STR(CHANNEL_SELECTION_REQ)
	T2STR(CHANNEL_SELECTION_RESPONSE)
	T2STR(OPERATING_CHANNEL_REPORT)
	T2STR(CLIENT_CAPABILITY_QUERY)
	T2STR(CLIENT_CAPABILITY_REPORT)
	T2STR(AP_METRICS_QUERY)
	T2STR(AP_METRICS_RESPONSE)
	T2STR(ASSOC_STA_LINK_METRICS_QUERY)
	T2STR(ASSOC_STA_LINK_METRICS_RESPONSE)
	T2STR(UNASSOC_STA_LINK_METRIC_QUERY)
	T2STR(UNASSOC_STA_LINK_METRIC_RESPONSE)
	T2STR(BEACON_METRICS_QUERY)
	T2STR(BEACON_METRICS_RESPONSE)
	T2STR(COMBINED_INFRA_METRICS)
	T2STR(CLIENT_STEERING_REQUEST)
	T2STR(CLIENT_STEERING_BTM_REPORT)
	T2STR(CLIENT_ASSOC_CONTROL_REQUEST)
	T2STR(STEERING_COMPLETED)
	T2STR(HIGHER_LAYER_DATA)
	T2STR(BACKHAUL_STEER_REQUEST)
	T2STR(BACKHAUL_STEER_RESPONSE)
#if (EASYMESH_VERSION >= 2)
	T2STR(CHANNEL_SCAN_REQUEST)
	T2STR(CHANNEL_SCAN_REPORT)
#if (EASYMESH_VERSION >= 3)
	T2STR(DPP_CCE_INDICATION)
	T2STR(1905_REKEY_REQUEST)
	T2STR(1905_DECRYPT_FAIL)
#endif
	T2STR(CAC_REQUEST)
	T2STR(CAC_TERMINATION)
	T2STR(CLIENT_DISASSOCIATION_STATS)
#if (EASYMESH_VERSION >= 3)
	T2STR(SERVICE_PRIORITIZATION_REQUEST)
#endif
	T2STR(ERROR_RESPONSE)
	T2STR(ASSOCIATION_STATUS_NOTIFICATION)
	T2STR(TUNNELED)
	T2STR(BACKHAUL_STA_CAPABILITY_QUERY)
	T2STR(BACKHAUL_STA_CAPABILITY_REPORT)
#if (EASYMESH_VERSION >= 3)
	T2STR(PROXIED_ENCAP_DPP)
	T2STR(DIRECT_ENCAP_DPP)
	T2STR(RECONFIG_TRIGGER)
	T2STR(BSS_CONFIG_REQUEST)
	T2STR(BSS_CONFIG_RESPONSE)
	T2STR(BSS_CONFIG_RESULT)
	T2STR(CHIRP_NOTIFICATION)
	T2STR(1905_ENCAP_EAPOL)
	T2STR(DPP_BOOTSTRAPING_URI)
#if (EASYMESH_VERSION >= 4)
	T2STR(ANTICIPATED_CHANNEL_PREFERENCE)
#endif
#endif
	T2STR(FAILED_CONNECTION)
#if (EASYMESH_VERSION >= 3)
	T2STR(AGENT_LIST)
#endif
#if (EASYMESH_VERSION >= 4)
	T2STR(ANTICIPATED_CHANNEL_USAGE)
	T2STR(QOS_MANAGEMENT_NOTIFICATION)
#endif
#endif
	}

	return "UNKNOWN";

#undef T2STR
}

const char *map_tlv_type2str(uint8_t type)
{
	if (type >= TLV_TYPE_END_OF_MESSAGE && type <= TLV_TYPE_WSC)
		return tlv_type2str(type);

#define T2STR(t)	case MAP_TLV_ ## t: return #t;

	switch (type) {
	T2STR(SUPPORTED_SERVICE)
	T2STR(SEARCHED_SERVICE)
	T2STR(AP_RADIO_IDENTIFIER)
	T2STR(AP_OPERATIONAL_BSS)
	T2STR(ASSOCIATED_CLIENTS)
	T2STR(AP_CAPABILITY)
	T2STR(AP_RADIO_BASIC_CAPABILITIES)
	T2STR(AP_HT_CAPABILITIES)
	T2STR(AP_VHT_CAPABILITIES)
	T2STR(AP_HE_CAPABILITIES)
	T2STR(STEERING_POLICY)
	T2STR(METRIC_REPORTING_POLICY)
	T2STR(CHANNEL_PREFERENCE)
	T2STR(RADIO_OPERATION_RESTRICTION)
	T2STR(TRANSMIT_POWER_LIMIT)
	T2STR(CHANNEL_SELECTION_RESPONSE)
	T2STR(OPERATING_CHANNEL_REPORT)
	T2STR(CLIENT_INFO)
	T2STR(CLIENT_CAPABILITY_REPORT)
	T2STR(CLIENT_ASSOCIATION_EVENT)
	T2STR(AP_METRIC_QUERY)
	T2STR(AP_METRICS)
	T2STR(STA_MAC_ADDRESS)
	T2STR(ASSOCIATED_STA_LINK_METRICS)
	T2STR(UNASSOCIATED_STA_LINK_METRICS_QUERY)
	T2STR(UNASSOCIATED_STA_LINK_METRICS_RESPONSE)
	T2STR(BEACON_METRICS_QUERY)
	T2STR(BEACON_METRICS_RESPONSE)
	T2STR(STEERING_REQUEST)
	T2STR(STEERING_BTM_REPORT)
	T2STR(CLIENT_ASSOCIATION_CONTROL_REQUEST)
	T2STR(BACKHAUL_STEERING_REQUEST)
	T2STR(BACKHAUL_STEERING_RESPONSE)
	T2STR(HIGHER_LAYER_DATA)
	T2STR(ASSOCIATED_STA_TRAFFIC_STATS)
	T2STR(ERROR_CODE)
	T2STR(CHANNEL_SCAN_REPORTING_POLICY)
	T2STR(CHANNEL_SCAN_CAPABILITY)
	T2STR(CHANNEL_SCAN_REQ)
	T2STR(CHANNEL_SCAN_RES)
	T2STR(TIMESTAMP)
#if (EASYMESH_VERSION >= 3)
	T2STR(1905_SECURITY_CAPS)
	T2STR(AP_WIFI6_CAPS)
	T2STR(MIC)
	T2STR(ENCRYPTED_PAYLOAD)
#endif
	T2STR(CAC_REQ)
	T2STR(CAC_TERMINATION)
	T2STR(CAC_COMPLETION_REPORT)
#if (EASYMESH_VERSION >= 3)
	T2STR(ASSOCIATED_WIFI6_STA_STATUS)
#endif
	T2STR(CAC_STATUS_REPORT)
	T2STR(CAC_CAPABILITY)
	T2STR(MULTIAP_PROFILE)
	T2STR(PROFILE2_AP_CAPABILITY)
	T2STR(DEFAULT_8021Q_SETTINGS)
	T2STR(TRAFFIC_SEPARATION_POLICY)
#if (EASYMESH_VERSION >= 3)
	T2STR(BSS_CONFIGURATION_REPORT)
	T2STR(BSSID)
	T2STR(SERVICE_PRIORITIZATION_RULE)
	T2STR(DSCP_MAPPING_TABLE)
	T2STR(BSS_CONFIGURATION_REQUEST)
#endif
	T2STR(PROFILE2_ERR_CODE)
#if (EASYMESH_VERSION >= 3)
	T2STR(BSS_CONFIGURATION_RESPONSE)
#endif
	T2STR(AP_RADIO_ADV_CAPABILITY)
	T2STR(ASSOCIATION_STATUS_NOTIF)
	T2STR(SOURCE_INFO)
	T2STR(TUNNELED_MSG_TYPE)
	T2STR(TUNNELED)
	T2STR(PROFILE2_STEERING_REQ)
	T2STR(UNSUCCESS_ASSOCIATION_POLICY)
	T2STR(METRIC_COLLECTION_INTERVAL)
	T2STR(RADIO_METRICS)
	T2STR(AP_EXTENDED_METRICS)
	T2STR(ASSOCIATED_STA_EXT_LINK_METRICS)
	T2STR(STATUS_CODE)
	T2STR(REASON_CODE)
	T2STR(BACKHAUL_STA_RADIO_CAPABILITY)
#if (EASYMESH_VERSION >= 3)
	T2STR(AKM_SUITE_CAPS)
	T2STR(1905_ENCAP_DPP)
	T2STR(1905_ENCAP_EAPOL)
	T2STR(DPP_BOOTSTRAP_URI_NOTIFICATION)
#endif
	T2STR(BACKHAUL_BSS_CONFIG)
#if (EASYMESH_VERSION >= 3)
	T2STR(DPP_MESSAGE)
	T2STR(DPP_CCE_INDICATION)
	T2STR(DPP_CHIRP_VALUE)
	T2STR(DEVICE_INVENTORY)
	T2STR(AGENT_LIST)
#endif
#if (EASYMESH_VERSION >= 4)
	T2STR(ANTICIPATED_CHANNEL_PREF)
	T2STR(ANTICIPATED_CHANNEL_USAGE)
	T2STR(SPATIAL_REUSE_REQUEST)
	T2STR(SPATIAL_REUSE_REPORT)
	T2STR(SPATIAL_REUSE_CONFIG_RESPONSE)
	T2STR(QOS_MANAGEMENT_POLICY)
	T2STR(QOS_MANAGEMENT_DESCRIPTOR)
	T2STR(CONTROLLER_CAPS)
#endif
	}

	return "UNKNOWN";

#undef T2STR
}


struct mapmodule_context {
	void *bus;
	struct ubus_subscriber sub;
	uint32_t oid;
	void *priv;
	int (*sub_cb)(void *bus, void *priv, void *data);
	int (*del_cb)(void *bus, void *priv, void *data);
};

static void mapclient_sub_remove_cb(struct ubus_context *ctx,
				    struct ubus_subscriber *sub,
				    uint32_t obj)
{
	struct mapmodule_context *mod = container_of(sub, struct mapmodule_context, sub);

	fprintf(stdout, "Object 0x%x no longer present\n", obj);
	if (mod->del_cb)
		mod->del_cb(mod->bus, mod->priv, (void *)&obj);
}

static int mapclient_sub_cb(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req, const char *type,
			    struct blob_attr *msg)
{
	struct ubus_subscriber *s = container_of(obj, struct ubus_subscriber, obj);
	struct mapmodule_context *mod = container_of(s, struct mapmodule_context, sub);
	/*
	char *str;

	str = blobmsg_format_json(msg, true);
	fprintf(stdout, "Received notification '%s': %s\n", type, str);
	free(str);
	*/

	if (mod->sub_cb)
		mod->sub_cb(mod->bus, mod->priv, msg);

	return 0;
}

#if 0
static int mapclient_subscribe(void *bus, void *priv, uint32_t oid)
{
	struct mapmodule_context *modctx = (struct mapmodule_context *)priv;
	struct ubus_subscriber *sub = modctx->sub;
	int ret;


	/* register mapclient as a subscriber with ubus */
	sub->cb = mapclient_sub_cb;
	sub->remove_cb = mapclient_sub_remove_cb;
	ret = ubus_register_subscriber(bus, sub);
	if (ret)
		fprintf(stdout, "Failed to register subscriber: %s\n", ubus_strerror(ret));


	/* now subscribe to events from map plugin over passed oid */
	ret = ubus_subscribe(bus, sub, oid);
	if (ret)
		fprintf(stderr, "Failed to subscribe: %s\n", ubus_strerror(ret));

	return 0;
}
#endif

static void register_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	const struct blobmsg_policy pol[1] = {
		[0] = { .name = "oid", .type = BLOBMSG_TYPE_INT32 },
	};
	struct blob_attr *tb[1];
	//struct mapmodule_context *mod = req->priv;
	uint32_t *oid = (uint32_t *)req->priv;


	blobmsg_parse(pol, 1, tb, blob_data(msg), blob_len(msg));
	if (tb[0])
		*oid = blobmsg_get_u32(tb[0]);


#if 0
	{
		struct ubus_subscriber *sub;
		uint32_t oid = blobmsg_get_u32(tb[0]);
		int ret;

		fprintf(stderr, "Response ID: 0x%x\n", oid);
		//mapclient_subscribe(modpriv->bus, modpriv, oid);


		sub = calloc(1, sizeof(*sub));
		if (!sub)
			return;

		((struct ubus_subscriber *)mod->sub)->cb = mapclient_sub_cb;
		((struct ubus_subscriber *)mod->sub)->remove_cb = mapclient_sub_remove_cb;
		ret = ubus_register_subscriber(mod->bus, mod->sub);
		if (ret)
			fprintf(stdout, "Failed to register subscriber: %s\n", ubus_strerror(ret));

		/* now subscribe to events from map plugin over passed oid */
		ret = ubus_subscribe(mod->bus, mod->sub, oid);
		if (ret)
			fprintf(stderr, "Failed to subscribe: %s\n", ubus_strerror(ret));
	}
#endif
}

int map_subscribe(void *bus, void *publisher, /* struct mapmodule_context *mod, */
		  const char *name, mapmodule_cmdu_mask_t *mask, void *priv,
		  int (*sub_cb)(void *bus, void *priv, void *data),
		  int (*del_cb)(void *bus, void *priv, void *data),
		  void **subscriber)
{
	char data[2 * sizeof(struct map_module) + 1] = {0};
	unsigned int seedp = getpid();
	struct mapmodule_context *mod;
	struct map_module m = {0};
	struct blob_buf bb = {};
	uint32_t oid = -1;
	int ret;


	//mod->bus = bus;
	m.id = rand_r(&seedp);
	memcpy(m.cmdu_mask, mask, sizeof(mapmodule_cmdu_mask_t));
	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "module", name);
	btostr((unsigned char *)&m, sizeof(struct map_module), data);
	blobmsg_add_string(&bb, "data", data);
	ret = ubus_invoke(bus, *(uint32_t *)publisher, "register", bb.head,
			  register_cb, &oid /* mod */, 1000);
	if (ret) {
		fprintf(stderr, "Error map_subscribe(): err = %s\n",
			ubus_strerror(ret));
	}

	blob_buf_free(&bb);

	fprintf(stderr, "Response ID: 0x%x\n", oid);
	//mapclient_subscribe(modpriv->bus, modpriv, oid);

	mod = calloc(1, sizeof(*mod));
	if (!mod)
		return -1;

	mod->oid = oid;
	mod->bus = bus;
	mod->priv = priv;
	mod->sub_cb = sub_cb;
	mod->del_cb = del_cb;
	mod->sub.cb = mapclient_sub_cb;
	mod->sub.remove_cb = mapclient_sub_remove_cb;

	ret = ubus_register_subscriber(bus, &mod->sub);
	if (ret) {
		fprintf(stdout, "Failed to register subscriber: %s\n", ubus_strerror(ret));
		free(mod);
		return ret;
	}

	/* now subscribe to events from map plugin over passed oid */
	ret = ubus_subscribe(bus, &mod->sub, oid);
	if (ret) {
		fprintf(stderr, "Failed to subscribe: %s\n", ubus_strerror(ret));
		free(mod);
		return ret;
	}

	if (subscriber)
		*subscriber = mod;

	return 0;
}

int map_unsubscribe(void *bus, void *subscriber)
{
	struct mapmodule_context *mod = subscriber;
	int ret;

	if (!bus || !subscriber)
		return -1;

	ret = ubus_unsubscribe(bus, &mod->sub, mod->oid);
	ubus_unregister_subscriber(bus, &mod->sub);
	free(mod);

	return ret;
}

int map_cmdu_get_multiap_profile(struct cmdu_buff *cmdu)
{
	struct tlv_map_profile *p;
	struct tlv *t;

	if (!cmdu || !cmdu->cdata) {
		map_error =  MAP_STATUS_ERR_CMDU_MALFORMED;
		return -1;
	}

	t = cmdu_peek_tlv(cmdu, MAP_TLV_MULTIAP_PROFILE);
	if (!t)
		return MULTIAP_PROFILE_1;

	if (tlv_length(t) != sizeof(struct tlv_map_profile)) {
		map_error =  MAP_STATUS_ERR_TLV_MALFORMED;
		return -1;
	}

	p = (struct tlv_map_profile *)t->data;

	return p->profile;
}
