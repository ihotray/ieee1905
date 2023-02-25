/*
 * sendcmdu.c - fuzz 1905 cmdus and send through 'cmdu' ubus command.
 *
 * Copyright (C) 2021-2022 IOPSYS Software Solutions AB. All rights reserved.
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
#include <errno.h>
#include <assert.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>

#include <easy/easy.h>

#include "cmdu.h"
#include "1905_tlvs.h"

const char *fuzz_ifname = "eth0";
uint16_t fuzz_mid = 0;

struct tlv_policy_1905 {
	size_t num;
	struct tlv_policy *pol;
};

#define DEFINE_POLICY(t)	static struct tlv_policy policy_ ## t[]
#define P(t)			{ .num = ARRAY_SIZE(policy_ ## t), .pol = policy_ ## t }


DEFINE_POLICY(CMDU_TYPE_TOPOLOGY_DISCOVERY) = {
	{
		.type = TLV_TYPE_AL_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6
	},
	{
		.type = TLV_TYPE_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6
	},
};

DEFINE_POLICY(CMDU_TYPE_TOPOLOGY_NOTIFICATION) = {
	{
		.type = TLV_TYPE_AL_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6
	},
};

DEFINE_POLICY(CMDU_TYPE_TOPOLOGY_RESPONSE) = {
	{	.type = TLV_TYPE_DEVICE_INFORMATION_TYPE,
		.present = TLV_PRESENT_ONE
	},
	{	.type = TLV_TYPE_DEVICE_BRIDGING_CAPABILITIES,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	{	.type = TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	{	.type = TLV_TYPE_NEIGHBOR_DEVICE_LIST,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	{	.type = TLV_TYPE_POWER_OFF_INTERFACE,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	{	.type = TLV_TYPE_L2_NEIGHBOR_DEVICE,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
};

DEFINE_POLICY(CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH) = {
	[0] = { .type = TLV_TYPE_AL_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6,
	},
	[1] = { .type = TLV_TYPE_SEARCHED_ROLE,
		.present = TLV_PRESENT_ONE,
		.len = 1,
	},
	[2] = { .type = TLV_TYPE_AUTOCONFIG_FREQ_BAND,
		.present = TLV_PRESENT_ONE,
		.len = 1,
	},
};

DEFINE_POLICY(CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE) = {
	[0] = { .type = TLV_TYPE_SUPPORTED_ROLE,
		.present = TLV_PRESENT_ONE,
		.len = 1,
	},
	[1] = { .type = TLV_TYPE_SUPPORTED_FREQ_BAND,
		.present = TLV_PRESENT_ONE,
		.len = 1,
	},
};

DEFINE_POLICY(CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW) = {
	[0] = { .type = TLV_TYPE_AL_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6
	},
	[1] = { .type = TLV_TYPE_SUPPORTED_ROLE,
		.present = TLV_PRESENT_ONE,
		.len = sizeof(struct tlv_supported_role)
	},
	[2] = { .type = TLV_TYPE_SUPPORTED_FREQ_BAND,
		.present = TLV_PRESENT_ONE,
		.len = sizeof(struct tlv_supported_band)
	},
};

DEFINE_POLICY(CMDU_TYPE_AP_AUTOCONFIGURATION_WSC) = {
	[0] = { .type = TLV_TYPE_WSC,
		.present = TLV_PRESENT_ONE
	},
};

DEFINE_POLICY(CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION) = {
	[0] = {
		.type = TLV_TYPE_AL_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6
	},
	[1] = { .type = TLV_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION,
		.present = TLV_PRESENT_ONE
	},
};

DEFINE_POLICY(CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION) = {
	[0] = { .type = TLV_TYPE_AL_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6
	},
	[1] = { .type = TLV_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION,
		.present = TLV_PRESENT_ONE,
		.len = sizeof(struct tlv_pbc_join_notification)
	},
};

DEFINE_POLICY(CMDU_TYPE_HIGHER_LAYER_RESPONSE) = {
	[0] = { .type = TLV_TYPE_AL_MAC_ADDRESS_TYPE,
		.present = TLV_PRESENT_ONE,
		.len = 6
	},
	[1] = { .type = TLV_TYPE_1905_PROFILE_VERSION,
		.present = TLV_PRESENT_ONE,
		.len = sizeof(struct tlv_1905_profile)
	},
	[2] = { .type = TLV_TYPE_DEVICE_IDENTIFICATION,
		.present = TLV_PRESENT_ONE,
		.len = sizeof(struct tlv_device_identification)
	},
	[3] = { .type = TLV_TYPE_CONTROL_URL,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
	[4] = { .type = TLV_TYPE_IPV4,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
	[5] = { .type = TLV_TYPE_IPV6,
		.present = TLV_PRESENT_OPTIONAL_ONE
	},
};

DEFINE_POLICY(CMDU_TYPE_LINK_METRIC_QUERY) = {
	[0] = { .type = TLV_TYPE_LINK_METRIC_QUERY,
		.present = TLV_PRESENT_ONE
	},
};

DEFINE_POLICY(CMDU_TYPE_LINK_METRIC_RESPONSE) = {
	[0] = { .type = TLV_TYPE_TRANSMITTER_LINK_METRIC,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
	[1] = { .type = TLV_TYPE_RECEIVER_LINK_METRIC,
		.present = TLV_PRESENT_OPTIONAL_MORE
	},
};

static struct tlv_policy_1905 policy[] = {
	P(CMDU_TYPE_TOPOLOGY_DISCOVERY),
	P(CMDU_TYPE_TOPOLOGY_NOTIFICATION),
	{ 0, NULL },
	P(CMDU_TYPE_TOPOLOGY_RESPONSE),
	{ 0, NULL },
	P(CMDU_TYPE_LINK_METRIC_QUERY),
	P(CMDU_TYPE_LINK_METRIC_RESPONSE),
	P(CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH),
	P(CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE),
	P(CMDU_TYPE_AP_AUTOCONFIGURATION_WSC),
	P(CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW),
	P(CMDU_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION),
	P(CMDU_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION),
	{ 0, NULL },
	P(CMDU_TYPE_HIGHER_LAYER_RESPONSE),
};


/* Slightly modified cmdu_parse_tlvs() for passing flattened tlvs data buffer
 * instead of struct cmdu_buff.
 */
int cmdu_parse_tlvs_raw(const uint8_t *data, size_t datalen, struct tlv *tv[][16],
			struct tlv_policy *policy, int policy_len)
{
	int idx[policy_len];
	struct tlv *t;
	int len;
	int i;


	if (!data || !datalen)
		return -1;

	for (i = 0; i < policy_len; i++) {
		memset(tv[i], 0, 16 * sizeof(struct tlv *));
		idx[i] = 0;
	}
	len = datalen;

	cmdu_for_each_tlv(t, data, len) {
		for (i = 0; i < policy_len; i++) {
			if (policy[i].type != t->type)
				continue;

			if (policy[i].len && tlv_length(t) != policy[i].len)
				return -1;

			if (policy[i].minlen > 0 &&
			    tlv_length(t) < policy[i].minlen)
				continue;

			if (policy[i].maxlen > 0 &&
			    tlv_length(t) > policy[i].maxlen)
				continue;

			//if (tlv_length(t) < tlv_minsize(t))	//TODO: tlv_minsize()
			//	continue;

			if (tv[i][0]) {
				if (policy[i].present == TLV_PRESENT_ONE ||
				    policy[i].present == TLV_PRESENT_OPTIONAL_ONE)
					return -1;
			}

			tv[i][idx[i]++] = t;
		}
	}

	/* malformed cmdu if data remaining; only allow zero padding */
	if (len) {
		int k = 0;

		while (k < len) {
			if (data[datalen - len + k++] != 0)
				return -1;
		}
	}

	/* strictly check against tlv policies */
	for (i = 0; i < policy_len; i++) {
		if ((policy[i].present == TLV_PRESENT_ONE ||
		    policy[i].present == TLV_PRESENT_MORE) && !tv[i][0])
			return -1;
	}

	return 0;
}

int fuzzer_init_ieee1905(struct ubus_context **ctx, uint32_t *id)
{
	uloop_init();
	*ctx = ubus_connect(NULL);
        if (*ctx == NULL) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
        }

        ubus_add_uloop(*ctx);
	if (ubus_lookup_id(*ctx, "ieee1905", id) != UBUS_STATUS_OK) {
		ubus_free(*ctx);
		uloop_done();
		*id = 0;
		return -1;
	}

	return 0;
}

void fuzzer_deinit_ieee1905(struct ubus_context *ctx)
{
	ubus_free(ctx);
	uloop_done();
}

/* valid payloads are saved for corpus generation (with minimal effort)
 * and also to determine the input that caused a crash (if any).
 */
static int save_input(const char *file, struct blob_buf *b)
{
	char *str;

	str = blobmsg_format_json(b->head, true);
	if (str) {
		FILE *fp;

		fp = fopen(file, "a");
                if (fp) {
                        fprintf(fp, "%s", "ubus call ieee1905 cmdu ");
                        fprintf(fp, "'%s'\n", str);
			fclose(fp);
		}
		free(str);
		return 0;
	}

	return -1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const char *fuzz_dst = "02:10:10:11:11:11";  // TODO: from neighbor 1905-alid
	//const char *fuzz_dst_mcast = "01:80:C2:00:00:13";
	struct ubus_context *ctx = NULL;
	char fuzz_cmdutype[8] = {0};
	//uint16_t cmdutype = size ? data[0] % 0x0e : 3;
	uint16_t cmdutype = 0x0e;
	struct tlv_policy *pol;
	struct tlv *tv[12][16];
	uint32_t i1905 = 0;
	int num_pol;
	int ret = 0;


	snprintf(fuzz_cmdutype, sizeof(fuzz_cmdutype), "0x%04x", cmdutype);

	num_pol = policy[cmdutype].num;
	pol = policy[cmdutype].pol;

	/* if cmtutype requires no policy checking */
	if (num_pol == 0 || !pol)
		return 0;

	ret = fuzzer_init_ieee1905(&ctx, &i1905);
	if (ret) {
		fprintf(stderr, "Error connecting ieee1905 for fuzz tests!\n");
		exit(0);
	}


	ret = cmdu_parse_tlvs_raw(data, size, tv, pol, num_pol);
	if (!ret) {
		char *fuzz_data;
		struct blob_buf b = { 0 };

		fuzz_data = calloc(1, (2*size + 1)*sizeof(char));
		if (!fuzz_data)
			goto out;

		blob_buf_init(&b, 0);
		blobmsg_add_string(&b, "dst", fuzz_dst);
		blobmsg_add_u32(&b, "type", cmdutype);
		btostr((uint8_t *)data, size, fuzz_data);
		blobmsg_add_string(&b, "data", fuzz_data);

		save_input("./sendcmdu.log", &b);

		ret = ubus_invoke(ctx, i1905, "cmdu", b.head, NULL, NULL, 3000);
		if (ret) {
			fprintf(stderr, "Error: ubus ieee1905 cmdu (err = %s)\n",
			ubus_strerror(ret));
		}
		blob_buf_free(&b);
		free(fuzz_data);
	}

out:
	fuzzer_deinit_ieee1905(ctx);
	assert(ret == 0);

	return 0;
}

static void fill_random_bytes(uint8_t *buf, size_t len, unsigned int seed)
{
	int i;

	srandom(seed);
	for (i = 0; i < len; i++)
		buf[i] = random() & 0xff;
}

uint8_t *write_tlv(uint8_t tlv_type, uint8_t *buf, size_t len, unsigned int seed)
{
	buf[0] = tlv_type;
	buf_put_be16(&buf[1], len);
	fill_random_bytes(&buf[3], len, seed);

	return &buf[3 + len - 1];
}

/* This function splits a buf of buflen size into num-tlvs with the provided tlvtypes.
 * To have variability, each tlv chunk is based on the passed random seed value.
 */
void split_and_write_tlv(uint8_t *buf, size_t buflen, size_t num_tlvs,
			 uint8_t *tlvtypes, size_t seed, struct tlv_policy *pol)
{
	size_t rem = buflen;
	uint8_t *ptr = buf;
	int i;

	srandom(seed);
	for (i = 0; i < num_tlvs - 1; i++) {
		size_t plen = 0;

		if (pol[i].len)
			plen = pol[i].len;
		else
			plen = rem ? random() % rem : 0;

		ptr = write_tlv(tlvtypes[i], ptr, plen, seed);
		rem -= plen;
		ptr++;
	}

	write_tlv(tlvtypes[i], ptr, rem, seed);
}

/* This function mutates passed data into syntcatically valid payload within maxsize.
 * Only two mutations are performed now. This can be extended as needed.
 * The type of mutation is based on the random seed value passed to the function.
 */
size_t mutate_payload(uint16_t cmdutype, uint8_t *data, size_t size,
		      size_t maxsize, unsigned int seed)
{
#define MAX_TLV_TYPES_IN_CMDU	32
#define NUM_MUTATIONS	2

	uint8_t tlvtypes[MAX_TLV_TYPES_IN_CMDU] = {0};
	size_t available = maxsize - 3;
	struct tlv_policy *pol = NULL;
	size_t newsize = 0;
	size_t minreq = 0;
	int min_pol = 0;
	int num_pol;
	int mutation;
	int i;



	srandom(seed);
	//mutation = random() % NUM_MUTATIONS;
	mutation = 1;

	num_pol = policy[cmdutype].num;
	pol = policy[cmdutype].pol;
	if (!num_pol || !pol) {
		/* no tlvs required for this cmdutype */
		memset(data, 0, 3 * sizeof(uint8_t));
		return 3;
	}

	for (i = 0; i < num_pol; i++) {
		if (pol[i].present == TLV_PRESENT_ONE) {
			tlvtypes[min_pol++] = pol[i].type;
			if (pol[i].len)
				minreq += pol[i].len;
			else if (pol[i].minlen)
				minreq += pol[i].minlen;
		}
	}

	if (available < min_pol * 3 + minreq) {
		/* XXX: no syntactically valid mutations possible with this
		 * cmdutype and maxsize.
		 */
		return 0;
	}

	switch (mutation) {
	case 0:
		{
		int res = 0;

		/* only mandatory tlvs included */
		if (min_pol == 0) {
			memset(data, 0, 3 * sizeof(uint8_t));
			return 3;
		}

		available -= min_pol * 3;
		newsize = min_pol * 3;
		res = available	- newsize;
		if (res > 0)
			newsize += random() % res;

		split_and_write_tlv(data, newsize, min_pol, tlvtypes, seed, pol);
		}
		break;
	case 1:
		{
		int res = 0;

		/* all allowed tlvs for this cmdutype are included */
		if (available < num_pol * 3) {
			/* XXX: mutation not possible with provided maxsize */
			return 0;
		}

		available -= (num_pol * 3 + minreq);
		newsize = num_pol * 3 + minreq;
		res = available	- newsize;
		if (res > 0)
			newsize += random() % res;

		for (i = 0; i < num_pol; i++)
			tlvtypes[i] = pol[i].type;

		split_and_write_tlv(data, newsize, num_pol, tlvtypes, seed, pol);
		}
		break;
	}

	return newsize;
}

size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t maxsize,
			       unsigned int seed)
{
	size_t newsize;
	int ret;

	uint16_t cmdutype;
	int num_pol;
	struct tlv_policy *pol;
	struct tlv *tv[12][16];


	//srandom(seed);
	//cmdutype = random() % 0xe;
	cmdutype = 0xe;
	num_pol = policy[cmdutype].num;
	pol = policy[cmdutype].pol;
	if (num_pol == 0 || !pol) {
		memset(data, 0, 3);
		return 3;
	}

	ret = cmdu_parse_tlvs_raw(data, size, tv, pol, num_pol);
	if (ret) {
		return mutate_payload(cmdutype, data, size, maxsize, seed);
	}

	newsize = LLVMFuzzerMutate(data, size, maxsize);
	ret = cmdu_parse_tlvs_raw(data, size, tv, pol, num_pol);
	if (ret)
		return 0;

	return newsize;
}
