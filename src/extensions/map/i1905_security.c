/*
 * i1905_security.c - implements 1905 security as needed by Easymesh.
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
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* remove following includes */
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>
/*-----------------------*/

#include "debug.h"
#include "util.h"
#include "cmdu.h"
#include "cryptutil.h"

#include "1905_tlvs.h"
#include "easymesh.h"

#include "timer.h"
#include "config.h"
#include "cmdu.h"
#include "cmdu_ackq.h"
#include "cmdufrag.h"
#include "i1905_dm.h"
#include "i1905.h"

#include "i1905_security.h"
#include "i1905_eapol.h"

#ifndef ETH_ALEN
#define ETH_ALEN	6
#endif


/** i1905_generate_gmk() - generate random GMK. */
int i1905_generate_gmk(uint8_t *gmk, size_t len)
{
	get_random_bytes(len, gmk);
	return 0;
}

/**
 * i1905_calc_ptk - calculate PTK from PMK.
 *
 * PRF-Length(PMK, "Pairwise key expansion",
 *	      Min(AA, SPA) || Max(AA, SPA) ||
 *	      Min(ANonce, SNonce) || Max(ANonce, SNonce))
 */
int i1905_calc_ptk(uint8_t *pmk, size_t pmk_len, const char *label,
		   uint8_t *addr1, uint8_t *addr2,
		   uint8_t *nonce1, uint8_t *nonce2,
		   struct i1905_ptk *ptk)
{
	uint8_t tmp[KCK_LEN + KEK_LEN + TK_LEN];
	size_t data_len = 2 * ETH_ALEN + 2 * NONCE_LEN;
	uint8_t data[data_len];
	size_t ptk_len;
	int ret;


	if (pmk_len != PMK_LEN) {
		fprintf(stderr, "%s: invalid PMK length\n", __func__);
		return -1;
	}

	if (memcmp(addr1, addr2, ETH_ALEN) < 0) {
		memcpy(data, addr1, ETH_ALEN);
		memcpy(data + ETH_ALEN, addr2, ETH_ALEN);
	} else {
		memcpy(data, addr2, ETH_ALEN);
		memcpy(data + ETH_ALEN, addr1, ETH_ALEN);
	}

	if (memcmp(nonce1, nonce2, NONCE_LEN) < 0) {
		memcpy(data + 2 * ETH_ALEN, nonce1, NONCE_LEN);
		memcpy(data + 2 * ETH_ALEN + NONCE_LEN, nonce2, NONCE_LEN);
	} else {
		memcpy(data + 2 * ETH_ALEN, nonce2, NONCE_LEN);
		memcpy(data + 2 * ETH_ALEN + NONCE_LEN, nonce1, NONCE_LEN);
	}

	ptk->kck_len = KCK_LEN;
	ptk->kek_len = KEK_LEN;
	ptk->tk_len = TK_LEN;
	ptk_len = ptk->kck_len + ptk->kek_len + ptk->tk_len;

	ret = SHA256_PRF(pmk, pmk_len, label, data, data_len, tmp, ptk_len);
	if (ret < 0)
		return -1;

	//bufprintf(pmk, pmk_len, "PMK");
	//bufprintf(tmp, ptk_len, "PTK");
	memcpy(ptk->kck, tmp, ptk->kck_len);
	memcpy(ptk->kek, tmp + ptk->kck_len, ptk->kek_len);
	memcpy(ptk->tk, tmp + ptk->kck_len + ptk->kek_len, ptk->tk_len);

	memset(tmp, 0, sizeof(tmp));
	memset(data, 0, data_len);
	return 0;
}


/**
 * i1905_calc_gtk() - calculate GTK from GMK.
 *
 * PRF-Length(GMK, "Group key expansion", AA || GNonce)
 */
int i1905_calc_gtk(uint8_t *gmk, const char *label, uint8_t *aa,
		   uint8_t *gnonce, uint8_t *gtk, size_t gtk_len)
{
	uint8_t data[ETH_ALEN + NONCE_LEN + 8 + GTK_LEN];
	uint8_t *pos;
	int ret = 0;

	memset(data, 0, sizeof(data));
	memcpy(data, aa, ETH_ALEN);
	memcpy(data + ETH_ALEN, gnonce, NONCE_LEN);
	pos = data + ETH_ALEN + NONCE_LEN;
	get_random_bytes(8, pos);
	pos += 8;
	get_random_bytes(gtk_len, pos);

	ret = SHA256_PRF(gmk, GMK_LEN, label, data, sizeof(data), gtk, gtk_len);
	if (ret < 0)
		return -1;

	memset(data, 0, sizeof(data));
	return ret;
}

/**
 * i1905_inc_integrity_counter() - increment replay bytes counter
 */
void i1905_inc_integrity_counter(uint8_t *counter, int sizeof_counter)
{
	int i;

	for (i = sizeof_counter - 1; i >= 0; i--) {
		counter[i]++;
		if (counter[i] != 0)
			break;
	}
}

/* The passed cmdu must have EOM */
int cmdu_append_mic(struct cmdu_buff *cmdu, uint8_t *key, uint8_t *itc,
		    uint8_t *macaddr)
{
	uint8_t micbuf[15 + SHA256_MAC_LEN] = {0};
	const uint8_t *addr[3];
	size_t len[3];
	int ret;
	struct tlv *t;

	memcpy(&micbuf[1], itc, 6);
	memcpy(&micbuf[7], macaddr, 6);
	buf_put_be16(&micbuf[13], SHA256_MAC_LEN);

	addr[0] = (const uint8_t *)cmdu->cdata;
	addr[1] = micbuf;
	addr[2] = cmdu->data;
	len[0] = 6;
	len[1] = 13;
	len[2] = cmdu->datalen;

	ret = PLATFORM_HMAC_SHA256(key, 32, 3, addr, len, &micbuf[15]);
	if (ret)
		return -1;

	cmdu_pull_eom(cmdu);
	t = cmdu_reserve_tlv(cmdu, sizeof(micbuf));
	if (!t) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	t->type = MAP_TLV_MIC;
	t->len = sizeof(micbuf);
	memcpy(t->data, micbuf, sizeof(micbuf));
	ret = cmdu_put_tlv(cmdu, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	cmdu_put_eom(cmdu);
	return 0;
}

/* The passed cmdu must have EOM. If successful, update irc */
int cmdu_verify_mic(struct cmdu_buff *cmdu, uint8_t *key, uint8_t *irc,
		     uint8_t *macaddr)
{
	uint8_t rxmic[SHA256_MAC_LEN] = {0};
	const uint8_t *addr[3];
	uint16_t tlen = 0;
	struct tlv *t;
	size_t len[3];
	int ret;


	t = cmdu_peek_tlv(cmdu, MAP_TLV_MIC);
	if (!t)
		return -1;

	tlen = tlv_length(t);
	if (tlen != (sizeof(struct tlv_mic) + SHA256_MAC_LEN))
		return -1;

	memset((uint8_t *)t, 0, 3);	/* temp put eom for mic calculation */

	addr[0] = (const uint8_t *)cmdu->cdata;
	addr[1] = t->data;
	addr[2] = cmdu->data;
	len[0] = 6;
	len[1] = 13;
	len[2] = cmdu->datalen - 50;	/* tlv_total_len(mic) = 47 + 3 */

	ret = PLATFORM_HMAC_SHA256(key, 32, 3, addr, len, rxmic);
	if (ret)
		return -1;

	if (memcmp(rxmic, &t->data[15], SHA256_MAC_LEN)) {
		fprintf(stderr, "%s: error: MIC mismatch\n", __func__);
		return -1;
	}

	t->type = MAP_TLV_MIC;
	BUF_PUT_BE16(t->len, tlen);

	//TODO: update irc

	return 0;
}

/* The passed cmdu should not have EOM;
 * Key = TK of PTK;
 * src = src-aladdr;
 * dst = dst-aladdr
 */
int cmdu_encrypt(struct cmdu_buff *cmdu, uint8_t *key, uint8_t *etc,
		 uint8_t *src, uint8_t *dst)
{
	size_t plen = cmdu->datalen;
	uint8_t out[AES_BLOCK_SIZE + plen];
	struct tlv_enc_payload *e;
	const uint8_t *addr[4];
	size_t len[4];
	struct tlv *t;
	uint8_t *p;
	int ret;


	p = cmdu->data;

	addr[0] = (const uint8_t *)cmdu->cdata;
	len[0] = 6;

	addr[1] = etc;
	len[1] = 6;

	addr[2] = src;
	len[2] = 6;

	addr[3] = dst;
	len[3] = 6;

	printf("sizeof(out) = %zu\n", sizeof(out));

	ret = AES_SIV_ENCRYPT(key, 32, p, plen, 4, addr, len, out);
	if (ret) {
		fprintf(stderr, "%s: error: aes-siv encrypt failed\n", __func__);
		return -1;
	}


	/* replace plaintext tlvs with encrypted tlv payload */
	cmdu->tail -= plen;
	cmdu->datalen -= plen;

	t = cmdu_reserve_tlv(cmdu, sizeof(struct tlv_enc_payload) + sizeof(out));
	if (!t) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	t->type = MAP_TLV_ENCRYPTED_PAYLOAD;
	t->len = sizeof(struct tlv_enc_payload) + sizeof(out);
	e = (struct tlv_enc_payload *)t->data;
	memcpy(e->etc, etc, 6);
	memcpy(e->src, src, 6);
	memcpy(e->dst, dst, 6);
	BUF_PUT_BE16(e->len, sizeof(out));
	memcpy(e->enc, out, sizeof(out));
	ret = cmdu_put_tlv(cmdu, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	cmdu_put_eom(cmdu);
	//bufprintf("Encrypted-Payload", e->enc, BUF_GET_BE16(e->len));
	bufprintf(cmdu->data, cmdu->datalen, "Encrypted CMDU");

	return 0;
}

int cmdu_decrypt(struct cmdu_buff *cmdu, uint8_t *key, uint8_t *erc,
		 uint8_t *src, uint8_t *dst)
{
	struct tlv_enc_payload *e;
	const uint8_t *addr[4];
	struct tlv *t;
	size_t len[4];
	size_t zlen;
	int ret;


	t = cmdu_peek_tlv(cmdu, MAP_TLV_ENCRYPTED_PAYLOAD);
	if (!t)
		return -1;

	e = (struct tlv_enc_payload *)t->data;
	zlen = BUF_GET_BE16(e->len);

	addr[0] = (const uint8_t *)cmdu->cdata;
	len[0] = 6;

	addr[1] = e->etc;
	len[1] = 6;

	addr[2] = e->src;
	len[2] = 6;

	addr[3] = e->dst;
	len[3] = 6;


	uint8_t out[zlen];

	ret = AES_SIV_DECRYPT(key, 32, e->enc, zlen, 4, addr, len, out);
	if (ret) {
		fprintf(stderr, "%s: error: aes-siv decrypt failed\n", __func__);
		return -1;
	}

	/* replace encrypted payload with decrypted plaintext */
	memcpy(cmdu->data, out, zlen - AES_BLOCK_SIZE);
	cmdu->datalen = zlen - AES_BLOCK_SIZE;
	cmdu->tail = cmdu->data + cmdu->datalen;

	cmdu_put_eom(cmdu);

	//bufprintf("Plaintext-Payload", out, zlen - AES_BLOCK_SIZE);
	bufprintf(cmdu->data, cmdu->datalen, "Decrypted CMDU");

	return 0;
}

struct cmdu_buff *i1905_build_encap_eapol(struct i1905_interface *iface,
					  uint8_t *eapol, size_t len)
{
	struct cmdu_buff *frm = NULL;
	uint16_t mid = 0x1111;	/* dummy */
	struct tlv *t;
	int ret = 0;


	//trace("%s: Build ENCAP-EAPOL\n", __func__);
	frm = cmdu_alloc_simple(CMDU_1905_ENCAP_EAPOL, &mid);
	if (!frm) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	/* prepare the only encapped TLV */
	t = cmdu_reserve_tlv(frm, 512);
	if (!t) {
		cmdu_free(frm);
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	t->type = MAP_TLV_1905_ENCAP_EAPOL;
	t->len = len;
	memcpy(t->data, eapol, len);
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		cmdu_free(frm);
		return NULL;
	}

	cmdu_put_eom(frm);

	return frm;
}

int i1905_send_encap_eapol_frame(struct i1905_interface *iface, uint8_t *dest,
				 uint16_t *mid,
				 uint8_t *eapol, size_t len)
{
	struct cmdu_buff *frm = NULL;
	int ret = 0;


	trace("%s: [%s] Send ENCAP-EAPOL to " MACFMT "\n", __func__,
	      iface->ifname, MAC2STR(dest));

	frm = i1905_build_encap_eapol(iface, eapol, len);
	if (!frm)
		return -1;

	if (*mid == 0)
		*mid = cmdu_get_next_mid();

	cmdu_set_mid(frm, *mid);

	ret = i1905_send_cmdu(iface->priv, iface->vid, dest, iface->aladdr,
			      ETHERTYPE_1905, frm);
	if (ret) {
		fprintf(stderr, "Error sending ENCAP-EAPOL FRAME\n");
	}

	cmdu_free(frm);

	return 0;
}

#if 0
int test_main()
{
	/* Test vector from IEEE P802.11az/D2.6, J.13 */
	uint8_t pmk[] = {
		0xde, 0xf4, 0x3e, 0x55, 0x67, 0xe0, 0x1c, 0xa6,
		0x64, 0x92, 0x65, 0xf1, 0x9a, 0x29, 0x0e, 0xef,
		0xf8, 0xbd, 0x88, 0x8f, 0x6c, 0x1d, 0x9c, 0xc9,
		0xd1, 0x0f, 0x04, 0xbd, 0x37, 0x8f, 0x3c, 0xad
	};
	uint8_t aa[] = {
		0xc0, 0xff, 0xd4, 0xa8, 0xdb, 0xc1
	};
	uint8_t sa[] = {
		0x00, 0x90, 0x4c, 0x01, 0xc1, 0x07
	};
	uint8_t anonce[] = {
		0xbe, 0x7a, 0x1c, 0xa2, 0x84, 0x34, 0x7b, 0x5b,
		0xd6, 0x7d, 0xbd, 0x2d, 0xfd, 0xb4, 0xd9, 0x9f,
		0x1a, 0xfa, 0xe0, 0xb8, 0x8b, 0xa1, 0x8e, 0x00,
		0x87, 0x18, 0x41, 0x7e, 0x4b, 0x27, 0xef, 0x5f
	};
	uint8_t snonce[] = {
		0x40, 0x4b, 0x01, 0x2f, 0xfb, 0x43, 0xed, 0x0f,
		0xb4, 0x3e, 0xa1, 0xf2, 0x87, 0xc9, 0x1f, 0x25,
		0x06, 0xd2, 0x1b, 0x4a, 0x92, 0xd7, 0x4b, 0x5e,
		0xa5, 0x0c, 0x94, 0x33, 0x50, 0xce, 0x86, 0x71
	};

	struct i1905_ptk ptk;
	int ret;

	/* calc-ptk */
	ret = i1905_calc_ptk(pmk, sizeof(pmk),
			     "Pairwise key expansion",
			     sa, aa, snonce, anonce,
			     &ptk);
	if (ret) {
		fprintf(stderr, "error calculating ptk from pmk\n");
		return ret;
	}


	uint8_t GTK[32] = {0};
	uint8_t GMK[32];

	/* generate random gmk and calc-gtk */
	i1905_generate_gmk(GMK, GMK_LEN);
	ret = i1905_calc_gtk(GMK, "Group key expansion", aa, snonce, GTK, 32);
	if (ret) {
		fprintf(stderr, "error calculating gtk from gmk\n");
		return ret;
	}
	bufprintf(GTK, 32, "GTK");


	/* increment counter test */
	uint8_t itc[6] = {0};

	for (int i = 0; i < 1024; i++) {
		i1905_inc_integrity_counter(itc, sizeof(itc));
		printf("[%d] : %02x-%02x-%02x-%02x-%02x-%02x\n", i, MAC2STR(itc));
	}

	/* encrypt-decrypt test */
	struct cmdu_buff *frm;
	size_t tlvbuflen = 1000;
	uint8_t tlvbuf[1000];
	uint8_t etc[6] = {0};
	uint8_t erc[6] = {0};


	for (int i = 0; i < 1000; i++)
		tlvbuf[i] = i % 0xff;

	fprintf(stderr, "cmdu-len = %zd\n", tlvbuflen);

	frm = cmdu_alloc_frame(tlvbuflen + 256);
	ret = cmdu_put(frm, tlvbuf, tlvbuflen);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put()\n", __func__);
		cmdu_free(frm);
		return ret;
	}

	bufprintf(frm->data, frm->datalen, "Plaintext CMDU");
	cmdu_encrypt(frm, ptk.tk, etc, aa, sa);
	bufprintf(frm->data, frm->datalen, "Encrypted CMDU");

	cmdu_decrypt(frm, ptk.tk, erc, sa, aa);
	bufprintf(frm->data, frm->datalen, "Decrypted CMDU");


	/* eapol-key 4-way-hs exchange test */
	struct i1905_eapol_sm sm = {0};

	memcpy(sm.pmk, pmk, sizeof(pmk));
	sm.pmklen = sizeof(pmk);
	memcpy(sm.gtk, GTK, sizeof(GTK));
	sm.gtklen = sizeof(GTK);
	memcpy(sm.own_macaddr, aa, 6);
	memcpy(sm.aa, aa, 6);
	memcpy(sm.sa, sa, 6);
	memcpy(sm.anonce, anonce, sizeof(anonce));
	memcpy(sm.snonce, snonce, sizeof(snonce));

	ret = i1905_send_eapol_msg1(&sm, sa, anonce);
	return ret;
}
#endif
