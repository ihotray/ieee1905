/*
 * i1905_eapol.c - implements EAPOL 4Way-HS as needed by 1905 security.
 *
 * Copyright (C) 2021-2022 IOPSYS Software Solutions AB. All rights reserved.
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

#include "debug.h"
#include "util.h"
#include "timer.h"
#include "bufutil.h"
#include "cryptutil.h"

#include "i1905_security.h"
#include "i1905_eapol.h"


int i1905_process_eapol(struct i1905_eapol_sm *sm, uint8_t *addr, uint8_t *buf, size_t len);


int i1905_send_eapol_frame(struct i1905_eapol_sm *sm, uint8_t *addr,
			   struct eapol_frame *frm, size_t len)
{
	//TODO: i1905_send_encap_eapol_frame(iface, addr, sm->mid, frm, len);
	bufprintf((uint8_t *)frm, len, "Tx EAPOL-Key");

#ifdef TEST
	i1905_process_eapol(sm, addr, (uint8_t *)frm, len);
#endif

	return 0;
}

int i1905_send_eapol(struct i1905_eapol_sm *sm, uint8_t *addr, struct eapol_frame *frm,
		     size_t len, struct i1905_ptk *ptk)
{
	//TODO: i1905_send_encap_eapol_frame(iface, addr, sm->mid, frm, len);
	//sm->use_ptk
	bufprintf((uint8_t *)frm, len, "Tx EAPOL-Keyx");

#ifdef TEST
	i1905_process_eapol(sm, addr, (uint8_t *)frm, len);
#endif
	return 0;
}

int i1905_install_gtk(struct i1905_eapol_sm *sm, uint8_t *addr, uint8_t *gtk, size_t gtklen)
{
	//TODO: use GTK
	fprintf(stderr, "GTK installed from " MACFMT "\n", MAC2STR(addr));
	return 0;
}

int i1905_install_ptk(struct i1905_eapol_sm *sm, uint8_t *addr, struct i1905_ptk *ptk)
{
	//TODO: use PTK
	fprintf(stderr, "PTK installed for " MACFMT "\n", MAC2STR(addr));
	return 0;
}

int i1905_calc_eapol_key_mic(struct eapol_frame *frm, size_t len,
			     uint8_t *key, size_t keylen)
{
	uint8_t hash[64] = {0};
	int ret;

	const uint8_t *addr[1];
	size_t addrlen[1];

	addr[0] = (const uint8_t *)frm;
	addrlen[0] = len;

	//bufprintf((uint8_t *)frm, len, "Calculating MIC for frame");

	ret = PLATFORM_HMAC_SHA256(key, keylen, 1, addr, addrlen, hash);
	if (!ret) {
		memcpy(frm->mic, hash, keylen);
		bufprintf(frm->mic, 16, "calc-MIC");
	}

	return ret;
}

int i1905_verify_eapol_key_mic(struct i1905_eapol_sm *sm, struct eapol_frame *frm, size_t len)
{
	uint8_t rxmic[16];
	int ret = -1;

	memcpy(rxmic, frm->mic, 16);
	if (sm->tptk_set) {
		uint8_t tmic[64] = {0};

		const uint8_t *addr[1];
		size_t addrlen[1];


		memset(frm->mic, 0, sizeof(frm->mic));
		addr[0] = (const uint8_t *)frm;
		addrlen[0] = len;

		//bufprintf((uint8_t *)frm, len, "Verifying MIC for frame");
		//bufprintf(sm->tptk.kck, sm->tptk.kck_len, "MIC kck");
		ret = PLATFORM_HMAC_SHA256(sm->tptk.kck, sm->tptk.kck_len, 1,
					   addr, addrlen, tmic);
		if (!ret) {
			//bufprintf(tmic, 16, "re-calc-MIC");
			ret = memcmp(rxmic, tmic, 16);
		}

		if (ret) {
			fprintf(stderr, "%s: MIC mismatch!\n", __func__);
			return -1;
		}

		/* mic verified */
		memcpy(frm->mic, tmic, 16);
		sm->ptk_set = true;
		memcpy(&sm->ptk, &sm->tptk, sizeof(sm->ptk));
		//sm->tptk_set = false;
		//memset(&sm->tptk, 0, sizeof(sm->tptk));

		memcpy(sm->rx_replay_cnt, frm->replay_cnt, REPLAY_CNT_LEN);
		sm->rx_replay_cnt_set = true;
	}

	return ret;
}

int i1905_send_eapol_msg2(struct i1905_eapol_sm *sm, uint8_t *addr,
			  struct eapol_frame *msg1,
			  uint8_t *nonce,
			  struct i1905_ptk *ptk)
{
	struct eapol_frame *frm;
	uint16_t keyinfo = 0;
	int ret;


	frm = calloc(1, sizeof(struct eapol_frame));
	if (!frm) {
		fprintf(stderr, "%s: calloc failed\n", __func__);
		return -1;
	}

	frm->version = EAPOL_VERSION;
	frm->type = EAPOL_KEY_FRAME;
	frm->length = htons(sizeof(struct eapol_frame) - EAPOL_HLEN);
	frm->keydesc = EAPOL_KEY_TYPE_RSN;

	keyinfo = EAPOL_KEY_INFO_TYPE_HMAC_SHA1_AES |
		  EAPOL_KEY_INFO_MIC |
		  EAPOL_KEY_INFO_PAIRWISE;

	BUF_PUT_BE16(frm->keyinfo, keyinfo);
	BUF_PUT_BE16(frm->keylen, 0);
	memcpy(frm->nonce, nonce, NONCE_LEN);
	memcpy(frm->replay_cnt, msg1->replay_cnt, REPLAY_CNT_LEN);
	//bufprintf(frm->replay_cnt, REPLAY_CNT_LEN, "Msg2 Replay Counter");

	ret = i1905_calc_eapol_key_mic(frm, sizeof(struct eapol_frame), ptk->kck, ptk->kck_len);
	if (ret) {
		fprintf(stderr, "EAPOL-Key: failed to generate MIC for msg2\n");
		goto out;
	}

	ret = i1905_send_eapol_frame(sm, addr, frm, sizeof(struct eapol_frame));

out:
	free(frm);
	return ret;
}

int i1905_process_eapol_msg1(struct i1905_eapol_sm *sm, uint8_t *addr,
			     struct eapol_frame *msg1)
{
	struct i1905_ptk *ptk;
	int ret;


	ptk = &sm->tptk;
	ret = i1905_calc_ptk(sm->pmk, sm->pmklen,
			 "Pairwise key expansion",
			 /* sm->own_macaddr */ sm->sa,
			 /* addr */ sm->aa, sm->snonce, msg1->nonce,
			 ptk);
	if (ret) {
		fprintf(stderr, "EAPOL-Key: calc-ptk() failed\n");
		return -1;
	}

	//bufprintf(ptk->kck, ptk->kck_len, "PTK kck");
	sm->tptk_set = true;
	ret = i1905_send_eapol_msg2(sm, addr, msg1, sm->snonce, ptk);
	if (ret) {
		fprintf(stderr, "%s: failed to send msg2\n", __func__);
		return -1;
	}

	memcpy(sm->anonce, msg1->nonce, NONCE_LEN);
	return 0;
}

int i1905_send_eapol_msg4(struct i1905_eapol_sm *sm, uint8_t *addr,
			  struct eapol_frame *msg3, struct i1905_ptk *ptk)
{
	struct eapol_frame *frm;
	uint16_t keyinfo = 0;
	int ret;


	frm = calloc(1, sizeof(struct eapol_frame));
	if (!frm)
		return -1;

	frm->version = EAPOL_VERSION;
	frm->type = EAPOL_KEY_FRAME;
	frm->length = htons(sizeof(struct eapol_frame) - EAPOL_HLEN);
	frm->keydesc = EAPOL_KEY_TYPE_RSN;
	keyinfo = EAPOL_KEY_INFO_TYPE_HMAC_SHA1_AES |
		  EAPOL_KEY_INFO_SECURE |
		  EAPOL_KEY_INFO_MIC |
		  EAPOL_KEY_INFO_PAIRWISE;

	BUF_PUT_BE16(frm->keyinfo, keyinfo);
	BUF_PUT_BE16(frm->keylen, 0);
	memcpy(frm->replay_cnt, msg3->replay_cnt, REPLAY_CNT_LEN);

	ret = i1905_calc_eapol_key_mic(frm, sizeof(struct eapol_frame), ptk->kck, ptk->kck_len);
	if (ret) {
		fprintf(stderr, "EAPOL-Key: Failed to generate MIC for msg4\n");
		goto out;
	}

	ret = i1905_send_eapol(sm, addr, frm, sizeof(struct eapol_frame), ptk);

out:
	free(frm);
	return ret;
}

int i1905_process_eapol_msg3(struct i1905_eapol_sm *sm, uint8_t *addr,
			     struct eapol_frame *msg3)
{
	uint8_t *gtk = NULL;
	size_t gtk_kdelen = 0;
	struct gtk_kde *gk;
	uint16_t keyinfo;
	int gtk_keyidx;
	int ret;



	keyinfo = BUF_GET_BE16(msg3->keyinfo);

	gtk = msg3->keydata;
	gtk_kdelen = BUF_GET_BE16(msg3->keydata_len);
	if (gtk_kdelen != sizeof(struct gtk_kde)) {
		fprintf(stderr, "%s: incorrect gtk length\n", __func__);
		return -1;
	}

	gk = (struct gtk_kde *)gtk;
	if (gk->id != 0xdd || gk->len != GTK_KDE_LEN ||
	    memcmp(gk->oui, WFA_OUI, 3) || gk->type != 0) {

		fprintf(stderr, "%s: invalid gtk-kde\n", __func__);
		return -1;
	}

	gtk_keyidx = gk->keyid & 0x3;
	(void)gtk_keyidx;	//unused now
	bufprintf(gtk, gtk_kdelen, "Msg3 KeyData");

	if (memcmp(sm->anonce, msg3->nonce, NONCE_LEN)) {
		fprintf(stderr, "EAPOL-Key: msg3 anonce mismatch for " MACFMT "\n", MAC2STR(addr));
		return -1;
	}

	if (BUF_GET_BE16(msg3->keylen) != 16) {
		fprintf(stderr, "EAPOL-Key: invalid keylen from " MACFMT "\n", MAC2STR(addr));
		return -1;
	}

	ret = i1905_send_eapol_msg4(sm, addr, msg3, &sm->ptk);
	if (ret) {
		fprintf(stderr, "%s: failed to send msg4\n", __func__);
		return -1;
	}

	sm->reset_snonce = true;	//TODO: reset_i1905_eapol_sm()

	if (keyinfo & EAPOL_KEY_INFO_INSTALL) {
		ret = i1905_install_ptk(sm, addr, &sm->ptk);
		if (ret) {
			fprintf(stderr, "EAPOL-Key: Failed to install GTK\n");
			return -1;
		}
	}

	if (keyinfo & EAPOL_KEY_INFO_SECURE) {
		/* mark 1905 traffic secured */
		sm->secured = true;
	}

	ret = i1905_install_gtk(sm, addr, gk->gtk, 32);	//TODO: keyid ?
	if (ret) {
		fprintf(stderr, "EAPOL-Key: Failed to install GTK\n");
		return -1;
	}

	return 0;
}

/* Decrypt EAPOL-Key keydata */
int i1905_eapol_decrypt_keydata(struct eapol_frame *frm, uint8_t *kek, size_t kek_len)
{
	uint16_t kdlen = BUF_GET_BE16(frm->keydata_len);
	size_t plen = 0;
	int ret;


	fprintf(stderr, "Encrypted keydata length = %d\n", kdlen);
	bufprintf(frm->keydata, kdlen, "Encrypted keydata");

	/* AES-wrapped keydata */
	if (kdlen < 8 || kdlen % 8) {
		fprintf(stderr, "EAPOL-Key: keydata_len = %hu invalid, ignore.\n", kdlen);
		return -1;
	}

	ret = AES_UNWRAP_128(kek, frm->keydata, kdlen, frm->keydata, &plen);
	if (ret) {
		fprintf(stderr, "EAPOL-Key: Error decrypting keydata\n");
		return -1;
	}

	BUF_PUT_BE16(frm->keydata_len, plen);
	bufprintf(frm->keydata, plen, "Decrypted keydata");

	return 0;
}

int i1905_send_eapol_msg3(struct i1905_eapol_sm *sm, uint8_t *addr,
			  struct eapol_frame *msg2,
			  struct i1905_ptk *ptk)
{
	struct eapol_frame *frm;
	uint16_t keyinfo = 0;
	struct gtk_kde *kde;
	size_t clen = 0;
	size_t len;
	int ret;


	len = sizeof(struct eapol_frame) + sizeof(struct gtk_kde) + 32;	//FIXME
	frm = calloc(1, len);
	if (!frm)
		return -1;

	frm->version = EAPOL_VERSION;
	frm->type = EAPOL_KEY_FRAME;
	frm->length = 0;
	frm->keydesc = EAPOL_KEY_TYPE_RSN;
	keyinfo = EAPOL_KEY_INFO_SECURE |
		  EAPOL_KEY_INFO_MIC |
		  EAPOL_KEY_INFO_ACK |
		  EAPOL_KEY_INFO_INSTALL |
		  EAPOL_KEY_INFO_PAIRWISE |
		  EAPOL_KEY_INFO_ENCR_KEY_DATA |
		  EAPOL_KEY_INFO_TYPE_HMAC_SHA1_AES;

	BUF_PUT_BE16(frm->keyinfo, keyinfo);
	BUF_PUT_BE16(frm->keylen, 16);

	/* inc replay_cnt */
	i1905_inc_integrity_counter(sm->tx_replay_cnt, REPLAY_CNT_LEN);
	memcpy(frm->replay_cnt, sm->tx_replay_cnt, REPLAY_CNT_LEN);
	//bufprintf(frm->replay_cnt, REPLAY_CNT_LEN, "Msg3 Replay Counter");

	memcpy(frm->nonce, sm->anonce, NONCE_LEN);

	BUF_PUT_BE16(frm->keydata_len, 0);

	/* append GTK and AES-WRAP encrypt it */
	kde = (struct gtk_kde *)(frm + 1);
	kde->id = 0xdd;
	kde->len = GTK_KDE_LEN;
	memcpy(kde->oui, WFA_OUI, 3);
	kde->type = 0;
	kde->keyid = GTK_KEY_ID;
	memcpy(kde->gtk, sm->gtk, sm->gtklen);

	//bufprintf(frm->keydata, sizeof(struct gtk_kde), "msg3 Plain keydata");

	ret = AES_WRAP_128(sm->ptk.kek, frm->keydata, sizeof(struct gtk_kde), frm->keydata, &clen);
	if (ret) {
		fprintf(stderr, "EAPOL-Key: Failed to AES-wrap keydata\n");
		goto out;
	}

	//bufprintf(frm->keydata, clen, "msg3 AES-wrapped keydata");
	BUF_PUT_BE16(frm->keydata_len, clen);

	/* update eapol-key frame length */
	frm->length = htons(sizeof(struct eapol_frame) - EAPOL_HLEN + clen);

	ret = i1905_calc_eapol_key_mic(frm, sizeof(struct eapol_frame) + clen, ptk->kck, ptk->kck_len);
	if (ret) {
		fprintf(stderr, "EAPOL-Key: failed to generate MIC for msg3\n");
		goto out;
	}

	ret = i1905_send_eapol(sm, addr, frm, sizeof(struct eapol_frame) + clen, ptk);

out:
	free(frm);
	return ret;
}

int i1905_process_eapol_msg2(struct i1905_eapol_sm *sm, uint8_t *addr,
			     struct eapol_frame *msg2)
{
	struct i1905_ptk PTK;
	int ret;


	sm->state = PTKCALCNEGOTIATING;
	sm->num_timeout = 0;
	/* derive ptk for this 'addr' */
	memset(&PTK, 0, sizeof(PTK));
	ret = i1905_calc_ptk(sm->pmk, sm->pmklen,
			 "Pairwise key expansion",
			 /* sm->own_macaddr */ sm->aa, /* FIXME: own_macaddr */
			 /* addr */ sm->sa,
			 sm->anonce, msg2->nonce,
			 &PTK);
	if (ret) {
		fprintf(stderr, "EAPOL-Key: calc-ptk() error\n");
		return -1;
	}

	/* msg2 MIC already verified in i1905_process_eapol() */

	sm->state = PTKINITNEGOTIATING;
	//bufprintf(PTK.kck, PTK.kck_len, "msg2 PTK kck");
	ret = i1905_send_eapol_msg3(sm, addr, msg2, &PTK);
	if (ret) {
		fprintf(stderr, "EAPOL-Key: failed to send Msg3\n");
		return -1;
	}

	memcpy(&sm->ptk, &PTK, sizeof(PTK));
	memset(&PTK, 0, sizeof(struct i1905_ptk));
	sm->ptk_valid = true;
	return 0;
}

int i1905_process_eapol_msg4(struct i1905_eapol_sm *sm, uint8_t *addr,
			     struct eapol_frame *msg4)
{
	sm->state = PTKINITDONE;
	//TODO verify replay-cnt
	// start enc

	return 0;
}

int i1905_process_eapol(struct i1905_eapol_sm *sm, uint8_t *addr, uint8_t *buf, size_t len)
{
	struct eapol_frame *frm;
	int keydesc_version = 0;
	uint16_t keydata_len;
	uint16_t keyinfo;
	int ret = -1;
	size_t flen;


	if (len < sizeof(struct eapol_frame)) {
		fprintf(stderr, "EAPOL-Key: len = %zu invalid, ignore.\n", len);
		return 0;
	}

	frm = (struct eapol_frame *)buf;
	flen = BUF_GET_BE16(frm->length);

	fprintf(stderr, "EAPOL: Received frame (ver = %d, type = %d, flen = %zu), rx-size = %zu\n",
		frm->version, frm->type, flen, len);

	if (frm->type != EAPOL_KEY_FRAME) {
		fprintf(stderr, "EAPOL: frame type = %d, ignore.\n", frm->type);
		return 0;
	}

	if (flen != len - EAPOL_HLEN) {
		fprintf(stderr, "EAPOL-Key: invalid frame length %zu, ignore.\n", flen);
		return -1;
	}

	if (frm->keydesc != EAPOL_KEY_TYPE_RSN) {
		fprintf(stderr, "EAPOL-Key: desc = 0x%02x, ignore.\n", frm->keydesc);
		return 0;
	}

	keydata_len = BUF_GET_BE16(frm->keydata_len);
	if (keydata_len != len - sizeof(struct eapol_frame)) {
		fprintf(stderr, "EAPOL-Key: invalid keydata_len %hu, ignore.\n", keydata_len);
		return -1;
	}

	keyinfo = BUF_GET_BE16(frm->keyinfo);

	fprintf(stderr, "%s: keyinfo = (S = %d, M = %d, A = %d, I = %d, K = %d, Enc = %d)\n",
			__func__,
			!!(keyinfo & EAPOL_KEY_INFO_SECURE),
			!!(keyinfo & EAPOL_KEY_INFO_MIC),
			!!(keyinfo & EAPOL_KEY_INFO_ACK),
			!!(keyinfo & EAPOL_KEY_INFO_INSTALL),
			!!(keyinfo & EAPOL_KEY_INFO_KEY_TYPE),
			!!(keyinfo & EAPOL_KEY_INFO_ENCR_KEY_DATA));

	keydesc_version = keyinfo & 0x7;
	if (keydesc_version != EAPOL_KEY_INFO_TYPE_HMAC_SHA1_AES) {
		fprintf(stderr, "EAPOL-Key: keydesc version = %d, ignore.\n", keyinfo & 0x7);
		return 0;
	}

#if 0	//TODO: open
	if (sm->rx_replay_cnt_set) {
		if (memcmp(frm->replay_cnt, sm->rx_replay_cnt, REPLAY_CNT_LEN) <= 0) {
			fprintf(stderr, "EAPOL-Key: replay_cnt <= last-replay-cnt, ignore.\n");
			return -1;
		}
	}
#endif

	if (!!(keyinfo & EAPOL_KEY_INFO_REQUEST)) {
		fprintf(stderr, "EAPOL-Key: R=1, ignore.\n");
		return -1;
	}

	if (!(keyinfo & EAPOL_KEY_INFO_KEY_TYPE)) {
		fprintf(stderr, "EAPOL-Key: P=0, ignore.\n");
		return -1;
	}

	if (!!(keyinfo & EAPOL_KEY_INFO_MIC)) {
		ret = i1905_verify_eapol_key_mic(sm, frm, len);
		if (ret) {
			fprintf(stderr, "EAPOL-Key: MIC invalid, ignore.\n");
			return -1;
		}
	}

	if (!!(keyinfo & EAPOL_KEY_INFO_ENCR_KEY_DATA)) {
		if (!(keyinfo & EAPOL_KEY_INFO_MIC)) {
			fprintf(stderr, "EAPOL-Key: E=1, but M=0, ignore\n");
			return -1;
		}

		if (!sm->ptk_set) {
			fprintf(stderr, "EAPOL-Key: KEK not available to decrypt keydata, ignore.\n");
			return -1;
		}

		ret = i1905_eapol_decrypt_keydata(frm, sm->ptk.kek, sm->ptk.kek_len);
		if (ret)
			return -1;
	}

	uint16_t cond1 = (EAPOL_KEY_INFO_ACK |
			  EAPOL_KEY_INFO_PAIRWISE |
			  EAPOL_KEY_INFO_TYPE_HMAC_SHA1_AES);

	uint16_t cond2 = (EAPOL_KEY_INFO_MIC |
			  EAPOL_KEY_INFO_PAIRWISE |
			  EAPOL_KEY_INFO_TYPE_HMAC_SHA1_AES);

	uint16_t cond3 = (EAPOL_KEY_INFO_SECURE |
		     EAPOL_KEY_INFO_MIC |
		     EAPOL_KEY_INFO_ACK |
		     EAPOL_KEY_INFO_INSTALL |
		     EAPOL_KEY_INFO_PAIRWISE |
		     EAPOL_KEY_INFO_ENCR_KEY_DATA |
		     EAPOL_KEY_INFO_TYPE_HMAC_SHA1_AES);

	uint16_t cond4 = (EAPOL_KEY_INFO_SECURE |
		     EAPOL_KEY_INFO_MIC |
		     EAPOL_KEY_INFO_PAIRWISE |
		     EAPOL_KEY_INFO_TYPE_HMAC_SHA1_AES);

	ret = -1;

	//TODO: cond: authenticator/supplicant sm states

	fprintf(stderr, "keyinfo: 0x%04x\n", keyinfo);
	fprintf(stderr, "cond1: 0x%04x\n", cond1);
	fprintf(stderr, "cond2: 0x%04x\n", cond2);
	fprintf(stderr, "cond3: 0x%04x\n", cond3);
	fprintf(stderr, "cond4: 0x%04x\n", cond4);
	fprintf(stderr, "keyinfo: 0x%04x\n", keyinfo);

	if (!(keyinfo ^ cond1))
		ret = i1905_process_eapol_msg1(sm, addr, frm);
	else if (!(keyinfo ^ cond2))
		ret = i1905_process_eapol_msg2(sm, addr, frm);
	else if (!(keyinfo ^ cond3))
		ret = i1905_process_eapol_msg3(sm, addr, frm);
	else if (!(keyinfo ^ cond4))
		ret = i1905_process_eapol_msg4(sm, addr, frm);

	return ret;
}

int i1905_send_eapol_msg1(struct i1905_eapol_sm *sm, uint8_t *addr, uint8_t *nonce)
{
	struct eapol_frame *frm;
	uint16_t keyinfo = 0;
	int ret;


	if (!addr || !nonce)
		return -1;

	frm = calloc(1, sizeof(struct eapol_frame));
	if (!frm)
		return -1;

	frm->version = EAPOL_VERSION;
	frm->type = EAPOL_KEY_FRAME;
	frm->length = htons(sizeof(struct eapol_frame) - EAPOL_HLEN);
	frm->keydesc = EAPOL_KEY_TYPE_RSN;

	keyinfo = EAPOL_KEY_INFO_TYPE_HMAC_SHA1_AES |
		  EAPOL_KEY_INFO_ACK |
		  EAPOL_KEY_INFO_PAIRWISE;

	BUF_PUT_BE16(frm->keyinfo, keyinfo);
	BUF_PUT_BE16(frm->keylen, 16);
	memcpy(frm->nonce, nonce, NONCE_LEN);

	i1905_inc_integrity_counter(sm->tx_replay_cnt, REPLAY_CNT_LEN);
	memcpy(frm->replay_cnt, sm->tx_replay_cnt, REPLAY_CNT_LEN);
	//bufprintf(frm->replay_cnt, REPLAY_CNT_LEN, "Msg1 Replay Counter");

	ret = i1905_send_eapol_frame(sm, addr, frm, sizeof(struct eapol_frame));
	free(frm);

	return ret;
}

void i1905_eapol_timer_cb(atimer_t *t)
{
	struct i1905_eapol_sm *sm = container_of(t, struct i1905_eapol_sm, tm);

	sm->num_timeout++;
	if (sm->num_timeout > I1905_EAPOL_MSG_RETRY_MAX) {
		//i1905_eapol_sm_reset();
		sm->state = TIMEOUT;
		return;
	}

	switch (sm->state) {
	case PTKSTART:
	case PTKCALCNEGOTIATING:
		sm->state = PTKSTART;
		timer_set(t, 2000);
		break;
	case PTKINITNEGOTIATING:
		timer_set(t, 2000);
		break;
	default:
		break;
	}
}

struct i1905_eapol_sm *i1905_eapol_sm_alloc(void)
{
	struct i1905_eapol_sm *sm = calloc(1, sizeof(*sm));

	if (!sm)
		fprintf(stderr, "%s: ENOMEM\n", __func__);

	timer_init(&sm->tm, i1905_eapol_timer_cb);
	return sm;
}

void i1905_eapol_sm_free(struct i1905_eapol_sm *sm)
{
	if (sm) {
		memset(sm, 0, sizeof(*sm));
		free(sm);
	}
}
