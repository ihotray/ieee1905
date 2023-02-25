/*
 * i1905_eapol.h - EAPOL frame definitions for 4Way-HS.
 *
 * Copyright (C) 2021-2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef I1905_EAPOL_H
#define I1905_EAPOL_H


#define EAPOL_HLEN		4
#define EAPOL_VERSION		2
#define EAPOL_KEY_FRAME		3
#define EAPOL_KEY_TYPE_RSN	2

#define EAPOL_KEY_INFO_TYPE_MASK		((uint16_t)(BIT(0) | BIT(1) | BIT(2)))

#define EAPOL_KEY_INFO_DESC_VERSION_MASK	((uint16_t)(BIT(0) | BIT(1) | BIT(2)))

#define EAPOL_KEY_INFO_TYPE_AKM_DEFINED		0
#define EAPOL_KEY_INFO_TYPE_HMAC_MD5_RC4	BIT(0)
#define EAPOL_KEY_INFO_TYPE_HMAC_SHA1_AES	BIT(1)
#define EAPOL_KEY_INFO_TYPE_AES_128_CMAC	3

#define EAPOL_KEY_INFO_KEY_TYPE		BIT(3)
#define EAPOL_KEY_INFO_PAIRWISE		BIT(3)	/* pairwise = 1; group = 0 */

#define EAPOL_KEY_INFO_INSTALL		BIT(6)
#define EAPOL_KEY_INFO_ACK		BIT(7)
#define EAPOL_KEY_INFO_MIC		BIT(8)
#define EAPOL_KEY_INFO_SECURE		BIT(9)
#define EAPOL_KEY_INFO_ERROR		BIT(10)
#define EAPOL_KEY_INFO_REQUEST		BIT(11)
#define EAPOL_KEY_INFO_ENCR_KEY_DATA	BIT(12)

#define WPA_KEY_MGMT_SAE BIT(10)
#define WPA_CIPHER_CCMP BIT(4)


/* EAPOL-Key frame */
struct eapol_frame {
	/* eapol frame header */
	uint8_t version;
	uint8_t type;
	uint16_t length;

	/* eapol-key frame */
	uint8_t keydesc;
	uint8_t keyinfo[2];
	uint16_t keylen;
	uint8_t replay_cnt[REPLAY_CNT_LEN];
	uint8_t nonce[NONCE_LEN];
	uint8_t iv[16];
	uint8_t rsc[8];
	uint8_t keyid[8];
	uint8_t mic[16];
	uint16_t keydata_len;
	uint8_t keydata[];
} __attribute__ ((packed));

/* GTK-KDE keydata */
struct gtk_kde {
	uint8_t id;
	uint8_t len;
	uint8_t oui[3];
	uint8_t type;
	uint8_t keyid;	/* bits(0-1) */
	uint8_t gtk[32];
} __attribute__ ((packed));

#define WFA_OUI		"\x50\x6F\x9A"
#define GTK_KDE_LEN	37
#define GTK_KEY_ID	1

enum i1905_eapol_sm_state {
	INITPMK,
	PTKSTART,
	PTKCALCNEGOTIATING,
	PTKINITNEGOTIATING,
	PTKINITDONE,
	KEYERROR,
	TIMEOUT = KEYERROR,
	IDLE,
	REKEYNEGOTIATING,
	REKEYESTABLISHED,
};

enum i1905_eapol_sm_state_supplicant {
	UNKNOWN,
	STAKEYSTART,
	MICOK,
	FAILED,
};

struct i1905_eapol_sm {
	uint8_t own_macaddr[6];
	uint8_t aa[6];
	uint8_t sa[6];
	enum i1905_eapol_sm_state state;
	atimer_t tm;
	uint8_t num_timeout;
#define I1905_EAPOL_MSG_RETRY_MAX	3
	bool secured;
	bool reset_snonce;
	uint8_t gtk[GTK_LEN];
	size_t gtklen;
	bool tptk_set;
	struct i1905_ptk tptk;
	bool ptk_set;
	bool ptk_valid;
	struct i1905_ptk ptk;
	bool rx_replay_cnt_set;
	uint8_t rx_replay_cnt[REPLAY_CNT_LEN];
	uint8_t tx_replay_cnt[REPLAY_CNT_LEN];
	uint8_t pmk[PMK_LEN];
	size_t pmklen;
	uint8_t anonce[NONCE_LEN];
	uint8_t snonce[NONCE_LEN];
};

#endif /* I1905_EAPOL_H */
