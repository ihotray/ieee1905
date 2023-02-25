/*
 * i1905_security.h - 1905 security header file.
 *
 * Copyright (C) 2021-2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef I1905_SECURITY_H
#define I1905_SECURITY_H


#define NONCE_LEN	32
#define PMK_LEN		32
#define GMK_LEN		32
#define GTK_LEN		32
#define PMKID_LEN	16
#define KEY_RSC_LEN	8
#define REPLAY_CNT_LEN	8


/* From Table-12.10 IEEE-802.11 Std., for HMAC-SHA-256,
 * KCK_bits = 128, KEK_bits = 128.
 *
 * And, from Table 12.7, for Cipher = CCMP-128,
 * key-length = 16 octets, TK_bits = 128.
 */
#define KCK_LEN		16
#define KEK_LEN		16
#define TK_LEN		16


/** struct i1905_ptk - pairwise transient key */
struct i1905_ptk {
	uint8_t kck[KCK_LEN];
	uint8_t kek[KEK_LEN];
	uint8_t tk[TK_LEN];
	size_t kck_len;
	size_t kek_len;
	size_t tk_len;
	int installed;
};

int i1905_generate_gmk(uint8_t *gmk, size_t len);

int i1905_calc_ptk(uint8_t *pmk, size_t pmk_len, const char *label,
		   uint8_t *addr1, uint8_t *addr2,
		   uint8_t *nonce1, uint8_t *nonce2,
		   struct i1905_ptk *ptk);


int i1905_calc_gtk(uint8_t *gmk, const char *label, uint8_t *aa,
		   uint8_t *gnonce, uint8_t *gtk, size_t gtk_len);

void i1905_inc_integrity_counter(uint8_t *counter, int sizeof_counter);

#endif /* I1905_SECURITY_H */
