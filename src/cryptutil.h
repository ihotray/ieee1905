/*
 * cryptutil.h
 * utility functions for crypt and hashing.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */


#ifndef CRYPT_UTIL_H
#define CRYPT_UTIL_H

#include <stdint.h>
#include <sys/types.h>


#define SHA256_MAC_LEN	32
#define AES_BLOCK_SIZE	16

int PLATFORM_GENERATE_DH_KEY_PAIR(uint8_t **priv, uint16_t *priv_len,
				      uint8_t **pub, uint16_t *pub_len);

int PLATFORM_COMPUTE_DH_SHARED_SECRET(uint8_t **shared_secret,
					uint16_t *shared_secret_len,
					uint8_t *remote_pub,
					uint16_t remote_pub_len,
					uint8_t *local_priv,
					uint8_t local_priv_len);


int PLATFORM_SHA256(size_t num_elem, const uint8_t *addr[], const size_t *len,
		    uint8_t *mac);



int PLATFORM_HMAC_SHA256(const uint8_t *key, size_t key_len, size_t num_elem,
			 const uint8_t *addr[], const size_t *len, uint8_t *mac);


int SHA256_PRF(const uint8_t *key, size_t key_len, const char *label,
	       const uint8_t *data, size_t data_len, uint8_t *buf, size_t buf_len);

int PLATFORM_AES_ENCRYPT(uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t data_len);
int PLATFORM_AES_DECRYPT(uint8_t *key, uint8_t *iv, uint8_t *data, uint32_t data_len);


int AES_WRAP_128(uint8_t *key, uint8_t *plain, size_t plen,
		 uint8_t *cipher, size_t *clen);

int AES_UNWRAP_128(uint8_t *key, uint8_t *cipher, size_t clen,
		   uint8_t *plain, size_t *plen);


int omac1_aes_vector(const uint8_t *key, size_t key_len, size_t num_elem,
		     const uint8_t *addr[], const size_t *len, uint8_t *mac);

int aes_ctr_encrypt(const uint8_t *key, size_t key_len, const uint8_t *nonce,
		    uint8_t *data, size_t data_len);

int AES_SIV_ENCRYPT(const uint8_t *key, size_t key_len,
		    const uint8_t *pw, size_t pwlen,
		    size_t num_elem, const uint8_t *addr[], const size_t *len,
		    uint8_t *out);
int AES_SIV_DECRYPT(const uint8_t *key, size_t key_len,
		    const uint8_t *iv_crypt, size_t iv_c_len,
		    size_t num_elem, const uint8_t *addr[], const size_t *len,
		    uint8_t *out);


#endif /* CRYPT_UTIL_H */
