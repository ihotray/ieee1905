/*
 * cntlrsync.c - APIs to sync dynamic controller config
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
#include <string.h>
#include <errno.h>

#include "util.h"
#include "bufutil.h"

#include "cryptutil.h"
#include "i1905_wsc.h"
#include "cntlrsync.h"


int build_sync_config_request(uint8_t *aladdr, uint8_t **m1, uint16_t *m1_size,
			      void **key)
{
	struct wsc_key *private_key;
	uint8_t nonce_e[16];
	uint8_t *buf;
	uint8_t *p;
	size_t rem;
	uint8_t *priv, *pub;
	uint16_t priv_len = 0, pub_len = 0;



	buf = calloc(1000, sizeof(uint8_t));
	if (!buf)
		return -ENOMEM;


	/* generate key-pair */
	PLATFORM_GENERATE_DH_KEY_PAIR(&priv, &priv_len, &pub, &pub_len);
	fprintf(stderr, "privlen = %d  publen = %d\n", priv_len, pub_len);

	private_key = calloc(1, sizeof(*private_key));
	if (!private_key) {
		free(buf);
		free(priv);
		free(pub);
		fprintf(stderr, "-ENOMEM\n");
		return -ENOMEM;
	}

	private_key->key = calloc(priv_len, sizeof(uint8_t));
	if (!private_key->key) {
		free(private_key);
		free(buf);
		free(priv);
		free(pub);
		fprintf(stderr, "-ENOMEM\n");
		return -ENOMEM;
	}
	private_key->keylen = priv_len;
	if (priv_len > 0)
		memcpy(private_key->key, priv, priv_len);

	memcpy(private_key->macaddr, aladdr, 6);
	get_random_bytes(16, nonce_e);
	memcpy(private_key->nonce, nonce_e, 16);

	p = buf;
	rem = 1000;


	if (wsc_put(&p, &rem, ATTR_MAC_ADDR, aladdr, 6) ||
	    wsc_put(&p, &rem, ATTR_ENROLLEE_NONCE, nonce_e, 16) ||
	    wsc_put(&p, &rem, ATTR_PUBLIC_KEY, pub, pub_len)) {
		free(private_key->key);
		free(private_key);
		free(buf);
		free(priv);
		free(pub);
		fprintf(stderr, "Error adding wsc attributes\n");
		return -1;
	}

	*m1 = buf;
	*m1_size = abs(p - buf);
	*key = private_key;

	free(pub);
	free(priv);

	return 0;
}

int build_sync_config_response(uint8_t *m1, uint16_t m1_size,
			       struct sync_config *cred,
			       uint8_t **m2, uint16_t *m2_size)
{
	uint8_t keywrapkey[WPS_KEYWRAPKEY_LEN];
	uint8_t authkey[WPS_AUTHKEY_LEN];
	uint8_t emsk[WPS_EMSK_LEN];

	uint8_t m1_macaddr_present = 0;
	uint8_t m1_pubkey_present = 0;
	uint8_t m1_nonce_present = 0;
	uint16_t m1_pubkey_len = 0;

	uint8_t *m1_macaddr = NULL;
	uint8_t *m1_pubkey = NULL;
	uint8_t *m1_nonce = NULL;

	uint16_t local_privkey_len;
	uint8_t *local_privkey;
	uint16_t priv_len = 0;
	uint16_t pub_len = 0;
	uint8_t nonce_r[16];
	uint8_t *priv;
	uint8_t *pub;

	uint8_t *buffer;
	uint8_t *p;
	size_t rem;
	int i;
	int ret = 0;



	if (!m1 || !m1_size || !cred || !cred->len) {
		fprintf(stderr, "%s: invalid args\n", __func__);
		return -1;
	}

	p = m1;
	while (abs(p - m1) < m1_size) {
		uint16_t attr_type;
		uint16_t attr_len;

		attr_type = buf_get_be16(p);
		p += 2;
		attr_len = buf_get_be16(p);
		p += 2;


		switch (attr_type) {
		case ATTR_MAC_ADDR:
			if (attr_len != 6) {
				fprintf(stderr, "Incorrect macaddr length (%d)\n",
					attr_len);
				return -EINVAL;
			}
			m1_macaddr = p;
			m1_macaddr_present = 1;
			break;
		case ATTR_ENROLLEE_NONCE:
			if (attr_len != 16) {
				fprintf(stderr, "Incorrect nonce-e  length (%d)\n",
					attr_len);
				return -EINVAL;
			}
			m1_nonce = p;
			m1_nonce_present = 1;
			break;
		case ATTR_PUBLIC_KEY:
			m1_pubkey_len = attr_len;
			m1_pubkey = p;
			m1_pubkey_present = 1;
			break;
		default:
			break;
		}

		p += attr_len;
	}

	if (!m1_pubkey_present || !m1_nonce_present || !m1_macaddr_present) {
		fprintf(stderr, "Required attrs in M1 not present!\n");
		return -1;
	}

	get_random_bytes(16, nonce_r);

	/* key-pair */
	ret = PLATFORM_GENERATE_DH_KEY_PAIR(&priv, &priv_len, &pub, &pub_len);
	if (ret)
		return -1;

	fprintf(stderr, "plen|%d|, publen|%d|\n", priv_len, pub_len);
	local_privkey = priv;
	local_privkey_len = priv_len;
	{
		uint8_t keys[WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN + WPS_EMSK_LEN];
		uint8_t dhkey[SHA256_MAC_LEN];
		uint8_t kdk[SHA256_MAC_LEN];
		uint16_t shared_secret_len;
		uint8_t *shared_secret;
		const uint8_t *addr[3];
		size_t len[3];

		/* DH shared secret = enrollee's public key from M1 +  private
		 * key (generated above).
		 *
		 * The enrollee after receiving M2, will obtain the same DH shared
		 * secret using its private key and our public key (sent in M2).
		 */
		ret = PLATFORM_COMPUTE_DH_SHARED_SECRET(&shared_secret,
							&shared_secret_len,
							m1_pubkey,
							m1_pubkey_len,
							local_privkey,
							local_privkey_len);

		if (ret)
			goto out;

		/* dhkey = SHA-256 digest of the DH shared secret. */
		addr[0] = shared_secret;
		len[0] = shared_secret_len;

		ret = PLATFORM_SHA256(1, addr, len, dhkey);
		if (ret) {
			free(shared_secret);
			goto out;
		}

		/* Derive KDK -
		 *
		 * KDK = HMAC-SHA-256_DHKey (N1 || EnrolleeMAC || N2), where
		 *  N1 is enrollee's nonce from M1,
		 *  N2 is registrar's nonce generated above.
		 *
		 */

		/* Compute HMAC of the following using 'dhkey' -
		 *    the enrollee's nonce from M1,
		 *    the enrolle MAC address from M1, and
		 *    the our nonce generated above.
		 */
		addr[0] = m1_nonce;
		addr[1] = m1_macaddr;
		addr[2] = nonce_r;
		len[0] = 16;
		len[1] = 6;
		len[2] = 16;

		ret = PLATFORM_HMAC_SHA256(dhkey, SHA256_MAC_LEN, 3, addr, len, kdk);
		if (ret) {
			free(shared_secret);
			goto out;
		}

		ret = wps_kdf(kdk, NULL, 0,
			      "Secure Key Derivation for Configuration exchange",
			      keys, sizeof(keys));
		if (ret) {
			free(shared_secret);
			goto out;
		}

		memcpy(authkey, keys, WPS_AUTHKEY_LEN);
		memcpy(keywrapkey, keys + WPS_AUTHKEY_LEN, WPS_KEYWRAPKEY_LEN);
		memcpy(emsk, keys + WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN, WPS_EMSK_LEN);

		fprintf(stderr, "WPS keys: \n");
		bufprintf(m1_pubkey, m1_pubkey_len, "Enrollee public key");
		/* bufprintf(local_privkey, local_privkey_len, "Registrar private key"); */
		bufprintf(shared_secret, shared_secret_len, "DH Shared secret");
		//bufprintf(dhkey, 32, "DH Key");
		//bufprintf(m1_nonce, 16, "Nonce-E");
		//bufprintf(nonce_r, 16, "Nonce-R");
		//bufprintf(kdk, 32, "KDK");
		//bufprintf(authkey, WPS_AUTHKEY_LEN, "WPS authkey");
		//bufprintf(keywrapkey, WPS_KEYWRAPKEY_LEN, "WPS keywrapkey");
		//bufprintf(emsk, WPS_EMSK_LEN, "WPS emsk");

		free(shared_secret);
	}

	buffer = calloc(cred->len + 1024, sizeof(uint8_t));
	if (!buffer) {
		fprintf(stderr, "-ENOMEM\n");
		ret = -1;
		goto out;
	}

	p = buffer;
	rem = 1000;

	if (wsc_put(&p, &rem, ATTR_ENROLLEE_NONCE, m1_nonce, 16) ||
	    wsc_put(&p, &rem, ATTR_REGISTRAR_NONCE, nonce_r, 16) ||
	    wsc_put(&p, &rem, ATTR_PUBLIC_KEY, pub, pub_len)) {
		free(buffer);
		free(priv);
		free(pub);
		fprintf(stderr, "Error adding wsc attributes\n");
		return -1;
	}

	/* encrypted settings */
	{
		uint8_t *plain;
		uint8_t hash[SHA256_MAC_LEN];
		uint8_t *iv_start;
		uint8_t *data_start;
		uint8_t num_pad_bytes;
		uint8_t *r;
		size_t rlen;
		const uint8_t *addr[1];
		size_t len[1];



		rlen = cred->len + 512;
		plain = calloc(1, rlen);
		if (!plain) {
			free(buffer);
			free(priv);
			free(pub);
			fprintf(stderr, "Error adding settings attributes\n");
			return -1;
		}

		r = plain;
		if (wsc_put(&r, &rlen, ATTR_NETWORK_KEY, cred->data, cred->len) ||
		    wsc_put(&r, &rlen, ATTR_MAC_ADDR, m1_macaddr, 6)) {
			free(plain);
			free(buffer);
			free(priv);
			free(pub);
			fprintf(stderr, "Error adding wsc settings attributes\n");
			return -1;
		}

		fprintf(stderr, "AP configuration settings --->\n");
		fprintf(stderr, "\tkey            : (len = %u) %s\n", cred->len, cred->data);

		/* compute HMAC of the settings buffer using "authkey" */
		addr[0] = plain;
		len[0] = abs(r - plain);

		ret = PLATFORM_HMAC_SHA256(authkey, WPS_AUTHKEY_LEN, 1, addr, len, hash);
		if (ret) {
			free(plain);
			free(buffer);
			goto out;
		}

		/* append first 8 bytes of hash to settings buffer */
		wsc_put(&r, &rlen, ATTR_KEY_WRAP_AUTH, hash, 8);

		/* AES encrypt and add result to M2 as "ATTR_ENCR_SETTINGS" */

		/* Pad length of the message to encrypt to a multiple of
		 * AES_BLOCK_SIZE. Each padded byte must have their value equal
		 * to the number of padded bytes (PKCS#5 v2.0 pad).
		 */
		num_pad_bytes = AES_BLOCK_SIZE - (abs(r - plain) % AES_BLOCK_SIZE);
		for (i = 0; i < num_pad_bytes; i++) {
			bufptr_put_u8(r, num_pad_bytes);
		}
		rlen -= num_pad_bytes;

		/* Add "ATTR_ENCR_SETTINGS" attribute to the M2 buffer,
		 * followed by the IV and the settings data to encrypt.
		 */
		uint32_t setting_len = abs(r - plain);

		bufptr_put_be16(p, ATTR_ENCR_SETTINGS);
		bufptr_put_be16(p, AES_BLOCK_SIZE + setting_len);
		iv_start = p;
		get_random_bytes(AES_BLOCK_SIZE, p);
		p += AES_BLOCK_SIZE;
		data_start = p;
		bufptr_put(p, plain, setting_len);

		rem -= (4 + AES_BLOCK_SIZE + setting_len);

		/* Encrypt the data in-place.
		 * Note that the "ATTR_ENCR_SETTINGS" attribute containes both
		 * the IV and the encrypted data.
		 */
		bufprintf(data_start, setting_len, "Cleartext AP settings");
		bufprintf(iv_start, AES_BLOCK_SIZE, "IV");

		ret = PLATFORM_AES_ENCRYPT(keywrapkey, iv_start, data_start, setting_len);
		if (ret) {
			free(plain);
			free(buffer);
			goto out;
		}

		free(plain);
		bufprintf(data_start, setting_len, "Encrypted AP settings");
	}

	/* authenticator */
	{
		/* Concatenate M1 and M2 (everything in the M2 buffer up to
		 * this point) and calculate the HMAC.
		 * Finally, append it to M2 as a attribute.
		 */
		uint8_t hash[SHA256_MAC_LEN];
		const uint8_t *addr[2];
		size_t len[2];

		addr[0] = m1;
		addr[1] = buffer;
		len[0] = m1_size;
		len[1] = abs(p - buffer);

		ret = PLATFORM_HMAC_SHA256(authkey, WPS_AUTHKEY_LEN, 2, addr, len, hash);
		if (ret) {
			free(buffer);
			goto out;
		}

		wsc_put(&p, &rem, ATTR_AUTHENTICATOR, hash, 8);
	}

	*m2 = buffer;
	*m2_size = abs(p - buffer);

out:
	free(local_privkey);
	free(pub);

	return ret;
}

int process_sync_config_response(uint8_t *m1, uint16_t m1_size, void *key,
				 uint8_t *m2, uint16_t m2_size,
				 struct sync_config *out)
{
	struct wsc_key *k;

	uint8_t network_key_present;
	uint8_t authkey[WPS_AUTHKEY_LEN];
	uint8_t keywrapkey[WPS_KEYWRAPKEY_LEN];
	uint8_t emsk[WPS_EMSK_LEN];

	uint8_t *m2_nonce = NULL;
	uint8_t m2_nonce_present = 0;
	uint8_t *m2_pubkey = NULL;
	uint8_t m2_pubkey_present = 0;
	uint16_t m2_pubkey_len = 0;
	uint8_t *m2_encrypted_settings = NULL;
	uint8_t m2_encrypted_settings_present = 0;
	uint16_t m2_encrypted_settings_len = 0;
	uint8_t *m2_authenticator = NULL;
	uint8_t m2_authenticator_present = 0;
	uint8_t *m1_privkey;
	uint16_t m1_privkey_len;
	uint8_t *m1_macaddr;
	uint8_t *m1_nonce;

	uint8_t *m2_end;
	uint8_t *p;
	int ret = 0;

	if (!out)
		return -1;

	out->len = 0;
	out->data = NULL;

	if (!m1 || m1_size == 0 || !key) {
		fprintf(stderr, "Missing m1 or wsc key\n");
		return -1;
	}

	if (!m2 || m2_size == 0) {
		fprintf(stderr, "Missing m2\n");
		return -1;
	}


	k = (struct wsc_key *)key;
	m1_privkey = k->key;
	m1_privkey_len = k->keylen;
	m1_macaddr = k->macaddr;
	m1_nonce = k->nonce;

	p = m2;
	m2_end = m2 + m2_size;

	while (abs(p - m2) < m2_size - 4) {
		uint16_t attr_type;
		uint16_t attr_len;


		attr_type = buf_get_be16(p);
		p += 2;
		attr_len = buf_get_be16(p);
		p += 2;

		if (p + attr_len > m2_end) {
			fprintf(stderr, "Invalid wsc m2\n");
			return -EINVAL;
		}

		switch (attr_type) {
		case ATTR_REGISTRAR_NONCE:
			if (attr_len != 16) {
				fprintf(stderr, "Err length (%d) for wsc attr\n",
					attr_len);
				return -EINVAL;
			}
			m2_nonce = p;
			m2_nonce_present = 1;
			break;
		case ATTR_PUBLIC_KEY:
			m2_pubkey_len = attr_len;
			m2_pubkey = p;
			m2_pubkey_present = 1;
			break;
		case ATTR_ENCR_SETTINGS:
			m2_encrypted_settings_len = attr_len;
			m2_encrypted_settings = p;
			m2_encrypted_settings_present = 1;
			break;
		case ATTR_AUTHENTICATOR:
			if (attr_len != 8) {
				fprintf(stderr, "Err length (%d) for wsc attr\n",
					attr_len);
				return -EINVAL;
			}
			m2_authenticator = p;
			m2_authenticator_present = 1;
			break;
		default:
			break;
		}

		p += attr_len;
	}

	if (!m2_nonce_present ||
	    !m2_pubkey_present ||
	    !m2_encrypted_settings_present ||
	    !m2_authenticator_present) {
		fprintf(stderr, "Missing attributes in the received M2 message\n");
		return -EINVAL;
	}

	/* derive keys - authkey, keywrapkey and emsk */
	{
		uint8_t *shared_secret;
		uint16_t shared_secret_len;
		const uint8_t *addr[3];
		size_t len[3];
		uint8_t dhkey[SHA256_MAC_LEN];
		uint8_t kdk[SHA256_MAC_LEN];
		uint8_t keys[WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN + WPS_EMSK_LEN];


		ret = PLATFORM_COMPUTE_DH_SHARED_SECRET(&shared_secret,
							&shared_secret_len,
							m2_pubkey,
							m2_pubkey_len,
							m1_privkey,
							m1_privkey_len);
		if (ret)
			return -1;

		addr[0] = shared_secret;
		len[0] = shared_secret_len;

		ret = PLATFORM_SHA256(1, addr, len, dhkey);
		if (ret) {
			free(shared_secret);
			return -1;
		}

		addr[0] = m1_nonce;
		addr[1] = m1_macaddr;
		addr[2] = m2_nonce;
		len[0] = 16;
		len[1] = 6;
		len[2] = 16;

		ret = PLATFORM_HMAC_SHA256(dhkey, SHA256_MAC_LEN, 3, addr, len, kdk);
		if (ret) {
			free(shared_secret);
			return -1;
		}

		ret = wps_kdf(kdk, NULL, 0,
			      "Secure Key Derivation for Configuration exchange",
			      keys, sizeof(keys));

		if (ret) {
			free(shared_secret);
			return -1;
		}

		memcpy(authkey, keys, WPS_AUTHKEY_LEN);
		memcpy(keywrapkey, keys + WPS_AUTHKEY_LEN, WPS_KEYWRAPKEY_LEN);
		memcpy(emsk, keys + WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN, WPS_EMSK_LEN);

		fprintf(stderr, "WPS keys: \n");
		bufprintf(m2_pubkey, m2_pubkey_len, "Registrar public key");
		/* bufprintf(m1_privkey, m1_privkey_len, "Enrollee private key"); */
		bufprintf(shared_secret, shared_secret_len, "DH Shared secret");
		//bufprintf(dhkey, 32, "DH Key");
		//bufprintf(m1_nonce, 16, "Nonce-E");
		//bufprintf(m2_nonce, 16, "Nonce-R");
		//bufprintf(kdk, 32, "KDK");
		//bufprintf(authkey, WPS_AUTHKEY_LEN, "WPS authkey");
		//bufprintf(keywrapkey, WPS_KEYWRAPKEY_LEN, "WPS keywrapkey");
		//bufprintf(emsk, WPS_EMSK_LEN, "WPS emsk");

		free(shared_secret);
	}


	/* Verify message authentication -
	 *
	 * Concatenate M1 and M2 (excluding the last 12 bytes, where the
	 * authenticator attribute is present) and calculate the HMAC.
	 * Check it against the actual authenticator attribute value.
	 */
	{
		uint8_t hash[SHA256_MAC_LEN];
		const uint8_t *addr[2];
		size_t len[2];

		addr[0] = m1;
		addr[1] = m2;
		len[0] = m1_size;
		len[1] = m2_size - 12;

		ret = PLATFORM_HMAC_SHA256(authkey, WPS_AUTHKEY_LEN, 2, addr, len, hash);
		if (ret)
			return -1;

		if (memcmp(m2_authenticator, hash, 8)) {
			fprintf(stderr, "Message M2 authentication failed\n");
			return -1;
		}
	}

	/* Decrypt the message and check the keywrap */
	{
		uint8_t *plain, *plain_end;
		uint32_t plain_len;
		uint8_t m2_keywrap_present;

		plain = m2_encrypted_settings + AES_BLOCK_SIZE;
		plain_len = m2_encrypted_settings_len - AES_BLOCK_SIZE;

		fprintf(stderr, "m2_encrypted_settings_len = %u  plain_len = %u\n",
			m2_encrypted_settings_len, plain_len);

		bufprintf(plain, plain_len, "Encrypted AP settings");
		bufprintf(m2_encrypted_settings, AES_BLOCK_SIZE, "IV");

		ret = PLATFORM_AES_DECRYPT(keywrapkey, m2_encrypted_settings, plain, plain_len);
		if (ret)
			return -1;

		fprintf(stderr, "plain_len = %u  (padding = %d)\n", plain_len, plain[plain_len - 1]);
		bufprintf(plain, plain_len, "Cleartext AP settings");
		plain_len -= plain[plain_len - 1];	/* remove padding */
		if (plain_len < 4) {
			fprintf(stderr, "Invalid AP settings!\n");
			return -1;
		}

		/* Parse contents of AP settings */
		network_key_present = 0;
		m2_keywrap_present = 0;
		p = plain;

		plain_end = plain + plain_len;
		while ((uint32_t)(abs(p - plain)) < plain_len - 4) {
			uint16_t attr_type;
			uint16_t attr_len;

			attr_type = buf_get_be16(p);
			p += 2;
			attr_len = buf_get_be16(p);
			p += 2;

			if (p + attr_len > plain_end) {
				fprintf(stderr, "Malformed AP setting attrs!\n");
				goto error;
			}

			switch (attr_type) {
			case ATTR_NETWORK_KEY:
				network_key_present = 1;
				out->len = attr_len;
				out->data = calloc(1, out->len + 1);
				if (!out->data)
					goto error;
				memcpy(out->data, p, out->len);
				break;
			case ATTR_KEY_WRAP_AUTH:
				{
					uint8_t *end_of_hmac;
					uint8_t hash[SHA256_MAC_LEN];
					const uint8_t *addr[1];
					size_t len[1];


					if (attr_len != 8)
						break;

					end_of_hmac = p - 4;
					addr[0] = plain;
					len[0] = abs(end_of_hmac - plain);

					ret = PLATFORM_HMAC_SHA256(authkey, WPS_AUTHKEY_LEN, 1, addr, len, hash);
					if (ret)
						goto error;

					if (memcmp(p, hash, 8)) {
						fprintf(stderr, "M2 keywrap check failed\n");
						goto error;
					}
					m2_keywrap_present = 1;
				}
				break;
			default:
				break;
			}

			p += attr_len;
		}

		if (!network_key_present || !m2_keywrap_present) {
			fprintf(stderr, "WSC M2 is missing settings attributes\n");
			goto error;
		}
	}

	return 0;

error:
	if (out->data)
		free(out->data);

	out->len = 0;
	out->data = NULL;

	return -1;
}
