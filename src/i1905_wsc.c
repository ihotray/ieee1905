/*
 * i1905_wsc.c - implements IEEE-1905 WSC CMDUs
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

int wsc_put_u8(uint8_t **p, size_t *remain, uint16_t attr, uint8_t data)
{
	if (*remain < 5)
		return -1;

	bufptr_put_be16(*p, attr);
	bufptr_put_be16(*p, 1);
	bufptr_put_u8(*p, data);

	*remain -= 5;
	return 0;
}

int wsc_put_u16(uint8_t **p, size_t *remain, uint16_t attr, uint16_t data)
{
	if (*remain < 6)
		return -1;

	bufptr_put_be16(*p, attr);
	bufptr_put_be16(*p, 2);
	bufptr_put_be16(*p, data);

	*remain -= 6;
	return 0;
}

int wsc_put_u32(uint8_t **p, size_t *remain, uint16_t attr, uint32_t data)
{
	if (*remain < 8)
		return -1;

	bufptr_put_be16(*p, attr);
	bufptr_put_be16(*p, 4);
	bufptr_put_be32(*p, data);

	*remain -= 8;
	return 0;
}

int wsc_put(uint8_t **p, size_t *remain, uint16_t attr, void *data, uint16_t len)
{
	if (*remain < (4 + len))
		return -1;

	bufptr_put_be16(*p, attr);
	bufptr_put_be16(*p, len);
	bufptr_put(*p, data, len);

	*remain -= (4 + len);
	return 0;
}

int wps_kdf(const uint8_t *key, const uint8_t *label_prefix,
	     size_t label_prefix_len, const char *label, uint8_t *res,
	     size_t res_len)
{

	uint8_t i_buf[4], key_bits[4];
	const uint8_t *addr[4];
	size_t len[4];
	int i, iter;
	uint8_t hash[SHA256_MAC_LEN], *opos;
	size_t left;
	int ret = 0;

	buf_put_be32(key_bits, res_len * 8);

	addr[0] = i_buf;
	len[0] = sizeof(i_buf);
	addr[1] = label_prefix;
	len[1] = label_prefix_len;
	addr[2] = (const uint8_t *) label;
	len[2] = strlen(label);
	addr[3] = key_bits;
	len[3] = sizeof(key_bits);

	iter = (res_len + SHA256_MAC_LEN - 1) / SHA256_MAC_LEN;
	opos = res;
	left = res_len;

	for (i = 1; i <= iter; i++) {
		buf_put_be32(i_buf, i);
		ret = PLATFORM_HMAC_SHA256(key, SHA256_MAC_LEN, 4, addr, len, hash);
		if (ret)
			return -1;

		if (i < iter) {
			memcpy(opos, hash, SHA256_MAC_LEN);
			opos += SHA256_MAC_LEN;
			left -= SHA256_MAC_LEN;
		} else
			memcpy(opos, hash, left);
	}

	return 0;
}

uint8_t wsc_get_message_type(uint8_t *m, uint16_t m_size)
{
	uint8_t *p = m;

	while (labs(p - m) < m_size) {
		uint16_t attr_type;
		uint16_t attr_len;
		uint8_t msg_type;

		attr_type = buf_get_be16(p);
		p += 2;
		attr_len = buf_get_be16(p);
		p += 2;


		switch (attr_type) {
		case ATTR_MSG_TYPE:
			if (attr_len != 1) {
				fprintf(stderr,
					"Incorrect length (%d) for ATTR_MSG_TYPE\n", attr_len);
				return -EINVAL;
			}
			bufptr_get(p, &msg_type, 1);
			return msg_type;
		default:
			break;
		}

		p += attr_len;
	}

	return 0xff;
}

int wsc_build_m1(struct wps_credential *in, uint8_t **m1,
		 uint16_t *m1_size, void **key)
{
	uint8_t oui[4] = { 0x00, 0x50, 0xf2, 0x00 };
	struct wsc_key *private_key;
	uint8_t nonce_e[16];
	uint8_t *buf;
	uint8_t *p;
	size_t rem;
	uint8_t pdev_type[8] = {0, WPS_DEV_NETWORK_INFRA,
				oui[0], oui[1], oui[2], oui[3],
				0, WPS_DEV_NETWORK_INFRA_ROUTER};

	uint8_t ver2_vendor_ext[6] = { WFA_VENDOR_ID_1, WFA_VENDOR_ID_2,
				       WFA_VENDOR_ID_3, WFA_ELEM_VERSION2,
				       0x1, WPS_VERSION };

	uint8_t *priv, *pub;
	uint16_t priv_len = 0, pub_len = 0;



	buf = calloc(1000, sizeof(uint8_t));
	if (!buf)
		return -ENOMEM;


	/* generate keys */
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

	memcpy(private_key->macaddr, in->macaddr, 6);

	get_random_bytes(16, nonce_e);
	memcpy(private_key->nonce, nonce_e, 16);



	p = buf;
	rem = 1000;


	if (wsc_put_u8(&p, &rem, ATTR_VERSION, 0x10) ||
	    wsc_put_u8(&p, &rem, ATTR_MSG_TYPE, WPS_M1) ||
	    wsc_put(&p, &rem, ATTR_UUID_E, in->uuid, 16) ||
	    wsc_put(&p, &rem, ATTR_MAC_ADDR, in->macaddr, 6) ||
	    wsc_put(&p, &rem, ATTR_ENROLLEE_NONCE, nonce_e, 16) ||
	    wsc_put(&p, &rem, ATTR_PUBLIC_KEY, pub, pub_len) ||
	    wsc_put_u16(&p, &rem, ATTR_AUTH_TYPE_FLAGS, in->auth_type) ||
	    wsc_put_u16(&p, &rem, ATTR_ENCR_TYPE_FLAGS, in->enc_type) ||
	    wsc_put_u8(&p, &rem, ATTR_CONN_TYPE_FLAGS, WPS_CONN_ESS) ||
	    wsc_put_u16(&p, &rem, ATTR_CONFIG_METHODS, WPS_CONFIG_PHY_PUSHBUTTON | WPS_CONFIG_VIRT_PUSHBUTTON) ||
	    wsc_put_u8(&p, &rem, ATTR_WPS_STATE, WPS_STATE_NOT_CONFIGURED) ||
	    wsc_put(&p, &rem, ATTR_MANUFACTURER, in->manufacturer, strlen(in->manufacturer)) ||
	    wsc_put(&p, &rem, ATTR_MODEL_NAME, in->model_name, strlen(in->model_name)) ||
	    wsc_put(&p, &rem, ATTR_MODEL_NUMBER, in->model_number, strlen(in->model_number)) ||
	    wsc_put(&p, &rem, ATTR_SERIAL_NUMBER, in->serial_number, strlen(in->serial_number)) ||
	    wsc_put(&p, &rem, ATTR_PRIMARY_DEV_TYPE, pdev_type, 8) ||
	    wsc_put(&p, &rem, ATTR_DEV_NAME, in->device_name, strlen(in->device_name)) ||
	    wsc_put_u8(&p, &rem, ATTR_RF_BANDS, in->band) ||
	    wsc_put_u16(&p, &rem, ATTR_ASSOC_STATE, WPS_ASSOC_NOT_ASSOC) ||
	    wsc_put_u16(&p, &rem, ATTR_DEV_PASSWORD_ID, DEV_PW_PUSHBUTTON) ||
	    wsc_put_u16(&p, &rem, ATTR_CONFIG_ERROR, WPS_CFG_NO_ERROR) ||
	    wsc_put_u32(&p, &rem, ATTR_OS_VERSION, 0x80000000 | in->os_version) ||
	    wsc_put(&p, &rem, ATTR_VENDOR_EXTENSION, ver2_vendor_ext, 6)) {
		free(private_key->key);
		free(private_key);
		free(buf);
		free(priv);
		free(pub);
		fprintf(stderr, "Error adding wsc attributes\n");
		return -1;
	}

#if 0
	if (wsc->last_msg)
		free(wsc->last_msg);

	if (wsc->key)
		free(wsc->key);

	wsc->last_msg = buf;
	wsc->last_msglen = labs(p - buf);
	wsc->key = private_key;
#endif

	*m1 = buf;
	*m1_size = labs(p - buf);
	*key = private_key;

	free(pub);
	free(priv);

	return 0;
}

int wsc_msg_get_attr(uint8_t *msg, uint16_t msglen, uint16_t attr, uint8_t *out,
		     uint16_t *olen)
{
	uint8_t *p;
	uint8_t *msg_end;


	if (!msg || msglen == 0 || !out)
		return -1;

	p = msg;
	msg_end = msg + msglen;

	while (labs(p - msg) < msglen - 4) {
		uint16_t attr_type;
		uint16_t attr_len;

		attr_type = buf_get_be16(p);
		p += 2;
		attr_len = buf_get_be16(p);
		p += 2;

		if (p + attr_len > msg_end)
			return -1;

		if (attr_type == attr) {
			memcpy(out, p, attr_len);
			*olen = attr_len;
			return 0;
		}

		p += attr_len;
	}

	*olen = 0;
	return -1;
}

int wsc_build_m2(uint8_t *m1, uint16_t m1_size, struct wps_credential *cred,
		 struct wsc_vendor_ie *ven_ies, uint8_t num_ven_ies,
		 uint8_t **m2, uint16_t *m2_size)
{
#if 0
	uint8_t oui[4] = { 0x00, 0x50, 0xf2, 0x00 };

	uint8_t pdev_type[8] = { 0, WPS_DEV_NETWORK_INFRA,
				 oui[0], oui[1], oui[2], oui[3],
				 0, WPS_DEV_NETWORK_INFRA_ROUTER};
#endif

	uint8_t ver2_vendor_ext[6] = { 0x00, 0x37, 0x2a,
				       WFA_ELEM_VERSION2, 0x1, WPS_VERSION };

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
	uint8_t m1_rf_band = 0;

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



	if (!m1 || !m1_size || !cred) {
		fprintf(stderr, "%s: invalid args\n", __func__);
		return -1;
	}

	p = m1;
	while (labs(p - m1) < m1_size) {
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
		case ATTR_RF_BANDS:
			m1_rf_band = *p;
			break;
		default:
			break;
		}

		p += attr_len;
	}

	if (!m1_pubkey_present || !m1_nonce_present || !m1_macaddr_present ||
	    !m1_rf_band) {

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

		ret = wps_kdf(kdk, NULL, 0, "Wi-Fi Easy and Secure Key Derivation",
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
		/* bufprintf(shared_secret, shared_secret_len, "DH Shared secret"); */
		bufprintf(dhkey, 32, "DH Key");
		bufprintf(m1_nonce, 16, "Nonce-E");
		bufprintf(nonce_r, 16, "Nonce-R");
		bufprintf(kdk, 32, "KDK");
		bufprintf(authkey, WPS_AUTHKEY_LEN, "WPS authkey");
		bufprintf(keywrapkey, WPS_KEYWRAPKEY_LEN, "WPS keywrapkey");
		bufprintf(emsk, WPS_EMSK_LEN, "WPS emsk");

		free(shared_secret);
	}


	buffer = calloc(1000, sizeof(uint8_t));
	if (!buffer) {
		fprintf(stderr, "-ENOMEM\n");
		ret = -1;
		goto out;
	}

	p = buffer;
	rem = 1000;

	if (wsc_put_u8(&p, &rem, ATTR_VERSION, 0x10) ||
	    wsc_put_u8(&p, &rem, ATTR_MSG_TYPE, WPS_M2) ||
	    wsc_put(&p, &rem, ATTR_ENROLLEE_NONCE, m1_nonce, 16) ||
	    wsc_put(&p, &rem, ATTR_REGISTRAR_NONCE, nonce_r, 16) ||
	    wsc_put(&p, &rem, ATTR_UUID_R, cred->uuid, 16) ||
	    wsc_put(&p, &rem, ATTR_PUBLIC_KEY, pub, pub_len) ||
	    wsc_put_u16(&p, &rem, ATTR_AUTH_TYPE_FLAGS, cred->auth_type) ||
	    wsc_put_u16(&p, &rem, ATTR_ENCR_TYPE_FLAGS, cred->enc_type) ||
	    wsc_put_u8(&p, &rem, ATTR_CONN_TYPE_FLAGS, WPS_CONN_ESS) ||
	    wsc_put_u16(&p, &rem, ATTR_CONFIG_METHODS, WPS_CONFIG_PHY_PUSHBUTTON | WPS_CONFIG_VIRT_PUSHBUTTON) ||
	    wsc_put(&p, &rem, ATTR_MANUFACTURER, cred->manufacturer, strlen(cred->manufacturer)) ||
	    wsc_put(&p, &rem, ATTR_MODEL_NAME, cred->model_name, strlen(cred->model_name)) ||
	    wsc_put(&p, &rem, ATTR_MODEL_NUMBER, cred->model_number, strlen(cred->model_number)) ||
	    wsc_put(&p, &rem, ATTR_SERIAL_NUMBER, cred->serial_number, strlen(cred->serial_number)) ||
	    wsc_put(&p, &rem, ATTR_PRIMARY_DEV_TYPE, cred->device_type, 8) ||
	    wsc_put(&p, &rem, ATTR_DEV_NAME, cred->device_name, strlen(cred->device_name)) ||
	    wsc_put_u8(&p, &rem, ATTR_RF_BANDS, cred->band) ||
	    wsc_put_u16(&p, &rem, ATTR_ASSOC_STATE, WPS_ASSOC_CONN_SUCCESS) ||
	    wsc_put_u16(&p, &rem, ATTR_CONFIG_ERROR, WPS_CFG_NO_ERROR) ||
	    wsc_put_u16(&p, &rem, ATTR_DEV_PASSWORD_ID, DEV_PW_PUSHBUTTON) ||
	    wsc_put_u32(&p, &rem, ATTR_OS_VERSION, 0x80000000 | cred->os_version) ||
	    wsc_put(&p, &rem, ATTR_VENDOR_EXTENSION, ver2_vendor_ext, 6)) {
		free(buffer);
		free(priv);
		free(pub);
		fprintf(stderr, "Error adding wsc attributes\n");
		return -1;
	}

	/* encrypted settings */
	{
		uint8_t ext[9] = { WFA_VENDOR_ID_1, WFA_VENDOR_ID_2, WFA_VENDOR_ID_3,
				  WFA_ELEM_VERSION2, 0x1, WPS_VERSION,
				  WFA_ELEM_MAP, 0x1, cred->mapie };

		uint8_t plain[512];
		uint8_t hash[SHA256_MAC_LEN];
		uint8_t *iv_start;
		uint8_t *data_start;
		uint8_t num_pad_bytes;
		uint8_t *r;
		size_t rlen;

		const uint8_t *addr[1];
		size_t len[1];


		r = plain;
		rlen = sizeof(plain);

		if (wsc_put(&r, &rlen, ATTR_SSID, cred->ssid, cred->ssidlen) ||
		    wsc_put_u16(&r, &rlen, ATTR_AUTH_TYPE, cred->auth_type) ||
		    wsc_put_u16(&r, &rlen, ATTR_ENCR_TYPE, cred->enc_type) ||
		    wsc_put(&r, &rlen, ATTR_NETWORK_KEY, cred->key, cred->keylen) ||
		    wsc_put(&r, &rlen, ATTR_MAC_ADDR, cred->macaddr, 6) ||
		    wsc_put(&r, &rlen, ATTR_VENDOR_EXTENSION, ext, sizeof(ext))) {
			free(buffer);
			free(priv);
			free(pub);
			fprintf(stderr, "Error adding wsc settings attributes\n");
			return -1;
		}

#if 0
		fprintf(stderr, "AP configuration settings --->\n");
		fprintf(stderr, "\tssid           : %s\n", cred->ssid);
		fprintf(stderr, "\tbssid          : " MACFMT "\n", MAC2STR(cred->macaddr));
		fprintf(stderr, "\tauth_type      : 0x%04x\n", cred->auth_type);
		fprintf(stderr, "\tenc_type       : 0x%04x\n", cred->enc_type);
		fprintf(stderr, "\tkey            : %s\n", cred->key);
		fprintf(stderr, "\tmap_extension  : 0x%02x\n", cred->mapie);
#endif

		/* user passed vendor extension buffer starting with oui */
		for (i = 0; i < num_ven_ies; i++) {
			if (ven_ies && num_ven_ies > 0 && ven_ies[i].len < rlen) {
				uint8_t *ie_buf;
				uint8_t ie_buflen = 3 + /* oui */
						    ven_ies[i].len; /* payload */

				ie_buf = calloc(1, ie_buflen);
				if (!ie_buf)
					continue;

				memcpy(ie_buf, (uint8_t *) ven_ies[i].oui, 3);
				memcpy(ie_buf + 3, ven_ies[i].payload,
				       ven_ies[i].len);

				wsc_put(&r, &rlen, ATTR_VENDOR_EXTENSION,
					ie_buf, ie_buflen);
				free(ie_buf);
			}
		}

		/* compute HMAC of the settings buffer using "authkey" */
		addr[0] = plain;
		len[0] = labs(r - plain);
		ret = PLATFORM_HMAC_SHA256(authkey, WPS_AUTHKEY_LEN, 1, addr, len, hash);
		if (ret) {
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
		num_pad_bytes = AES_BLOCK_SIZE - (labs(r - plain) % AES_BLOCK_SIZE);
		for (i = 0; i < num_pad_bytes; i++) {
			bufptr_put_u8(r, num_pad_bytes);
		}
		rlen -= num_pad_bytes;

		/* Add "ATTR_ENCR_SETTINGS" attribute to the M2 buffer,
		 * followed by the IV and the settings data to encrypt.
		 */
		uint32_t setting_len = labs(r - plain);

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
			free(buffer);
			goto out;
		}

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
		len[1] = labs(p - buffer);

		ret = PLATFORM_HMAC_SHA256(authkey, WPS_AUTHKEY_LEN, 2, addr, len, hash);
		if (ret) {
			free(buffer);
			goto out;
		}

		wsc_put(&p, &rem, ATTR_AUTHENTICATOR, hash, 8);
	}

	*m2 = buffer;
	*m2_size = labs(p - buffer);

out:
	free(local_privkey);
	free(pub);

	return ret;
}

int wsc_process_m2(uint8_t *m1, uint16_t m1_size, void *key,
		   uint8_t *m2, uint16_t m2_size, struct wps_credential *out,
		   uint8_t **ext, uint16_t *extlen)
{
	struct wsc_key *k;

	uint8_t mapie = 0;

	uint8_t ssid[33] = {0};
	uint8_t ssid_present;
	int ssidlen = 0;
	uint8_t bssid[6] = {0};
	uint8_t bssid_present;
	uint16_t auth_type = 0;
	uint8_t auth_type_present;
	uint16_t enc_type = 0;
	uint8_t enc_type_present;
	uint8_t network_key[64] = {0};
	int network_keylen = 0;
	uint8_t network_key_present;
	uint8_t band = 0;

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

	char serial_number[33] = {0};
	char model_number[33] = {0};
	uint8_t device_type[8] = {0};
	char manufacturer[65] = {0};
	char device_name[33] = {0};
	char model_name[33] = {0};

	uint8_t *m1_privkey;
	uint16_t m1_privkey_len;
	uint8_t *m1_macaddr;
	uint8_t *m1_nonce;

	uint8_t *m2_end;
	uint8_t *p;
	int ret = 0;

	if (ext)
		*ext = NULL;

	if (extlen)
		*extlen = 0;

	if (!m1 || m1_size == 0 || !key) {
		fprintf(stderr, "Missing m1 or wsc key\n");
		return -1;
	}

	if (!m2 || m2_size == 0) {
		fprintf(stderr, "Missing m2\n");
		return -1;
	}


	//k = (struct wsc_key *)wsc->key;
	k = (struct wsc_key *)key;
	m1_privkey = k->key;
	m1_privkey_len = k->keylen;
	m1_macaddr = k->macaddr;
	m1_nonce = k->nonce;

	//m1 = wsc->last_msg;
	//m1_size = wsc->last_msglen;


	p = m2;
	m2_end = m2 + m2_size;

	while (labs(p - m2) < m2_size - 4) {
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
		case ATTR_RF_BANDS:
			memcpy(&band, p, 1);
			break;
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
		case ATTR_MANUFACTURER:
			if (attr_len > 64) {
				fprintf(stderr, "Err length (%d) for wsc attr 0x%04x\n",
					attr_len, attr_type);
				return -EINVAL;
			}
			memcpy(manufacturer, p, attr_len);
			break;
		case ATTR_MODEL_NAME:
			if (attr_len > 32) {
				fprintf(stderr, "Err length (%d) for wsc attr 0x%04x\n",
					attr_len, attr_type);
				return -EINVAL;
			}
			memcpy(model_name, p, attr_len);
			break;
		case ATTR_DEV_NAME:
			if (attr_len > 32) {
				fprintf(stderr, "Err length (%d) for wsc attr 0x%04x\n",
					attr_len, attr_type);
				return -EINVAL;
			}
			memcpy(device_name, p, attr_len);
			break;
		case ATTR_MODEL_NUMBER:
			if (attr_len > 32) {
				fprintf(stderr, "Err length (%d) for wsc attr 0x%04x\n",
					attr_len, attr_type);
				return -EINVAL;
			}
			memcpy(model_number, p, attr_len);
			break;
		case ATTR_SERIAL_NUMBER:
			if (attr_len > 32) {
				fprintf(stderr, "Err length (%d) for wsc attr 0x%04x\n",
					attr_len, attr_type);
				return -EINVAL;
			}
			memcpy(serial_number, p, attr_len);
			break;
		case ATTR_PRIMARY_DEV_TYPE:
			if (attr_len != 8) {
				fprintf(stderr, "Err length (%d) for wsc attr 0x%04x\n",
					attr_len, attr_type);
				return -EINVAL;
			}
			memcpy(device_type, p, attr_len);
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

		ret = wps_kdf(kdk, NULL, 0, "Wi-Fi Easy and Secure Key Derivation",
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
		/* bufprintf(shared_secret, shared_secret_len, "DH Shared secret"); */
		bufprintf(dhkey, 32, "DH Key");
		bufprintf(m1_nonce, 16, "Nonce-E");
		bufprintf(m2_nonce, 16, "Nonce-R");
		bufprintf(kdk, 32, "KDK");
		bufprintf(authkey, WPS_AUTHKEY_LEN, "WPS authkey");
		bufprintf(keywrapkey, WPS_KEYWRAPKEY_LEN, "WPS keywrapkey");
		bufprintf(emsk, WPS_EMSK_LEN, "WPS emsk");

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

		bufprintf(plain, plain_len, "Encrypted AP settings");
		bufprintf(m2_encrypted_settings, AES_BLOCK_SIZE, "IV");

		ret = PLATFORM_AES_DECRYPT(keywrapkey, m2_encrypted_settings, plain, plain_len);
		if (ret)
			return -1;

		bufprintf(plain, plain_len, "Cleartext AP settings");
		plain_len -= plain[plain_len - 1];	/* remove padding */
		if (plain_len < 4) {
			fprintf(stderr, "Invalid AP settings!\n");
			return -1;
		}

		/* Parse contents of AP settings */
		ssid_present = 0;
		bssid_present = 0;
		auth_type_present = 0;
		enc_type_present = 0;
		network_key_present = 0;
		m2_keywrap_present = 0;
		p = plain;

		plain_end = plain + plain_len;
		while ((uint32_t)(labs(p - plain)) < plain_len - 4) {
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
			case ATTR_SSID:
				if (attr_len > 32)
					break;

				memcpy(ssid, p, attr_len);
				ssidlen = attr_len;
				ssid_present = 1;
				break;
			case ATTR_AUTH_TYPE:
				auth_type = buf_get_be16(p);
				auth_type_present = 1;
				break;
			case ATTR_ENCR_TYPE:
				enc_type = buf_get_be16(p);
				enc_type_present = 1;
				break;
			case ATTR_NETWORK_KEY:
				if (attr_len > 64)
					break;

				memcpy(network_key, p, attr_len);
				network_keylen = attr_len;
				network_key_present = 1;
				break;
			case ATTR_MAC_ADDR:
				if (attr_len != 6)
					break;

				memcpy(bssid, p, 6);
				bssid_present = 1;
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
					len[0] = labs(end_of_hmac - plain);

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
			case ATTR_VENDOR_EXTENSION:
				{
					uint8_t id[3];
					uint8_t *end_of_ext;
					uint8_t subelem;
					uint8_t len;
					uint8_t *tmp_p;

					tmp_p = p;

					/* May be one or more subelements (Section 12 of WSC spec) */
					end_of_ext = p + attr_len;
					memcpy(id, tmp_p, sizeof(id));
					tmp_p += 3;

					if (id[0] == WFA_VENDOR_ID_1
							&& id[1] == WFA_VENDOR_ID_2
							&& id[2] == WFA_VENDOR_ID_3) {
						while (tmp_p < end_of_ext) {
							memcpy(&subelem, tmp_p, 1);
							tmp_p += 1;

							memcpy(&len, tmp_p, 1);
							tmp_p += 1;

							if (subelem == WFA_ELEM_MAP) {
								/* Map extension subelement will be 1 byte */
								memcpy(&mapie, tmp_p, 1);
								tmp_p += 1;
							} else {
								tmp_p += len;
							}

						}
					} else {
						/* for any other vendor oui */
						uint16_t start;
						uint8_t *ext_ptr;

						if (!ext || !extlen)
							break;

						start = *extlen;
						if (!*ext) {
							*ext = calloc(1, attr_len + 4);
							if (!*ext) {
								fprintf(stderr, "OOM\n");
								goto error;
							}
						} else {
							uint8_t *tmp;

							tmp = realloc(*ext, *extlen + attr_len + 4);
							if (!tmp)
								goto error;

							*ext = tmp;
						}
						ext_ptr = *ext + start;
						bufptr_put_be16(ext_ptr, attr_type);
						bufptr_put_be16(ext_ptr, attr_len);
						memcpy(ext_ptr, p, attr_len);
						tmp_p  += attr_len;
						*extlen += attr_len + 4;
					}
				}
				break;
			default:
				break;
			}

			p += attr_len;
		}

		if (!ssid_present || !bssid_present || !auth_type_present ||
		    !enc_type_present || !network_key_present || !m2_keywrap_present) {
			fprintf(stderr, "WSC M2 is missing settings attributes\n");
			goto error;
		}
	}

	memcpy(out->ssid, ssid, ssidlen);
	out->ssidlen = ssidlen;
	memcpy(out->key, network_key, network_keylen);
	out->keylen = network_keylen;
	out->auth_type = auth_type;
	out->enc_type = enc_type;
	out->mapie = mapie;
	memcpy(out->macaddr, bssid, 6);
	out->band = band;
	snprintf(out->manufacturer, sizeof(out->manufacturer), "%s", manufacturer);
	snprintf(out->model_name, sizeof(out->model_name), "%s", model_name);
	snprintf(out->device_name, sizeof(out->device_name), "%s", device_name);
	snprintf(out->model_number, sizeof(out->model_number), "%s", model_number);
	snprintf(out->serial_number, sizeof(out->serial_number), "%s", serial_number);
	memcpy(out->device_type, device_type, 8);

	return 0;

error:
	if (ext) {
		if (*ext)
			free(*ext);
		*ext = NULL;
	}

	if (extlen)
		*extlen = 0;

	return -1;
}
