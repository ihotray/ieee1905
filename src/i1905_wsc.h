/*
 * i1905_wcs.h
 * IEEE-1905 AP-autoconfig WSC messages defintions.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */


#ifndef I1905_WSC_H
#define I1905_WSC_H


#include <stdint.h>
#include <stdarg.h>

#define ATTR_VERSION           (0x104a)
#define ATTR_MSG_TYPE          (0x1022)
#define WPS_M1                 (0x04)
#define WPS_M2                 (0x05)
#define ATTR_UUID_E            (0x1047)
#define ATTR_UUID_R            (0x1048)
#define ATTR_MAC_ADDR          (0x1020)
#define ATTR_ENROLLEE_NONCE    (0x101a)
#define ATTR_REGISTRAR_NONCE   (0x1039)
#define ATTR_PUBLIC_KEY        (0x1032)
#define ATTR_AUTH_TYPE_FLAGS   (0x1004)
#define WPS_AUTH_OPEN          (0x0001)
#define WPS_AUTH_WPAPSK        (0x0002)	/* deprecated */
#define WPS_AUTH_SHARED        (0x0004)	/* deprecated */
#define WPS_AUTH_WPA           (0x0008)	/* deprecated */
#define WPS_AUTH_WPA2          (0x0010)
#define WPS_AUTH_WPA2PSK       (0x0020)
#define WPS_AUTH_SAE           (0x0040)
#define WPS_AUTH_WPA3_T        (WPS_AUTH_WPA2PSK | WPS_AUTH_SAE)

#define ATTR_ENCR_TYPE_FLAGS   (0x1010)
#define WPS_ENCR_NONE          (0x0001)
#define WPS_ENCR_WEP           (0x0002)	/* deprecated */
#define WPS_ENCR_TKIP          (0x0004)
#define WPS_ENCR_AES           (0x0008)
#define ATTR_CONN_TYPE_FLAGS   (0x100d)
#define WPS_CONN_ESS           (0x01)
#define WPS_CONN_IBSS          (0x02)
#define ATTR_CONFIG_METHODS    (0x1008)
#define WPS_CONFIG_VIRT_PUSHBUTTON (0x0280)
#define WPS_CONFIG_PHY_PUSHBUTTON  (0x0480)
#define ATTR_WPS_STATE         (0x1044)
#define WPS_STATE_NOT_CONFIGURED (1)
#define WPS_STATE_CONFIGURED     (2)
#define ATTR_MANUFACTURER      (0x1021)
#define ATTR_MODEL_NAME        (0x1023)
#define ATTR_MODEL_NUMBER      (0x1024)
#define ATTR_SERIAL_NUMBER     (0x1042)
#define ATTR_PRIMARY_DEV_TYPE  (0x1054)
#define WPS_DEV_COMPUTER                           (1)
#define WPS_DEV_COMPUTER_PC                       (1)
#define WPS_DEV_COMPUTER_SERVER                   (2)
#define WPS_DEV_COMPUTER_MEDIA_CENTER             (3)
#define WPS_DEV_COMPUTER_ULTRA_MOBILE             (4)
#define WPS_DEV_COMPUTER_NOTEBOOK                 (5)
#define WPS_DEV_COMPUTER_DESKTOP                  (6)
#define WPS_DEV_COMPUTER_MID                      (7)
#define WPS_DEV_COMPUTER_NETBOOK                  (8)
#define WPS_DEV_COMPUTER_TABLET                   (9)
#define WPS_DEV_INPUT                              (2)
#define WPS_DEV_INPUT_KEYBOARD                    (1)
#define WPS_DEV_INPUT_MOUSE                       (2)
#define WPS_DEV_INPUT_JOYSTICK                    (3)
#define WPS_DEV_INPUT_TRACKBALL                   (4)
#define WPS_DEV_INPUT_GAMING                      (5)
#define WPS_DEV_INPUT_REMOTE                      (6)
#define WPS_DEV_INPUT_TOUCHSCREEN                 (7)
#define WPS_DEV_INPUT_BIOMETRIC_READER            (8)
#define WPS_DEV_INPUT_BARCODE_READER              (9)
#define WPS_DEV_PRINTER                            (3)
#define WPS_DEV_PRINTER_PRINTER                   (1)
#define WPS_DEV_PRINTER_SCANNER                   (2)
#define WPS_DEV_PRINTER_FAX                       (3)
#define WPS_DEV_PRINTER_COPIER                    (4)
#define WPS_DEV_PRINTER_ALL_IN_ONE                (5)
#define WPS_DEV_CAMERA                             (4)
#define WPS_DEV_CAMERA_DIGITAL_STILL_CAMERA       (1)
#define WPS_DEV_CAMERA_VIDEO                      (2)
#define WPS_DEV_CAMERA_WEB                        (3)
#define WPS_DEV_CAMERA_SECURITY                   (4)
#define WPS_DEV_STORAGE                            (5)
#define WPS_DEV_STORAGE_NAS                       (1)
#define WPS_DEV_NETWORK_INFRA                      (6)
#define WPS_DEV_NETWORK_INFRA_AP                  (1)
#define WPS_DEV_NETWORK_INFRA_ROUTER              (2)
#define WPS_DEV_NETWORK_INFRA_SWITCH              (3)
#define WPS_DEV_NETWORK_INFRA_GATEWAY             (4)
#define WPS_DEV_NETWORK_INFRA_BRIDGE              (5)
#define WPS_DEV_DISPLAY                            (7)
#define WPS_DEV_DISPLAY_TV                        (1)
#define WPS_DEV_DISPLAY_PICTURE_FRAME             (2)
#define WPS_DEV_DISPLAY_PROJECTOR                 (3)
#define WPS_DEV_DISPLAY_MONITOR                   (4)
#define WPS_DEV_MULTIMEDIA                         (8)
#define WPS_DEV_MULTIMEDIA_DAR                    (1)
#define WPS_DEV_MULTIMEDIA_PVR                    (2)
#define WPS_DEV_MULTIMEDIA_MCX                    (3)
#define WPS_DEV_MULTIMEDIA_SET_TOP_BOX            (4)
#define WPS_DEV_MULTIMEDIA_MEDIA_SERVER           (5)
#define WPS_DEV_MULTIMEDIA_PORTABLE_VIDEO_PLAYER  (6)
#define WPS_DEV_GAMING                             (9)
#define WPS_DEV_GAMING_XBOX                       (1)
#define WPS_DEV_GAMING_XBOX360                    (2)
#define WPS_DEV_GAMING_PLAYSTATION                (3)
#define WPS_DEV_GAMING_GAME_CONSOLE               (4)
#define WPS_DEV_GAMING_PORTABLE_DEVICE            (5)
#define WPS_DEV_PHONE                             (10)
#define WPS_DEV_PHONE_WINDOWS_MOBILE              (1)
#define WPS_DEV_PHONE_SINGLE_MODE                 (2)
#define WPS_DEV_PHONE_DUAL_MODE                   (3)
#define WPS_DEV_PHONE_SP_SINGLE_MODE              (4)
#define WPS_DEV_PHONE_SP_DUAL_MODE                (5)
#define WPS_DEV_AUDIO                             (11)
#define WPS_DEV_AUDIO_TUNER_RECV                  (1)
#define WPS_DEV_AUDIO_SPEAKERS                    (2)
#define WPS_DEV_AUDIO_PMP                         (3)
#define WPS_DEV_AUDIO_HEADSET                     (4)
#define WPS_DEV_AUDIO_HEADPHONES                  (5)
#define WPS_DEV_AUDIO_MICROPHONE                  (6)
#define WPS_DEV_AUDIO_HOME_THEATRE                (7)
#define ATTR_DEV_NAME          (0x1011)
#define ATTR_RF_BANDS          (0x103c)
#define WPS_RF_24GHZ           (0x01)
#define WPS_RF_50GHZ           (0x02)
#define WPS_RF_60GHZ           (0x04)
#define ATTR_ASSOC_STATE       (0x1002)
#define WPS_ASSOC_NOT_ASSOC     (0)
#define WPS_ASSOC_CONN_SUCCESS  (1)
#define ATTR_DEV_PASSWORD_ID   (0x1012)
#define DEV_PW_PUSHBUTTON      (0x0004)
#define ATTR_CONFIG_ERROR      (0x1009)
#define WPS_CFG_NO_ERROR       (0)
#define ATTR_OS_VERSION        (0x102d)
#define ATTR_VENDOR_EXTENSION  (0x1049)
#define WPS_VENDOR_ID_WFA_1    (0x00)
#define WPS_VENDOR_ID_WFA_2    (0x37)
#define WPS_VENDOR_ID_WFA_3    (0x2A)
#define WFA_VENDOR_ID_1		WPS_VENDOR_ID_WFA_1
#define WFA_VENDOR_ID_2		WPS_VENDOR_ID_WFA_2
#define WFA_VENDOR_ID_3		WPS_VENDOR_ID_WFA_3

#define WPS_VERSION            (0x20)

#define WFA_ELEM_VERSION2      0x00

/* Multi-AP subelement ids */
#define WFA_ELEM_MAP           0x06
#define WFA_ELEM_MAP_PROFILE   0x07
#define WFA_ELEM_MAP_8021Q     0x08


#define ATTR_SSID              (0x1045)
#define ATTR_AUTH_TYPE         (0x1003)
#define ATTR_ENCR_TYPE         (0x100f)
#define ATTR_NETWORK_KEY       (0x1027)
#define ATTR_KEY_WRAP_AUTH     (0x101e)
#define ATTR_ENCR_SETTINGS     (0x1018)
#define ATTR_AUTHENTICATOR     (0x1005)

#define WPS_DEFAULT_DEVICE_TYPE         (uint8_t *)"\x00\x06\x00\x50\xf2\x04\x00\x02"
#define WPS_DEFAULT_UUID                "12345678-9abc-def0-1234-56789abcdef0"
#define WPS_DEFAULT_MANUFACTURER        "IOPSYS"
#define WPS_DEFAULT_MODEL_NAME          "1905-SampleDev"
#define WPS_DEFAULT_DEVICE_NAME         "1905Device"
#define WPS_DEFAULT_MODEL_NUM           "12345678"
#define WPS_DEFAULT_SERIAL_NUM          "1.2345.6789"
#define WPS_DEFAULT_OS_VERSION          "0x80000000"

struct wsc_vendor_ie {
	uint8_t oui[3];
	uint16_t len;
	uint8_t *payload;
};

struct wps_credential {
	uint8_t ssid[32];
	size_t ssidlen;
	uint16_t auth_type;
	uint16_t enc_type;
	uint8_t key[64];
	size_t keylen;
	uint8_t macaddr[6];
	uint8_t band;
	uint8_t mapie;

	/* per radio wsc attributes */
	uint8_t uuid[16];
	char manufacturer[65];		/* with terminating '\0' */
	char model_name[33];
	char device_name[33];
	char model_number[33];
	char serial_number[33];
	uint8_t device_type[8];		/* hexstring: <category>0050F204<subcategory> */
	uint32_t os_version;
};

struct i1905_interface_private_wsc {
	/* union {
		enum { SEND_M1, RECV_M2 } e;
		enum { RECV_M1, SEND_M2 } r;
	} state; */
	//uint8_t nonce[WPS_NONCE_LEN];

	struct wps_credential cred;

	uint8_t *last_msg;
	uint16_t last_msglen;
	void *key;
};


uint8_t wsc_get_message_type(uint8_t *m, uint16_t m_size);

int wsc_msg_get_attr(uint8_t *msg, uint16_t msglen, uint16_t attr,
		     uint8_t *out, uint16_t *olen);

/**
 * Prepares WSC vendor extension buffer from any number of {attr,len,value} tuples
 * @param[in|out] out  pointer to output buffer
 * @param[in|out] olen length of output buffer
 * @param[in] oui      3-bytes vendor OUI
 * @param[in] ...      sequence of {attr, length, value} tuples, ending with attr = -1
 *
 * @return 0 on success, -1 on failure.
 *
 * This function can be used to prepare wsc vendor extension buffer, which can
 * later to passed as 'ext' argument during M2 message building.
 */
int wsc_build_vendor_extension(uint8_t *out, size_t *olen, uint8_t *oui, ...);

int wsc_build_m1(struct wps_credential *in,
		 uint8_t **m1, uint16_t *m1_size, void **key);


int wsc_build_m2(uint8_t *m1, uint16_t m1_size, struct wps_credential *cred,
		 struct wsc_vendor_ie *ven_ies, uint8_t num_ven_ies,
		 uint8_t **m2, uint16_t *m2_size);

int wsc_process_m2(uint8_t *m1, uint16_t m1_size, void *key,
		   uint8_t *m2, uint16_t m2_size, struct wps_credential *out,
		   uint8_t **ext, uint16_t *extlen);

int wsc_put_u8(uint8_t **p, size_t *remain, uint16_t attr, uint8_t data);
int wsc_put_u16(uint8_t **p, size_t *remain, uint16_t attr, uint16_t data);
int wsc_put_u32(uint8_t **p, size_t *remain, uint16_t attr, uint32_t data);
int wsc_put(uint8_t **p, size_t *remain, uint16_t attr, void *data, uint16_t len);

#define AES_BLOCK_SIZE		16
#define SHA256_MAC_LEN		32

#define WPS_AUTHKEY_LEN		32
#define WPS_KEYWRAPKEY_LEN	16
#define WPS_EMSK_LEN		32

struct wsc_key {
	uint8_t *key;
	uint32_t keylen;
	uint8_t nonce[16];
	uint8_t macaddr[6];
};

int wps_kdf(const uint8_t *key, const uint8_t *label_prefix,
	     size_t label_prefix_len, const char *label, uint8_t *res,
	     size_t res_len);


#endif /* I1905_WSC_H */
