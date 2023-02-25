/*
 * config.c - IEEE-1905 config handling.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <uci.h>
#include <uci_blob.h>

#include <easy/easy.h>

#include "bufutil.h"
#include "util.h"
#include "config.h"
#include "i1905_wsc.h"


static void uci_add_option(struct uci_context *ctx, struct uci_package *p,
			   struct uci_section *s, const char *option,
			   void *value, bool is_list)
{
	struct uci_ptr ptr = { 0 };

	ptr.p = p;
	ptr.s = s;
	ptr.package = p->e.name;
	ptr.section = s->e.name;
	ptr.option = option;
	ptr.target = UCI_TYPE_OPTION;
	ptr.flags |= UCI_LOOKUP_EXTENDED;
	ptr.value = (char *)value;

	if (is_list)
		uci_add_list(ctx, &ptr);
	else
		uci_set(ctx, &ptr);
}

static int uci_update_section_ap(const char *config, struct i1905_apconfig *ap)
{
	const char *section_type = "ap";
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_section *sec;
	struct uci_element *e;
	struct uci_option *op;
	bool found = false;
	char bandstr[8] = {0};


	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	if (uci_load(ctx, config, &pkg)) {
		uci_free_context(ctx);
		return -1;
	}

	uci_foreach_element(&pkg->sections, e) {
		struct uci_element *x, *tmp;

		sec = uci_to_section(e);

		if (strcmp(sec->type, section_type))
			continue;

		uci_foreach_element_safe(&sec->options, tmp, x) {
			op = uci_to_option(x);
			if (op->type == UCI_TYPE_STRING && !strncmp(x->name, "band", 4)) {
				int t = atoi(op->v.string);

				if (t == ap->band) {
					found = true;
					break;
				}
			}
		}

		if (found) {
			fprintf(stderr, "section 'ap' for band %u present\n",
				ap->band);
			break;
		}
	}

	if (!found)
		uci_add_section(ctx, pkg, section_type, &sec);

	snprintf(bandstr, sizeof(bandstr) - 1, "%u", ap->band);
	uci_add_option(ctx, pkg, sec, "band", bandstr, false);
	uci_add_option(ctx, pkg, sec, "ssid", ap->ssid, false);
	uci_add_option(ctx, pkg, sec, "key", ap->key, false);
	if ((ap->auth_type & WPS_AUTH_WPA3_T) == WPS_AUTH_WPA3_T)
		uci_add_option(ctx, pkg, sec, "encryption", "sae-mixed", false);
	else if ((ap->auth_type & WPS_AUTH_SAE) == WPS_AUTH_SAE)
		uci_add_option(ctx, pkg, sec, "encryption", "sae", false);
	else if ((ap->auth_type & WPS_AUTH_WPA2PSK) == WPS_AUTH_WPA2PSK)
		uci_add_option(ctx, pkg, sec, "encryption", "psk2", false);
	else if (ap->auth_type == 0x0022)
		uci_add_option(ctx, pkg, sec, "encryption", "psk-mixed", false);
	else if (ap->auth_type == 0x0002)
		uci_add_option(ctx, pkg, sec, "encryption", "psk", false);
	else if (ap->auth_type == 0x0001)
		uci_add_option(ctx, pkg, sec, "encryption", "none", false);

	uci_commit(ctx, &pkg, false);
	uci_free_context(ctx);

	return 0;
}

int i1905_config_update_ap(struct i1905_config *cfg, struct i1905_apconfig *ap)
{
	return uci_update_section_ap(IEEE1905_CONFFILE, ap);
}

static int i1905_config_get_base(struct i1905_config *cfg, struct uci_section *s)
{
	enum {
		I1905_ENABLED,
		I1905_MACADDRESS,
		I1905_PRIMARY_VLANID,
		I1905_REGISTRAR,
		I1905_EXTENSION,
		I1905_EXTMODULE,
		I1905_MANUFACTURER,
		I1905_MODEL_NAME,
		I1905_DEVICE_NAME,
		I1905_CONTROL_URL,
		I1905_UUID,
		I1905_MODEL_NUMBER,
		I1905_SERIAL_NUMBER,
		I1905_DEVICE_TYPE,
		I1905_OS_VERSION,
		NUM_I1905_ATTRS,
	};
	const struct uci_parse_option opts[] = {
		{ .name = "enabled", .type = UCI_TYPE_STRING },
		{ .name = "macaddress", .type = UCI_TYPE_STRING },
		{ .name = "primary_vid", .type = UCI_TYPE_STRING },
		{ .name = "registrar", .type = UCI_TYPE_STRING },
		{ .name = "extension", .type = UCI_TYPE_STRING },
		{ .name = "extmodule", .type = UCI_TYPE_LIST },
		{ .name = "manufacturer", .type = UCI_TYPE_STRING },
		{ .name = "model_name", .type = UCI_TYPE_STRING },
		{ .name = "device_name", .type = UCI_TYPE_STRING },
		{ .name = "control_url", .type = UCI_TYPE_STRING },
		{ .name = "uuid", .type = UCI_TYPE_STRING },
		{ .name = "model_number", .type = UCI_TYPE_STRING },
		{ .name = "serial_number", .type = UCI_TYPE_STRING },
		{ .name = "device_type", .type = UCI_TYPE_STRING },
		{ .name = "os_version", .type = UCI_TYPE_STRING },
	};
	struct uci_option *tb[NUM_I1905_ATTRS];
	bool auto_macaddr = false;


	uci_parse_section(s, opts, NUM_I1905_ATTRS, tb);

	if (tb[I1905_ENABLED]) {
		const char *val = tb[I1905_ENABLED]->v.string;

		cfg->enabled = atoi(val) == 1 ? true : false;
	}


	if (tb[I1905_MACADDRESS]) {
		const char *val = tb[I1905_MACADDRESS]->v.string;

		if (!strncmp(val, "auto", 4)) {
			auto_macaddr = true;
		} else {
			if (strlen(val) != 17)
				return -1;

			hwaddr_aton(val, cfg->macaddr);
		}
	} else {
		auto_macaddr = true;
	}

	if (auto_macaddr) {
		/* generate random al-addr */
		get_random_bytes(6, cfg->macaddr);
		cfg->macaddr[0] &= 0xfe;
		cfg->macaddr[0] |= 0x02;
		cfg->update_config = true;

		fprintf(stderr, "%s: random al-addr = " MACFMT "\n",
			__func__, MAC2STR(cfg->macaddr));
	}

	if (tb[I1905_PRIMARY_VLANID]) {
		const char *val = tb[I1905_PRIMARY_VLANID]->v.string;
		int vid = atoi(val);

		if (vid > 0 && vid < 4095)
			cfg->primary_vid = vid;
		else
			fprintf(stderr, "Ignore invalid primary vlan %d\n", vid);
	}

	if (tb[I1905_REGISTRAR]) {
		const char *val = tb[I1905_REGISTRAR]->v.string;


		if (!strstr(val, "*")) {
			cfg->registrar = I1905_CONFIG_REGISTRAR_ALL;
		} else {
			if (strstr(val, "5"))
				cfg->registrar |= BIT(I1905_CONFIG_REGISTRAR_5G);

			if (strstr(val, "2"))
				cfg->registrar |= BIT(I1905_CONFIG_REGISTRAR_2G);

			if (strstr(val, "60"))
				cfg->registrar |= BIT(I1905_CONFIG_REGISTRAR_60G);
		}
	}


	if (tb[I1905_EXTENSION]) {
		const char *val = tb[I1905_EXTENSION]->v.string;

		cfg->extensions = atoi(val) == 1 ? true : false;
	}

	if (tb[I1905_EXTMODULE]) {
		struct uci_element *e;
		struct i1905_extension_config *n;

		fprintf(stderr, "Extension module: ");
		uci_foreach_element(&tb[I1905_EXTMODULE]->v.list, e) {
			fprintf(stderr, "%s ", e->name);

			n = calloc(1, sizeof(*n));
			if (n) {
				strncpy(n->name, e->name, 31);
				list_add_tail(&n->list, &cfg->extlist);
			}
		}
		fprintf(stderr, "\n");
	}

	if (tb[I1905_MANUFACTURER]) {
		char *val = tb[I1905_MANUFACTURER]->v.string;

		if (strlen(val) <= 64) {
			memset(cfg->manufacturer, 0, sizeof(cfg->manufacturer));
			strncpy(cfg->manufacturer, val, strlen(val));
		}
	}

	if (tb[I1905_MODEL_NAME]) {
		char *val = tb[I1905_MODEL_NAME]->v.string;

		if (strlen(val) <= 32) {
			memset(cfg->model_name, 0, sizeof(cfg->model_name));
			strncpy(cfg->model_name, val, strlen(val));
		}
	}

	if (tb[I1905_DEVICE_NAME]) {
		char *val = tb[I1905_DEVICE_NAME]->v.string;

		if (strlen(val) <= 32) {
			memset(cfg->device_name, 0, sizeof(cfg->device_name));
			strncpy(cfg->device_name, val, strlen(val));
		}
	}

	if (tb[I1905_CONTROL_URL]) {
		char *val = tb[I1905_CONTROL_URL]->v.string;

		if (cfg->url)
			free(cfg->url);

		cfg->url = strdup(val);
	} else {
		if (cfg->url) {
			free(cfg->url);
			cfg->url = NULL;
		}
	}

	if (tb[I1905_UUID]) {
		char *val = tb[I1905_UUID]->v.string;
		char uuidstr[37] = {0};

		if (strlen(val) == 36) {
			strncpy(uuidstr, val, sizeof(uuidstr));
			uuid_strtob(uuidstr, cfg->uuid);
		}
	}

	if (tb[I1905_MODEL_NUMBER]) {
		char *val = tb[I1905_MODEL_NUMBER]->v.string;

		if (strlen(val) <= 32) {
			memset(cfg->model_number, 0, sizeof(cfg->model_number));
			strncpy(cfg->model_number, val, strlen(val));
		}
	}

	if (tb[I1905_SERIAL_NUMBER]) {
		char *val = tb[I1905_SERIAL_NUMBER]->v.string;

		if (strlen(val) <= 32) {
			memset(cfg->serial_number, 0, sizeof(cfg->serial_number));
			strncpy(cfg->serial_number, val, strlen(val));
		}
	}

	if (tb[I1905_DEVICE_TYPE]) {
		char *val = tb[I1905_DEVICE_TYPE]->v.string;
		uint8_t oui[4] = {0};
		int subcat;
		int cat;
		int ret;

		ret = sscanf(val, "%2d-%02hhx%02hhx%02hhx%02hhx-%2d", &cat,
		       &oui[0], &oui[1], &oui[2], &oui[3], &subcat);

		if (ret != 6) {
			/* supplied device-type is invalid; using default */
			memcpy(cfg->device_type, WPS_DEFAULT_DEVICE_TYPE, 8);
		} else {
			buf_put_be16(cfg->device_type, cat);
			memcpy(&cfg->device_type[2], oui, 4);
			buf_put_be16(&cfg->device_type[6], subcat);
		}
	}

	if (tb[I1905_OS_VERSION])
		cfg->os_version = strtoul(tb[I1905_OS_VERSION]->v.string, NULL, 0);

	return 0;
}

static int i1905_config_get_ap(struct i1905_config *cfg, struct uci_section *s)
{
	enum {
		I1905_AP_BAND,
		I1905_AP_SSID,
		I1905_AP_ENCRYPTION,
		I1905_AP_KEY,
		I1905_AP_UUID,
		I1905_AP_MANUFACTURER,
		I1905_AP_MODEL_NAME,
		I1905_AP_DEVICE_NAME,
		I1905_AP_MODEL_NUMBER,
		I1905_AP_SERIAL_NUMBER,
		I1905_AP_DEVICE_TYPE,
		I1905_AP_OS_VERSION,
		NUM_I1905_AP_ATTRS,
	};
	const struct uci_parse_option opts[] = {
		{ .name = "band", .type = UCI_TYPE_STRING },
		{ .name = "ssid", .type = UCI_TYPE_STRING },
		{ .name = "encryption", .type = UCI_TYPE_STRING },
		{ .name = "key", .type = UCI_TYPE_STRING },
		{ .name = "uuid", .type = UCI_TYPE_STRING },
		{ .name = "manufacturer", .type = UCI_TYPE_STRING },
		{ .name = "model_name", .type = UCI_TYPE_STRING },
		{ .name = "device_name", .type = UCI_TYPE_STRING },
		{ .name = "model_number", .type = UCI_TYPE_STRING },
		{ .name = "serial_number", .type = UCI_TYPE_STRING },
		{ .name = "device_type", .type = UCI_TYPE_STRING },
		{ .name = "os_version", .type = UCI_TYPE_STRING },
	};
	struct uci_option *tb[NUM_I1905_AP_ATTRS];
	struct i1905_apconfig *ap;



	uci_parse_section(s, opts, NUM_I1905_AP_ATTRS, tb);

	if (!tb[I1905_AP_BAND] || !tb[I1905_AP_SSID]) {
		fprintf(stderr, "Invalid ap config section!"
				"'band' or 'ssid' missing. Ignore..\n");
		return 0;
	}

	ap = calloc(1, sizeof(*ap));
	if (!ap) {
		fprintf(stderr, "-ENOMEM\n");
		return -1;
	}

	if (tb[I1905_AP_BAND]) {
		const char *val = tb[I1905_AP_BAND]->v.string;
		int band = atoi(val);

		if (band < 0) {
			fprintf(stderr, "Ignore ap config for band %d\n", band);
			free(ap);
			return 0;
		}

		ap->band = band;
	}

	if (tb[I1905_AP_SSID]) {
		ap->ssidlen = strlen(tb[I1905_AP_SSID]->v.string);
		memcpy(ap->ssid, tb[I1905_AP_SSID]->v.string, ap->ssidlen);
	}


	if (tb[I1905_AP_ENCRYPTION]) {
		const char *val = tb[I1905_AP_ENCRYPTION]->v.string;

		if (strstr(val, "psk2")) {
			ap->auth_type = 0x0020;  /* WPS_AUTH_WPA2PSK */
			ap->enc_type = 0x0008;	 /* WPS_ENCR_AES */
		} else if (strstr(val, "sae-mixed")) {
			ap->auth_type = 0x0060;  /* WPS_AUTH_SAE | WPS_AUTH_WPA2PSK */
			ap->enc_type = 0x0008;	 /* WPS_ENCR_AES */
		} else if (strstr(val, "sae")) {
			ap->auth_type = 0x0040;  /* WPS_AUTH_SAE */
			ap->enc_type = 0x0008;	 /* WPS_ENCR_AES */
		} else if (strstr(val, "psk-mixed")) {
			ap->auth_type = 0x0022;	/* WPS_AUTH_WPAPSK | WPS_AUTH_WPA2PSK */
			ap->enc_type = 0x0008;	/* WPS_ENCR_AES */
		} else if (strstr(val, "psk")) {
			ap->auth_type = 0x0002;	/* WPS_AUTH_WPAPSK */
			ap->enc_type = 0x0008;	/* WPS_ENCR_AES */
		} else if (strstr(val, "none")) {
			ap->auth_type = 0x0001;	/* WPS_AUTH_OPEN */
			ap->enc_type = 0x0001;	/* WPS_ENCR_NONE */
		} else {
			free(ap);
			fprintf(stderr, "Unsupported ap encryption in config\n");
			return 0;
		}
	}

	if (tb[I1905_AP_KEY]) {
		char *val = tb[I1905_AP_KEY]->v.string;

		ap->keylen = strlen(val);
		if (ap->keylen == 0 || ap->keylen > 64) {
			free(ap);
			fprintf(stderr, "Invalid ap keylen in config\n");
			return 0;
		}
		memcpy(ap->key, val, ap->keylen);
	}

	if (tb[I1905_AP_UUID]) {
		char *val = tb[I1905_AP_UUID]->v.string;
		char uuidstr[37] = {0};

		if (strlen(val) != 36) {
			free(ap);
			fprintf(stderr, "Invalid UUID in config\n");
			return 0;
		}

		strncpy(uuidstr, val, sizeof(uuidstr));
		uuid_strtob(uuidstr, ap->uuid);
	} else {
		uuid_strtob(WPS_DEFAULT_UUID, ap->uuid);
	}

	if (tb[I1905_AP_MANUFACTURER]) {
		char *val = tb[I1905_AP_MANUFACTURER]->v.string;

		if (strlen(val) > 64) {
			free(ap);
			fprintf(stderr, "Invalid manufacturer in config\n");
			return 0;
		}
		strncpy(ap->manufacturer, val, strlen(val));
	} else {
		strcpy(ap->manufacturer, "IOPSYS");
	}


	if (tb[I1905_AP_MODEL_NAME]) {
		char *val = tb[I1905_AP_MODEL_NAME]->v.string;

		if (strlen(val) > 32) {
			free(ap);
			fprintf(stderr, "Invalid model_name in config\n");
			return 0;
		}
		strncpy(ap->model_name, val, strlen(val));
	} else {
		strcpy(ap->model_name, "Multi-AP-device");
	}


	if (tb[I1905_AP_DEVICE_NAME]) {
		char *val = tb[I1905_AP_DEVICE_NAME]->v.string;

		if (strlen(val) > 32) {
			free(ap);
			fprintf(stderr, "Invalid device_name in config\n");
			return 0;
		}
		strncpy(ap->device_name, val, strlen(val));
	} else {
		strcpy(ap->device_name, "Multi-AP-device");
	}


	if (tb[I1905_AP_MODEL_NUMBER]) {
		char *val = tb[I1905_AP_MODEL_NUMBER]->v.string;

		if (strlen(val) > 32) {
			free(ap);
			fprintf(stderr, "Invalid model number in config\n");
			return 0;
		}
		strncpy(ap->model_number, val, strlen(val));
	}

	if (tb[I1905_AP_SERIAL_NUMBER]) {
		char *val = tb[I1905_AP_SERIAL_NUMBER]->v.string;

		if (strlen(val) > 32) {
			free(ap);
			fprintf(stderr, "Invalid serial number in config\n");
			return 0;
		}
		strncpy(ap->serial_number, val, strlen(val));
	}

	if (tb[I1905_AP_DEVICE_TYPE]) {
		char *val = tb[I1905_AP_DEVICE_TYPE]->v.string;
		uint8_t oui[4] = {0};
		int subcat;
		int cat;
		int ret;

		ret = sscanf(val, "%2d-%02hhx%02hhx%02hhx%02hhx-%2d", &cat,
		       &oui[0], &oui[1], &oui[2], &oui[3], &subcat);

		if (ret != 6) {
			/* supplied device-type is invalid; using default */
			memcpy(ap->device_type, WPS_DEFAULT_DEVICE_TYPE, 8);
		} else {
			buf_put_be16(ap->device_type, cat);
			memcpy(&ap->device_type[2], oui, 4);
			buf_put_be16(&ap->device_type[6], subcat);
		}
	} else {
		memcpy(ap->device_type, WPS_DEFAULT_DEVICE_TYPE, 8);
	}

	if (tb[I1905_AP_OS_VERSION])
		ap->os_version = strtoul(tb[I1905_AP_OS_VERSION]->v.string, NULL, 0);


	list_add_tail(&ap->list, &cfg->reglist);

	return 0;
}

static struct i1905_iface_config *i1905_config_alloc_iface(const char *name)
{
	struct i1905_iface_config *n;

	if (strlen(name) >= 16)
		return NULL;

	n = calloc(1, sizeof(*n));
	if (n) {
		fprintf(stderr, "%s: name = %s\n", __func__, name);
		strncpy(n->ifname, name, 15);
	}

	return n;
}

int i1905_config_add_interface(struct i1905_config *cfg, const char *ifname)
{
	struct i1905_iface_config *p;

	if (!ifname || ifname[0] == '\0')
		return -1;

	list_for_each_entry(p, &cfg->iflist, list) {
		if (!strncmp(p->ifname, ifname, strlen(ifname)))
			return -1;
	}

	p = i1905_config_alloc_iface(ifname);
	if (!p)
		return -1;

	list_add_tail(&p->list, &cfg->iflist);
	if (if_isbridge(ifname))
		p->is_bridge = true;

	return 0;
}

#if 0
static void i1905_config_free_iface(struct i1905_iface_config *ifcfg)
{
	if (ifcfg) {
		list_del(&ifcfg->list);
		free(ifcfg);
	}
}
#endif

static int i1905_config_get_aliface(struct i1905_config *cfg,
				    struct uci_section *s)
{
	enum {
		I1905_IFACE_NAME,
		NUM_IFACE_ATTRS,
	};
	const struct blobmsg_policy aliface_attrs[NUM_IFACE_ATTRS] = {
		[I1905_IFACE_NAME] = { .name = "ifname", .type = BLOBMSG_TYPE_ARRAY },
	};
	const struct uci_blob_param_list aliface_list = {
		.n_params = NUM_IFACE_ATTRS,
		.params = aliface_attrs,
	};
	struct blob_attr *ctb, *attr;
	struct blob_buf b = {0};
	int rem;


	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &aliface_list);
	ctb = blob_memdup(b.head);
	if (!ctb) {
		blob_buf_free(&b);
		return 0;
	}

	fprintf(stderr, "Interface list: ");
	blobmsg_for_each_attr(attr, ctb, rem) {
		if (blobmsg_type(attr) == BLOBMSG_TYPE_ARRAY) {
			struct blob_attr *x;
			int rem1;

			blobmsg_for_each_attr(x, attr, rem1) {
				if (blobmsg_type(x) != BLOBMSG_TYPE_STRING)
					continue;

				char *in = strdup(blobmsg_data(x));
				const char delim[] = ", ";
				char *token, *tmp;

				token = strtok_r(in, delim, &tmp);
				while (token != NULL) {
					struct i1905_iface_config *ifcfg = NULL;

					fprintf(stderr, "%s ", token);
					ifcfg = i1905_config_alloc_iface(token);
					if (ifcfg) {
						list_add_tail(&ifcfg->list, &cfg->iflist);
						if (if_isbridge(token))
							ifcfg->is_bridge = true;
					}

					token = strtok_r(NULL, delim, &tmp);
				}
				free(in);
			}
		}
	}
	fprintf(stderr, "\n");

	free(ctb);
	blob_buf_free(&b);
	return 0;
}

void i1905_config_free(struct i1905_config *cfg)
{
	if (!cfg)
		return;

	if (cfg->url) {
		free(cfg->url);
		cfg->url = NULL;
	}

	list_flush(&cfg->iflist, struct i1905_iface_config, list);
	list_flush(&cfg->extlist, struct i1905_extension_config, list);
	list_flush(&cfg->reglist, struct i1905_apconfig, list);
}

int i1905_reconfig(struct i1905_config *cfg, const char *path, const char *file)
{
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_element *e;
	int ret = 0;


	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	if (path) {
		uci_set_confdir(ctx, path);
		fprintf(stderr, "config path: %s  file: %s\n", path, file);
	}

	if (uci_load(ctx, file, &pkg)) {
		uci_free_context(ctx);
		return -1;
	}

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, "ieee1905"))
			ret |= i1905_config_get_base(cfg, s);
		else if (!strcmp(s->type, "al-iface"))
			ret |= i1905_config_get_aliface(cfg, s);
		else if (!strcmp(s->type, "ap"))
			ret |= i1905_config_get_ap(cfg, s);
	}

	if (cfg->update_config) {
		struct uci_section *s;
		char aladdr[18] = {0};

		s = uci_lookup_section(ctx, pkg, "ieee1905");
		if (s) {
			hwaddr_ntoa(cfg->macaddr, aladdr);
			uci_add_option(ctx, pkg, s, "macaddress", aladdr, false);
			uci_commit(ctx, &pkg, false);
		}
	}

	uci_free_context(ctx);
	return ret;
}

int i1905_set_apconfig_defaults(struct i1905_apconfig *ap)
{
	if (!ap)
		return -1;

	memset(ap, 0, sizeof(*ap));
	ap->band = 0;
	ap->ssidlen = 0;
	ap->keylen = 0;
	ap->auth_type = WPS_AUTH_WPA2PSK;
	ap->enc_type = WPS_ENCR_AES;
	strcpy(ap->manufacturer, WPS_DEFAULT_MANUFACTURER);
	strcpy(ap->model_name, WPS_DEFAULT_MODEL_NAME);
	strcpy(ap->device_name, WPS_DEFAULT_DEVICE_NAME);
	uuid_strtob(WPS_DEFAULT_UUID, ap->uuid);
	strcpy(ap->model_number, WPS_DEFAULT_MODEL_NUM);
	strcpy(ap->serial_number, WPS_DEFAULT_SERIAL_NUM);
	memcpy(ap->device_type, WPS_DEFAULT_DEVICE_TYPE, 8);
	ap->os_version = strtoul(WPS_DEFAULT_OS_VERSION, NULL, 0);
	ap->os_version |= 0x80000000;	/* msb reserved and always 1 */

	return 0;
}

int i1905_config_defaults(struct i1905_config *cfg)
{
	cfg->registrar = 0;
	cfg->primary_vid = 0;

	INIT_LIST_HEAD(&cfg->iflist);
	INIT_LIST_HEAD(&cfg->extlist);
	INIT_LIST_HEAD(&cfg->reglist);
	cfg->url = NULL;

	strcpy(cfg->manufacturer, WPS_DEFAULT_MANUFACTURER);
	strcpy(cfg->model_name, WPS_DEFAULT_MODEL_NAME);
	strcpy(cfg->device_name, WPS_DEFAULT_DEVICE_NAME);
	uuid_strtob(WPS_DEFAULT_UUID, cfg->uuid);
	strcpy(cfg->model_number, WPS_DEFAULT_MODEL_NUM);
	strcpy(cfg->serial_number, WPS_DEFAULT_SERIAL_NUM);
	memcpy(cfg->device_type, WPS_DEFAULT_DEVICE_TYPE, 8);
	cfg->os_version = strtoul(WPS_DEFAULT_OS_VERSION, NULL, 0);
	cfg->os_version |= 0x80000000;	/* msb reserved and always 1 */

	return 0;
}

int i1905_dump_config(struct i1905_config *cfg)
{
	struct i1905_apconfig *ap;
	struct i1905_iface_config *ifcfg;

	if (!cfg)
		return -1;

	fprintf(stderr, "Configuration\n");
	fprintf(stderr, "---\n");
	fprintf(stderr, " Enabled      : %d\n", cfg->enabled);
	fprintf(stderr, " Primary VLAN : %d\n", cfg->primary_vid);
	fprintf(stderr, " AL-macaddr   : " MACFMT"\n", MAC2STR(cfg->macaddr));
	fprintf(stderr, " Manufacturer : %s\n", cfg->manufacturer);
	fprintf(stderr, " ModelName    : %s\n", cfg->model_name);
	fprintf(stderr, " ModelNumber  : %s\n", cfg->model_number);
	fprintf(stderr, " DeviceName   : %s\n", cfg->device_name);
	fprintf(stderr, " DeviceType   : %d-%02hhx%02hhx%02hhx%02hhx-%d\n",
		buf_get_be16(cfg->device_type),
		cfg->device_type[2], cfg->device_type[3], cfg->device_type[4], cfg->device_type[5],
		buf_get_be16(&cfg->device_type[6]));
	fprintf(stderr, " SerialNumber : %s\n", cfg->serial_number);
	fprintf(stderr, " OS version   : %8x\n", cfg->os_version);
	fprintf(stderr, " Control-URL  : %s\n", cfg->url ? cfg->url : "");
	fprintf(stderr, " Interfaces   : ");
	list_for_each_entry(ifcfg, &cfg->iflist, list) {
		fprintf(stderr, "%s ", ifcfg->ifname);
	}
	fprintf(stderr, "\n");

	fprintf(stderr, " Role         : %s\n", cfg->registrar ? "Registrar" : "Non-Registrar");
	if (cfg->registrar) {
		int i = 1;

		list_for_each_entry(ap, &cfg->reglist, list) {
			fprintf(stderr, "[%d]\n", i++);
			fprintf(stderr, "      Freq band    : %u GHz\n", ap->band);
			fprintf(stderr, "      Ssid         : %s\n", ap->ssid);
			fprintf(stderr, "      AuthType     : 0x%04x\n", ap->auth_type);
			fprintf(stderr, "      Encryption   : 0x%04x\n", ap->enc_type);
			fprintf(stderr, "      Manufacturer : %s\n", ap->manufacturer);
			fprintf(stderr, "      ModelName    : %s\n", ap->model_name);
			fprintf(stderr, "      ModelNumber  : %s\n", ap->model_number);
			fprintf(stderr, "      DeviceName   : %s\n", ap->device_name);
			fprintf(stderr, "      DeviceType   : %2d-%02hhx%02hhx%02hhx%02hhx-%2d\n",
				buf_get_be16(ap->device_type),
				ap->device_type[2], ap->device_type[3],
				ap->device_type[4], ap->device_type[5],
				buf_get_be16(&ap->device_type[6]));
			fprintf(stderr, "      SerialNumber : %s\n", ap->serial_number);
			fprintf(stderr, "      OS-version   : 0x%8x\n", ap->os_version);
		}
	}
	fprintf(stderr, "---\n");

	return 0;
}

