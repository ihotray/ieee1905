/*
 * i1905_extension.c - for extending core IEEE-1905 CMDUs.
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
#include <string.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/time.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>

#include "timer.h"
#include "util.h"
#include "bufutil.h"
#include "config.h"
#include "cmdu.h"
#include "cmdu_ackq.h"
#include "cmdufrag.h"
#include "1905_tlvs.h"
#include "i1905_dm.h"
#include "i1905.h"
#include "i1905_extension.h"

#define I1905_EXTMODULE_PATH	"/usr/lib/"IEEE1905_OBJECT

static int extmodule_load(const char *path, const char *name, void **handle)
{
	void *h;
	char abspath[256] = {0};
	int flags = 0;

	if (!handle || !name || !path)
		return -1;

	flags |= RTLD_NOW | RTLD_GLOBAL;

	snprintf(abspath, sizeof(abspath) - 1, "%s/%s", path, name);

	h = dlopen(abspath, flags);
	if (!h) {
		fprintf(stderr, "%s: Error: %s\n", __func__, dlerror());
		return -1;
	}

	*handle = h;
	return 0;
}

static int extmodule_unload(void *handle)
{
	if (!handle)
		return -1;

	return dlclose(handle);
}

int i1905_unload_extmodule(struct i1905_extmodule *mod)
{
	if (mod) {
		int ret;

		if (mod->exit)
			mod->exit(mod->priv);

		ret = extmodule_unload(mod->handle);
		fprintf(stderr, "%s: ret = %d\n", __func__, ret);
		list_del(&mod->list);
		fprintf(stderr, "Unloaded extension\n");

		return ret;
	}

	return -1;
}

struct i1905_extmodule *i1905_load_extmodule(struct i1905_private *priv,
					     const char *name)
{
	struct i1905_extmodule *p;
	char extmodule_file[128] = {0};
	struct i1905_extmodule *pp = NULL;
	void *handle;
	int ret;
	struct i1905_context i1905ctx = {
		.bus = priv->ctx,
		.context = priv,
	};

	snprintf(extmodule_file, 127, "%s.so", name);
	ret = extmodule_load(I1905_EXTMODULE_PATH, extmodule_file, &handle);
	if (ret)
		return NULL;

	pp = dlsym(handle, name);
	if (!pp) {
		fprintf(stderr, "Symbol '%s' not found\n", name);
		return NULL;
	}

	p = calloc(1, sizeof(struct i1905_extmodule));
	if (!p) {
		extmodule_unload(handle);
		return NULL;
	}

	memcpy(p, pp, sizeof(struct i1905_extmodule));
	p->handle = handle;

	if (p->init)
		p->init(&p->priv, &i1905ctx);

	fprintf(stderr, "Loaded extension %s (priv = 0x%p)\n", name, p->priv);

	return p;
}

int extmodules_load(int argc, char *argv[], struct list_head *extensions)
{
	struct i1905_extmodule *p;
	int i;

	for (i = 0; i < argc && argv[i]; i++) {
		char extmodule_file[128] = {0};
		void *handle;
		struct i1905_extmodule *pp = NULL;
		int ret;

		snprintf(extmodule_file, 127, "%s.so", argv[i]);
		ret = extmodule_load(I1905_EXTMODULE_PATH, extmodule_file, &handle);
		if (ret)
			continue;

		pp = dlsym(handle, argv[i]);
		if (!pp) {
			fprintf(stderr, "Symbol '%s' not found\n", argv[i]);
			continue;
		}

		p = calloc(1, sizeof(struct i1905_extmodule));
		if (!p) {
			ret = extmodule_unload(handle);
			continue;
		}

		memcpy(p, pp, sizeof(struct i1905_extmodule));
		list_add_tail(&p->list, extensions);
		if (p->init)
			p->init(&p->priv, NULL);
	}

	return 0;
}

int extmodules_unload(struct list_head *extensions)
{
	struct i1905_extmodule *p, *tmp;
	int ret = 0;

	list_for_each_entry_safe(p, tmp, extensions, list) {
		if (p->exit)
			p->exit(p->priv);

		list_del(&p->list);
		ret |= extmodule_unload(p->handle);
		free(p);
	}

	return ret;
}

int extmodule_maybe_process_cmdu(struct list_head *extensions,
				 struct cmdu_buff *frm)
{
	struct i1905_extmodule *e;
	int ret = CMDU_NOP;
	uint16_t type;
	int i;

	type = buf_get_be16((uint8_t *)&frm->cdata->hdr.type);

	list_for_each_entry(e, extensions, list) {
		//if (!e->active)
		//	continue;

		if ((e->num_ext == -1 || (e->from_newtype <= type && type <= e->to_newtype))
		    && e->process_cmdu) {
			ret = e->process_cmdu(e->priv, frm);
			if (ret == CMDU_OK)
				continue;

			if (ret == CMDU_DONE || ret == CMDU_DROP)
				return ret;
		}

		if (type <= CMDU_TYPE_MAX) {
			for (i = 0; i < e->num_ext; i++) {
				if (e->ext[i].type == type) {
					ret = e->process_cmdu(e->priv, frm);
					if (ret == CMDU_OK)
						break;

					if (ret == CMDU_DONE || ret == CMDU_DROP)
						return ret;
				}
			}
		}
	}

	return ret;
}

static int i1905_extmodules_notify_event(struct i1905_private *priv, char *msg,
					 size_t len)
{
	struct i1905_extmodule *m;

	list_for_each_entry(m, &priv->extlist, list) {
		if (m->event_cb)
			m->event_cb(m->priv, msg, len);
	}

	return 0;
}

int i1905_extmodules_notify(struct i1905_private *priv, uint32_t event, ...)
{
	char evbuf[512] = {0};
	va_list ap;


	va_start(ap, event);

	switch (event) {
	case IEEE1905_NBR_REMOVED:
		{
			uint8_t *nbr_aladdr = (uint8_t *)va_arg(ap, void *);

			snprintf(evbuf, sizeof(evbuf) - 1,
				 "ieee1905.neighbor.del '{\"nbr_ieee1905id\":\""MACFMT
				 "\", \"is1905\":true }'",
				 MAC2STR(nbr_aladdr));
		}
		break;
	case IEEE1905_NBR_ADDED:
		{
			uint8_t *nbr_aladdr = (uint8_t *)va_arg(ap, void *);
			uint8_t *nbr_ifmacaddr = (uint8_t *)va_arg(ap, void *);
			uint8_t *rx_ifmacaddr = (uint8_t *)va_arg(ap, void *);

			snprintf(evbuf, sizeof(evbuf) - 1,
				 "ieee1905.neighbor.add '{\"nbr_ieee1905id\":\"" MACFMT
				 "\", \"nbr_macaddress\":\"" MACFMT
				 "\", \"macaddress\":\"" MACFMT
				 "\", \"is1905\":true }'",
				 MAC2STR(nbr_aladdr),
				 MAC2STR(nbr_ifmacaddr),
				 MAC2STR(rx_ifmacaddr));
		}
		break;
	case IEEE1905_LINK_ADDED:
		{
			uint8_t *aladdr = (uint8_t *)va_arg(ap, void *);
			uint8_t *ifmacaddr = (uint8_t *)va_arg(ap, void *);
			uint8_t *nbr_aladdr = (uint8_t *)va_arg(ap, void *);
			uint8_t *nbr_ifmacaddr = (uint8_t *)va_arg(ap, void *);
			bool direct = (bool)va_arg(ap, void *);

			snprintf(evbuf, sizeof(evbuf) - 1,
				 "ieee1905.link.add '{\"ieee1905id\":\"" MACFMT
				 "\", \"macaddress\":\"" MACFMT
				 "\", \"nbr_ieee1905id\":\"" MACFMT
				 "\", \"nbr_macaddress\":\"" MACFMT
				 "\", \"direct\":\"%s\" }'",
				 MAC2STR(aladdr),
				 MAC2STR(ifmacaddr),
				 MAC2STR(nbr_aladdr),
				 MAC2STR(nbr_ifmacaddr),
				 direct ? "true" : "false");
		}
		break;
	case IEEE1905_LINK_REMOVED:
		{
			uint8_t *aladdr = (uint8_t *)va_arg(ap, void *);
			uint8_t *ifmacaddr = (uint8_t *)va_arg(ap, void *);
			uint8_t *nbr_aladdr = (uint8_t *)va_arg(ap, void *);
			uint8_t *nbr_ifmacaddr = (uint8_t *)va_arg(ap, void *);
			int timeout = (int)va_arg(ap, int);

			snprintf(evbuf, sizeof(evbuf) - 1,
				 "ieee1905.link.del '{\"ieee1905id\":\"" MACFMT
				 "\", \"macaddress\":\"" MACFMT
				 "\", \"nbr_ieee1905id\":\"" MACFMT
				 "\", \"nbr_macaddress\":\"" MACFMT
				 "\", \"reason\":\"%s\" }'",
				 MAC2STR(aladdr),
				 MAC2STR(ifmacaddr),
				 MAC2STR(nbr_aladdr),
				 MAC2STR(nbr_ifmacaddr),
				 timeout ? "timeout" : "invalid");
		}
		break;
	default:
		va_end(ap);
		return 0;
	}

	va_end(ap);
	i1905_extmodules_notify_event(priv, evbuf, strlen(evbuf));

	return 0;
}

int ieee1905_get_non1905_neighbors(void *ieee1905, void *buf, size_t *sz)
{
	struct i1905_non1905_ifneighbor *ent;
	struct i1905_selfdevice *self;
	struct i1905_context *i1905;
	struct i1905_interface *lif;
	struct i1905_private *p;
	int pos = 0;
	int rsz = 0;


	if (!ieee1905) {
		errno = -EINVAL;
		return -1;
	}

	i1905 = (struct i1905_context *)ieee1905;
	if (!i1905->context) {
		errno = -EINVAL;
		return -1;
	}

	p = i1905->context;
	self = &p->dm.self;

	list_for_each_entry(lif, &self->iflist, list) {
		if (list_empty(&lif->non1905_nbrlist))
			continue;

		if (lif->lo || hwaddr_is_zero(lif->macaddr))
			continue;

		rsz += sizeof(struct i1905_non1905_ifneighbor) + 6 * lif->num_neighbor_non1905;
	}

	if (*sz < rsz) {
		*sz = rsz;
		errno = -E2BIG;
		return -1;
	}

	memset(buf, 0, *sz);
	*sz = 0;
	pos = 0;
	ent = (struct i1905_non1905_ifneighbor *)buf;

	list_for_each_entry(lif, &self->iflist, list) {
		struct i1905_non1905_neighbor *nnbr;
		int i = 0;

		if (list_empty(&lif->non1905_nbrlist))
			continue;

		if (lif->lo || hwaddr_is_zero(lif->macaddr))
			continue;

		ent = (struct i1905_non1905_ifneighbor *)((uint8_t *)buf + pos);
		memcpy(ent->if_macaddr, lif->macaddr, 6);
		pos += 6;
		list_for_each_entry(nnbr, &lif->non1905_nbrlist, list) {
			memcpy(&ent->non1905_macaddr[i*6], nnbr->macaddr, 6);
			pos += 6;
			i++;
		}

		ent->num_non1905 = i;
		pos += sizeof(ent->num_non1905);
	}

	*sz = pos;
	return 0;
}

int ieee1905_send_cmdu(void *ieee1905, uint8_t *dst, uint8_t *src,
		       uint16_t type, uint16_t *mid, uint8_t *data, int len)
{
	struct i1905_interface_private *ifpriv;
	struct i1905_interface *iface;
	struct i1905_context *i1905;
	struct i1905_private *p;
	uint8_t dstmac[6] = {0};
	uint8_t srcmac[6] = {0};
	uint16_t msgid = 0;
	int ret = -1;


	if (!ieee1905 || !mid)
		return -1;

	i1905 = (struct i1905_context *)ieee1905;
	if (!i1905->context)
		return -1;

	p = i1905->context;

	if (!dst || hwaddr_is_zero(dst))
		memcpy(dstmac, p->dm.self.aladdr, 6);
	else
		memcpy(dstmac, dst, 6);

	if (src && !hwaddr_is_zero(src))
		memcpy(srcmac, src, 6);

	if (*mid != 0)
		msgid = *mid;


	if (hwaddr_is_mcast(dstmac) || hwaddr_is_bcast(dstmac)) {
		bool lo = true;

		if (!msgid)
			msgid = cmdu_get_next_mid();

		/* send out through all interfaces */
		list_for_each_entry(iface, &p->dm.self.iflist, list) {
			ifpriv = iface->priv;
			ret &= i1905_cmdu_tx(ifpriv, iface->vid, dstmac, srcmac,
					     type, &msgid, data, len, lo);
			lo = false;
		}
	} else if (hwaddr_equal(dstmac, p->dm.self.aladdr)) {
		if (list_empty(&p->dm.self.iflist))
			return -1;

		iface = i1905_lookup_interface(p, "lo");
		if (!iface)
			return -1;

		ifpriv = iface->priv;
		ret = i1905_cmdu_tx(ifpriv, iface->vid, dstmac, srcmac, type, &msgid,
				    data, len, true);
	} else {
		struct i1905_neighbor_interface *nif;
		bool sent = false;

		ret = -1;

		list_for_each_entry(iface, &p->dm.self.iflist, list) {
			if (list_empty(&iface->nbriflist))
				continue;

			list_for_each_entry(nif, &iface->nbriflist, list) {
				if (hwaddr_equal(nif->aladdr, dstmac)) {
					ret = i1905_cmdu_tx(iface->priv, iface->vid,
							    dstmac, srcmac, type,
							    &msgid, data, len, true);
					sent = true;
					break;
				}
			}

			if (sent)
				break;
		}
	}

	*mid = !ret ? msgid : 0xffff;
	return ret;
}

int ieee1905_get_alid(void *ieee1905, uint8_t *aladdr)
{
	struct i1905_context *i1905;
	struct i1905_private *p;

	if (!ieee1905 || !aladdr)
		return -1;

	i1905 = (struct i1905_context *)ieee1905;
	if (!i1905->context)
		return -1;

	p = i1905->context;
	memcpy(aladdr, p->dm.self.aladdr, 6);

	return 0;
}
