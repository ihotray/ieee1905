/*
 * i1905.h - header file for ieee1905d daemon.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */


#ifndef I1905_H
#define I1905_H


#include "neigh.h"
#include "i1905_wsc.h"


#define OBJECT_INVALID	((uint32_t)-1)

#define IEEE1905_NBR_REMOVED	0x1
#define IEEE1905_NBR_ADDED	0x2
#define IEEE1905_LINK_ADDED	0x4
#define IEEE1905_LINK_REMOVED	0x8

struct i1905_private {
	struct i1905_config cfg;
	atimer_t hbtimer;
	atimer_t topotimer;
	atimer_t refreshtimer;
	struct list_head extlist;
	struct list_head iflist;
	struct i1905_dm dm;
	struct cmdu_ackq txack_q;
	struct neigh_queue neigh_q;

	/* XXX: */
	int al_ifindex;
	char al_ifname[16];

	bool paused;
	int start_apconfig;

	struct ubus_context *ctx;
	struct ubus_object obj;
	struct ubus_event_handler evh;
	struct ubus_object objext;
};


struct i1905_interface_private {
	int sock_1905;
	int sock_lldp;
	uint32_t flags;
	struct uloop_fd uloop_1905;
	struct uloop_fd uloop_lldp;
	struct cmdufrag_queue rxfrag_queue;
	void *i1905private;

	/* keep track of the latest allocated cmdus for Rx.
	 * Used mainly for freeing during module exit.
	 */
	struct cmdu_buff *rxcmdu;
	struct cmdu_buff *rxlldp;
	bool registrar;
	bool configured;

#define I1905_MID_LOOKBACK_MAX	4
	uint16_t lastmid[I1905_MID_LOOKBACK_MAX];
	int lastmid_idx;
	struct i1905_interface_private_wsc *wsc;

	void *iface;	/* points to i1905_interface */
	struct ubus_object obj;
	struct ubus_object_type obj_type;
};

static inline void *i1905_interface_priv(struct i1905_interface_private *p)
{
	return p->iface;
}

struct i1905_private *i1905_selfdevice_to_context(struct i1905_selfdevice *dev);

int i1905_extension_register(struct i1905_private *p, char *name);
int i1905_extension_unregister(struct i1905_private *p, char *name);
int i1905_extension_start(struct i1905_private *p, char *name);
int i1905_extension_stop(struct i1905_private *p, char *name);


int i1905_init(void **priv, void *user_opts);
int i1905_exit(void *priv);
void i1905_run(void *priv);
int i1905_start();
int i1905_stop(struct i1905_private *p);

int i1905_get_known_neighbors(struct i1905_private *priv, char *ifname);

int i1905_register_misc_events(struct i1905_private *priv);
int i1905_unregister_misc_events(struct i1905_private *priv);

int i1905_register_nlevents(struct i1905_private *priv);
void i1905_unregister_nlevents(struct i1905_private *priv);

bool i1905_has_registrar(void *priv, uint8_t freqband);
bool i1905_is_registrar(void *priv);

int i1905_handle_iflink_change(struct i1905_private *priv, const char *ifname,
			       bool is_brif, int br_ifindex, bool dellink);

#if 0
int i1905_handle_if_newlink(struct i1905_private *priv, const char *ifname,
			    bool is_brif, int br_ifindex);

int i1905_handle_if_dellink(struct i1905_private *priv, const char *ifname);
#endif

int i1905_init_apsettings_for_band(void *priv, uint8_t band,
				   struct wps_credential *ap);

int i1905_get_apsettings_for_band(void *priv, uint8_t band,
				  struct wps_credential *cred);

int i1905_apconfig_request(void *priv, uint8_t band);
int i1905_apconfig_renew(void *priv, uint8_t band);

bool i1905_lookup_interface_in_config(struct i1905_private *priv, char *ifname);
char *i1905_brport_to_ifname(struct i1905_private *priv, uint16_t port);

struct i1905_interface *i1905_ifname_to_interface(struct i1905_private *priv,
						  const char *ifname);


struct i1905_interface *i1905_setup_interface(struct i1905_private *priv,
					      const char *ifname);
void i1905_teardown_interface(struct i1905_private *priv, const char *ifname);

int i1905_rebind_interface(struct i1905_private *priv, struct i1905_interface *iface);


int i1905_cmdu_tx(struct i1905_interface_private *ifpriv, uint16_t vid,
		  uint8_t *dst, uint8_t *src, uint16_t type,
		  uint16_t *mid, uint8_t *data, int datalen,
		  bool loopback);

int i1905_send_cmdu(struct i1905_interface_private *ifpriv, uint16_t vid,
		    uint8_t *dst, uint8_t *src, uint16_t ethtype,
		    struct cmdu_buff *frm);

int i1905_send_cmdu_relay_mcast(struct i1905_private *priv, const char *ifname,
				uint8_t *dst, uint8_t *src, uint16_t ethtype,
				struct cmdu_buff *frm);

int i1905_relay_cmdu(struct i1905_private *priv, const char *ifname,
		     uint8_t *dst, uint8_t *src, uint16_t ethtype,
		     struct cmdu_buff *frm);


int i1905_process_cmdu(struct i1905_private *priv, struct cmdu_buff *rxf);
int i1905_process_lldp(struct i1905_private *priv, struct cmdu_buff *rxf);


int i1905_send_bridge_discovery(struct i1905_interface *iface);


struct cmdu_buff *i1905_build_topology_discovery(struct i1905_interface *iface);
struct cmdu_buff *i1905_build_topology_notification(struct i1905_interface *iface);
struct cmdu_buff *i1905_build_topology_response(struct i1905_interface *iface);
struct cmdu_buff *i1905_build_higher_layer_response(struct i1905_interface *iface);
struct cmdu_buff *i1905_build_link_metric_query(struct i1905_interface *iface);
struct cmdu_buff *i1905_build_link_metric_response(struct i1905_interface *iface,
						   uint8_t *neighbor,
						   uint8_t query_type);

struct cmdu_buff *i1905_build_ap_autoconfig_search(struct i1905_interface *iface,
						   uint8_t freqband);

struct cmdu_buff *i1905_build_ap_autoconfig_renew(struct i1905_interface *iface,
						  uint8_t freqband);

struct cmdu_buff *i1905_build_ap_autoconfig_response(struct i1905_interface *iface,
						     uint8_t freqband);

struct cmdu_buff *i1905_build_vendor_specific(struct i1905_interface *iface,
					      int argc, char *argv[]);

int i1905_send_topology_discovery(struct i1905_interface *iface);

int i1905_send_topology_notification(struct i1905_private *priv, const char *ifname);

int i1905_send_topology_query(struct i1905_interface *iface, uint8_t *dest);

int i1905_send_topology_response(struct i1905_interface *iface, uint8_t *dest,
				 uint16_t mid);


int i1905_send_link_metric_query(struct i1905_interface *iface, uint8_t *dest);

int i1905_send_link_metric_response(struct i1905_interface *iface, uint8_t *dest,
				    uint8_t *neighbor, uint8_t query_type,
				    uint16_t mid);

int i1905_send_ap_autoconfig_search(struct i1905_private *priv, uint8_t rf_band);
int i1905_send_ap_autoconfig_renew(struct i1905_private *priv, uint8_t rf_band);

int i1905_send_ap_autoconfig_response(struct i1905_interface *pif, uint8_t *dest,
				      uint8_t band, uint16_t mid);

int i1905_send_ap_autoconfig_wsc_m1(struct i1905_interface_private *out_pif,
				    struct i1905_interface_private *pif,
				    uint8_t *dest);

int i1905_send_ap_autoconfig_wsc_m2(struct i1905_interface_private *out_pif,
				    struct wps_credential *cred,
				    uint16_t mid, uint8_t *dest,
				    uint8_t *m1, uint16_t m1_size);

int i1905_send_higherlayer_query(struct i1905_interface *pif, uint8_t *dest);

int i1905_send_higherlayer_response(struct i1905_interface *pif, uint8_t *dest,
				    uint16_t mid);

int i1905_send_pbc_event_notification(struct i1905_private *priv,
				      uint8_t num_media, uint16_t media_type[],
				      void *media_info[]);

int i1905_send_pbc_join_notification(struct i1905_private *priv, uint8_t *macaddr,
				     uint8_t *new_macaddr);

int extmodule_maybe_process_cmdu(struct list_head *extensions,
				 struct cmdu_buff *rxf);

int i1905_publish_object(struct i1905_private *p, const char *objname);
int i1905_remove_object(struct i1905_private *p);
int i1905_publish_interface_object(struct i1905_private *priv, const char *ifname);
int i1905_remove_interface_object(struct i1905_private *priv, const char *ifname);

struct i1905_extmodule *i1905_load_extmodule(struct i1905_private *priv,
					     const char *name);
int i1905_unload_extmodule(struct i1905_extmodule *mod);

int i1905_extmodules_notify(struct i1905_private *priv, uint32_t event, ...);

int extmodules_load(int argc, char *argv[], struct list_head *extensions);
int extmodules_unload(struct list_head *extensions);

struct i1905_dm *i1905_dm_get();
int i1905_dm_init(struct i1905_dm *dm, struct i1905_config *cfg);
int i1905_dm_free(struct i1905_dm *dm);

int i1905_dm_refresh_self(struct i1905_private *p);

int i1905_dm_neighbor_discovered(struct i1905_interface *iface, uint8_t *aladdr,
				 uint8_t *macaddr, uint16_t cmdu_type);

int i1905_dm_neighbor_changed(struct i1905_interface *iface, uint8_t *aladdr);

int i1905_dm_neighbor_update(struct i1905_interface *iface, uint8_t *aladdr,
			     struct tlv *t);

void i1905_dm_neighbor_free(struct i1905_device *dev);

struct i1905_device *i1905_dm_neighbor_lookup(struct i1905_interface *iface,
					      uint8_t *aladdr);

struct i1905_device *i1905_get_neigh_device(struct i1905_interface *iface,
					    uint8_t *aladdr);

struct i1905_interface *i1905_lookup_interface(struct i1905_private *p,
					       char *ifname);

struct i1905_interface *i1905_dm_neighbor_interface_lookup(struct i1905_device *rdev,
							   uint8_t *ifmacaddr);


struct i1905_neighbor_interface *i1905_link_neighbor_lookup(struct i1905_interface *iface,
						      uint8_t *macaddr);

void i1905_free_interface_links(struct i1905_interface *iface);

void i1905_free_all_invalid_links(struct i1905_interface *iface, uint8_t *aladdr);

void i1905_free_all_non1905_nbrs_of_neighbor(struct i1905_interface *iface, uint8_t *aladdr);

int i1905_dm_neighbor_update_non1905_neighbors(struct i1905_interface *iface,
					       uint8_t *aladdr);

int if_getmediatype(const char *ifname, enum if_mediatype *mtype);

int i1905_cmdu_parse_tlvs(struct cmdu_buff *cmdu, struct tlv *tv[][16], int num_tv);

#endif /* I1905_H */
