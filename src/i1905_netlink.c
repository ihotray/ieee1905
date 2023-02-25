/*
 * i1905_netlink.c - netlink interface to kernel.
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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <netlink/netlink.h>
#include <netlink/utils.h>

#include <netlink/route/rtnl.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/attr.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>


#include <easy/easy.h>

#include "debug.h"
#include "bufutil.h"
#include "util.h"
#include "timer.h"
#include "config.h"
#include "cmdu.h"
#include "cmdu_ackq.h"
#include "cmdufrag.h"
#include "i1905_dm.h"
#include "i1905.h"
#include "1905_tlvs.h"
#include "i1905_wifi.h"

struct i1905_nlevent {
	struct uloop_fd uloop;
	void (*error_cb)(struct i1905_nlevent *e, int error);
	void (*event_cb)(struct i1905_nlevent *e);
};

struct event_socket {
	struct i1905_nlevent ev;
	struct nl_sock *sock;
	int sock_bufsize;
};

static int i1905_nlevents_cb(struct nl_msg *msg, void *arg);

static void handle_error(struct i1905_nlevent *e, int error)
{
	struct event_socket *ev_sock = container_of(e, struct event_socket, ev);

	if (error != ENOBUFS)
		goto err;

	ev_sock->sock_bufsize *= 2;
	if (nl_socket_set_buffer_size(ev_sock->sock, ev_sock->sock_bufsize, 0))
		goto err;

	return;

err:
	e->uloop.cb = NULL;
	uloop_fd_delete(&e->uloop);
}

static void recv_nlevents(struct i1905_nlevent *e)
{
	struct event_socket *ev_sock = container_of(e, struct event_socket, ev);

	nl_recvmsgs_default(ev_sock->sock);
}

static struct event_socket rtnl_event = {
	.ev = {
		.uloop = {.fd = - 1, },
		.error_cb = handle_error,
		.event_cb = recv_nlevents,
	},
	.sock = NULL,
	.sock_bufsize = 0x20000,
};

struct br_fdb_entry {
	uint8_t macaddr[6];
	uint16_t port;
};

/* defined in linux/if_bridge.h */
struct __fdb_entry {
        __u8 mac_addr[6];
        __u8 port_no;
        __u8 is_local;
        __u32 ageing_timer_value;
        __u8 port_hi;
        __u8 pad0;
        __u16 unused;
};

int i1905_update_neigh_brport(struct i1905_private *priv, char *brname)
{
	struct br_fdb_entry fdbs[512];
	struct __fdb_entry fdb[256];
	bool skiplocal = true;
	char path[512] = {0};
	long offset = 0;
	int i, n;
	int num = 0;
	FILE *f;


	snprintf(path, 512, "/sys/class/net/%s/brforward", brname);
	f = fopen(path, "r");
	if (!f)
		return -1;

	do {
		memset(fdb, 0, sizeof(fdb));
		fseek(f, offset * sizeof(struct __fdb_entry), SEEK_SET);
		n = fread(fdb, sizeof(struct __fdb_entry), 256, f);
		if (n <= 0)
			break;

		//TODO: extend when more than 256 entries
		if (num > 255)
			break;

		for (i = 0; i < n; i++) {
			if (skiplocal && fdb[i].is_local == 1)
				continue;

			memcpy(fdbs[num].macaddr, fdb[i].mac_addr, 6);
			fdbs[num].port = fdb[i].port_no;
			num++;
		}
		offset += n;
	} while (n > 0);

	fclose(f);

	for (i = 0; i < num; i++) {
		struct neigh_entry *t;

		dbg7("FDB[%d] : " MACFMT "  port = %hu\n", i,
		    MAC2STR(fdbs[i].macaddr), fdbs[i].port);

		t = neigh_lookup(&priv->neigh_q, fdbs[i].macaddr);
		if (t) {
			t->brport = fdbs[i].port;
#if 0
			char *ifname;

			ifname = i1905_brport_to_ifname(priv, fdbs[i].port);
			if (ifname) {
				memset(t->ifname, 0, 16);
				strncpy(t->ifname, ifname, 16);
			}
#endif
		}
	}

	return 0;
}

static int i1905_neigh_is_wifi_type(struct i1905_private *priv, char *ifname,
				    uint8_t *macaddr)
{
	struct i1905_interface *iface;
	struct ieee80211_info *wifi;
	enum if_mediatype mtype;
	uint8_t stas[768] = {0};
	int num = 128;
	int ret;
	int i;



	if (if_isbridge(ifname)) {
		warn("Only non-composite ifname is allowed in this function\n");
		return 0;
	}


	if_getmediatype(ifname, &mtype);
	if (mtype != IF_MEDIA_WIFI)
		return 0;


	iface = i1905_ifname_to_interface(priv, ifname);
	if (!iface || iface->mediainfo == NULL)
		return 0;

	wifi = (struct ieee80211_info *)iface->mediainfo;
	if (wifi->role != IEEE80211_ROLE_AP)
		return 0;

	ret = platform_wifi_get_assoclist(ifname, stas, &num);
	if (ret)
		return 0;

	for (i = 0; i < num; i++) {
		if (!memcmp(&stas[i*6], macaddr, 6)) {
			return 1;
		}
	}

	return 0;
}

static int i1905_handle_neigh_tbl_change(struct i1905_private *priv, bool add,
					 char *ifname, uint8_t *macaddr,
					 struct ip_address *ip,
					 uint16_t state)
{
	int ret;


	if (hwaddr_is_zero(macaddr))
		return 0;


	ret = neigh_enqueue(&priv->neigh_q, macaddr, state, ifname,
			    NEIGH_TYPE_UNKNOWN, ip, NEIGH_AGEOUT_DEFAULT, NULL);

	if (ret > 0)
		i1905_send_topology_notification(priv, ifname);

	/* update bridge port_nos on which the hosts are last seen */
	if (if_isbridge(ifname)) {
		i1905_update_neigh_brport(priv, ifname);

		if (1 /* ret > 0 */) {
			uint16_t brport;

			brport = neigh_get_brport(&priv->neigh_q, macaddr);
			if (brport != 0xffff)
				ifname = i1905_brport_to_ifname(priv, brport);
		}
	}

	/* if the new neigh is of wifi type, mark it accordingly */
	if (/* ret > 0 && */ ifname) {
		if (i1905_neigh_is_wifi_type(priv, ifname, macaddr))
			neigh_set_type(&priv->neigh_q, macaddr, NEIGH_TYPE_WIFI);
	}

#ifdef NEIGH_DEBUG
	neigh_queue_print(&priv->neigh_q);
#endif

	return 0;
}

static int i1905_handle_nlevents_neigh(struct i1905_private *priv,
				       struct nlmsghdr *hdr, bool add)
{
	struct ndmsg *ndm = nlmsg_data(hdr);
	struct nlattr *nla[__NDA_MAX];
	uint8_t macaddr[6] = {0};
	struct ip_address ip;
	char ipbuf[256] = {0};
	char ifname[16] = {0};
	char state[128] = {0};


	if (!nlmsg_valid_hdr(hdr, sizeof(*ndm)))
		return NL_SKIP;

	nlmsg_parse(hdr, sizeof(*ndm), nla, __NDA_MAX - 1, NULL);
	if (!nla[NDA_DST])
		return NL_SKIP;


	nla_memcpy(&ip.addr, nla[NDA_DST], sizeof(ip.addr));
	nla_memcpy(macaddr, nla[NDA_LLADDR], sizeof(macaddr));
	ip.family = ndm->ndm_family;

	if (IN6_IS_ADDR_LINKLOCAL(&ip.addr) || IN6_IS_ADDR_MULTICAST(&ip.addr))
		return NL_SKIP;

	if (ndm->ndm_family == AF_INET || ndm->ndm_family == AF_INET6)
		inet_ntop(ip.family, &ip.addr, ipbuf, sizeof(ipbuf));

	if_indextoname(ndm->ndm_ifindex, ifname);

	loud("Netlink neigh %s on %s   state = %s\n", ipbuf, ifname,
	     rtnl_neigh_state2str(ndm->ndm_state, state, sizeof(state)));


	i1905_handle_neigh_tbl_change(priv, add, ifname, macaddr, &ip,
				      ndm->ndm_state);

	return NL_OK;
}

static int i1905_handle_nlevents_link(struct i1905_private *priv,
				      struct nlmsghdr *hdr, bool add)
{
	struct ifinfomsg *ifi = nlmsg_data(hdr);
	struct nlattr *nla[__IFLA_MAX];
	struct i1905_interface *iface;
	struct i1905_iface_config *f;
	uint8_t macaddr[6] = {0};
	char ifname[16] = {0};
	int br_ifindex = 0;
	int ret;



	trace("%s: ------------->\n", __func__);

	if (!nlmsg_valid_hdr(hdr, sizeof(*ifi)))
		return NL_SKIP;

	nlmsg_parse(hdr, sizeof(*ifi), nla, __IFLA_MAX - 1, NULL);
	if (!nla[IFLA_IFNAME])
		return NL_SKIP;

	nla_memcpy(ifname, nla[IFLA_IFNAME], 15);
	nla_memcpy(macaddr, nla[IFLA_ADDRESS], sizeof(macaddr));


	iface = i1905_ifname_to_interface(priv, ifname);
	if (iface)
		iface->ifstatus = ifi->ifi_flags;

	if (if_isbridge(ifname)) {
		dbg("%s: %s: %s (ifindex = %d) bridge\n", __func__,
		    add ? "NEWLINK" : "DELLINK", ifname, ifi->ifi_index);

		if (i1905_lookup_interface_in_config(priv, ifname)) {
			struct i1905_interface *ifs;


			dbg("%s: link changed! invalidate member ports\n",
			    ifname);

			list_for_each_entry(ifs, &priv->dm.self.iflist, list) {
				if (ifs->br_ifindex == ifi->ifi_index) {
					fprintf(stderr, "TODO: handle br link change!\n");
					//ifs->invalid = true;
				}
			}
		}

		return NL_OK;
	}

	if (!!(ifi->ifi_flags & IFF_RUNNING)) {
		dbg("%s: %s is UP RUNNING\n", __func__, ifname);
	}

	if (!(ifi->ifi_flags & IFF_UP)) {
		dbg("%s: %s is down. skip..\n", __func__, ifname);
		return NL_OK;
	}


	br_ifindex = if_isbridge_interface(ifname);
	if (br_ifindex < 0) {
		dbg("%s: %s error getting br_ifindex\n", __func__, ifname);
		return NL_SKIP;
	}

	dbg("%s: %s : %s (" MACFMT ", %d), master = %d, fam = %d, flags = 0x%x\n",
	    __func__, add ? "NEWLINK" : "DELLINK",
	    ifname, MAC2STR(macaddr), ifi->ifi_index,
	    br_ifindex, ifi->ifi_family,
	    ifi->ifi_flags);


	if (add && br_ifindex > 0 && iface && ifi->ifi_family == AF_BRIDGE) {
		i1905_handle_iflink_change(priv, ifname, true, br_ifindex, false);
		trace("%s: %s <----------\n", __func__, ifname);

		return NL_OK;
	}

	/* for delif bridged interface, br_ifindex = 0 */
	if (br_ifindex == 0) {
		if (iface) {
			if (!add && ifi->ifi_family == AF_BRIDGE) {
				char ifmaster[16] = {0};

				if_indextoname(iface->br_ifindex, ifmaster);
				dbg("%s removed from bridge %s\n", ifname, ifmaster);

				ret = i1905_remove_interface_object(priv, ifname);
				i1905_teardown_interface(priv, ifname);
				err("%s: %s cleanup %s\n", __func__, ifname,
				    !ret ? "SUCCESS" : "FAILED");
			}

			return NL_OK;
		}

		dbg("%s: %d: %s\n", __func__, __LINE__, ifname);
		if (!i1905_lookup_interface_in_config(priv, ifname)) {
			dbg("%s not known from config. Skipping...\n", ifname);
			return NL_OK;
		}

		dbg("%s: %s  TODO non-bridged interface!\n", __func__, ifname);
		/* handle for non-bridged 1905 interface */
		i1905_handle_iflink_change(priv, ifname, false, -1, !add);
		return NL_OK;
	}

	if (!add) {
		dbg("%s: %d: %s Unhandled DELLINK!\n", __func__, __LINE__, ifname);
		return NL_OK;
	}


	/* for addif bridged interface that is not known to us yet, check if
	 * ifname belongs to a 1905 bridge that is managed by us.
	 */
	list_for_each_entry(f, &priv->cfg.iflist, list) {
		if (f->is_bridge && if_isbridge(f->ifname) &&
		    if_nametoindex(f->ifname) == br_ifindex) {

			dbg("%s: Preparing  %s ...\n", __func__, ifname);
			ret = i1905_handle_iflink_change(priv, ifname, true,
							 br_ifindex, !add);

			err("%s: %s setup %s\n", __func__, ifname,
			    !ret ? "SUCCESS" : "FAILED");

			return NL_OK;
		}
	}

	return NL_OK;
}

static int i1905_nlevents_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct i1905_private *priv = arg;
	int ret = NL_SKIP;
	bool add = false;


	switch (hdr->nlmsg_type) {
	case RTM_NEWLINK:
		add = true;
	case RTM_DELLINK:
		ret = i1905_handle_nlevents_link(priv, hdr, add);
		break;
#if 0	//TODO: when needed
	case RTM_NEWADDR:
		add = true;
	case RTM_DELADDR:
		ret = i1905_handle_nlevents_addr(priv, hdr, add);
		break;
#endif
	case RTM_NEWNEIGH:
		add = true;
	case RTM_DELNEIGH:
		ret = i1905_handle_nlevents_neigh(priv, hdr, add);
		break;

	default:
		break;
	}

	return ret;
}


static void i1905_receive_nlevents(struct uloop_fd *u, unsigned int events)
{
	struct i1905_nlevent *e = container_of(u, struct i1905_nlevent, uloop);

	if (u->error) {
		int ret = -1;
		socklen_t ret_len = sizeof(ret);

		u->error = false;
		if (e->error_cb &&
		    getsockopt(u->fd, SOL_SOCKET, SO_ERROR, &ret, &ret_len) == 0) {
			e->error_cb(e, ret);
		}
	}

	if (e->event_cb) {
		e->event_cb(e);
		return;
	}
}

int i1905_register_nlevents(struct i1905_private *priv)
{
	struct nl_sock *sk;


	sk = nl_socket_alloc();
	if (!sk) {
		err("Unable to open nl event socket: %m");
		return -1;
	}

	if (nl_connect(sk, NETLINK_ROUTE) < 0) {
		nl_socket_free(sk);
		return -1;
	}

	rtnl_event.sock = sk;

	if (nl_socket_set_buffer_size(rtnl_event.sock, rtnl_event.sock_bufsize, 0)) {
		err("%s: %d\n", __func__, __LINE__);
		goto out_err;
	}

	nl_socket_disable_seq_check(rtnl_event.sock);

	nl_socket_modify_cb(rtnl_event.sock, NL_CB_VALID, NL_CB_CUSTOM,
			    i1905_nlevents_cb, priv);

	if (nl_socket_add_memberships(rtnl_event.sock,
				      RTNLGRP_NEIGH, RTNLGRP_LINK, 0))
		goto out_err;

	rtnl_event.ev.uloop.fd = nl_socket_get_fd(rtnl_event.sock);
	rtnl_event.ev.uloop.cb = i1905_receive_nlevents;
	uloop_fd_add(&rtnl_event.ev.uloop, ULOOP_READ |
		     ((rtnl_event.ev.error_cb) ? ULOOP_ERROR_CB : 0));

	return 0;

out_err:
	if (rtnl_event.sock) {
		nl_socket_free(rtnl_event.sock);
		rtnl_event.sock = NULL;
		rtnl_event.ev.uloop.fd = -1;
	}

	return -1;
}

void i1905_unregister_nlevents(struct i1905_private *priv)
{
	UNUSED(priv);

	if (rtnl_event.sock) {
		uloop_fd_delete(&rtnl_event.ev.uloop);
		rtnl_event.ev.uloop.fd = -1;
		nl_socket_free(rtnl_event.sock);
		rtnl_event.sock = NULL;
	}
}

int i1905_get_known_neighbors(struct i1905_private *priv, char *ifname)
{
	struct rtnl_neigh *neigh;
	struct nl_object *nobj;
	struct nl_cache *cache;
	uint32_t ifindex = 0;
	struct nl_sock *sk;
	int i, num;
	int ret;



	ifindex = if_nametoindex(ifname);
	if (!ifindex)
		return -1;

	sk = nl_socket_alloc();
	if (!sk) {
		err("Unable to open nl event socket\n");
		return -1;
	}

	if (nl_connect(sk, NETLINK_ROUTE) < 0) {
		nl_socket_free(sk);
		return -1;
	}

	ret = rtnl_neigh_alloc_cache(sk, &cache);
	if (ret) {
		nl_socket_free(sk);
		return -1;
	}


	num = nl_cache_nitems(cache);
	nobj = nl_cache_get_first(cache);
	neigh = (struct rtnl_neigh *)nobj;

	for (i = 0; i < num; i++) {
		if (rtnl_neigh_get_ifindex(neigh) == ifindex) {
			struct nl_addr *lladdr;
			struct nl_addr *ipaddr;
			struct ip_address ip = {0};
			uint8_t hwaddr[6] = {0};
			uint16_t state;

			nl_object_get((struct nl_object *) neigh);

			state = rtnl_neigh_get_state(neigh);
			lladdr = rtnl_neigh_get_lladdr(neigh);
			if (lladdr)
				memcpy(hwaddr, nl_addr_get_binary_addr(lladdr),
					nl_addr_get_len(lladdr));

			if (hwaddr_is_zero(hwaddr) || hwaddr_is_mcast(hwaddr)) {
				nl_object_put((struct nl_object *) neigh);
				nobj = nl_cache_get_next(nobj);
				neigh = (struct rtnl_neigh *)nobj;
				continue;
			}

			ipaddr = rtnl_neigh_get_dst(neigh);
			if (ipaddr) {
				ip.family = nl_addr_get_family(ipaddr);
				if (ip.family == AF_INET6 || ip.family == AF_INET) {
					memcpy(&ip.addr, nl_addr_get_binary_addr(ipaddr),
					       nl_addr_get_len(ipaddr));
				}
			}

			neigh_enqueue(&priv->neigh_q, hwaddr, state, ifname,
				      NEIGH_TYPE_UNKNOWN, &ip,
				      NEIGH_AGEOUT_DEFAULT, NULL);
			nl_object_put((struct nl_object *) neigh);
		}

		nobj = nl_cache_get_next(nobj);
		neigh = (struct rtnl_neigh *)nobj;
	}

	nl_cache_free(cache);
	nl_socket_free(sk);


	if (if_isbridge(ifname)) {
		/* bridge port_nos on which the hosts are last seen */
		i1905_update_neigh_brport(priv, ifname);
	}

#ifdef NEIGH_DEBUG
	fprintf(stderr, "-------------------------------\n");
	neigh_queue_print(&priv->neigh_q);
	fprintf(stderr, "-------------------------------\n");
#endif

	return 0;
}
