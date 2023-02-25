/*
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

#include <easy/easy.h>

#include <libubus.h>

#include "debug.h"
#include "util.h"
#include "timer.h"
#include "neigh.h"

#include "cmdu.h"
#include "cmdu_ackq.h"
#include "cmdufrag.h"
#include "config.h"
#include "i1905_dm.h"
#include "i1905.h"

//TODO: move to utils
static int getcurrtime(struct timeval *out)
{
	struct timespec nowts = { 0 };
	struct timeval now = { 0 };
	int ret;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &nowts);
	if (!ret) {
		now.tv_sec = nowts.tv_sec;
		now.tv_usec = nowts.tv_nsec / 1000;
	} else {
		ret = gettimeofday(&now, NULL);
	}

	now.tv_usec = (now.tv_usec / 1000) * 1000;
	out->tv_sec = now.tv_sec;
	out->tv_usec = now.tv_usec;

	return ret;
}

struct neigh_entry *neigh_entry_create(uint8_t *macaddr, uint16_t state,
				       const char *ifname, enum neigh_type type,
				       uint32_t timeout, void *cookie)
{
	struct neigh_entry *e;
	struct timeval tsp = { 0 };


	e = calloc(1, sizeof(*e));
	if (!e) {
		err("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	INIT_LIST_HEAD(&e->iplist);
	e->state = state;
	strncpy(e->ifname, ifname, 15);
	memcpy(e->macaddr, macaddr, 6);
	if (type != NEIGH_TYPE_UNKNOWN)
		e->type = type;

	getcurrtime(&tsp);
	e->ageing_time = timeout;
	timeradd_msecs(&tsp, e->ageing_time, &e->ageing_tmo);

	//e->ageing_tmo.tv_usec = roundup(e->ageing_tmo.tv_usec, 1000);
	e->ageing_tmo.tv_usec = (e->ageing_tmo.tv_usec / 1000) * 1000;
	e->cookie = cookie;
	/* fprintf(stderr,
		"    CREATE entry: " MACFMT " state = 0x%04x timeout = { %u (%lu:%lu) }\n",
		MAC2STR(macaddr), state, e->ageing_time,
		e->ageing_tmo.tv_sec, e->ageing_tmo.tv_usec / 1000); */

	return e;
}

static void neigh_entry_delete(struct neigh_entry *e)
{
	if (e) {
		dbg("Removing entry " MACFMT"\n", MAC2STR(e->macaddr));
		timer_del(&e->probing_timer);

		if (e->cookie)
			free(e->cookie);

		list_flush(&e->iplist, struct ip_address_entry, list);
		free(e);
	}
}

static void neigh_probing_timer_run(atimer_t *t)
{
	struct neigh_entry *e = container_of(t, struct neigh_entry, probing_timer);
	struct ip_address_entry *x;
	struct timeval now = {0};

	getcurrtime(&now);

	list_for_each_entry(x, &e->iplist, list) {
		char cmd[256] = {0};
		char ipbuf[46] = {0};

		if (x->ip.family != AF_INET)
			continue;

		inet_ntop(x->ip.family, &x->ip.addr, ipbuf, sizeof(ipbuf));
		snprintf(cmd, 255, "arping -q -I %s -c 1 -w 1 -f %s &", e->ifname, ipbuf);
		dbg("[%jd.%jd]  %s\n", (uintmax_t)now.tv_sec, (uintmax_t)now.tv_usec, cmd);
		runCmd(cmd); /* Flawfinder: ignore */
	}
}

static void neigh_entry_ageout(struct neigh_queue *st, struct hlist_head *head,
			       struct timeval *min_next_tmo)
{
	struct neigh_entry *e;
	struct hlist_node *tmp;
	struct timeval now = { 0 };
	struct timeval new_next_tmo = { 0 };
	struct i1905_private *priv = container_of(st, struct i1905_private, neigh_q);


	getcurrtime(&now);

	hlist_for_each_entry_safe(e, tmp, head, hlist) {
		if (!timercmp(&e->ageing_tmo, &now, >)) {
			/* schedule a one-time probing for this entry after 1s.
			 * If it does not become reachable within 15s, then delete it.
			 */
			if (e->state != NEIGH_STATE_REACHABLE) {
				if (!e->probing) {
					dbg7("probing timer started for " MACFMT " probe count = %d \n",
							MAC2STR(e->macaddr), e->probe_cnt);
					timer_init(&e->probing_timer, neigh_probing_timer_run);
					timer_set(&e->probing_timer, 1000);
					e->probe_cnt++;
					if (e->probe_cnt > MAX_PROBE_COUNT)
						e->probing = 1;

					/* give 1+15s for probing the entry to complete */
					e->ageing_time = 16000;
					timeradd_msecs(&now, e->ageing_time, &e->ageing_tmo);

					timersub(&e->ageing_tmo, &now, &new_next_tmo);
					if (!timercmp(min_next_tmo, &new_next_tmo, <)) {
						min_next_tmo->tv_sec = new_next_tmo.tv_sec;
						min_next_tmo->tv_usec = new_next_tmo.tv_usec;
					}

				} else {
					dbg7("probing done!, remove entry for " MACFMT "\n",
							MAC2STR(e->macaddr));
					dbg("Removing probe entry[%jd.%jd] \n", (uintmax_t)now.tv_sec,
							(uintmax_t)now.tv_usec);
					st->pending_cnt--;
					hlist_del(&e->hlist, head);
					/* fprintf(stderr, MACFMT " state = 0x%04x aged out!\n",
					   MAC2STR(e->macaddr), e->state); */
					i1905_send_topology_notification(priv, e->ifname);
					neigh_entry_delete(e);
				}
			}
		} else {
			timersub(&e->ageing_tmo, &now, &new_next_tmo);
			if (!timercmp(min_next_tmo, &new_next_tmo, <)) {
				min_next_tmo->tv_sec = new_next_tmo.tv_sec;
				min_next_tmo->tv_usec = new_next_tmo.tv_usec;
			}
		}
	}
}

static void neigh_ageing_timer_run(atimer_t *t)
{
	struct neigh_queue *st = container_of(t, struct neigh_queue, ageing_timer);
	struct timeval min_next_tmo = { .tv_sec = 999999 };
	int remain_cnt = 0;
	struct timeval nu;
	int i;

	getcurrtime(&nu);

	for (i = 0; i < NEIGH_ENTRIES_MAX; i++) {
		if (hlist_empty(&st->table[i]))
			continue;

		neigh_entry_ageout(st, &st->table[i], &min_next_tmo);
	}

	remain_cnt = st->pending_cnt;
	timeradd(&nu, &min_next_tmo, &st->next_tmo);

	if (remain_cnt) {
		uint32_t tmo_msecs =
			min_next_tmo.tv_sec * 1000 + min_next_tmo.tv_usec / 1000;

		if (tmo_msecs > 0)
			timer_set(&st->ageing_timer, tmo_msecs);
	}
}

int neigh_queue_init(void *nq)
{
	struct neigh_queue *q = (struct neigh_queue *)nq;

	memset(q, 0, sizeof(*q));
	timer_init(&q->ageing_timer, neigh_ageing_timer_run);

	return 0;
}

struct neigh_entry *neigh_lookup(void *nq, uint8_t *macaddr)
{
	struct neigh_queue *q = (struct neigh_queue *)nq;
	int idx = neigh_hash(macaddr);
	struct neigh_entry *e = NULL;


	hlist_for_each_entry(e, &q->table[idx], hlist) {
		if (!memcmp(e->macaddr, macaddr, 6)) {
			return e;
		}
	}

	return NULL;
}

#if 0	//TODO
int i1905_get_non1905_for_interface(void *nq, struct i1905_interface *iface)
{
	struct neigh_queue *q = (struct neigh_queue *)nq;
	struct neigh_entry *e = NULL;
	int i;


	for (i = 0; i < NEIGH_ENTRIES_MAX; i++) {
		hlist_for_each_entry(e, &q->table[i], hlist) {
			if ((iface->brport && e->brport == iface->brport) ||
			    !strncmp(e->ifname, iface->ifname, 16)) {
				struct i1905_non1905_neighbor *nnbr;

				nnbr = calloc(1, sizeof(*nnbr));
				if (nnbr) {
					memcpy(nnbr->macaddr, e->macaddr, 6);
					list_add_tail(&nnbr->list, &iface->non1905_nbrlist);
					iface->num_neighbor_non1905++;
				}
			}
		}
	}

	return 0;
}
#endif

struct neigh_entry *neigh_queue_print(void *nq)
{
	struct neigh_queue *q = (struct neigh_queue *)nq;
	struct neigh_entry *e = NULL;
	int idx = 0;


	for (idx = 0; idx < NEIGH_ENTRIES_MAX; idx++) {
		hlist_for_each_entry(e, &q->table[idx], hlist) {
			struct ip_address_entry *t;
			char buf[512] = {0};

			snprintf(buf, sizeof(buf) - 1,
				"Entry: " MACFMT " wifi = %d | ifname = %s (port = %hu)   state = %02x ipaddrs: ",
				MAC2STR(e->macaddr),
				e->type == NEIGH_TYPE_WIFI ? 1 : 0,
				e->ifname,
				e->brport,
				e->state);

			list_for_each_entry(t, &e->iplist, list) {
				char ipbuf[46] = {0};

				inet_ntop(t->ip.family, &t->ip.addr, ipbuf, sizeof(ipbuf));
				snprintf(buf + strlen(buf), sizeof(buf) -1,
					 "%s ", ipbuf);
			}
			snprintf(buf + strlen(buf), sizeof(buf) - 1, "%s", "\n");
			dbg7("%s", buf);
		}
	}

	return NULL;
}

void neigh_queue_flush(void *nq)
{
	struct neigh_queue *q = (struct neigh_queue *)nq;
	struct neigh_entry *e = NULL;
	int idx = 0;

	for (idx = 0; idx < NEIGH_ENTRIES_MAX; idx++) {
		hlist_for_each_entry(e, &q->table[idx], hlist)
			neigh_entry_delete(e);

		q->table[idx].first = NULL;
	}

	q->pending_cnt = 0;
}

void neigh_queue_free(void *nq)
{
	struct neigh_queue *q = (struct neigh_queue *)nq;

	neigh_queue_flush(q);
	timer_del(&q->ageing_timer);
}

int ipaddr_equal(struct ip_address *a, struct ip_address *b)
{
	if (!a || !b)
		return 0;

	return !memcmp(&a->addr, &b->addr, a->family == AF_INET ?
			sizeof(struct in_addr) :
			sizeof(struct in6_addr));
}

int neigh_set_type(void *nq, uint8_t *macaddr, enum neigh_type type)
{
	struct neigh_entry *e = NULL;


	e = neigh_lookup(nq, macaddr);
	if (!e)
		return -1;

	e->type = type;

	return 0;
}

uint16_t neigh_get_brport(void *nq, uint8_t *macaddr)
{
	struct neigh_entry *e = NULL;
	uint16_t brport = 0xffff;


	e = neigh_lookup(nq, macaddr);
	if (!e)
		return 0xffff;

	brport = e->brport;

	return brport;
}

int neigh_set_1905(void *nq, uint8_t *macaddr)
{
	struct neigh_entry *e = NULL;


	e = neigh_lookup(nq, macaddr);
	if (!e)
		return -1;

	e->is1905 = 1;

	return 0;
}

int neigh_set_1905_slave(void *nq, uint8_t *macaddr)
{
	struct neigh_entry *e = NULL;


	e = neigh_lookup(nq, macaddr);
	if (!e)
		return -1;

	e->is1905_slave = 1;

	return 0;
}

bool is_neigh_1905(void *nq, uint8_t *macaddr)
{
	struct neigh_entry *e = NULL;
	bool is1905;


	e = neigh_lookup(nq, macaddr);
	if (!e)
		return false;

	is1905 = e->is1905 == 1 ? true : false;

	return is1905;
}

int neigh_enqueue(void *nq, uint8_t *macaddr, uint16_t state, const char *ifname,
		  enum neigh_type type, struct ip_address *ip, uint32_t timeout,
		  void *cookie)
{
	struct neigh_queue *q = (struct neigh_queue *)nq;
	struct neigh_entry *e = NULL;
	struct timeval tsp = { 0 };


	getcurrtime(&tsp);

	e = neigh_lookup(nq, macaddr);
	if (e) {
		struct ip_address_entry *ipaddr;
		bool ipknown = false;

		dbg("[%jd.%jd] Neigh " MACFMT " changed. state 0x%04x -> 0x%04x\n",
		    (uintmax_t)tsp.tv_sec, (uintmax_t)tsp.tv_usec, MAC2STR(macaddr), e->state, state);

		e->state = state;
		if (type != NEIGH_TYPE_UNKNOWN)
			e->type = type;

		strncpy(e->ifname, ifname, 15);

		if (e->state == NEIGH_STATE_REACHABLE) {
			if (timer_pending(&e->probing_timer)) {
				/* stop probing timer as state becomes reachable */
				timer_del(&e->probing_timer);
			}
			e->probing = 0;
			e->probe_cnt = 0;

			/* reset ageing timer for entry */
			e->ageing_time = timeout;
			timeradd_msecs(&tsp, e->ageing_time, &e->ageing_tmo);
			e->ageing_tmo.tv_usec = (e->ageing_tmo.tv_usec / 1000) * 1000;
		}

		if (ip) {
			list_for_each_entry(ipaddr, &e->iplist, list) {
				if (ipaddr_equal(&ipaddr->ip, ip))
					ipknown = true;
			}

			if (!ipknown) {
				struct ip_address_entry *new;

				new = calloc(1, sizeof(*new));
				if (new) {
					memcpy(&new->ip, ip, sizeof(*ip));
					list_add_tail(&new->list, &e->iplist);
				}
			}
		}

		if (!timer_pending(&q->ageing_timer)) {
			q->next_tmo.tv_sec = e->ageing_tmo.tv_sec;
			q->next_tmo.tv_usec = e->ageing_tmo.tv_usec;
			timer_set(&q->ageing_timer, e->ageing_time);
		}
		return 0;
	}

	e = neigh_entry_create(macaddr, state, ifname, type, timeout, cookie);
	if (e) {
		int idx = neigh_hash(macaddr);
		struct ip_address_entry *ipaddr;
		bool ipknown = false;


		hlist_add_head(&e->hlist, &q->table[idx]);

		q->pending_cnt++;
		/* fprintf(stderr,
			"    ENQ:        " MACFMT " state = 0x%04x  ifname = %s\n",
			MAC2STR(macaddr), state, ifname); */


		if (timer_pending(&q->ageing_timer)) {
			if (timercmp(&q->next_tmo, &e->ageing_tmo, >)) {
				q->next_tmo.tv_sec = e->ageing_tmo.tv_sec;
				q->next_tmo.tv_usec = e->ageing_tmo.tv_usec;
				timer_set(&q->ageing_timer, e->ageing_time);
			}
		} else {
			q->next_tmo.tv_sec = e->ageing_tmo.tv_sec;
			q->next_tmo.tv_usec = e->ageing_tmo.tv_usec;
			timer_set(&q->ageing_timer, e->ageing_time);
		}

		if (ip) {
			list_for_each_entry(ipaddr, &e->iplist, list) {
				if (ipaddr_equal(&ipaddr->ip, ip))
					ipknown = true;
			}

			if (!ipknown) {
				struct ip_address_entry *new;

				new = calloc(1, sizeof(*new));
				if (new) {
					memcpy(&new->ip, ip, sizeof(*ip));
					list_add_tail(&new->list, &e->iplist);
				}
			}
		}

		return 1;	/* XXX: when an entry gets added */
	}

	return -1;
}

int neigh_dequeue(void *nq, uint8_t *macaddr, void **cookie)
{
	struct neigh_queue *q = (struct neigh_queue *)nq;
	struct neigh_entry *e = NULL;
	int idx;


	e = neigh_lookup(nq, macaddr);
	if (!e) {
		//fprintf(stderr, "DEQ: Entry " MACFMT " not found!\n",
		//	MAC2STR(macaddr));
		return -1;
	}

	idx = neigh_hash(macaddr);

	hlist_del(&e->hlist, &q->table[idx]);
	q->pending_cnt--;
	//fprintf(stderr, "DEQ: Entry " MACFMT "\n", MAC2STR(macaddr));


	/* After returning cookie back to user, we can safely delete the e */
	if (cookie && *cookie)
		*cookie = e->cookie;

	e->cookie = NULL;

	neigh_entry_delete(e);

	return 0;
}
