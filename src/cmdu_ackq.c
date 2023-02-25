/*
 * cmdu_ackq.c
 * CMDU response and ack queue management
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <easy/easy.h>

#include "timer.h"
#include "cmdu_ackq.h"

#define err(...)	log_stderr(0, __VA_ARGS__)
#define dbg(...)	log_stderr(3, __VA_ARGS__)
#define loud(...)	log_stderr(5, __VA_ARGS__)

static int timeradd_msecs(struct timeval *a, unsigned long msecs,
			  struct timeval *res)
{
	if (res) {
		struct timeval t = { 0 };

		if (msecs > 1000) {
			t.tv_sec += msecs / 1000;
			t.tv_usec = (msecs % 1000) * 1000;
		} else {
			t.tv_usec = msecs * 1000;
		}

		timeradd(a, &t, res);
		return 0;
	}

	return -1;
}

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

struct cmdu_ackq_entry *cmdu_ackq_create_msg(uint16_t type, uint16_t mid,
					     uint8_t *dest, uint32_t timeout,
					     int resend_cnt, void *cookie)
{
	struct cmdu_ackq_entry *msg;
	struct timeval tsp = { 0 };

	msg = calloc(1, sizeof(*msg));
	if (!msg) {
		err("calloc failed! -ENOMEM\n");
		return NULL;
	}

	msg->type = type;
	msg->mid = mid;
	getcurrtime(&tsp);
	msg->ageing_time = timeout;
	timeradd_msecs(&tsp, msg->ageing_time, &msg->ageing_tmo);

	//msg->ageing_tmo.tv_usec = roundup(msg->ageing_tmo.tv_usec, 1000);
	msg->ageing_tmo.tv_usec = (msg->ageing_tmo.tv_usec / 1000) * 1000;
	memcpy(msg->origin, dest, 6);
	msg->resend_cnt = resend_cnt;
	msg->cookie = cookie;
	dbg("    CREATE msg: type = 0x%04x  mid = %hu origin = " MACFMT " timeout = { %u ms (now = %lu.%lu, when = %lu.%lu) }\n",
		type, mid, MAC2STR(dest), msg->ageing_time,
		tsp.tv_sec, tsp.tv_usec / 1000,
		msg->ageing_tmo.tv_sec, msg->ageing_tmo.tv_usec / 1000);

	return msg;
}

static void cmdu_ackq_delete_msg(struct cmdu_ackq *st, struct cmdu_ackq_entry *msg)
{
	if (!msg)
		return;

	if (msg->cookie) {
		if (st->delete_cb)
			st->delete_cb(st, msg);
		else
			free(msg->cookie);
	}

	free(msg);
}

static void cmdu_ackq_ageout_entry(struct cmdu_ackq *st, struct hlist_head *head,
				   struct timeval *min_next_tmo)
{
	struct cmdu_ackq_entry *msg;
	struct hlist_node *tmp;
	struct timeval now = { 0 };


	getcurrtime(&now);

	hlist_for_each_entry_safe(msg, tmp, head, hlist) {
		int action = CMDU_ACKQ_TMO_NONE;
		struct timeval new_next_tmo = { 0 };

		dbg("%s(): check entry msg->ageout? (when = %lu.%lu), now = (%lu.%lu)\n",
		     __func__, msg->ageing_tmo.tv_sec, msg->ageing_tmo.tv_usec,
		     now.tv_sec, now.tv_usec);

		if (!timercmp(&msg->ageing_tmo, &now, >)) {
			dbg("%s(): No response from " MACFMT " with CMDU 0x%x mid = %hu\n",
			       __func__, MAC2STR(msg->origin), msg->type, msg->mid);

			if (st->timeout_cb) {
				action = st->timeout_cb(st, msg);
				if (action == CMDU_ACKQ_TMO_REARM) {
					timeradd_msecs(&now, msg->ageing_time,
							&msg->ageing_tmo);
				}
			} else {
				action = CMDU_ACKQ_TMO_DELETE;
			}
		} else {
			action = CMDU_ACKQ_TMO_REARM;
		}

		switch (action) {
		case CMDU_ACKQ_TMO_DELETE:
			st->pending_cnt--;
			hlist_del(&msg->hlist, head);
			dbg("DEQ: type = 0x%04x  mid = %hu origin = " MACFMT " (reason: timeout)\n",
			    msg->type, msg->mid, MAC2STR(msg->origin));
			cmdu_ackq_delete_msg(st, msg);
			break;
		case CMDU_ACKQ_TMO_REARM:
			timersub(&msg->ageing_tmo, &now, &new_next_tmo);
			if (!timercmp(min_next_tmo, &new_next_tmo, <)) {
				min_next_tmo->tv_sec = new_next_tmo.tv_sec;
				min_next_tmo->tv_usec = new_next_tmo.tv_usec;
				loud("Adjusted next-tmo = (%lu.%lu)\n",
					min_next_tmo->tv_sec,
					min_next_tmo->tv_usec);
			}
			break;
		}
	}
}

static void cmdu_ackq_ageing_timer_run(atimer_t *t)
{
	struct cmdu_ackq *st = container_of(t, struct cmdu_ackq, ageing_timer);
	//struct timeval *next_tmo = &st->next_tmo;
	struct timeval min_next_tmo = { .tv_sec = 999999 };
	int remain_cnt = 0;
	struct timeval nu;
	int i;


	getcurrtime(&nu);
	loud("\n ----In timer ---- time now = %lu.%lu,  msg-cnt = %d\n",
	     nu.tv_sec, nu.tv_usec, st->pending_cnt);

	for (i = 0; i < CMDU_BACKLOG_MAX; i++) {
		if (hlist_empty(&st->table[i]))
			continue;

		loud("cmdu_ackq row %d has msg\n", i);
		cmdu_ackq_ageout_entry(st, &st->table[i], &min_next_tmo);
	}

	remain_cnt = st->pending_cnt;
	timeradd(&nu, &min_next_tmo, &st->next_tmo);

	dbg("\n ----Next timer ---- when = %lu.%lu, after = %lu.%lu,  msg-cnt = %d\n",
	       st->next_tmo.tv_sec, st->next_tmo.tv_usec,
	       min_next_tmo.tv_sec, min_next_tmo.tv_usec,
	       remain_cnt);

	if (remain_cnt) {
		uint32_t tmo_msecs =
			min_next_tmo.tv_sec * 1000 + min_next_tmo.tv_usec / 1000;

		if (tmo_msecs > 0) {
			dbg(" ----Next timer set after %u ms, msg-cnt = %d\n", tmo_msecs, remain_cnt);
			timer_set(&st->ageing_timer, tmo_msecs);
		}
	}
}

int cmdu_ackq_init(void *cmdu_q)
{
	struct cmdu_ackq *q = (struct cmdu_ackq *)cmdu_q;

	memset(q, 0, sizeof(*q));
	timer_init(&q->ageing_timer, cmdu_ackq_ageing_timer_run);

	return 0;
}

struct cmdu_ackq_entry *cmdu_ackq_lookup(void *cmdu_q, uint16_t type,
					 uint16_t mid, uint8_t *dest)
{
	struct cmdu_ackq *q = (struct cmdu_ackq *)cmdu_q;
	int idx = cmdu_ackq_hash(type, mid, dest);
	struct cmdu_ackq_entry *msg = NULL;

	hlist_for_each_entry(msg, &q->table[idx], hlist) {
		if (msg->type == type && msg->mid == mid &&
		    !memcmp(msg->origin, dest, 6)) {

			return msg;
		}
	}

	return NULL;
}

void cmdu_ackq_flush(void *cmdu_q)
{
	struct cmdu_ackq *q = (struct cmdu_ackq *)cmdu_q;
	struct cmdu_ackq_entry *msg = NULL;
	int idx = 0;

	for (idx = 0; idx < CMDU_BACKLOG_MAX; idx++) {
		hlist_for_each_entry(msg, &q->table[idx], hlist)
			cmdu_ackq_delete_msg(q, msg);

		q->table[idx].first = NULL;
	}

	q->pending_cnt = 0;
}

void cmdu_ackq_free(void *cmdu_q)
{
	struct cmdu_ackq *q = (struct cmdu_ackq *)cmdu_q;

	cmdu_ackq_flush(q);
	timer_del(&q->ageing_timer);
}

/* In this function, type = cmdutype that is expected with 'mid' from 'dest' */
int cmdu_ackq_enqueue(void *cmdu_q, uint16_t type, uint16_t mid, uint8_t *dest,
		      uint32_t timeout, int resend_cnt, void *cookie)
{
	struct cmdu_ackq *q = (struct cmdu_ackq *)cmdu_q;
	struct cmdu_ackq_entry *msg = NULL;

	msg = cmdu_ackq_lookup(cmdu_q, type, mid, dest);
	if (msg) {
		dbg("Duplicate: type = 0x%04x  mid = %hu origin = " MACFMT "\n",
		     type, mid, MAC2STR(dest));
		return -1;
	}

	msg = cmdu_ackq_create_msg(type, mid, dest, timeout, resend_cnt, cookie);
	if (msg) {
		int idx = cmdu_ackq_hash(type, mid, dest);

		hlist_add_head(&msg->hlist, &q->table[idx]);

		q->pending_cnt++;
		dbg("    ENQ:        type = 0x%04x  mid = %hu origin = " MACFMT " (pending msg-cnt = %d)\n",
		     type, mid, MAC2STR(dest), q->pending_cnt);

		if (timer_pending(&q->ageing_timer)) {
			loud("Pending timer === next_tmo = %lu.%lu,  msg-ageing_tmo = %lu.%lu\n",
			     q->next_tmo.tv_sec, q->next_tmo.tv_usec,
			     msg->ageing_tmo.tv_sec, msg->ageing_tmo.tv_usec);

			if (timercmp(&q->next_tmo, &msg->ageing_tmo, >)) {
				q->next_tmo.tv_sec = msg->ageing_tmo.tv_sec;
				q->next_tmo.tv_usec = msg->ageing_tmo.tv_usec;

				timer_set(&q->ageing_timer, msg->ageing_time);
				loud("Adjusted next_tmo = %lu.%lu,  msg-cnt = %d\n",
				     q->next_tmo.tv_sec, q->next_tmo.tv_usec, q->pending_cnt);
			}
		} else {
			loud("Start ageout timer ===\n");
			q->next_tmo.tv_sec = msg->ageing_tmo.tv_sec;
			q->next_tmo.tv_usec = msg->ageing_tmo.tv_usec;
			timer_set(&q->ageing_timer, msg->ageing_time);
		}

		return 0;
	}

	return -1;
}

int cmdu_ackq_dequeue(void *cmdu_q, uint16_t type, uint16_t mid, uint8_t *src, void **cookie)
{
	struct cmdu_ackq *q = (struct cmdu_ackq *)cmdu_q;
	struct cmdu_ackq_entry *msg = NULL;
	int idx;

	msg = cmdu_ackq_lookup(cmdu_q, type, mid, src);
	if (!msg) {
		dbg("DROP! CMDU not found: type = 0x%04x  mid = %hu origin = " MACFMT "\n",
		     type, mid, MAC2STR(src));
		return -1;
	}

	idx = cmdu_ackq_hash(type, mid, src);

	hlist_del(&msg->hlist, &q->table[idx]);
	q->pending_cnt--;

	dbg("DEQ: type = 0x%04x  mid = %hu origin = " MACFMT " (reason: response)\n",
	    type, mid, MAC2STR(src));


	/* After returning cookie back to user, we can safely delete the msg */
	if (cookie)
		*cookie = msg->cookie;
	msg->cookie = NULL;

	cmdu_ackq_delete_msg(q, msg);

	return 0;
}
