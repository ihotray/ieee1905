/*
 * cmdufrag.c - IEEE1905 CMDU fragmentation and defragmentation handling
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
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "debug.h"
#include "timer.h"
#include "util.h"
#include "bufutil.h"
#include "1905_tlvs.h"
#include "cmdu.h"
#include "cmdufrag.h"

static struct cmdu_frag *alloc_frag(struct cmdu_buff *cmdu, size_t len)
{
	struct cmdu_frag *frag = NULL;

	frag = calloc(1, len + sizeof(*frag));
	if (!frag) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	frag->data = (uint8_t *)(frag + 1);
	list_add_tail(&frag->list, &cmdu->fraglist);
	cmdu->num_frags++;

	return frag;
}

static struct cmdu_buff *alloc_cmdu(size_t size)
{
	struct cmdu_buff *cmdu;

	cmdu = cmdu_alloc_frame(size);
	if (!cmdu) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	return cmdu;
}

#ifndef IEEE1905_CMDU_FRAGMENT_TLV_BOUNDARY
struct cmdu_buff *cmdu_fragment(uint8_t *data, int datalen)
{
	struct cmdu_buff *cmdu = NULL;
	struct cmdu_frag *frag = NULL;
	uint8_t *pos = data;
	int rem = datalen;
	size_t sz;



	if (datalen < FRAG_DATA_SIZE_TLV)
		return NULL;

	cmdu = alloc_cmdu(FRAG_DATA_SIZE_TLV);
	if (!cmdu)
		return NULL;

	cmdu_put(cmdu, pos, FRAG_DATA_SIZE_TLV);
	rem -= FRAG_DATA_SIZE_TLV;
	pos += FRAG_DATA_SIZE_TLV;

	while (rem) {
		sz = rem > FRAG_DATA_SIZE_TLV ? FRAG_DATA_SIZE_TLV : rem;

		frag = alloc_frag(cmdu, sz);
		if (!frag) {
			fprintf(stderr, "%s: -ENOMEM\n", __func__);
			goto out_free;
		}
		memcpy(frag->data, pos, sz);
		frag->len = sz;
		pos += sz;
		rem -= sz;
	}

	return cmdu;

out_free:
	cmdu_free(cmdu);
	return NULL;
}

#else
struct cmdu_buff *cmdu_fragment(uint8_t *data, int datalen)
{
	struct cmdu_frag *nextfrag = NULL;
	size_t rem = FRAG_DATA_SIZE_TLV;
	struct cmdu_buff *cmdu = NULL;
	bool use_frag = false;
	int remlen = datalen;
	struct tlv *p = NULL;
	uint8_t *ptr = data;


	if (datalen < FRAG_DATA_SIZE_TLV)
		return NULL;

	cmdu = alloc_cmdu(FRAG_DATA_SIZE_TLV);
	if (!cmdu)
		return NULL;

	cmdu_for_each_tlv(p, data, remlen) {
		size_t tlen = tlv_total_length(p);
		size_t flen = 0;

		ptr = (uint8_t *)p;

		if (tlen <= rem) {
			if (use_frag) {
				uint16_t l = nextfrag->len;

				memcpy(&nextfrag->data[l], ptr, tlen);
				nextfrag->len += tlen;
			} else {
				cmdu_put(cmdu, ptr, tlen);
			}

			rem -= tlen;
			continue;
		}

		if (tlen < FRAG_DATA_SIZE_TLV) {
			nextfrag = alloc_frag(cmdu, FRAG_DATA_SIZE_TLV);
			if (!nextfrag) {
				fprintf(stderr, "%s: -ENOMEM\n", __func__);
				goto out_free;
			}
			rem = FRAG_DATA_SIZE_TLV;

			memcpy(&nextfrag->data[0], ptr, tlen);
			nextfrag->len += tlen;
			use_frag = true;
			rem -= tlen;
			continue;
		}

		if (!cmdu->datalen) {
			uint8_t *pos = cmdu->tail;

			cmdu_put(cmdu, ptr, rem);
			/* update tlv's length in cmdu */
			buf_put_be16(pos + 1, rem - TLV_HLEN);
		} else {
			nextfrag = alloc_frag(cmdu, FRAG_DATA_SIZE_TLV);
			if (!nextfrag) {
				fprintf(stderr, "%s: -ENOMEM\n", __func__);
				goto out_free;
			}
			rem = FRAG_DATA_SIZE_TLV;
			nextfrag->data[0] = p->type;
			buf_put_be16(&nextfrag->data[1], rem - TLV_HLEN);
			memcpy(&nextfrag->data[3], ptr + 3, rem);
			nextfrag->len += rem;
		}

		use_frag = true;
		flen = tlen - rem;
		ptr += rem;

		while (flen >= FRAG_DATA_SIZE) {
			nextfrag = alloc_frag(cmdu, FRAG_DATA_SIZE_TLV);
			if (!nextfrag) {
				fprintf(stderr, "%s: -ENOMEM\n", __func__);
				goto out_free;
			}

			rem = FRAG_DATA_SIZE_TLV;
			nextfrag->data[0] = p->type;
			buf_put_be16(&nextfrag->data[1], FRAG_DATA_SIZE);
			memcpy(&nextfrag->data[3], ptr, FRAG_DATA_SIZE);
			nextfrag->len = FRAG_DATA_SIZE_TLV;

			flen -= FRAG_DATA_SIZE;
			ptr += FRAG_DATA_SIZE;
		}

		/* residue */
		nextfrag = alloc_frag(cmdu, FRAG_DATA_SIZE_TLV);
		if (!nextfrag) {
			fprintf(stderr, "%s: -ENOMEM\n", __func__);
			goto out_free;
		}

		rem = FRAG_DATA_SIZE_TLV;
		nextfrag->data[0] = p->type;
		buf_put_be16(&nextfrag->data[1], flen);
		memcpy(&nextfrag->data[3], ptr, flen);
		nextfrag->len = flen + TLV_HLEN;
		rem -= nextfrag->len;
	}

#ifdef I1905_DEBUG
{
	int j = 1;
	char fraglabel[64] = "";

	bufprintf(cmdu->data, cmdu->datalen, "CMDU");
	list_for_each_entry(frag, &cmdu->fraglist, list) {
		snprintf(fraglabel, sizeof(fraglabel), "Fragment[%d]: len = %d",
			 j++, frag->len);
		bufprintf(frag->data, frag->len, fraglabel);
	}
}
#endif
	return cmdu;

out_free:
	cmdu_free(cmdu);
	return NULL;
}
#endif /* IEEE1905_CMDU_FRAGMENT_TLV_BOUNDARY */

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

static struct cmdu_frag_rx *cmdufrag_lookup(void *rxfq, uint16_t type,
					    uint16_t mid, uint8_t fid,
					    uint8_t *origin)
{
	struct cmdufrag_queue *q = (struct cmdufrag_queue *)rxfq;
	int idx = cmdu_frag_hash(type, mid, origin);
	struct cmdu_frag_rx *frag = NULL;


	hlist_for_each_entry(frag, &q->table[idx], hlist) {
		if (frag->type == type && frag->mid == mid &&
		    !memcmp(frag->origin, origin, 6)) {
			if (frag->fid == fid) {
				return frag;
			}
		}
	}

	return NULL;
}

static void cmdu_fragqueue_delete_chain(struct cmdu_frag_rx *frag)
{
	struct cmdu_frag_rx *ee = NULL, *e;

	if (!frag)
		return;

	for (e = frag; e; e = e->next) {
		if (ee) {
			printf("freeing ee ..fid = %d ....\n", ee->fid);
			free(ee);
		}
		ee = e;
	}

	if (ee) {
		printf("freeing ee ..fid = %d ...\n", ee->fid);
		free(ee);
	}
}

static void cmdu_fragqueue_free_entry(struct cmdu_frag_rx *frag)
{
	if (frag)
		free(frag);
}

static struct cmdu_frag_rx *cmdu_create_rxfrag(struct cmdu_buff *cmdu,
					       uint32_t timeout)
{
	struct cmdu_frag_rx *frag;
	struct timeval tsp = { 0 };

	frag = calloc(1, sizeof(*frag));
	if (!frag) {
		fprintf(stderr, "calloc failed. err = NOMEM\n");
		return NULL;
	}

	frag->cmdu = cmdu;
	frag->type = cmdu_get_type(cmdu);
	frag->mid = cmdu_get_mid(cmdu);
	frag->fid = cmdu_get_fid(cmdu);
	frag->last_frag = IS_CMDU_LAST_FRAGMENT(cmdu->cdata) ? true : false;
	memcpy(frag->origin, cmdu_get_origin(cmdu), 6);
	frag->next = NULL;
	frag->last = frag;
	frag->tlen = cmdu->datalen;	//0;
	frag->numfrags = 1;
	getcurrtime(&tsp);
	frag->ageing_time = timeout;
	timeradd_msecs(&tsp, frag->ageing_time, &frag->ageing_tmo);
	frag->ageing_tmo.tv_usec = (frag->ageing_tmo.tv_usec / 1000) * 1000;
	fprintf(stderr,
		"CREATE frag: type = 0x%04x  mid = %hu (%d) datalen = %d  origin = " MACFMT " timeout = { %u (%jd:%jd) }\n",
		cmdu_get_type(cmdu),
		cmdu_get_mid(cmdu),
		cmdu_get_fid(cmdu),
		frag->tlen,
		MAC2STR(cmdu_get_origin(cmdu)),
		frag->ageing_time,
		(intmax_t) frag->ageing_tmo.tv_sec,
		(intmax_t) frag->ageing_tmo.tv_usec / 1000);

	return frag;
}

int cmdufrag_queue_enqueue(void *rxfq, struct cmdu_buff *cmdu, uint32_t timeout)
{
	struct cmdufrag_queue *q = (struct cmdufrag_queue *)rxfq;
	struct cmdu_frag_rx *frag = NULL;
	uint8_t *origin;
	uint16_t type;
	uint16_t mid;
	uint8_t fid;


	type = cmdu_get_type(cmdu);
	mid = cmdu_get_mid(cmdu);
	fid = cmdu_get_fid(cmdu);
	origin = cmdu_get_origin(cmdu);

	frag = cmdufrag_lookup(rxfq, type, mid, fid, origin);
	if (frag) {
		fprintf(stderr,
			"DROP duplicate: type = 0x%04x mid = %hu fid = %d origin = " MACFMT "\n",
			type, mid, fid, MAC2STR(origin));

		return -1;
	}

	frag = cmdu_create_rxfrag(cmdu, timeout);
	if (frag) {
		int idx = cmdu_frag_hash(type, mid, origin);

		q->pending_cnt++;

		fprintf(stderr,
			"ENQ: type = 0x%04x  mid = %hu fid = %d  origin = " MACFMT "\n",
			type, mid, fid, MAC2STR(origin));

		if (fid > 0) {
			struct cmdu_frag_rx *firstfrag = NULL;

			firstfrag = cmdufrag_lookup(rxfq, type, mid, 0, origin);
			if (!firstfrag) {
				fprintf(stderr,
					"First fragment missing for mid = %hu\n", mid);
				cmdu_fragqueue_free_entry(frag);
				return -1;
			}

			firstfrag->last->next = frag;
			firstfrag->last = frag;
			firstfrag->tlen += frag->cmdu->datalen;
			firstfrag->numfrags++;
			fprintf(stderr, "%s: tlen = %d   numfrags = %d\n", __func__,
				firstfrag->tlen, firstfrag->numfrags);

			/* do not ageout fragments other than the first.
			 * If the first one ages-out, then all the related
			 * fragments will be cleaned up.
			 */
			return 0;
		}

		hlist_add_head(&frag->hlist, &q->table[idx]);

		if (timer_pending(&q->ageing_timer)) {
			if (timercmp(&q->next_tmo, &frag->ageing_tmo, >)) {
				q->next_tmo.tv_sec = frag->ageing_tmo.tv_sec;
				q->next_tmo.tv_usec = frag->ageing_tmo.tv_usec;

				timer_set(&q->ageing_timer, frag->ageing_time);
			}
		} else {
			q->next_tmo.tv_sec = frag->ageing_tmo.tv_sec;
			q->next_tmo.tv_usec = frag->ageing_tmo.tv_usec;
			timer_set(&q->ageing_timer, frag->ageing_time);
		}

		return 0;
	}

	return -1;
}

static void cmdu_frag_ageout(struct cmdufrag_queue *st, struct hlist_head *head,
			     struct timeval *min_next_tmo)
{
	struct cmdu_frag_rx *frag;
	struct hlist_node *tmp;
	struct timeval now = { 0 };


	getcurrtime(&now);

	hlist_for_each_entry_safe(frag, tmp, head, hlist) {
		if (!timercmp(&frag->ageing_tmo, &now, >)) {
			st->pending_cnt--;
			hlist_del(&frag->hlist, head);
			fprintf(stderr, "Fragments from " MACFMT " aged out.\n",
				MAC2STR(frag->origin));
			cmdu_fragqueue_delete_chain(frag);
		} else {
			struct timeval new_next_tmo = { 0 };

			timersub(&frag->ageing_tmo, &now, &new_next_tmo);
			if (!timercmp(min_next_tmo, &new_next_tmo, <)) {
				min_next_tmo->tv_sec = new_next_tmo.tv_sec;
				min_next_tmo->tv_usec = new_next_tmo.tv_usec;
			}
		}
	}
}

static void cmdu_fragqueue_ageing_timer_run(atimer_t *t)
{
	struct cmdufrag_queue *st = container_of(t, struct cmdufrag_queue, ageing_timer);
	struct timeval min_next_tmo = { .tv_sec = 999999 };
	int remain_cnt = 0;
	struct timeval nu;
	int i;

	getcurrtime(&nu);

	fprintf(stderr, "\n Timer now = %jd.%jd   cnt = %d\n",
		(intmax_t) nu.tv_sec, (intmax_t) nu.tv_usec, st->pending_cnt);

	for (i = 0; i < NUM_FRAGMENTS; i++) {
		if (hlist_empty(&st->table[i]))
			continue;

		cmdu_frag_ageout(st, &st->table[i], &min_next_tmo);
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

void free_rxfrag(struct cmdu_frag_rx *e) {
	if (e->next) {
		free_rxfrag(e->next);
	}


	fprintf(stderr, "freeing fid = %d\n", e->fid);
	cmdu_free(e->cmdu);
	free(e);
}

struct cmdu_buff *cmdu_defrag(void *rxfq, struct cmdu_buff *lastfrag)
{
	struct cmdufrag_queue *q = (struct cmdufrag_queue *)rxfq;
	struct cmdu_frag_rx *e;
	struct cmdu_frag_rx *frag = NULL;
	struct cmdu_buff *cmdu = NULL;
	struct hlist_node *tmp;
	uint32_t fidsum = 0;
	bool is_lastfrag;
	uint8_t *origin;
	uint16_t type;
	uint16_t mid;
	uint8_t fid;
	int idx;


	fprintf(stderr, "%s() >>>>>>>>\n", __func__);
	if (!lastfrag || !lastfrag->cdata)
		return NULL;

	type = cmdu_get_type(lastfrag);
	mid = cmdu_get_mid(lastfrag);
	fid = cmdu_get_fid(lastfrag);
	is_lastfrag = IS_CMDU_LAST_FRAGMENT(lastfrag->cdata);
	origin = cmdu_get_origin(lastfrag);

	if (!is_lastfrag)
		return NULL;

	idx = cmdu_frag_hash(type, mid, origin);

	hlist_for_each_entry_safe(frag, tmp, &q->table[idx], hlist) {
		if (frag->type == type && frag->mid == mid &&
			!memcmp(frag->origin, origin, 6)) {

			fprintf(stderr, "DEFRAG: type: 0x%04x mid = %hu  fid = %d " \
					"numfrags: %d\n", frag->type, frag->mid,
					frag->fid, frag->numfrags);

			hlist_del(&frag->hlist, &q->table[idx]);
			q->pending_cnt -= frag->numfrags;
			break;
		}
	}

	if (!frag)
		return NULL;

	/* alloc unfragmented cmdu */
	cmdu = cmdu_alloc_frame(frag->tlen + 3);  /* including EOM if missing */
	if (!cmdu) {
		fprintf(stderr, "-ENOMEM\n");
		return NULL;
	}

	fprintf(stderr, "%s: reassembled CMDU datalen = %d\n", __func__, frag->tlen);
	cmdu_set_type(cmdu, type);
	cmdu_set_mid(cmdu, mid);
	memcpy(cmdu->origin, origin, 6);
	memcpy(cmdu->dev_macaddr, lastfrag->dev_macaddr, 6);
	strncpy(cmdu->dev_ifname, lastfrag->dev_ifname, 15);
	CMDU_SET_LAST_FRAGMENT(cmdu->cdata);

	for (e = frag; e; e = e->next) {
		fidsum += e->fid;
		memcpy(cmdu->tail, e->cmdu->data, e->cmdu->datalen);
		cmdu->datalen += e->cmdu->datalen;
		cmdu->tail += e->cmdu->datalen;
	}
	fprintf(stderr, "%s: reassembled CMDU datalen (%d), expected len (%d)\n", __func__, cmdu->datalen, frag->tlen);

	free_rxfrag(frag);

	fprintf(stderr, "frags sum = %d\n", fidsum);
	if (fid * (fid + 1) != 2 * fidsum) {
		fprintf(stderr, "Defrag Failure!\n");
		cmdu_free(cmdu);
		return NULL;
	}

	bufprintf(cmdu->data, cmdu->datalen, "=== DEFRAG CMDU ===");

	return cmdu;
}

int cmdufrag_queue_init(void *rxfq)
{
	struct cmdufrag_queue *q = (struct cmdufrag_queue *)rxfq;

	memset(q, 0, sizeof(*q));
	timer_init(&q->ageing_timer, cmdu_fragqueue_ageing_timer_run);

	return 0;
}

void cmdufrag_queue_flush(void *rxfq)
{
	struct cmdufrag_queue *q = (struct cmdufrag_queue *)rxfq;
	struct cmdu_frag_rx *msg = NULL;
	int idx = 0;

	for (idx = 0; idx < NUM_FRAGMENTS; idx++) {
		hlist_for_each_entry(msg, &q->table[idx], hlist)
			cmdu_fragqueue_delete_chain(msg);

		q->table[idx].first = NULL;
	}

	q->pending_cnt = 0;
}

void cmdufrag_queue_free(void *rxfq)
{
	struct cmdufrag_queue *q = (struct cmdufrag_queue *)rxfq;

	cmdufrag_queue_flush(q);
	timer_del(&q->ageing_timer);
}
