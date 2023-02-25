/*
 * cmdufrag.h
 * implments structs and functions for CMDU fragments.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */


#ifndef CMDUFRAG_H
#define CMDUFRAG_H

#include <stdint.h>
#include <sys/time.h>
#include <libubox/list.h>

#include <easy/easy.h>

#include "bufutil.h"
#include "cmdu.h"


#define FRAG_DATA_SIZE_TLV	1460	/* max is 1492 including eom */
#define FRAG_DATA_SIZE		(FRAG_DATA_SIZE_TLV - TLV_HLEN)


struct cmdu_buff *cmdu_fragment(uint8_t *data, int datalen);
struct cmdu_buff *cmdu_defrag(void *rxfq, struct cmdu_buff *lastfrag);


struct cmdu_frag_rx {
	struct cmdu_buff *cmdu;
	uint16_t type;
	uint16_t mid;
	uint8_t fid;
	bool last_frag;
	uint8_t origin[6];
	struct cmdu_frag_rx *next, *last;
	uint32_t tlen;
	uint16_t numfrags;
	struct hlist_node hlist;
	uint32_t ageing_time;    /* in msecs */
	struct timeval ageing_tmo;
};

#ifndef MAC_ADDR_HASH
#define MAC_ADDR_HASH(_a)	(_a[0] ^ _a[1] ^ _a[2] ^ _a[3] ^ _a[4] ^ _a[5])
#endif

#define NUM_FRAGMENTS	128

// TODO: improve func
#define cmdu_frag_hash(t, m, o)		\
		((MAC_ADDR_HASH(o) ^ (t) ^ (m)) & (NUM_FRAGMENTS - 1))

struct cmdufrag_queue {
	struct hlist_head table[NUM_FRAGMENTS];
	int pending_cnt;
	atimer_t ageing_timer;
	struct timeval next_tmo;
};

int cmdufrag_queue_init(void *rxfq);
void cmdufrag_queue_free(void *rxfq);
int cmdufrag_queue_enqueue(void *rxfq, struct cmdu_buff *frag, uint32_t timeout);


#endif /* CMDUFRAG_H */
