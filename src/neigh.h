/*
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef NEIGH_H
#define NEIGH_H

#include <easy/easy.h>


#define NEIGH_ENTRIES_MAX		128
#define NEIGH_AGEOUT_DEFAULT		60000	/* msecs */
#define MAX_PROBE_COUNT			2

#ifndef MAC_ADDR_HASH
#define MAC_ADDR_HASH(a)	(a[0] ^ a[1] ^ a[2] ^ a[3] ^ a[4] ^ a[5])
#endif

#define neigh_hash(o)	(MAC_ADDR_HASH(o) & (NEIGH_ENTRIES_MAX - 1))

struct ip_address_entry {
	struct ip_address ip;
	struct list_head list;
};

enum neigh_state {
	NEIGH_STATE_UNKNOWN    = 0x00,
	NEIGH_STATE_INCOMPLETE = 0x01,
	NEIGH_STATE_REACHABLE  = 0x02,
	NEIGH_STATE_STALE      = 0x04,
	NEIGH_STATE_PROBING    = 0x10,
	NEIGH_STATE_FAILED     = 0x20,
};

enum neigh_type {
	NEIGH_TYPE_UNKNOWN,
	NEIGH_TYPE_ETH,
	NEIGH_TYPE_WIFI,
};

struct neigh_entry {
	uint8_t macaddr[6];
	uint16_t state;
	char ifname[16];
	uint16_t brport;		/* valid when 'ifname' is bridge type */
	enum neigh_type type;
	uint8_t is1905;
	uint8_t is1905_slave;		/* member interface of 1905 device */
	void *cookie;
	struct list_head iplist;	/* list of struct ip_address_entry */
	struct hlist_node hlist;
	int probing;			/* when probing entry through arping etc. */
	atimer_t probing_timer;

	uint32_t ageing_time;    /* in msecs */
	struct timeval ageing_tmo;
	int probe_cnt;
};

struct neigh_queue {
	struct hlist_head table[NEIGH_ENTRIES_MAX];

	int pending_cnt;
	atimer_t ageing_timer;
	struct timeval next_tmo;
};

extern int neigh_queue_init(void *q);
extern void neigh_queue_free(void *q);
extern void neigh_queue_flush(void *q);
struct neigh_entry *neigh_queue_print(void *q);

int neigh_set_type(void *q, uint8_t *macaddr, enum neigh_type type);
uint16_t neigh_get_brport(void *q, uint8_t *macaddr);
int neigh_set_1905(void *q, uint8_t *macaddr);
int neigh_set_1905_slave(void *q, uint8_t *macaddr);
bool is_neigh_1905(void *q, uint8_t *macaddr);

struct neigh_entry *neigh_lookup(void *q, uint8_t *macaddr);
int neigh_dequeue(void *q, uint8_t *macaddr, void **cookie);
int neigh_enqueue(void *q, uint8_t *macaddr, uint16_t state, const char *ifname,
		  enum neigh_type type, struct ip_address *ip, uint32_t timeout,
		  void *cookie);


#endif /* NEIGH_H */
