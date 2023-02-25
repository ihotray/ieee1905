/*
 * util.h
 * implements utility functions and definitions.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef UTIL_H
#define UTIL_H


#include <libubox/list.h>
#include <arpa/inet.h>
#include <sys/time.h>


struct i1905_useropts {
	const char *ubus_sockpath;
	const char *pidfile;
	const char *objname;
	bool daemonize;
	const char *conffile;
	const char *confpath;
	int debug_level;
	const char *logfile;
	bool logfile_isfifo;
	bool syslogging;
	const char *alid;
	bool lo;
};

/* default options */
#define IEEE1905_CONFFILE             "ieee1905"
#define IEEE1905_CONFFILE_PATH        "/etc/config"
#define IEEE1905_OBJECT               "ieee1905"
#define IEEE1905_OBJECT_EXT           IEEE1905_OBJECT".extension"
#define IEEE1905_PIDFILE              "/var/run/"IEEE1905_OBJECT".pid"



void do_daemonize(const char *pidfile);
int timeradd_msecs(struct timeval *a, unsigned long msecs, struct timeval *res);
void get_random_bytes(int num, uint8_t *buf);
void bufprintf(uint8_t *buf, int len, const char *label);

typedef unsigned int ifstatus_t;
typedef unsigned char ifopstatus_t;

enum if_mediatype {
	IF_MEDIA_ETH,
	IF_MEDIA_WIFI,
	IF_MEDIA_PLD,
	IF_MEDIA_MOCA,
	IF_MEDIA_UNKNOWN,
};


int if_brportnum(const char *ifname);

#ifndef BIT
#define BIT(x)	(1 << (x))
#endif

#define MACFMT		"%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(_m)	(_m)[0], (_m)[1], (_m)[2], (_m)[3], (_m)[4], (_m)[5]



#ifndef list_flush
#define list_flush(head, type, member)					\
do {									\
	type *__p, *__tmp;						\
									\
	if (!list_empty(head))						\
		list_for_each_entry_safe(__p, __tmp, head, member) {	\
			list_del(&__p->member);				\
			free(__p);					\
		}							\
} while (0)
#endif

#endif /* UTIL_H */
