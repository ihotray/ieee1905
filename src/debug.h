/*
 * debug.h - header file for debug and log messages.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#ifndef DEBUG_H
#define DEBUG_H

void start_logging(void *opts);
void stop_logging(void);
void log_message(int level, const char *fmt, ...)
	__attribute__((__format__(__printf__, 2, 3)));
void log_cmdu(uint8_t *buf, size_t len, const char *ifname, bool is_rx);

#define DEBUG_COLOR	1

#ifdef DEBUG_COLOR
#define red             "\033[0;31m"
#define green           "\033[0;32m"
#define yellow          "\033[1;33m"
#define brown           "\033[0;33m"
#define blue            "\033[0;34m"
#define magenta         "\033[0;35m"
#define bgred           "\033[48;5;196m"
#define bggreen         "\033[48;5;046m"
#define bgyellow        "\033[48;5;226m"
#define bgblue          "\033[48;5;037m"
#define nocl            "\033[0m"

#define err(fmt, ...)         log_message(0, red fmt nocl, ## __VA_ARGS__)
#define warn(fmt, ...)        log_message(1, red fmt nocl, ## __VA_ARGS__)
#define info(fmt, ...)        log_message(2, blue fmt nocl, ## __VA_ARGS__)
#define dbg(fmt, ...)         log_message(3, nocl fmt nocl, ## __VA_ARGS__)
#define trace(fmt, ...)       log_message(4, fmt, ## __VA_ARGS__)
#define loud(fmt, ...)        log_message(5, fmt, ## __VA_ARGS__)
#define dbg6(fmt, ...)        log_message(6, nocl fmt nocl, ## __VA_ARGS__)
#define dbg7(fmt, ...)        log_message(7, nocl fmt nocl, ## __VA_ARGS__)

#define logcmdu(b,l,i,t)      log_cmdu(b,l,i,t)
#else

#define err(...)	log_message(0, __VA_ARGS__)
#define warn(...)	log_message(1, __VA_ARGS__)
#define info(...)	log_message(2, __VA_ARGS__)
#define dbg(...)	log_message(3, __VA_ARGS__)
#define trace(...)	log_message(4, __VA_ARGS__)
#define trace_cmd(...)	log_message(4, __VA_ARGS__)
#define loud(...)	log_message(5, __VA_ARGS__)
#define dbg6(fmt, ...)  log_message(6, __VA_ARGS__)
#define dbg7(fmt, ...)  log_message(7, __VA_ARGS__)

#define logcmdu(b,l,i,t)
#endif /* DEBUG_COLOR */

#endif /* DEBUG_H */
