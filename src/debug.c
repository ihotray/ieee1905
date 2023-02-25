/*
 * debug.c - for debug and logging
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include <easy/easy.h>

#include "util.h"
#include "debug.h"

extern const char *PROG_NAME;

static int ffd;
static const char *logfile;
static FILE *outfile;
static int verbose;
static bool syslogging;
static bool logfile_isfifo;
static const int syslog_level[] = { LOG_ERR, LOG_WARNING, LOG_INFO, LOG_DEBUG };

void start_logging(void *args)
{
	struct i1905_useropts *opts = args;


	syslogging = opts->syslogging;
	logfile = opts->logfile;
	logfile_isfifo = opts->logfile_isfifo;
	verbose = opts->debug_level;

	if (syslogging)
		openlog(PROG_NAME, 0, LOG_DAEMON);

	if (!logfile) {
		outfile = stderr;
		return;
	}

	if (logfile_isfifo) {
		struct stat st;
		int rfd;

		if (stat(logfile, &st))
			unlink(logfile);

		mkfifo(logfile, 0600);
		if (stat(logfile, &st) == -1 || !S_ISFIFO(st.st_mode))
			return;

		rfd = open(logfile, O_RDONLY | O_NONBLOCK);
		if (rfd) {
			ffd = open(logfile, O_WRONLY | O_NONBLOCK);
			close(rfd);
		}
	} else {
		outfile = fopen(logfile, "w+");
	}
}

void stop_logging(void)
{
	if (syslogging)
		closelog();

	if (outfile)
		fclose(outfile);

	if (ffd) {
		close(ffd);
		unlink(logfile);
	}
}

void log_message(int level, const char *fmt, ...)
{
	va_list args;

	if (level != 0x10 && level > verbose)
		return;

	if (logfile_isfifo && ffd) {
		time_t now = time(NULL);
		struct tm *tm_now = localtime(&now);
		const char *tm_fmt = "[%d-%02d-%02d %02d:%02d:%02d] ";

		va_start(args, fmt);
		dprintf(ffd, tm_fmt,
			tm_now->tm_year + 1900,
			tm_now->tm_mon + 1,
			tm_now->tm_mday,
			tm_now->tm_hour,
			tm_now->tm_min,
			tm_now->tm_sec);
		vdprintf(ffd, fmt, args);
		va_end(args);

		return;
	}

	va_start(args, fmt);
	if (syslogging && level >= 0)
		vsyslog(syslog_level[level > 3 ? 3 : level], fmt, args);

	if (outfile) {
		fprintf(outfile, "[%d]: ", getpid());
		vfprintf(outfile, fmt, args); /* Flawfinder: ignore */
	}

	if (logfile_isfifo && ffd)
		vdprintf(ffd, fmt, args);

	va_end(args);
}

void log_cmdu(uint8_t *buf, size_t buflen, const char *ifname, bool is_rx)
{
	const char *fmt = "{\"type\":\"%s\", \"ifname\":\"%s\", \"cmdu\":\"%s\"}";
	const char *flag = getenv("IEEE1905_LOG_CMDU");
	size_t len = 256 + 3028;
	char cmdu[3028] = { 0 };


	if (!flag || atoi(flag) == 0)
		return;

	if (buf && buflen)
		btostr(buf, buflen, cmdu);

	if (ifname)
		len += strlen(ifname);

	char jdata[len];

	snprintf(jdata, sizeof(jdata), fmt, is_rx ? "rx" : "tx",
		 ifname ? ifname : "",
		 buf ? cmdu : "");

	log_message(0x10, "%s\n", jdata);
}
