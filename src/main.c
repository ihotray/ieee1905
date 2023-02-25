/*
 * main.c - main entry point.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * See LICENSE file for license related information.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include "version.h"
#include "util.h"

const char *PROG_NAME = "ieee1905d";
extern int i1905_main(void *user_options);


static void usage(void)
{
	fprintf(stderr, "Usage: %s [options]\n", PROG_NAME);
	fprintf(stderr, "\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "   -h               usage\n");
	fprintf(stderr, "   -v               print version\n");
	fprintf(stderr, "   -s <socket path> ubus socket\n");
	fprintf(stderr, "   -D               run as a daemon\n");
	fprintf(stderr, "   -c <conf-file>   specify configuration file\n");
	fprintf(stderr, "   -d               debug level; more 'd's mean more verbose\n");
	fprintf(stderr, "   -p <pidfile>     pid file path\n");
	fprintf(stderr, "   -o <file>        log to file\n");
	fprintf(stderr, "   -f               treat above file as fifo\n");
	fprintf(stderr, "\n");
}

static void print_version(void)
{
	printf("%s: version '%s-g%s'\n", PROG_NAME, verstring, githash);
}

int main(int argc, char **argv)
{
	struct i1905_useropts opts = {
		.ubus_sockpath = NULL,
		.pidfile = IEEE1905_PIDFILE,
		.objname = IEEE1905_OBJECT,
		.daemonize = false,
		.conffile = IEEE1905_CONFFILE,
		.confpath = IEEE1905_CONFFILE_PATH,
		.debug_level = 2,
		.syslogging = false,
		.logfile = NULL,
		.logfile_isfifo = false,
		.alid = NULL,
		.lo = true,
	};
	static struct option lopts[] = {
		{ "version", 0, 0, 0 },
		{ "alid", 1, 0, 0 },
		{ "config", 1, 0, 0 },
		{ "no-lo", 0, 0, 0 },
		{ "help", 0, 0, 0 },
		{ 0, 0, 0, 0 },
	};
	int lidx = 0;
	int ch;

	for (;;) {
		ch = getopt_long(argc, argv, "vhdDp:s:O:d:c:o:fl", lopts, &lidx);
		if (ch == -1)
			break;

		switch (ch) {
		case 0:
			switch (lidx) {
			case 0:
				print_version();
				exit(0);
			case 1:
				if (optarg) {
					opts.alid = optarg;
					printf("Request ALID: %s\n", optarg);
				}
				break;
			case 2:
				if (optarg) {
					opts.conffile = optarg;
					printf("Config file: %s\n", optarg);
				}
				break;
			case 3:
				opts.lo = false;
				break;
			case 4:
				usage();
				exit(0);
			default:
				break;
			}
			break;
		case 'v':
			print_version();
			exit(0);
		case 'h':
			usage();
			exit(0);
		case 'd':
			opts.debug_level++;
			break;
		case 's':
			opts.ubus_sockpath = optarg;
			break;
		case 'D':
			opts.daemonize = true;
			break;
		case 'p':
			opts.pidfile = optarg;
			break;
		case 'c':
			opts.conffile = optarg;
			break;
		case 'O':
			opts.objname = optarg;
			break;
		case 'o':
			opts.logfile = optarg;
			break;
		case 'f':
			opts.logfile_isfifo = true;
			break;
		case 'l':
			opts.syslogging = true;
			break;
		default:
			break;
		}
	}

	i1905_main(&opts);

	return 0;
}
