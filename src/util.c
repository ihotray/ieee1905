/*
 * util.c - implements utility functions.
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
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/route/link/bridge.h>
#include <netlink/route/link/macvlan.h>

#include <easy/easy.h>
#include "debug.h"
#include "util.h"


void do_daemonize(const char *pidfile)
{
	int f;

	daemon(0, 0);

	if (!pidfile)
		return;

	f = open(pidfile, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (f) {
		char buf[128] = {0};
		int flags;

		flags = fcntl(f, F_GETFD);
		if (flags != -1) {
			flags |= FD_CLOEXEC;
			fcntl(f, F_SETFD, flags);
		}
		if (lockf(f, F_TLOCK, 0) < 0) {
			fprintf(stderr, "File '%s' exists. Aborting...\n",
				pidfile);
			exit(-1);
		}
		ftruncate(f, 0);
		snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
		write(f, buf, strlen(buf));
	}
}

/* TODO: move following three functions to separate file */
int timeradd_msecs(struct timeval *a, unsigned long msecs, struct timeval *res)
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

void get_random_bytes(int num, uint8_t *buf)
{
	unsigned int seed;
	struct timespec res = {0};
	int i;

	clock_gettime(CLOCK_REALTIME, &res);

	seed = res.tv_nsec;

	srand(seed);
	for (i = 0; i < num; i++)
		buf[i] = rand_r(&seed) & 0xff;
}

void _bufprintf(uint8_t *buf, int len, const char *label)
{
	int rows, residue;
	int i;
	int k;

	if (label)
		fprintf(stderr, "---- %s ----\n", label);

	rows = len / 16;

	for (k = 0; k < rows; k++) {
		fprintf(stderr, "\n   0x%08x | ", k * 16);

		for (i = 0; i < 16; i++) {
			if (!(i % 4))
				fprintf(stderr, "  ");

			fprintf(stderr, "%02x ", buf[k*16 + i] & 0xff);
		}

		fprintf(stderr, "%8c", ' ');
		for (i = 0; i < 16; i++) {
			fprintf(stderr, "%c ",
				isalnum(buf[k*16 + i] & 0xff) ? buf[k*16 + i] : '.');
		}
	}

	residue = len % 16;
	k = len - len % 16;

	if (residue) {
		fprintf(stderr, "\n   0x%08x | ", rows * 16);
		for (i = k; i < len; i++) {
			if (!(i % 4))
				fprintf(stderr, "  ");

			fprintf(stderr, "%02x ", buf[i] & 0xff);
		}

		for (i = residue; i < 16; i++) {
			if (!(i % 4))
				fprintf(stderr, "  ");

			fprintf(stderr, "%s ", "  ");
		}

		fprintf(stderr, "%8c", ' ');
		for (i = k; i < len; i++) {
			fprintf(stderr, "%c ",
				isalnum(buf[i] & 0xff) ? buf[i] : '.');
		}

	}

	if (label)
		fprintf(stderr, "\n--------------\n");
}

void bufprintf(uint8_t *buf, int len, const char *label)
{
	//_bufprintf(buf, len, label);
}

int if_brportnum(const char *ifname)
{
	char path[512] = {0};
	int portnum = -1;
	FILE *f;

	snprintf(path, 512, "/sys/class/net/%s/brport/port_no", ifname);
	f = fopen(path, "r");
	if (!f)
		return -1;

	fscanf(f, "%i", &portnum);
	fclose(f);

	return portnum;
}
