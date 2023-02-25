/*
 * midgen.c - 1905 CMDU mid generator
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/types.h>
#include "bufutil.h"


struct i1905_msgid {
	sem_t s;
	uint16_t mid;
};


static void get_randombytes(uint8_t *buf, int num)
{
	unsigned int seed = (unsigned int)time(NULL);
	int i;

	srand(seed);
	for (i = 0; i < num; i++)
		buf[i] = rand_r(&seed) & 0xff;
}

int cmdu_midgen_init(void)
{
	struct i1905_msgid *m;
	uint16_t mid = 0xffff;
	uint8_t *data;
	uint8_t b[2];
	int f;


	f = shm_open("/i1905mid", O_CREAT | O_EXCL | O_RDWR, 0600);
	if (f < 0)
		return -1;

	ftruncate(f, sizeof(struct i1905_msgid));
	data = mmap(0, sizeof(struct i1905_msgid),
		    PROT_READ | PROT_WRITE,
		    MAP_SHARED, f, 0);

	if (data == MAP_FAILED) {
		close(f);
		return -1;
	}

	m = (struct i1905_msgid *)data;
	sem_init(&m->s, 1, 1);

	get_randombytes(b, 2);
	mid = *(uint16_t *)b;
	if (mid == 0)
		mid = 1;

	/* fprintf(stderr, "%s: Init mid = 0x%04x\n", __func__, mid); */
	m->mid = mid;
	munmap(data, sizeof(struct i1905_msgid));
	close(f);

	return 0;
}

void cmdu_midgen_exit(void)
{
	struct i1905_msgid *m;
	uint8_t *data;
	int f;


	f = shm_open("/i1905mid", O_RDWR, 0600);
	if (f < 0)
		return;

	data = mmap(0, sizeof(struct i1905_msgid),
		    PROT_READ | PROT_WRITE,
		    MAP_SHARED, f, 0);

	if (data == MAP_FAILED) {
		close(f);
		return;
	}

	m = (struct i1905_msgid *)data;
	sem_destroy(&m->s);
	munmap(data, sizeof(struct i1905_msgid));
	close(f);
	shm_unlink("/i1905mid");
}

uint16_t cmdu_get_next_mid(void)
{
	struct i1905_msgid *m;
	uint16_t ret = 0xffff;
	uint8_t *data;
	int f;


	f = shm_open("/i1905mid", O_RDWR, 0600);
	if (f < 0)
		return -1;

	data = mmap(0, sizeof(struct i1905_msgid),
		    PROT_READ | PROT_WRITE,
		    MAP_SHARED, f, 0);

	if (data == MAP_FAILED) {
		close(f);
		return -1;
	}

	m = (struct i1905_msgid *)data;
	sem_wait(&m->s);
	ret = m->mid;
	m->mid++;
	if (m->mid == 0xffff)
		m->mid++;
	/* fprintf(stderr, "%s: returned mid = 0x%04x   next mid = %hu (0x%04x)\n",
		__func__, ret, m->mid, m->mid); */
	sem_post(&m->s);
	munmap(data, sizeof(struct i1905_msgid));
	close(f);

	return ret;
}
