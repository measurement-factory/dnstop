/*
 * $Id$
 *
 * http://dnstop.measurement-factory.com/
 *
 * Copyright (c) 2006, The Measurement Factory, Inc.  All rights
 * reserved.  See the LICENSE file for details.
 */

#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#ifdef __linux__
#include <stdint.h>
#endif
#include "hashtbl.h"

hashtbl
*hash_create(int N, hashfunc *hasher, hashkeycmp *cmp)
{
	hashtbl *new = calloc(1, sizeof(*new));
	assert(new);
	new->modulus = N;
	new->hasher = hasher;
	new->keycmp = cmp;
	new->items = calloc(N, sizeof(hashitem*));
	return new;
}

int
hash_add(const void *key, void *data, hashtbl *tbl)
{
	hashitem *new = calloc(1, sizeof(*new));
	hashitem **I;
	int slot;
	new->key = key;
	new->data = data;
	slot = tbl->hasher(key) % tbl->modulus;
	for (I = &tbl->items[slot]; *I; I = &(*I)->next);
	*I = new;
	return 0;
}

void *
hash_find(const void *key, hashtbl *tbl)
{
	int slot = tbl->hasher(key) % tbl->modulus;
	hashitem *i;
	for (i = tbl->items[slot]; i; i = i->next) {
		if (0 == tbl->keycmp(key, i->key))
		    return i->data;
	}
	return NULL;
}

int
hash_count(hashtbl *tbl)
{
	int slot;
	int count = 0;
	for(slot = 0; slot < tbl->modulus; slot++) {
		hashitem *i;
		for (i = tbl->items[slot]; i; i=i->next)
			count++;
	}
	return count;
}

void
hash_free(hashtbl *tbl, void freefunc(void *))
{
	int slot;
	for(slot = 0; slot < tbl->modulus; slot++) {
		hashitem *i;
		for (i = tbl->items[slot]; i; i=i->next) {
			freefunc(i->data);
			free(i);
		}
		tbl->items[slot] = NULL;
	}
}

static void
hash_iter_next_slot(hashtbl *tbl)
{
	while (tbl->iter.next == NULL) {
		tbl->iter.slot++;
		if (tbl->iter.slot == tbl->modulus)
			break;
		tbl->iter.next = tbl->items[tbl->iter.slot];
	}
}

void
hash_iter_init(hashtbl *tbl)
{
	tbl->iter.slot = 0;
	tbl->iter.next = tbl->items[tbl->iter.slot];
	if (NULL == tbl->iter.next)
		hash_iter_next_slot(tbl);
}

void *
hash_iterate(hashtbl *tbl)
{
	hashitem *this = tbl->iter.next;
	if (this) {
		tbl->iter.next = this->next;
		if (NULL == tbl->iter.next)
			hash_iter_next_slot(tbl);
	}
	return this ? this->data : NULL;
}
