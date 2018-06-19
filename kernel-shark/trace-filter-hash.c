/*
 * Copyright (C) 2009, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "trace-filter-hash.h"

#define FILTER_HASH_SIZE	256

struct filter_id_item *
filter_id_find(struct filter_id *hash, int id)
{
	int key = knuth_hash8(id);
	struct filter_id_item *item = hash->hash[key];

	while (item) {
		if (item->id == id)
			break;
		item = item->next;
	}

	return item;
}

void filter_id_add(struct filter_id *hash, int id)
{
	int key = knuth_hash8(id);
	struct filter_id_item *item;

	item = calloc(1, sizeof(*item));
	assert(item);

	item->id = id;
	item->next = hash->hash[key];
	hash->hash[key] = item;

	hash->count++;
}

void filter_id_remove(struct filter_id *hash, int id)
{
	int key = knuth_hash8(id);
	struct filter_id_item **next = &hash->hash[key];
	struct filter_id_item *item;

	while (*next) {
		if ((*next)->id == id)
			break;
		next = &(*next)->next;
	}

	if (!*next)
		return;

	assert(hash->count);
	hash->count--;

	item = *next;

	*next = item->next;

	free(item);
}

void filter_id_clear(struct filter_id *hash)
{
	struct filter_id_item *item, *next;
	int i;

	for (i = 0; i < FILTER_HASH_SIZE; i++) {
		next = hash->hash[i];
		if (!next)
			continue;

		hash->hash[i] = NULL;
		while (next) {
			item = next;
			next = item->next;
			free(item);
		}
	}

	hash->count = 0;
}

struct filter_id *filter_id_hash_alloc(void)
{
	struct filter_id *hash;

	hash = calloc(1, sizeof(*hash));
	assert(hash);
	hash->hash = calloc(FILTER_HASH_SIZE, sizeof(*hash->hash));
	hash->count = 0;

	return hash;
}

void filter_id_hash_free(struct filter_id *hash)
{
	if (!hash)
		return;

	filter_id_clear(hash);
	free(hash->hash);
	free(hash);
}

struct filter_id *filter_id_hash_copy(struct filter_id *hash)
{
	struct filter_id *new_hash;
	struct filter_id_item *item, **pitem;
	int i;

	if (!hash)
		return NULL;

	new_hash = filter_id_hash_alloc();
	assert(new_hash);

	for (i = 0; i < FILTER_HASH_SIZE; i++) {
		item = hash->hash[i];
		if (!item)
			continue;

		pitem = &new_hash->hash[i];

		while (item) {
			*pitem = calloc(1, sizeof(*item));
			assert(*pitem);
			**pitem = *item;

			pitem = &(*pitem)->next;
			item = item->next;
		}
	}

	new_hash->count = hash->count;
	return new_hash;
}

int *filter_ids(struct filter_id *hash)
{
	struct filter_id_item *item;
	int *ids;
	int count = 0;
	int i;

	if (!hash->count)
		return NULL;

	ids = malloc(sizeof(*ids) * (hash->count + 1));
	if (!ids)
		return NULL;

	for (i = 0; i < FILTER_HASH_SIZE; i++) {
		item = hash->hash[i];
		while (item) {
			ids[count++] = item->id;
			item = item->next;
		}
	}

	ids[count] = -1;
	return ids;
}

/**
 * filter_id_compare - compare two id hashes to see if they are equal
 * @hash1: one hash to compare
 * @hash2: another hash to compare to @hash1
 *
 * Returns 1 if the two hashes are the same, 0 otherwise.
 */
int filter_id_compare(struct filter_id *hash1, struct filter_id *hash2)
{
	int *ids;
	int ret = 0;
	int i;

	/* If counts don't match, then they obviously are not the same */
	if (hash1->count != hash2->count)
		return 0;

	/* If both hashes are empty, they are the same */
	if (!hash1->count && !hash2->count)
		return 1;

	/* Now compare the pids of one hash with the other */
	ids = filter_ids(hash1);
	for (i = 0; ids[i] >= 0; i++) {
		if (!filter_id_find(hash2, ids[i]))
			break;
	}

	if (ids[i] == -1)
		ret = 1;

	free(ids);

	return ret;
}
