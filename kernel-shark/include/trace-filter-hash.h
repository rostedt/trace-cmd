/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
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
#ifndef _TRACE_FILTER_HASH_H
#define _TRACE_FILTER_HASH_H

#include <stdint.h>

struct filter_id_item {
	struct filter_id_item	*next;
	int			id;
};

struct filter_id {
	struct filter_id_item **hash;
	int			count;
};

struct filter_id_item *filter_id_find(struct filter_id *hash, int id);
void filter_id_add(struct filter_id *hash, int id);
void filter_id_remove(struct filter_id *hash, int id);
void filter_id_clear(struct filter_id *hash);
struct filter_id *filter_id_hash_alloc(void);
void filter_id_hash_free(struct filter_id *hash);
struct filter_id *filter_id_hash_copy(struct filter_id *hash);
int *filter_ids(struct filter_id *hash);
int filter_id_compare(struct filter_id *hash1, struct filter_id *hash2);

static inline int filter_task_count(struct filter_id *hash)
{
	return hash->count;
}

/*
 * Hashing functions, based on Donald E. Knuth's Multiplicative hashing.
 * See The Art of Computer Programming (TAOCP).
 */

static inline uint8_t knuth_hash8(uint32_t val)
{
	/*
	 * Multiplicative hashing function.
	 * Multiplication by the Prime number, closest to the golden
	 * ratio of 2^8.
	 */
	return UINT8_C(val) * UINT8_C(157);
}

static inline uint16_t knuth_hash16(uint32_t val)
{
	/*
	 * Multiplicative hashing function.
	 * Multiplication by the Prime number, closest to the golden
	 * ratio of 2^16.
	 */
	return UINT16_C(val) * UINT16_C(40507);
}

static inline uint32_t knuth_hash(uint32_t val)
{
	/*
	 * Multiplicative hashing function.
	 * Multiplication by the Prime number, closest to the golden
	 * ratio of 2^32.
	 */
	return val * UINT32_C(2654435761);
}

#endif /* _TRACE_FILTER_HASH_H */
