/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 * Copyright (C) 2018 VMware Inc, Steven Rostedt <rostedt@goodmis.org>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not,  see <http://www.gnu.org/licenses>
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

#endif /* _TRACE_FILTER_HASH_H */
