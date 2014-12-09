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
#ifndef _TRACE_HASH_H
#define _TRACE_HASH_H

#include <glib.h>
#include "trace-hash-local.h"

struct filter_task_item {
	struct filter_task_item	*next;
	gint			pid;
};

struct filter_task {
	struct filter_task_item **hash;
	gint			count;
};

struct filter_task_item *
filter_task_find_pid(struct filter_task *hash, gint pid);
void filter_task_add_pid(struct filter_task *hash, gint pid);
void filter_task_remove_pid(struct filter_task *hash, gint pid);
void filter_task_clear(struct filter_task *hash);
struct filter_task *filter_task_hash_alloc(void);
void filter_task_hash_free(struct filter_task *hash);
struct filter_task *filter_task_hash_copy(struct filter_task *hash);
int *filter_task_pids(struct filter_task *hash);
int filter_task_compare(struct filter_task *hash1, struct filter_task *hash2);

static inline gint filter_task_count(struct filter_task *hash)
{
	return hash->count;
}

#endif /* _TRACE_HASH_H */
