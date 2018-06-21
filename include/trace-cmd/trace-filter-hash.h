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

struct tracecmd_filter_id_item {
	struct tracecmd_filter_id_item	*next;
	int				id;
};

struct tracecmd_filter_id {
	struct tracecmd_filter_id_item **hash;
	int				count;
};

struct tracecmd_filter_id_item *
  tracecmd_filter_id_find(struct tracecmd_filter_id *hash, int id);
void tracecmd_filter_id_add(struct tracecmd_filter_id *hash, int id);
void tracecmd_filter_id_remove(struct tracecmd_filter_id *hash, int id);
void tracecmd_filter_id_clear(struct tracecmd_filter_id *hash);
struct tracecmd_filter_id *tracecmd_filter_id_hash_alloc(void);
void tracecmd_filter_id_hash_free(struct tracecmd_filter_id *hash);
struct tracecmd_filter_id *
  tracecmd_filter_id_hash_copy(struct tracecmd_filter_id *hash);
int *tracecmd_filter_ids(struct tracecmd_filter_id *hash);
int tracecmd_filter_id_compare(struct tracecmd_filter_id *hash1,
			       struct tracecmd_filter_id *hash2);

static inline int tracecmd_filter_task_count(struct tracecmd_filter_id *hash)
{
	return hash->count;
}

#endif /* _TRACE_FILTER_HASH_H */
