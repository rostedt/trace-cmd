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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "trace-hash.h"

#define FILTER_TASK_HASH_SIZE	256

guint trace_hash(gint val)
{
	gint hash, tmp;

	hash = 12546869;	/* random prime */

	/*
	 * The following hash is based off of Paul Hsieh's super fast hash:
	 *  http://www.azillionmonkeys.com/qed/hash.html
	 * Note, he released this code unde the GPL 2.0 license, which
	 *  is the same as the license for the programs that use it here.
	 */

	hash +=	(val & 0xffff);
	tmp = (val >> 16) ^ hash;
	hash = (hash << 16) ^ tmp;
	hash += hash >> 11;

	hash ^= hash << 3;
	hash += hash >> 5;
	hash ^= hash << 4;
	hash += hash >> 17;
	hash ^= hash << 25;
	hash += hash >> 6;

	return hash;
}

struct filter_task_item *
filter_task_find_pid(struct filter_task *hash, gint pid)
{
	gint key = trace_hash(pid) % FILTER_TASK_HASH_SIZE;
	struct filter_task_item *task = hash->hash[key];

	while (task) {
		if (task->pid == pid)
			break;
		task = task->next;
	}
	return task;
}

void filter_task_add_pid(struct filter_task *hash, gint pid)
{
	gint key = trace_hash(pid) % FILTER_TASK_HASH_SIZE;
	struct filter_task_item *task;

	task = g_new0(typeof(*task), 1);
	g_assert(task);

	task->pid = pid;
	task->next = hash->hash[key];
	hash->hash[key] = task;

	hash->count++;
}

void filter_task_remove_pid(struct filter_task *hash, gint pid)
{
	gint key = trace_hash(pid) % FILTER_TASK_HASH_SIZE;
	struct filter_task_item **next = &hash->hash[key];
	struct filter_task_item *task;

	while (*next) {
		if ((*next)->pid == pid)
			break;
		next = &(*next)->next;
	}
	if (!*next)
		return;

	g_assert(hash->count);
	hash->count--;

	task = *next;

	*next = task->next;

	g_free(task);
}

void filter_task_clear(struct filter_task *hash)
{
	struct filter_task_item *task, *next;;
	gint i;

	for (i = 0; i < FILTER_TASK_HASH_SIZE; i++) {
		next = hash->hash[i];
		if (!next)
			continue;

		hash->hash[i] = NULL;
		while (next) {
			task = next;
			next = task->next;
			g_free(task);
		}
	}

	hash->count = 0;
}

struct filter_task *filter_task_hash_alloc(void)
{
	struct filter_task *hash;

	hash = g_new0(typeof(*hash), 1);
	g_assert(hash);
	hash->hash = g_new0(typeof(*hash->hash), FILTER_TASK_HASH_SIZE);

	return hash;
}

void filter_task_hash_free(struct filter_task *hash)
{
	if (!hash)
		return;

	filter_task_clear(hash);
	g_free(hash->hash);
	g_free(hash);
}

struct filter_task *filter_task_hash_copy(struct filter_task *hash)
{
	struct filter_task *new_hash;
	struct filter_task_item *task, **ptask;
	gint i;

	if (!hash)
		return NULL;

	new_hash = filter_task_hash_alloc();
	g_assert(new_hash);

	for (i = 0; i < FILTER_TASK_HASH_SIZE; i++) {
		task = hash->hash[i];
		if (!task)
			continue;

		ptask = &new_hash->hash[i];

		while (task) {

			*ptask = g_new0(typeof(*task), 1);
			g_assert(*ptask);
			**ptask = *task;

			ptask = &(*ptask)->next;
			task = task->next;
		}
	}

	new_hash->count = hash->count;

	return new_hash;
}
