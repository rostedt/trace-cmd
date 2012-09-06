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

#include "trace-hash.h"

#define FILTER_TASK_HASH_SIZE	256

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

int *filter_task_pids(struct filter_task *hash)
{
	struct filter_task_item *task;
	int *pids;
	int count = 0;
	int i;

	if (!hash->count)
		return NULL;

	pids = malloc(sizeof(*pids) * (hash->count + 1));
	if (!pids)
		return NULL;

	for (i = 0; i < FILTER_TASK_HASH_SIZE; i++) {
		task = hash->hash[i];
		while (task) {
			pids[count++] = task->pid;
			task = task->next;
		}
	}
	pids[count] = -1;

	return pids;
}

/**
 * filter_task_compare - compare two task hashs to see if they are equal
 * @hash1: one hash to compare
 * @hash2: another hash to compare to @hash1
 *
 * Returns 1 if the two hashes are the same, 0 otherwise.
 */
int filter_task_compare(struct filter_task *hash1, struct filter_task *hash2)
{
	int *pids;
	int ret = 0;
	int i;

	/* If counts don't match, then they obviously are not the same */
	if (hash1->count != hash2->count)
		return 0;

	/* If both hashes are empty, they are the same */
	if (!hash1->count && !hash2->count)
		return 1;

	/* Now compare the pids of one hash with the other */
	pids = filter_task_pids(hash1);
	for (i = 0; pids[i] >= 0; i++) {
		if (!filter_task_find_pid(hash2, pids[i]))
			break;
	}

	if (pids[i] == -1)
		ret = 1;

	free(pids);

	return ret;
}
