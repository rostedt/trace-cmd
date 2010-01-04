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
