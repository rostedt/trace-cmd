#ifndef _TRACE_HASH_H
#define _TRACE_HASH_H

#include <glib.h>

struct filter_task_item {
	struct filter_task_item	*next;
	gint			pid;
};

struct filter_task {
	struct filter_task_item **hash;
	gint			count;
};

guint trace_hash(gint val);

struct filter_task_item *
filter_task_find_pid(struct filter_task *hash, gint pid);
void filter_task_add_pid(struct filter_task *hash, gint pid);
void filter_task_remove_pid(struct filter_task *hash, gint pid);
void filter_task_clear(struct filter_task *hash);
struct filter_task *filter_task_hash_alloc(void);
void filter_task_hash_free(struct filter_task *hash);
struct filter_task *filter_task_hash_copy(struct filter_task *hash);

static inline gint filter_task_count(struct filter_task *hash)
{
	return hash->count;
}

#endif /* _TRACE_HASH_H */
