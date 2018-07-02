// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov <y.karadz@gmail.com>
 */

 /**
 *  @file    libkshark.c
 *  @brief   API for processing of FTRACE (trace-cmd) data.
 */

/** Use GNU C Library. */
#define _GNU_SOURCE 1

// C
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>

// KernelShark
#include "libkshark.h"

static __thread struct trace_seq seq;

static struct kshark_context *kshark_context_handler = NULL;

static bool kshark_default_context(struct kshark_context **context)
{
	struct kshark_context *kshark_ctx;

	kshark_ctx = calloc(1, sizeof(*kshark_ctx));
	if (!kshark_ctx)
		return false;

	/* Will free kshark_context_handler. */
	kshark_free(NULL);

	/* Will do nothing if *context is NULL. */
	kshark_free(*context);

	*context = kshark_context_handler = kshark_ctx;

	return true;
}

static bool init_thread_seq(void)
{
	if (!seq.buffer)
		trace_seq_init(&seq);

	return seq.buffer != NULL;
}

/**
 * @brief Initialize a kshark session. This function must be called before
 *	  calling any other kshark function. If the session has been
 *	  initialized, this function can be used to obtain the session's
 *	  context.
 * @param kshark_ctx: Optional input/output location for context pointer.
 *		      If it points to a context, that context will become
 *		      the new session. If it points to NULL, it will obtain
 *		      the current (or new) session. The result is only
 *		      valid on return of true.
 * @returns True on success, or false on failure.
 */
bool kshark_instance(struct kshark_context **kshark_ctx)
{
	if (*kshark_ctx != NULL) {
		/* Will free kshark_context_handler */
		kshark_free(NULL);

		/* Use the context provided by the user. */
		kshark_context_handler = *kshark_ctx;
	} else {
		if (kshark_context_handler) {
			/*
			 * No context is provided by the user, but the context
			 * handler is already set. Use the context handler.
			 */
			*kshark_ctx = kshark_context_handler;
		} else {
			/* No kshark_context exists. Create a default one. */
			if (!kshark_default_context(kshark_ctx))
				return false;
		}
	}

	if (!init_thread_seq())
		return false;

	return true;
}

static void kshark_free_task_list(struct kshark_context *kshark_ctx)
{
	struct kshark_task_list *task;
	int i;

	if (!kshark_ctx)
		return;

	for (i = 0; i < KS_TASK_HASH_SIZE; ++i) {
		while (kshark_ctx->tasks[i]) {
			task = kshark_ctx->tasks[i];
			kshark_ctx->tasks[i] = task->next;
			free(task);
		}
	}
}

/**
 * @brief Open and prepare for reading a trace data file specified by "file".
 *	  If the specified file does not exist, or contains no trace data,
 *	  the function returns false.
 * @param kshark_ctx: Input location for context pointer.
 * @param file: The file to load.
 * @returns True on success, or false on failure.
 */
bool kshark_open(struct kshark_context *kshark_ctx, const char *file)
{
	struct tracecmd_input *handle;

	kshark_free_task_list(kshark_ctx);

	handle = tracecmd_open(file);
	if (!handle)
		return false;

	if (pthread_mutex_init(&kshark_ctx->input_mutex, NULL) != 0) {
		tracecmd_close(handle);
		return false;
	}

	kshark_ctx->handle = handle;
	kshark_ctx->pevent = tracecmd_get_pevent(handle);

	/*
	 * Turn off function trace indent and turn on show parent
	 * if possible.
	 */
	trace_util_add_option("ftrace:parent", "1");
	trace_util_add_option("ftrace:indent", "0");

	return true;
}

/**
 * @brief Close the trace data file and free the trace data handle.
 * @param kshark_ctx: Input location for the session context pointer.
 */
void kshark_close(struct kshark_context *kshark_ctx)
{
	if (!kshark_ctx || !kshark_ctx->handle)
		return;

	tracecmd_close(kshark_ctx->handle);
	kshark_ctx->handle = NULL;
	kshark_ctx->pevent = NULL;

	pthread_mutex_destroy(&kshark_ctx->input_mutex);
}

/**
 * @brief Deinitialize kshark session. Should be called after closing all
 *	  open trace data files and before your application terminates.
 * @param kshark_ctx: Optional input location for session context pointer.
 *		      If it points to a context of a sessuin, that sessuin
 *		      will be deinitialize. If it points to NULL, it will
 *		      deinitialize the current session.
 */
void kshark_free(struct kshark_context *kshark_ctx)
{
	if (kshark_ctx == NULL) {
		if (kshark_context_handler == NULL)
			return;

		kshark_ctx = kshark_context_handler;
		/* kshark_ctx_handler will be set to NULL below. */
	}

	kshark_free_task_list(kshark_ctx);

	if (seq.buffer)
		trace_seq_destroy(&seq);

	if (kshark_ctx == kshark_context_handler)
		kshark_context_handler = NULL;

	free(kshark_ctx);
}

static inline uint8_t knuth_hash8(uint32_t val)
{
	/*
	 * Hashing functions, based on Donald E. Knuth's Multiplicative
	 * hashing. See The Art of Computer Programming (TAOCP).
	 * Multiplication by the Prime number, closest to the golden
	 * ratio of 2^8.
	 */
	return UINT8_C(val) * UINT8_C(157);
}

static struct kshark_task_list *
kshark_find_task(struct kshark_context *kshark_ctx, uint8_t key, int pid)
{
	struct kshark_task_list *list;

	for (list = kshark_ctx->tasks[key]; list; list = list->next) {
		if (list->pid == pid)
			return list;
	}

	return NULL;
}

static struct kshark_task_list *
kshark_add_task(struct kshark_context *kshark_ctx, int pid)
{
	struct kshark_task_list *list;
	uint8_t key;

	key = knuth_hash8(pid);
	list = kshark_find_task(kshark_ctx, key, pid);
	if (list)
		return list;

	list = malloc(sizeof(*list));
	if (!list)
		return NULL;

	list->pid = pid;
	list->next = kshark_ctx->tasks[key];
	kshark_ctx->tasks[key] = list;

	return list;
}

/**
 * @brief Get an array containing the Process Ids of all tasks presented in
 *	  the loaded trace data file.
 * @param kshark_ctx: Input location for context pointer.
 * @param pids: Output location for the Pids of the tasks. The user is
 *		responsible for freeing the elements of the outputted array.
 * @returns The size of the outputted array of Pids in the case of success,
 *	    or a negative error code on failure.
 */
ssize_t kshark_get_task_pids(struct kshark_context *kshark_ctx, int **pids)
{
	size_t i, pid_count = 0, pid_size = KS_TASK_HASH_SIZE;
	struct kshark_task_list *list;
	int *temp_pids;

	*pids = calloc(pid_size, sizeof(int));
	if(!*pids)
		goto fail;

	for (i = 0; i < KS_TASK_HASH_SIZE; ++i) {
		list = kshark_ctx->tasks[i];
		while (list) {
			(*pids)[pid_count] = list->pid;
			list = list->next;
			if (++pid_count >= pid_size) {
				pid_size *= 2;
				temp_pids = realloc(*pids, pid_size * sizeof(int));
				if (!temp_pids) {
					goto fail;
				}
				*pids = temp_pids;
			}
		}
	}

	temp_pids = realloc(*pids, pid_count * sizeof(int));
	if (!temp_pids)
		goto fail;

	/* Paranoid: In the unlikely case of shrinking *pids, realloc moves it */
	*pids = temp_pids;

	return pid_count;

fail:
	fprintf(stderr, "Failed to allocate memory for Task Pids.\n");
	free(*pids);
	*pids = NULL;
	return -ENOMEM;
}

static void kshark_set_entry_values(struct kshark_context *kshark_ctx,
				    struct pevent_record *record,
				    struct kshark_entry *entry)
{
	/* Offset of the record */
	entry->offset = record->offset;

	/* CPU Id of the record */
	entry->cpu = record->cpu;

	/* Time stamp of the record */
	entry->ts = record->ts;

	/* Event Id of the record */
	entry->event_id = pevent_data_type(kshark_ctx->pevent, record);

	/*
	 * Is visible mask. This default value means that the entry
	 * is visible everywhere.
	 */
	entry->visible = 0xFF;

	/* Process Id of the record */
	entry->pid = pevent_data_pid(kshark_ctx->pevent, record);
}

/**
 * @brief Load the content of the trace data file into an array of
 *	  kshark_entries. This function provides fast loading, however the
 *	  "latency" and the "info" fields can be accessed only via the offset
 *	  into the file. This makes the access to these two fields much
 *	  slower.
 * @param kshark_ctx: Input location for context pointer.
 * @param data_rows: Output location for the trace data. The user is
 *		     responsible for freeing the elements of the outputted
 *		     array.
 * @returns The size of the outputted data in the case of success, or a
 *	    negative error code on failure.
 */
ssize_t kshark_load_data_entries(struct kshark_context *kshark_ctx,
				struct kshark_entry ***data_rows)
{
	struct kshark_entry **cpu_list, **rows;
	struct kshark_entry *entry, **next;
	struct kshark_task_list *task;
	struct pevent_record *rec;
	int cpu, n_cpus, next_cpu;
	size_t count, total = 0;
	uint64_t ts;

	if (*data_rows)
		free(*data_rows);

	n_cpus = tracecmd_cpus(kshark_ctx->handle);
	cpu_list = calloc(n_cpus, sizeof(struct kshark_entry *));

	for (cpu = 0; cpu < n_cpus; ++cpu) {
		count = 0;
		cpu_list[cpu] = NULL;
		next = &cpu_list[cpu];

		rec = tracecmd_read_cpu_first(kshark_ctx->handle, cpu);
		while (rec) {
			*next = entry = malloc(sizeof(struct kshark_entry));
			if (!entry)
				goto fail;

			kshark_set_entry_values(kshark_ctx, rec, entry);
			task = kshark_add_task(kshark_ctx, entry->pid);
			if (!task)
				goto fail;

			entry->next = NULL;
			next = &entry->next;
			free_record(rec);

			++count;
			rec = tracecmd_read_data(kshark_ctx->handle, cpu);
		}

		total += count;
	}

	rows = calloc(total, sizeof(struct kshark_entry *));
	if (!rows)
		goto fail;

	count = 0;
	while (count < total) {
		ts = 0;
		next_cpu = -1;
		for (cpu = 0; cpu < n_cpus; ++cpu) {
			if (!cpu_list[cpu])
				continue;

			if (!ts || cpu_list[cpu]->ts < ts) {
				ts = cpu_list[cpu]->ts;
				next_cpu = cpu;
			}
		}

		if (next_cpu >= 0) {
			rows[count] = cpu_list[next_cpu];
			cpu_list[next_cpu] = cpu_list[next_cpu]->next;
		}
		++count;
	}

	free(cpu_list);
	*data_rows = rows;
	return total;

fail:
	fprintf(stderr, "Failed to allocate memory during data loading.\n");
	return -ENOMEM;
}

/**
 * @brief Load the content of the trace data file into an array of
 *	  pevent_records. Use this function only if you need fast access
 *	  to all fields of the record.
 * @param kshark_ctx: Input location for the session context pointer.
 * @param data_rows: Output location for the trace data. Use free_record()
 *	 	     to free the elements of the outputted array.
 * @returns The size of the outputted data in the case of success, or a
 *	    negative error code on failure.
 */
ssize_t kshark_load_data_records(struct kshark_context *kshark_ctx,
				struct pevent_record ***data_rows)
{
	struct temp {
		struct pevent_record	*rec;
		struct temp		*next;
	} **cpu_list, **temp_next, *temp_rec;

	struct kshark_task_list *task;
	struct pevent_record **rows;
	struct pevent_record *data;
	int cpu, n_cpus, next_cpu;
	size_t count, total = 0;
	uint64_t ts;
	int pid;

	n_cpus = tracecmd_cpus(kshark_ctx->handle);
	cpu_list = calloc(n_cpus, sizeof(struct temp *));

	for (cpu = 0; cpu < n_cpus; ++cpu) {
		count = 0;
		cpu_list[cpu] = NULL;
		temp_next = &cpu_list[cpu];

		data = tracecmd_read_cpu_first(kshark_ctx->handle, cpu);
		while (data) {
			*temp_next = temp_rec = malloc(sizeof(*temp_rec));
			if (!temp_rec)
				goto fail;

			pid = pevent_data_pid(kshark_ctx->pevent, data);
			task = kshark_add_task(kshark_ctx, pid);
			if (!task)
				goto fail;

			temp_rec->rec = data;
			temp_rec->next = NULL;
			temp_next = &(temp_rec->next);

			++count;
			data = tracecmd_read_data(kshark_ctx->handle, cpu);
		}

		total += count;
	}

	rows = calloc(total, sizeof(struct pevent_record *));
	if (!rows)
		goto fail;

	count = 0;
	while (count < total) {
		ts = 0;
		next_cpu = -1;
		for (cpu = 0; cpu < n_cpus; ++cpu) {
			if (!cpu_list[cpu])
				continue;

			if (!ts || cpu_list[cpu]->rec->ts < ts) {
				ts = cpu_list[cpu]->rec->ts;
				next_cpu = cpu;
			}
		}

		if (next_cpu >= 0) {
			rows[count] = cpu_list[next_cpu]->rec;
			temp_rec = cpu_list[next_cpu];
			cpu_list[next_cpu] = cpu_list[next_cpu]->next;
			free (temp_rec);
		}

		++count;
	}

	free(cpu_list);
	*data_rows = rows;
	return total;

fail:
	fprintf(stderr, "Failed to allocate memory during data loading.\n");
	return -ENOMEM;
}

static struct pevent_record *kshark_read_at(struct kshark_context *kshark_ctx,
					    uint64_t offset)
{
	/*
	 * It turns that tracecmd_read_at() is not thread-safe.
	 * TODO: Understand why and see if this can be fixed.
	 * For the time being use a mutex to protect the access.
	 */
	pthread_mutex_lock(&kshark_ctx->input_mutex);

	struct pevent_record *data = tracecmd_read_at(kshark_ctx->handle,
						      offset, NULL);

	pthread_mutex_unlock(&kshark_ctx->input_mutex);

	return data;
}

static const char *kshark_get_latency(struct pevent *pe,
				      struct pevent_record *record)
{
	if (!record)
		return NULL;

	trace_seq_reset(&seq);
	pevent_data_lat_fmt(pe, &seq, record);
	return seq.buffer;
}

static const char *kshark_get_info(struct pevent *pe,
				   struct pevent_record *record,
				   struct event_format *event)
{
	char *pos;

	if (!record || !event)
		return NULL;

	trace_seq_reset(&seq);
	pevent_event_info(&seq, event, record);

	/*
	 * The event info string contains a trailing newline.
	 * Remove this newline.
	 */
	if ((pos = strchr(seq.buffer, '\n')) != NULL)
		*pos = '\0';

	return seq.buffer;
}

/**
 * @brief Dump into a string the content of one entry. The function allocates
 *	  a null terminated string and returns a pointer to this string. The
 *	  user has to free the returned string.
 * @param entry: A Kernel Shark entry to be printed.
 * @returns The returned string contains a semicolon-separated list of data
 *	    fields.
 */
char* kshark_dump_entry(struct kshark_entry *entry)
{
	const char *event_name, *task, *lat, *info;
	struct kshark_context *kshark_ctx;
	struct pevent_record *data;
	struct event_format *event;
	char *temp_str, *entry_str;
	int event_id, size = 0;

	kshark_ctx = NULL;
	if (!kshark_instance(&kshark_ctx) || !init_thread_seq())
		return NULL;

	data = kshark_read_at(kshark_ctx, entry->offset);

	event_id = pevent_data_type(kshark_ctx->pevent, data);
	event = pevent_data_event_from_type(kshark_ctx->pevent, event_id);

	event_name = event? event->name : "[UNKNOWN EVENT]";
	task = pevent_data_comm_from_pid(kshark_ctx->pevent, entry->pid);
	lat = kshark_get_latency(kshark_ctx->pevent, data);

	size = asprintf(&temp_str, "%li %s-%i; CPU %i; %s;",
			entry->ts,
			task,
			entry->pid,
			entry->cpu,
			lat);

	info = kshark_get_info(kshark_ctx->pevent, data, event);
	if (size > 0) {
		size = asprintf(&entry_str, "%s %s; %s; 0x%x",
				temp_str,
				event_name,
				info,
				entry->visible);

		free(temp_str);
	}

	free_record(data);

	if (size > 0)
		return entry_str;

	return NULL;
}
