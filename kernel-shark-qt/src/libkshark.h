/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov <y.karadz@gmail.com>
 */

 /**
 *  @file    libkshark.h
 *  @brief   API for processing of FTRACE (trace-cmd) data.
 */

#ifndef _LIB_KSHARK_H
#define _LIB_KSHARK_H

// C
#include <stdint.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// trace-cmd
#include "trace-cmd.h"
#include "trace-filter-hash.h"
#include "event-parse.h"
#include "trace-filter-hash.h"

/**
 * Kernel Shark entry contains all information from one trace record needed
 * in order to  visualize the time-series of trace records. The part of the
 * data which is not directly required for the visualization (latency, record
 * info etc.) is available on-demand via the offset into the trace file.
 */
struct kshark_entry {
	/** Pointer to the next (in time) kshark_entry on the same CPU core. */
	struct kshark_entry *next; /* MUST BE FIRST ENTRY */

	/**
	 * A bit mask controlling the visibility of the entry. A value of OxFF
	 * would mean that the entry is visible everywhere. Use
	 * kshark_filter_masks to check the level of visibility/invisibility
	 * of the entry.
	 */
	uint8_t		visible;

	/** The CPU core of the record. */
	uint8_t		cpu;

	/** The PID of the task the record was generated. */
	int16_t		pid;

	/** Unique Id ot the trace event type. */
	int		event_id;

	/** The offset into the trace file, used to find the record. */
	uint64_t	offset;

	/**
	 * The time of the record in nano seconds. The value is taken from
	 * the timestamps within the trace data file, which are architecture
	 * dependent. The time usually is the timestamp from when the system
	 * started.
	 */
	uint64_t	ts;
};

/** Size of the task's hash table. */
#define KS_TASK_HASH_SIZE 256

/** Linked list of tasks. */
struct kshark_task_list {
	/** Pointer to the next task's PID. */
	struct kshark_task_list	*next;

	/** PID of a task. */
	int			 pid;
};

/** Structure representing a kshark session. */
struct kshark_context {
	/** Input handle for the trace data file. */
	struct tracecmd_input	*handle;

	/** Page event used to parse the page. */
	struct pevent		*pevent;

	/** Hash table of task PIDs. */
	struct kshark_task_list	*tasks[KS_TASK_HASH_SIZE];

	/** A mutex, used to protect the access to the input file. */
	pthread_mutex_t		input_mutex;

	/** Hash of tasks to filter on. */
	struct tracecmd_filter_id	*show_task_filter;

	/** Hash of tasks to not display. */
	struct tracecmd_filter_id	*hide_task_filter;

	/** Hash of events to filter on. */
	struct tracecmd_filter_id	*show_event_filter;

	/** Hash of events to not display. */
	struct tracecmd_filter_id	*hide_event_filter;

	/**
	 * Bit mask, controlling the visibility of the entries after filtering.
	 * If given bit is set here, all entries which are filtered-out will
	 * have this bit unset in their "visible" fields.
	 */
	uint8_t				filter_mask;

	/**
	 * Filter allowing sophisticated filtering based on the content of
	 * the event.
	 */
	struct event_filter		*advanced_event_filter;
};

bool kshark_instance(struct kshark_context **kshark_ctx);

bool kshark_open(struct kshark_context *kshark_ctx, const char *file);

ssize_t kshark_load_data_entries(struct kshark_context *kshark_ctx,
				 struct kshark_entry ***data_rows);

ssize_t kshark_load_data_records(struct kshark_context *kshark_ctx,
				 struct pevent_record ***data_rows);

ssize_t kshark_get_task_pids(struct kshark_context *kshark_ctx, int **pids);

void kshark_close(struct kshark_context *kshark_ctx);

void kshark_free(struct kshark_context *kshark_ctx);

char* kshark_dump_entry(struct kshark_entry *entry);

/** Bit masks used to control the visibility of the entry after filtering. */
enum kshark_filter_masks {
	/**
	 * Use this mask to check the visibility of the entry in the text
	 * view.
	 */
	KS_TEXT_VIEW_FILTER_MASK	= 1 << 0,

	/**
	 * Use this mask to check the visibility of the entry in the graph
	 * view.
	 */
	KS_GRAPH_VIEW_FILTER_MASK	= 1 << 1,

	/** Special mask used whene filtering events. */
	KS_EVENT_VIEW_FILTER_MASK	= 1 << 2,
};

/** Filter type identifier. */
enum kshark_filter_type {
	/** Dummy filter identifier reserved for future use. */
	KS_NO_FILTER,

	/**
	 * Identifier of the filter, used to specified the events to be shown.
	 */
	KS_SHOW_EVENT_FILTER,

	/**
	 * Identifier of the filter, used to specified the events to be
	 * filtered-out.
	 */
	KS_HIDE_EVENT_FILTER,

	/**
	 * Identifier of the filter, used to specified the tasks to be shown.
	 */
	KS_SHOW_TASK_FILTER,

	/**
	 * Identifier of the filter, used to specified the tasks to be
	 * filtered-out.
	 */
	KS_HIDE_TASK_FILTER,
};

void kshark_filter_add_id(struct kshark_context *kshark_ctx,
			  int filter_id, int id);

void kshark_filter_clear(struct kshark_context *kshark_ctx, int filter_id);

void kshark_filter_entries(struct kshark_context *kshark_ctx,
			   struct kshark_entry **data,
			   size_t n_entries);

#ifdef __cplusplus
}
#endif

#endif // _LIB_KSHARK_H
