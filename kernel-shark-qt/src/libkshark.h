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
#include "event-parse.h"
#include "trace-filter-hash.h"

/**
 * Kernel Shark entry contains all information from one trace record needed
 * in order to  visualize the time-series of trace records. The part of the
 * data which is not directly required for the visualization (latency, record
 * info etc.) is available on-demand via the offset into the trace file.
 */
struct kshark_entry {
	/**
	 * A bit mask controlling the visibility of the entry. A value of OxFF
	 * would mean that the entry is visible everywhere.
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

	/** Pointer to the next (in time) kshark_entry on the same CPU core. */
	struct kshark_entry *next;
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

#ifdef __cplusplus
}
#endif

#endif // _LIB_KSHARK_H
