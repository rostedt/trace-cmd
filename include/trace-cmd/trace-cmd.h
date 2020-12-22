/* SPDX-License-Identifier: LGPL-2.1 */
/*
 * Copyright (C) 2008, 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#ifndef _TRACE_CMD_H
#define _TRACE_CMD_H

#include "traceevent/event-parse.h"
#include "tracefs/tracefs.h"

struct tracecmd_input;

struct tracecmd_input *tracecmd_open_head(const char *file);
void tracecmd_close(struct tracecmd_input *handle);
int tracecmd_pair_peer(struct tracecmd_input *handle,
		       struct tracecmd_input *peer);

int tracecmd_init_data(struct tracecmd_input *handle);
struct tep_record *
tracecmd_read_cpu_first(struct tracecmd_input *handle, int cpu);
struct tep_record *
tracecmd_read_data(struct tracecmd_input *handle, int cpu);
struct tep_record *
tracecmd_read_at(struct tracecmd_input *handle, unsigned long long offset,
		 int *cpu);
void tracecmd_free_record(struct tep_record *record);

struct tep_handle *tracecmd_get_pevent(struct tracecmd_input *handle);
unsigned long long tracecmd_get_traceid(struct tracecmd_input *handle);
int tracecmd_get_guest_cpumap(struct tracecmd_input *handle,
			      unsigned long long trace_id,
			      const char **name,
			      int *vcpu_count, const int **cpu_pid);
int tracecmd_buffer_instances(struct tracecmd_input *handle);
const char *tracecmd_buffer_instance_name(struct tracecmd_input *handle, int indx);
struct tracecmd_input *tracecmd_buffer_instance_handle(struct tracecmd_input *handle, int indx);

#endif /* _TRACE_CMD_H */
