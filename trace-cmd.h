/*
 * Copyright (C) 2008, 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#ifndef _TRACE_CMD_H
#define _TRACE_CMD_H

#include <stdlib.h>
#include "parse-events.h"

void parse_cmdlines(struct pevent *pevent, char *file, int size);
void parse_proc_kallsyms(struct pevent *pevent, char *file, unsigned int size);
void parse_ftrace_printk(struct pevent *pevent, char *file, unsigned int size);

extern int tracecmd_disable_sys_plugins;
extern int tracecmd_disable_plugins;

struct plugin_list;
struct plugin_list *tracecmd_load_plugins(struct pevent *pevent);
void tracecmd_unload_plugins(struct plugin_list *list);

enum {
	RINGBUF_TYPE_PADDING		= 29,
	RINGBUF_TYPE_TIME_EXTEND	= 30,
	RINGBUF_TYPE_TIME_STAMP		= 31,
};

#ifndef TS_SHIFT
#define TS_SHIFT		27
#endif

void free_record(struct record *record);

struct tracecmd_input;
struct tracecmd_output;
struct tracecmd_recorder;

static inline int tracecmd_host_bigendian(void)
{
	unsigned char str[] = { 0x1, 0x2, 0x3, 0x4 };
	unsigned int *ptr;

	ptr = (unsigned int *)str;
	return *ptr == 0x01020304;
}

char *tracecmd_find_tracing_dir(void);

/* --- Opening and Reading the trace.dat file --- */

enum {
	TRACECMD_OPTION_DONE,
};

struct tracecmd_input *tracecmd_alloc(const char *file);
struct tracecmd_input *tracecmd_alloc_fd(int fd);
struct tracecmd_input *tracecmd_open(const char *file);
struct tracecmd_input *tracecmd_open_fd(int fd);
void tracecmd_ref(struct tracecmd_input *handle);
void tracecmd_close(struct tracecmd_input *handle);
int tracecmd_read_headers(struct tracecmd_input *handle);
int tracecmd_long_size(struct tracecmd_input *handle);
int tracecmd_page_size(struct tracecmd_input *handle);
int tracecmd_cpus(struct tracecmd_input *handle);
int tracecmd_copy_headers(struct tracecmd_input *handle, int fd);

void tracecmd_print_events(struct tracecmd_input *handle);

int tracecmd_init_data(struct tracecmd_input *handle);

struct record *
tracecmd_peek_data(struct tracecmd_input *handle, int cpu);

struct record *
tracecmd_read_data(struct tracecmd_input *handle, int cpu);

struct record *
tracecmd_read_prev(struct tracecmd_input *handle, struct record *record);

struct record *
tracecmd_read_next_data(struct tracecmd_input *handle, int *rec_cpu);

struct record *
tracecmd_read_at(struct tracecmd_input *handle, unsigned long long offset,
		 int *cpu);
struct record *
tracecmd_translate_data(struct tracecmd_input *handle,
			void *ptr, int size);
struct record *
tracecmd_read_cpu_first(struct tracecmd_input *handle, int cpu);
struct record *
tracecmd_read_cpu_last(struct tracecmd_input *handle, int cpu);
int tracecmd_refresh_record(struct tracecmd_input *handle,
			    struct record *record);

int tracecmd_set_cpu_to_timestamp(struct tracecmd_input *handle,
				  int cpu, unsigned long long ts);
void
tracecmd_set_all_cpus_to_timestamp(struct tracecmd_input *handle,
				   unsigned long long time);

int tracecmd_set_cursor(struct tracecmd_input *handle,
			int cpu, unsigned long long offset);
unsigned long long
tracecmd_get_cursor(struct tracecmd_input *handle, int cpu);

int tracecmd_ftrace_overrides(struct tracecmd_input *handle);
struct pevent *tracecmd_get_pevent(struct tracecmd_input *handle);

#ifndef SWIG
/* hack for function graph work around */
extern __thread struct tracecmd_input *tracecmd_curr_thread_handle;
#endif


/* --- Creating and Writing the trace.dat file --- */

struct tracecmd_output *tracecmd_create_file_latency(const char *output_file, int cpus);
struct tracecmd_output *tracecmd_create_file(const char *output_file,
					     int cpus, char * const *cpu_data_files);
struct tracecmd_output *tracecmd_create_init_fd(int fd, int cpus);
void tracecmd_output_close(struct tracecmd_output *handle);
struct tracecmd_output *tracecmd_copy(struct tracecmd_input *ihandle,
				      const char *file);
int tracecmd_append_cpu_data(struct tracecmd_output *handle,
			     int cpus, char * const *cpu_data_files);
int tracecmd_attach_cpu_data(char *file, int cpus, char * const *cpu_data_files);
int tracecmd_attach_cpu_data_fd(int fd, int cpus, char * const *cpu_data_files);

/* --- Reading the Fly Recorder Trace --- */

void tracecmd_free_recorder(struct tracecmd_recorder *recorder);
struct tracecmd_recorder *tracecmd_create_recorder(const char *file, int cpu);
struct tracecmd_recorder *tracecmd_create_recorder_fd(int fd, int cpu);
int tracecmd_start_recording(struct tracecmd_recorder *recorder, unsigned long sleep);
void tracecmd_stop_recording(struct tracecmd_recorder *recorder);
void tracecmd_stat_cpu(struct trace_seq *s, int cpu);


#endif /* _TRACE_CMD_H */
