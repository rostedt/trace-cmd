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
 * License along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#ifndef _TRACE_CMD_H
#define _TRACE_CMD_H

#include <stdlib.h>
#include "event-utils.h"
#include "event-parse.h"

#define TRACECMD_ERR_MSK	((unsigned long)(-1) & ~((1UL << 14) - 1))
#define TRACECMD_ISERR(ptr)	((unsigned long)(ptr) > TRACECMD_ERR_MSK)
#define TRACECMD_ERROR(ret)	((void *)((unsigned long)(ret) | TRACECMD_ERR_MSK))
#define TRACECMD_PTR2ERR(ptr)	((unisgned long)(ptr) & ~TRACECMD_ERR_MSK)

void parse_cmdlines(struct pevent *pevent, char *file, int size);
void parse_proc_kallsyms(struct pevent *pevent, char *file, unsigned int size);
void parse_ftrace_printk(struct pevent *pevent, char *file, unsigned int size);

extern int tracecmd_disable_sys_plugins;
extern int tracecmd_disable_plugins;

struct plugin_list;
struct plugin_list *tracecmd_load_plugins(struct pevent *pevent);
void tracecmd_unload_plugins(struct plugin_list *list);

char **tracecmd_event_systems(const char *tracing_dir);
char **tracecmd_system_events(const char *tracing_dir, const char *system);
struct pevent *tracecmd_local_events(const char *tracing_dir);
int tracecmd_fill_local_events(const char *tracing_dir, struct pevent *pevent);
char **tracecmd_local_plugins(const char *tracing_dir);

char **tracecmd_add_list(char **list, const char *name, int len);
void tracecmd_free_list(char **list);
int *tracecmd_add_id(int *list, int id, int len);

enum {
	RINGBUF_TYPE_PADDING		= 29,
	RINGBUF_TYPE_TIME_EXTEND	= 30,
	RINGBUF_TYPE_TIME_STAMP		= 31,
};

void tracecmd_record_ref(struct pevent_record *record);
void free_record(struct pevent_record *record);

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
	TRACECMD_OPTION_DATE,
	TRACECMD_OPTION_CPUSTAT,
};

enum {
	TRACECMD_FL_IGNORE_DATE		= 1,
};

struct tracecmd_ftrace {
	struct tracecmd_input		*handle;
	struct event_format *fgraph_ret_event;
	int fgraph_ret_id;
	int long_size;
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
void tracecmd_set_flag(struct tracecmd_input *handle, int flag);
void tracecmd_clear_flag(struct tracecmd_input *handle, int flag);

void tracecmd_print_events(struct tracecmd_input *handle);

int tracecmd_init_data(struct tracecmd_input *handle);

void tracecmd_print_stats(struct tracecmd_input *handle);

struct pevent_record *
tracecmd_read_page_record(struct pevent *pevent, void *page, int size,
			  struct pevent_record *last_record);
struct pevent_record *
tracecmd_peek_data(struct tracecmd_input *handle, int cpu);

static inline struct pevent_record *
tracecmd_peek_data_ref(struct tracecmd_input *handle, int cpu)
{
	struct pevent_record *rec = tracecmd_peek_data(handle, cpu);
	if (rec)
		rec->ref_count++;
	return rec;
}

struct pevent_record *
tracecmd_read_data(struct tracecmd_input *handle, int cpu);

struct pevent_record *
tracecmd_read_prev(struct tracecmd_input *handle, struct pevent_record *record);

struct pevent_record *
tracecmd_read_next_data(struct tracecmd_input *handle, int *rec_cpu);

struct pevent_record *
tracecmd_read_at(struct tracecmd_input *handle, unsigned long long offset,
		 int *cpu);
struct pevent_record *
tracecmd_translate_data(struct tracecmd_input *handle,
			void *ptr, int size);
struct pevent_record *
tracecmd_read_cpu_first(struct tracecmd_input *handle, int cpu);
struct pevent_record *
tracecmd_read_cpu_last(struct tracecmd_input *handle, int cpu);
int tracecmd_refresh_record(struct tracecmd_input *handle,
			    struct pevent_record *record);

int tracecmd_set_cpu_to_timestamp(struct tracecmd_input *handle,
				  int cpu, unsigned long long ts);
void
tracecmd_set_all_cpus_to_timestamp(struct tracecmd_input *handle,
				   unsigned long long time);

int tracecmd_set_cursor(struct tracecmd_input *handle,
			int cpu, unsigned long long offset);
unsigned long long
tracecmd_get_cursor(struct tracecmd_input *handle, int cpu);

int tracecmd_ftrace_overrides(struct tracecmd_input *handle, struct tracecmd_ftrace *finfo);
struct pevent *tracecmd_get_pevent(struct tracecmd_input *handle);

char *tracecmd_get_tracing_file(const char *name);
void tracecmd_put_tracing_file(char *name);

#ifndef SWIG
/* hack for function graph work around */
extern __thread struct tracecmd_input *tracecmd_curr_thread_handle;
#endif


/* --- Creating and Writing the trace.dat file --- */

struct tracecmd_event_list {
	struct tracecmd_event_list	*next;
	const char			*glob;
};

struct tracecmd_output *tracecmd_create_file_latency(const char *output_file, int cpus);
struct tracecmd_output *tracecmd_create_file(const char *output_file,
					     int cpus, char * const *cpu_data_files);
struct tracecmd_output *
tracecmd_create_file_glob(const char *output_file,
			  int cpus, char * const *cpu_data_files,
			  struct tracecmd_event_list *event_globs);
struct tracecmd_output *
tracecmd_create_init_file_glob(const char *output_file,
			       struct tracecmd_event_list *list);
struct tracecmd_output *tracecmd_create_init_fd(int fd);
struct tracecmd_output *
tracecmd_create_init_fd_glob(int fd, struct tracecmd_event_list *list);
struct tracecmd_output *tracecmd_create_init_file(const char *output_file);
struct tracecmd_output *tracecmd_create_init_file_override(const char *output_file,
							   const char *tracing_dir,
							   const char *kallsyms);
int tracecmd_add_option(struct tracecmd_output *handle,
			unsigned short id,
			int size, void *data);
void tracecmd_output_close(struct tracecmd_output *handle);
struct tracecmd_output *tracecmd_copy(struct tracecmd_input *ihandle,
				      const char *file);
int tracecmd_append_cpu_data(struct tracecmd_output *handle,
			     int cpus, char * const *cpu_data_files);
int tracecmd_attach_cpu_data(char *file, int cpus, char * const *cpu_data_files);
int tracecmd_attach_cpu_data_fd(int fd, int cpus, char * const *cpu_data_files);

/* --- Reading the Fly Recorder Trace --- */

enum {
	TRACECMD_RECORD_NOSPLICE	= (1 << 0),	/* Use read instead of splice */
};

void tracecmd_free_recorder(struct tracecmd_recorder *recorder);
struct tracecmd_recorder *tracecmd_create_recorder(const char *file, int cpu, unsigned flags);
struct tracecmd_recorder *tracecmd_create_recorder_fd(int fd, int cpu, unsigned flags);
int tracecmd_start_recording(struct tracecmd_recorder *recorder, unsigned long sleep);
void tracecmd_stop_recording(struct tracecmd_recorder *recorder);
void tracecmd_stat_cpu(struct trace_seq *s, int cpu);
long tracecmd_flush_recording(struct tracecmd_recorder *recorder);

/* --- Plugin handling --- */
extern struct plugin_option trace_ftrace_options[];

void trace_util_add_options(const char *name, struct plugin_option *options);
void trace_util_remove_options(struct plugin_option *options);
void trace_util_add_option(const char *name, const char *val);
void trace_util_load_plugins(struct pevent *pevent, const char *suffix,
			     void (*load_plugin)(struct pevent *pevent,
						 const char *path,
						 const char *name,
						 void *data),
			     void *data);
struct plugin_option *trace_util_read_plugin_options(void);
void trace_util_free_options(struct plugin_option *options);
char **trace_util_find_plugin_files(const char *suffix);
void trace_util_free_plugin_files(char **files);
void trace_util_print_plugins(struct trace_seq *s, const char *prefix, const char *suffix,
			      const struct plugin_list *list);
void trace_util_print_plugin_options(struct trace_seq *s);
char **trace_util_list_plugin_options(void);
void trace_util_free_plugin_options_list(char **list);
const char *trace_util_plugin_option_value(const char *name);

/* Used for trace-cmd list */
void tracecmd_ftrace_load_options(void);

/* --- Hack! --- */
int tracecmd_blk_hack(struct tracecmd_input *handle);

#endif /* _TRACE_CMD_H */
