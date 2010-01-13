#ifndef _TRACE_CMD_H
#define _TRACE_CMD_H

#include <stdlib.h>
#include "parse-events.h"

void parse_cmdlines(struct pevent *pevent, char *file, int size);
void parse_proc_kallsyms(struct pevent *pevent, char *file, unsigned int size);
void parse_ftrace_printk(char *file, unsigned int size);

int trace_load_plugins(struct pevent *pevent);

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

void tracecmd_print_events(struct tracecmd_input *handle);

int tracecmd_init_data(struct tracecmd_input *handle);

struct record *
tracecmd_peek_data(struct tracecmd_input *handle, int cpu);

struct record *
tracecmd_read_data(struct tracecmd_input *handle, int cpu);

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
void tracecmd_output_close(struct tracecmd_output *handle);

/* --- Reading the Fly Recorder Trace --- */

void tracecmd_free_recorder(struct tracecmd_recorder *recorder);
struct tracecmd_recorder *tracecmd_create_recorder(const char *file, int cpu);
int tracecmd_start_recording(struct tracecmd_recorder *recorder, unsigned long sleep);
void tracecmd_stop_recording(struct tracecmd_recorder *recorder);
void tracecmd_stat_cpu(struct trace_seq *s, int cpu);


#endif /* _TRACE_CMD_H */
