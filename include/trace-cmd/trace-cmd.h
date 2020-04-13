/* SPDX-License-Identifier: LGPL-2.1 */
/*
 * Copyright (C) 2008, 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#ifndef _TRACE_CMD_H
#define _TRACE_CMD_H

#include "traceevent/event-parse.h"

#define TRACECMD_MAGIC { 23, 8, 68 }

#define ARRAY_SIZE(_a) (sizeof(_a) / sizeof((_a)[0]))
#define __weak __attribute__((weak))
#define __noreturn __attribute__((noreturn))

#define TRACECMD_ERR_MSK	((unsigned long)(-1) & ~((1UL << 14) - 1))
#define TRACECMD_ISERR(ptr)	((unsigned long)(ptr) > TRACECMD_ERR_MSK)
#define TRACECMD_ERROR(ret)	((void *)((unsigned long)(ret) | TRACECMD_ERR_MSK))
#define TRACECMD_PTR2ERR(ptr)	((unisgned long)(ptr) & ~TRACECMD_ERR_MSK)

void tracecmd_parse_cmdlines(struct tep_handle *pevent, char *file, int size);
void tracecmd_parse_proc_kallsyms(struct tep_handle *pevent, char *file, unsigned int size);
void tracecmd_parse_ftrace_printk(struct tep_handle *pevent, char *file, unsigned int size);
struct tep_plugin_list *trace_load_plugins(struct tep_handle *tep);

int *tracecmd_add_id(int *list, int id, int len);

enum {
	RINGBUF_TYPE_PADDING		= 29,
	RINGBUF_TYPE_TIME_EXTEND	= 30,
	RINGBUF_TYPE_TIME_STAMP		= 31,
};

void tracecmd_record_ref(struct tep_record *record);
void free_record(struct tep_record *record);

void tracecmd_set_debug(bool set_debug);
bool tracecmd_get_debug(void);

struct tracecmd_input;
struct tracecmd_output;
struct tracecmd_recorder;
struct hook_list;

/* --- tracecmd plugins --- */

extern int tracecmd_disable_sys_plugins;
extern int tracecmd_disable_plugins;

enum tracecmd_context {
	TRACECMD_INPUT,
	TRACECMD_OUTPUT,
};

enum tracecmd_plugin_flag {
	TRACECMD_DISABLE_SYS_PLUGINS	= 1,
	TRACECMD_DISABLE_PLUGINS	= 1 << 1,
};

struct trace_plugin_context;

struct trace_plugin_context *
tracecmd_plugin_context_create(enum tracecmd_context context, void *data);

void tracecmd_plugin_set_flag(struct trace_plugin_context *context,
			      enum tracecmd_plugin_flag flag);

#define TRACECMD_PLUGIN_LOADER tracecmd_plugin_loader
#define TRACECMD_PLUGIN_UNLOADER tracecmd_plugin_unloader
#define TRACECMD_PLUGIN_ALIAS tracecmd_plugin_alias
#define _MAKE_STR(x)	#x
#define MAKE_STR(x)	_MAKE_STR(x)
#define TRACECMD_PLUGIN_LOADER_NAME MAKE_STR(TRACECMD_PLUGIN_LOADER)
#define TRACECMD_PLUGIN_UNLOADER_NAME MAKE_STR(TRACECMD_PLUGIN_UNLOADER)
#define TRACECMD_PLUGIN_ALIAS_NAME MAKE_STR(TRACECMD_PLUGIN_ALIAS)

typedef int (*tracecmd_plugin_load_func)(struct trace_plugin_context *trace);
typedef int (*tracecmd_plugin_unload_func)(struct trace_plugin_context *trace);

struct tracecmd_input *
tracecmd_plugin_context_input(struct trace_plugin_context *trace_context);
struct tracecmd_output *
tracecmd_plugin_context_output(struct trace_plugin_context *trace_context);

void tracecmd_set_quiet(struct tracecmd_output *handle, bool set_quiet);
bool tracecmd_get_quiet(struct tracecmd_output *handle);

static inline int tracecmd_host_bigendian(void)
{
	unsigned char str[] = { 0x1, 0x2, 0x3, 0x4 };
	unsigned int *ptr;

	ptr = (unsigned int *)str;
	return *ptr == 0x01020304;
}

/* --- Opening and Reading the trace.dat file --- */

enum {
	TRACECMD_OPTION_DONE,
	TRACECMD_OPTION_DATE,
	TRACECMD_OPTION_CPUSTAT,
	TRACECMD_OPTION_BUFFER,
	TRACECMD_OPTION_TRACECLOCK,
	TRACECMD_OPTION_UNAME,
	TRACECMD_OPTION_HOOK,
	TRACECMD_OPTION_OFFSET,
	TRACECMD_OPTION_CPUCOUNT,
	TRACECMD_OPTION_VERSION,
	TRACECMD_OPTION_PROCMAPS,
	TRACECMD_OPTION_TRACEID,
	TRACECMD_OPTION_TIME_SHIFT,
	TRACECMD_OPTION_GUEST,
};

enum {
	TRACECMD_FL_IGNORE_DATE		= (1 << 0),
	TRACECMD_FL_BUFFER_INSTANCE	= (1 << 1),
	TRACECMD_FL_LATENCY		= (1 << 2),
	TRACECMD_FL_IN_USECS		= (1 << 3),
	TRACECMD_FL_FLYRECORD		= (1 << 4),
};

struct tracecmd_ftrace {
	struct tracecmd_input		*handle;
	struct tep_event *fgraph_ret_event;
	int fgraph_ret_id;
	int long_size;
};

struct tracecmd_proc_addr_map {
	unsigned long long	start;
	unsigned long long	end;
	char			*lib_name;
};

typedef void (*tracecmd_show_data_func)(struct tracecmd_input *handle,
					struct tep_record *record);
typedef void (*tracecmd_handle_init_func)(struct tracecmd_input *handle,
					  struct hook_list *hook, int global);

struct tracecmd_input *tracecmd_alloc(const char *file);
struct tracecmd_input *tracecmd_alloc_fd(int fd);
struct tracecmd_input *tracecmd_open(const char *file);
struct tracecmd_input *tracecmd_open_head(const char *file);
struct tracecmd_input *tracecmd_open_fd(int fd);
int tracecmd_pair_peer(struct tracecmd_input *handle,
		       struct tracecmd_input *peer);
void tracecmd_unpair_peer(struct tracecmd_input *handle);
void tracecmd_ref(struct tracecmd_input *handle);
void tracecmd_close(struct tracecmd_input *handle);
int tracecmd_read_headers(struct tracecmd_input *handle);
int tracecmd_get_parsing_failures(struct tracecmd_input *handle);
int tracecmd_long_size(struct tracecmd_input *handle);
int tracecmd_page_size(struct tracecmd_input *handle);
int tracecmd_cpus(struct tracecmd_input *handle);
int tracecmd_copy_headers(struct tracecmd_input *handle, int fd);
void tracecmd_set_flag(struct tracecmd_input *handle, int flag);
void tracecmd_clear_flag(struct tracecmd_input *handle, int flag);
unsigned long tracecmd_get_flags(struct tracecmd_input *handle);
unsigned long long tracecmd_get_traceid(struct tracecmd_input *handle);
int tracecmd_get_guest_cpumap(struct tracecmd_input *handle,
			      unsigned long long trace_id,
			      const char **name,
			      int *vcpu_count, const int **cpu_pid);
unsigned long long tracecmd_get_tsync_peer(struct tracecmd_input *handle);
int tracecmd_enable_tsync(struct tracecmd_input *handle, bool enable);

void tracecmd_parse_trace_clock(struct tracecmd_input *handle, char *file, int size);

int tracecmd_make_pipe(struct tracecmd_input *handle, int cpu, int fd, int cpus);

int tracecmd_buffer_instances(struct tracecmd_input *handle);
const char *tracecmd_buffer_instance_name(struct tracecmd_input *handle, int indx);
struct tracecmd_input *tracecmd_buffer_instance_handle(struct tracecmd_input *handle, int indx);
int tracecmd_is_buffer_instance(struct tracecmd_input *handle);

void tracecmd_set_ts_offset(struct tracecmd_input *handle, long long offset);
void tracecmd_set_ts2secs(struct tracecmd_input *handle, unsigned long long hz);

void tracecmd_print_events(struct tracecmd_input *handle, const char *regex);

struct hook_list *tracecmd_hooks(struct tracecmd_input *handle);

int tracecmd_init_data(struct tracecmd_input *handle);

void tracecmd_print_stats(struct tracecmd_input *handle);
void tracecmd_print_uname(struct tracecmd_input *handle);
void tracecmd_print_version(struct tracecmd_input *handle);

struct tep_record *
tracecmd_peek_data(struct tracecmd_input *handle, int cpu);

static inline struct tep_record *
tracecmd_peek_data_ref(struct tracecmd_input *handle, int cpu)
{
	struct tep_record *rec = tracecmd_peek_data(handle, cpu);
	if (rec)
		rec->ref_count++;
	return rec;
}

struct tep_record *
tracecmd_read_data(struct tracecmd_input *handle, int cpu);

struct tep_record *
tracecmd_read_prev(struct tracecmd_input *handle, struct tep_record *record);

struct tep_record *
tracecmd_read_next_data(struct tracecmd_input *handle, int *rec_cpu);

struct tep_record *
tracecmd_peek_next_data(struct tracecmd_input *handle, int *rec_cpu);

struct tep_record *
tracecmd_read_at(struct tracecmd_input *handle, unsigned long long offset,
		 int *cpu);
struct tep_record *
tracecmd_translate_data(struct tracecmd_input *handle,
			void *ptr, int size);
struct tep_record *
tracecmd_read_cpu_first(struct tracecmd_input *handle, int cpu);
struct tep_record *
tracecmd_read_cpu_last(struct tracecmd_input *handle, int cpu);
int tracecmd_refresh_record(struct tracecmd_input *handle,
			    struct tep_record *record);

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
struct tep_handle *tracecmd_get_pevent(struct tracecmd_input *handle);
bool tracecmd_get_use_trace_clock(struct tracecmd_input *handle);
tracecmd_show_data_func
tracecmd_get_show_data_func(struct tracecmd_input *handle);
void tracecmd_set_show_data_func(struct tracecmd_input *handle,
				 tracecmd_show_data_func func);

int tracecmd_record_at_buffer_start(struct tracecmd_input *handle, struct tep_record *record);
unsigned long long tracecmd_page_ts(struct tracecmd_input *handle,
				    struct tep_record *record);
unsigned int tracecmd_record_ts_delta(struct tracecmd_input *handle,
				      struct tep_record *record);

struct tracecmd_proc_addr_map *
tracecmd_search_task_map(struct tracecmd_input *handle,
			 int pid, unsigned long long addr);
#ifndef SWIG
/* hack for function graph work around */
extern __thread struct tracecmd_input *tracecmd_curr_thread_handle;
#endif


/* --- Creating and Writing the trace.dat file --- */

struct tracecmd_event_list {
	struct tracecmd_event_list	*next;
	const char			*glob;
};

struct tracecmd_option;
struct tracecmd_msg_handle;

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
struct tracecmd_output *
tracecmd_create_init_fd_msg(struct tracecmd_msg_handle *msg_handle,
			    struct tracecmd_event_list *list);
struct tracecmd_output *tracecmd_create_init_file(const char *output_file);
struct tracecmd_output *tracecmd_create_init_file_override(const char *output_file,
							   const char *tracing_dir,
							   const char *kallsyms);
struct tracecmd_option *tracecmd_add_option(struct tracecmd_output *handle,
					    unsigned short id, int size,
					    const void *data);
struct tracecmd_option *
tracecmd_add_option_v(struct tracecmd_output *handle,
		      unsigned short id, const struct iovec *vector, int count);

struct tracecmd_option *tracecmd_add_buffer_option(struct tracecmd_output *handle,
						   const char *name, int cpus);

int tracecmd_write_cpus(struct tracecmd_output *handle, int cpus);
int tracecmd_write_options(struct tracecmd_output *handle);
int tracecmd_append_options(struct tracecmd_output *handle);
int tracecmd_update_option(struct tracecmd_output *handle,
			   struct tracecmd_option *option, int size,
			   const void *data);
void tracecmd_output_close(struct tracecmd_output *handle);
void tracecmd_output_free(struct tracecmd_output *handle);
struct tracecmd_output *tracecmd_copy(struct tracecmd_input *ihandle,
				      const char *file);

int tracecmd_write_cpu_data(struct tracecmd_output *handle,
			    int cpus, char * const *cpu_data_files);
int tracecmd_append_cpu_data(struct tracecmd_output *handle,
			     int cpus, char * const *cpu_data_files);
int tracecmd_append_buffer_cpu_data(struct tracecmd_output *handle,
				    struct tracecmd_option *option,
				    int cpus, char * const *cpu_data_files);

struct tracecmd_output *tracecmd_get_output_handle_fd(int fd);

/* --- Reading the Fly Recorder Trace --- */

enum {
	TRACECMD_RECORD_NOSPLICE	= (1 << 0),	/* Use read instead of splice */
	TRACECMD_RECORD_SNAPSHOT	= (1 << 1),	/* Extract from snapshot */
	TRACECMD_RECORD_BLOCK		= (1 << 2),	/* Block on splice write */
	TRACECMD_RECORD_NOBRASS		= (1 << 3),	/* Splice directly without a brass pipe */
};

void tracecmd_free_recorder(struct tracecmd_recorder *recorder);
struct tracecmd_recorder *tracecmd_create_recorder(const char *file, int cpu, unsigned flags);
struct tracecmd_recorder *tracecmd_create_recorder_fd(int fd, int cpu, unsigned flags);
struct tracecmd_recorder *tracecmd_create_recorder_virt(const char *file, int cpu, unsigned flags, int trace_fd);
struct tracecmd_recorder *tracecmd_create_recorder_maxkb(const char *file, int cpu, unsigned flags, int maxkb);
struct tracecmd_recorder *tracecmd_create_buffer_recorder_fd(int fd, int cpu, unsigned flags, const char *buffer);
struct tracecmd_recorder *tracecmd_create_buffer_recorder(const char *file, int cpu, unsigned flags, const char *buffer);
struct tracecmd_recorder *tracecmd_create_buffer_recorder_maxkb(const char *file, int cpu, unsigned flags, const char *buffer, int maxkb);

int tracecmd_start_recording(struct tracecmd_recorder *recorder, unsigned long sleep);
void tracecmd_stop_recording(struct tracecmd_recorder *recorder);
long tracecmd_flush_recording(struct tracecmd_recorder *recorder);

enum tracecmd_msg_flags {
	TRACECMD_MSG_FL_USE_TCP		= 1 << 0,
};

/* for both client and server */
struct tracecmd_msg_handle {
	int			fd;
	short			cpu_count;
	short			version;	/* Current protocol version */
	unsigned long		flags;
	bool			done;
};

struct tracecmd_msg_handle *
  tracecmd_msg_handle_alloc(int fd, unsigned long flags);

/* Closes the socket and frees the handle */
void tracecmd_msg_handle_close(struct tracecmd_msg_handle *msg_handle);

/* for clients */
int tracecmd_msg_send_init_data(struct tracecmd_msg_handle *msg_handle,
				unsigned int **client_ports);
int tracecmd_msg_data_send(struct tracecmd_msg_handle *msg_handle,
			       const char *buf, int size);
int tracecmd_msg_finish_sending_data(struct tracecmd_msg_handle *msg_handle);
int tracecmd_msg_send_close_msg(struct tracecmd_msg_handle *msg_handle);
int tracecmd_msg_send_close_resp_msg(struct tracecmd_msg_handle *msg_handle);
int tracecmd_msg_wait_close(struct tracecmd_msg_handle *msg_handle);
int tracecmd_msg_wait_close_resp(struct tracecmd_msg_handle *msg_handle);

/* for server */
int tracecmd_msg_initial_setting(struct tracecmd_msg_handle *msg_handle);
int tracecmd_msg_send_port_array(struct tracecmd_msg_handle *msg_handle,
				 unsigned *ports);
int tracecmd_msg_read_data(struct tracecmd_msg_handle *msg_handle, int ofd);
int tracecmd_msg_collect_data(struct tracecmd_msg_handle *msg_handle, int ofd);
bool tracecmd_msg_done(struct tracecmd_msg_handle *msg_handle);
void tracecmd_msg_set_done(struct tracecmd_msg_handle *msg_handle);

int tracecmd_msg_send_trace_req(struct tracecmd_msg_handle *msg_handle,
				int argc, char **argv, bool use_fifos,
				unsigned long long trace_id,
				char *tsync_protos,
				int tsync_protos_size);
int tracecmd_msg_recv_trace_req(struct tracecmd_msg_handle *msg_handle,
				int *argc, char ***argv, bool *use_fifos,
				unsigned long long *trace_id,
				char **tsync_protos,
				unsigned int *tsync_protos_size);

int tracecmd_msg_send_trace_resp(struct tracecmd_msg_handle *msg_handle,
				 int nr_cpus, int page_size,
				 unsigned int *ports, bool use_fifos,
				 unsigned long long trace_id,
				 unsigned int tsync_proto,
				 unsigned int tsync_port);
int tracecmd_msg_recv_trace_resp(struct tracecmd_msg_handle *msg_handle,
				 int *nr_cpus, int *page_size,
				 unsigned int **ports, bool *use_fifos,
				 unsigned long long *trace_id,
				 unsigned int *tsync_proto,
				 unsigned int *tsync_port);

int tracecmd_msg_send_time_sync(struct tracecmd_msg_handle *msg_handle,
				unsigned int sync_protocol,
				unsigned int sync_msg_id,
				unsigned int payload_size, char *payload);
int tracecmd_msg_recv_time_sync(struct tracecmd_msg_handle *msg_handle,
				unsigned int *sync_protocol,
				unsigned int *sync_msg_id,
				unsigned int *payload_size, char **payload);

/* --- Timestamp synchronization --- */

enum{
	TRACECMD_TIME_SYNC_PROTO_NONE	= 0,
};
enum{
	TRACECMD_TIME_SYNC_CMD_PROBE	= 1,
	TRACECMD_TIME_SYNC_CMD_STOP	= 2,
};

#define TRACECMD_TIME_SYNC_PROTO_PTP_WEIGHT	10

struct tracecmd_time_sync {
	unsigned int			sync_proto;
	int				loop_interval;
	pthread_mutex_t			lock;
	pthread_cond_t			cond;
	char				*clock_str;
	struct tracecmd_msg_handle	*msg_handle;
	void				*context;
};

void tracecmd_tsync_init(void);
int tracecmd_tsync_proto_getall(char **proto_mask, int *words);
unsigned int tracecmd_tsync_proto_select(char *proto_mask, int words);
bool tsync_proto_is_supported(unsigned int proto_id);
void tracecmd_tsync_with_host(struct tracecmd_time_sync *tsync);
void tracecmd_tsync_with_guest(struct tracecmd_time_sync *tsync);
int tracecmd_tsync_get_offsets(struct tracecmd_time_sync *tsync,
				int *count,
				long long **ts, long long **offsets);
void tracecmd_tsync_free(struct tracecmd_time_sync *tsync);

/* --- Plugin handling --- */
extern struct tep_plugin_option trace_ftrace_options[];

char **trace_util_find_plugin_files(const char *suffix);
void trace_util_free_plugin_files(char **files);

/* Used for trace-cmd list */
void tracecmd_ftrace_load_options(void);

/* event hooks */

struct hook_list {
	struct hook_list	*next;
	struct buffer_instance	*instance;
	const char		*hook;
	char			*str;
	char			*start_system;
	char			*start_event;
	char			*start_match;
	char			*end_system;
	char			*end_event;
	char			*end_match;
	char			*pid;
	int			migrate;
	int			global;
	int			stack;
};

struct hook_list *tracecmd_create_event_hook(const char *arg);
void tracecmd_free_hooks(struct hook_list *hooks);

void tracecmd_plog(const char *fmt, ...);
void tracecmd_plog_error(const char *fmt, ...);
int tracecmd_set_logfile(char *logfile);

/* --- System --- */
unsigned long long tracecmd_generate_traceid(void);
int tracecmd_count_cpus(void);

/* --- Hack! --- */
int tracecmd_blk_hack(struct tracecmd_input *handle);

/* --- Stack tracer functions --- */
int tracecmd_stack_tracer_status(int *status);

/* --- Debugging --- */
struct kbuffer *tracecmd_record_kbuf(struct tracecmd_input *handle,
				     struct tep_record *record);
void *tracecmd_record_page(struct tracecmd_input *handle,
			   struct tep_record *record);
void *tracecmd_record_offset(struct tracecmd_input *handle,
			     struct tep_record *record);

#endif /* _TRACE_CMD_H */
