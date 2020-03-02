// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2008, 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#ifndef NO_PTRACE
#include <sys/ptrace.h>
#else
#ifdef WARN_NO_PTRACE
#warning ptrace not supported. -c feature will not work
#endif
#endif
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <sched.h>
#include <glob.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <pwd.h>
#include <grp.h>
#ifdef VSOCK
#include <linux/vm_sockets.h>
#endif

#include "tracefs.h"
#include "version.h"
#include "trace-local.h"
#include "trace-msg.h"

#define _STR(x) #x
#define STR(x) _STR(x)

#define TRACE_CTRL	"tracing_on"
#define TRACE		"trace"
#define AVAILABLE	"available_tracers"
#define CURRENT		"current_tracer"
#define ITER_CTRL	"trace_options"
#define MAX_LATENCY	"tracing_max_latency"
#define STAMP		"stamp"
#define FUNC_STACK_TRACE "func_stack_trace"

enum trace_type {
	TRACE_TYPE_RECORD	= 1,
	TRACE_TYPE_START	= (1 << 1),
	TRACE_TYPE_STREAM	= (1 << 2),
	TRACE_TYPE_EXTRACT	= (1 << 3),
};

static tracecmd_handle_init_func handle_init = NULL;

static int rt_prio;

static int keep;

static const char *output_file = DEFAUT_INPUT_FILE;

static int latency;
static int sleep_time = 1000;
static int recorder_threads;
static struct pid_record_data *pids;
static int buffers;

/* Clear all function filters */
static int clear_function_filters;

static bool no_fifos;

static char *host;

static bool quiet;

/* Max size to let a per cpu file get */
static int max_kb;

static bool use_tcp;

static int do_ptrace;
static int do_children;
static int get_procmap;

static int filter_task;
static bool no_filter = false;

static int local_cpu_count;

static int finished;

/* setting of /proc/sys/kernel/ftrace_enabled */
static int fset;

static unsigned recorder_flags;

/* Try a few times to get an accurate date */
static int date2ts_tries = 50;

static struct func_list *graph_funcs;

static int func_stack;

static int save_stdout = -1;

struct filter_pids {
	struct filter_pids *next;
	int pid;
	int exclude;
};

static struct filter_pids *filter_pids;
static int nr_filter_pids;
static int len_filter_pids;

static int have_set_event_pid;
static int have_event_fork;

struct opt_list {
	struct opt_list *next;
	const char	*option;
};

static struct opt_list *options;

static struct hook_list *hooks;

static char *common_pid_filter;

struct event_list {
	struct event_list *next;
	const char *event;
	char *trigger;
	char *filter;
	char *pid_filter;
	char *filter_file;
	char *trigger_file;
	char *enable_file;
	int neg;
};

struct tracecmd_event_list *listed_events;

struct events {
	struct events *sibling;
	struct events *children;
	struct events *next;
	char *name;
};

/* Files to be reset when done recording */
struct reset_file {
	struct reset_file	*next;
	char			*path;
	char			*reset;
	int			prio;
};

static struct reset_file *reset_files;

/* Triggers need to be cleared in a special way */
static struct reset_file *reset_triggers;

struct buffer_instance top_instance;
struct buffer_instance *buffer_instances;
struct buffer_instance *first_instance;

static struct tracecmd_recorder *recorder;

static int ignore_event_not_found = 0;

static inline int is_top_instance(struct buffer_instance *instance)
{
	return instance == &top_instance;
}

static inline int no_top_instance(void)
{
	return first_instance != &top_instance;
}

static void init_instance(struct buffer_instance *instance)
{
	instance->event_next = &instance->events;
}

enum {
	RESET_DEFAULT_PRIO	= 0,
	RESET_HIGH_PRIO		= 100000,
};

enum trace_cmd {
	CMD_extract,
	CMD_start,
	CMD_stream,
	CMD_profile,
	CMD_record,
	CMD_record_agent,
};

struct common_record_context {
	enum trace_cmd curr_cmd;
	struct buffer_instance *instance;
	const char *output;
	char *date2ts;
	char *user;
	int data_flags;

	int record_all;
	int total_disable;
	int disable;
	int events;
	int global;
	int filtered;
	int date;
	int manual;
	int topt;
	int do_child;
	int run_command;
	int saved_cmdlines_size;
};

static void add_reset_file(const char *file, const char *val, int prio)
{
	struct reset_file *reset;
	struct reset_file **last = &reset_files;

	/* Only reset if we are not keeping the state */
	if (keep)
		return;

	reset = malloc(sizeof(*reset));
	if (!reset)
		die("Failed to allocate reset");
	reset->path = strdup(file);
	reset->reset = strdup(val);
	reset->prio = prio;
	if (!reset->path || !reset->reset)
		die("Failed to allocate reset path or val");

	while (*last && (*last)->prio > prio)
		last = &(*last)->next;

	reset->next = *last;
	*last = reset;
}

static void add_reset_trigger(const char *file)
{
	struct reset_file *reset;

	/* Only reset if we are not keeping the state */
	if (keep)
		return;

	reset = malloc(sizeof(*reset));
	if (!reset)
		die("Failed to allocate reset");
	reset->path = strdup(file);

	reset->next = reset_triggers;
	reset_triggers = reset;
}

/* To save the contents of the file */
static void reset_save_file(const char *file, int prio)
{
	char *content;

	content = get_file_content(file);
	if (content) {
		add_reset_file(file, content, prio);
		free(content);
	}
}

/*
 * @file: the file to check
 * @nop: If the content of the file is this, use the reset value
 * @reset: What to write if the file == @nop
 */
static void reset_save_file_cond(const char *file, int prio,
				 const char *nop, const char *reset)
{
	char *content;
	char *cond;

	if (keep)
		return;

	content = get_file_content(file);

	cond = strstrip(content);

	if (strcmp(cond, nop) == 0)
		add_reset_file(file, reset, prio);
	else
		add_reset_file(file, content, prio);

	free(content);
}

/**
 * add_instance - add a buffer instance to the internal list
 * @instance: The buffer instance to add
 */
void add_instance(struct buffer_instance *instance, int cpu_count)
{
	init_instance(instance);
	instance->next = buffer_instances;
	if (first_instance == buffer_instances)
		first_instance = instance;
	buffer_instances = instance;
	instance->cpu_count = cpu_count;
	buffers++;
}

static void test_set_event_pid(void)
{
	static int tested;
	struct stat st;
	char *path;
	int ret;

	if (tested)
		return;

	path = tracefs_get_tracing_file("set_event_pid");
	ret = stat(path, &st);
	if (!ret) {
		have_set_event_pid = 1;
		reset_save_file(path, RESET_DEFAULT_PRIO);
	}
	tracefs_put_tracing_file(path);

	path = tracefs_get_tracing_file("options/event-fork");
	ret = stat(path, &st);
	if (!ret) {
		have_event_fork = 1;
		reset_save_file(path, RESET_DEFAULT_PRIO);
	}
	tracefs_put_tracing_file(path);

	tested = 1;
}

/**
 * create_instance - allocate a new buffer instance
 * @name: The name of the instance (instance will point to this)
 *
 * Returns a newly allocated instance. Note that @name will not be
 * copied, and the instance buffer will point to the string itself.
 */
struct buffer_instance *create_instance(const char *name)
{
	struct buffer_instance *instance;

	instance = malloc(sizeof(*instance));
	if (!instance)
		return NULL;
	memset(instance, 0, sizeof(*instance));
	instance->tracefs = tracefs_instance_alloc(name);
	if (!instance->tracefs) {
		free(instance);
		return NULL;
	}

	return instance;
}

static int __add_all_instances(const char *tracing_dir)
{
	struct dirent *dent;
	char *instances_dir;
	struct stat st;
	DIR *dir;
	int ret;

	if (!tracing_dir)
		return -1;

	instances_dir = append_file(tracing_dir, "instances");
	if (!instances_dir)
		return -1;

	ret = stat(instances_dir, &st);
	if (ret < 0 || !S_ISDIR(st.st_mode)) {
		ret = -1;
		goto out_free;
	}

	dir = opendir(instances_dir);
	if (!dir) {
		ret = -1;
		goto out_free;
	}

	while ((dent = readdir(dir))) {
		const char *name = strdup(dent->d_name);
		char *instance_path;
		struct buffer_instance *instance;

		if (strcmp(name, ".") == 0 ||
		    strcmp(name, "..") == 0)
			continue;

		instance_path = append_file(instances_dir, name);
		ret = stat(instance_path, &st);
		if (ret < 0 || !S_ISDIR(st.st_mode)) {
			free(instance_path);
			continue;
		}
		free(instance_path);

		instance = create_instance(name);
		if (!instance)
			die("Failed to create instance");
		add_instance(instance, local_cpu_count);
	}

	closedir(dir);
	ret = 0;

 out_free:
	free(instances_dir);
	return ret;
}

/**
 * add_all_instances - Add all pre-existing instances to the internal list
 * @tracing_dir: The top-level tracing directory
 *
 * Returns whether the operation succeeded
 */
void add_all_instances(void)
{
	char *tracing_dir = tracefs_find_tracing_dir();
	if (!tracing_dir)
		die("malloc");

	__add_all_instances(tracing_dir);

	tracefs_put_tracing_file(tracing_dir);
}

/**
 * tracecmd_stat_cpu - show the buffer stats of a particular CPU
 * @s: the trace_seq to record the data in.
 * @cpu: the CPU to stat
 *
 */
void tracecmd_stat_cpu_instance(struct buffer_instance *instance,
				struct trace_seq *s, int cpu)
{
	char buf[BUFSIZ];
	char *path;
	char *file;
	int fd;
	int r;

	file = malloc(40);
	if (!file)
		return;
	snprintf(file, 40, "per_cpu/cpu%d/stats", cpu);

	path = tracefs_instance_get_file(instance->tracefs, file);
	free(file);
	fd = open(path, O_RDONLY);
	tracefs_put_tracing_file(path);
	if (fd < 0)
		return;

	while ((r = read(fd, buf, BUFSIZ)) > 0)
		trace_seq_printf(s, "%.*s", r, buf);

	close(fd);
}

/**
 * tracecmd_stat_cpu - show the buffer stats of a particular CPU
 * @s: the trace_seq to record the data in.
 * @cpu: the CPU to stat
 *
 */
void tracecmd_stat_cpu(struct trace_seq *s, int cpu)
{
	tracecmd_stat_cpu_instance(&top_instance, s, cpu);
}

static void add_event(struct buffer_instance *instance, struct event_list *event)
{
	*instance->event_next = event;
	instance->event_next = &event->next;
	event->next = NULL;
}

static void reset_event_list(struct buffer_instance *instance)
{
	instance->events = NULL;
	init_instance(instance);
}

static char *get_temp_file(struct buffer_instance *instance, int cpu)
{
	const char *name;
	char *file = NULL;
	int size;

	name = tracefs_instance_get_name(instance->tracefs);
	if (name) {
		size = snprintf(file, 0, "%s.%s.cpu%d", output_file, name, cpu);
		file = malloc(size + 1);
		if (!file)
			die("Failed to allocate temp file for %s", name);
		sprintf(file, "%s.%s.cpu%d", output_file, name, cpu);
	} else {
		size = snprintf(file, 0, "%s.cpu%d", output_file, cpu);
		file = malloc(size + 1);
		if (!file)
			die("Failed to allocate temp file for %s", name);
		sprintf(file, "%s.cpu%d", output_file, cpu);
	}

	return file;
}

static char *get_guest_file(const char *file, const char *guest)
{
	const char *p;
	char *out = NULL;
	int ret, base_len;

	p = strrchr(file, '.');
	if (p && p != file)
		base_len = p - file;
	else
		base_len = strlen(file);

	ret = asprintf(&out, "%.*s-%s%s", base_len, file,
		       guest, file + base_len);
	if (ret < 0)
		return NULL;
	return out;
}

static void put_temp_file(char *file)
{
	free(file);
}

static void delete_temp_file(struct buffer_instance *instance, int cpu)
{
	const char *name;
	char file[PATH_MAX];

	name = tracefs_instance_get_name(instance->tracefs);
	if (name)
		snprintf(file, PATH_MAX, "%s.%s.cpu%d", output_file, name, cpu);
	else
		snprintf(file, PATH_MAX, "%s.cpu%d", output_file, cpu);
	unlink(file);
}

static int kill_thread_instance(int start, struct buffer_instance *instance)
{
	int n = start;
	int i;

	for (i = 0; i < instance->cpu_count; i++) {
		if (pids[n].pid > 0) {
			kill(pids[n].pid, SIGKILL);
			delete_temp_file(instance, i);
			pids[n].pid = 0;
			if (pids[n].brass[0] >= 0)
				close(pids[n].brass[0]);
		}
		n++;
	}

	return n;
}

static void kill_threads(void)
{
	struct buffer_instance *instance;
	int i = 0;

	if (!recorder_threads || !pids)
		return;

	for_all_instances(instance)
		i = kill_thread_instance(i, instance);
}

void die(const char *fmt, ...)
{
	va_list ap;
	int ret = errno;

	if (errno)
		perror("trace-cmd");
	else
		ret = -1;

	kill_threads();
	va_start(ap, fmt);
	fprintf(stderr, "  ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");
	exit(ret);
}

static int delete_thread_instance(int start, struct buffer_instance *instance)
{
	int n = start;
	int i;

	for (i = 0; i < instance->cpu_count; i++) {
		if (pids) {
			if (pids[n].pid) {
				delete_temp_file(instance, i);
				if (pids[n].pid < 0)
					pids[n].pid = 0;
			}
			n++;
		} else
			/* Extract does not allocate pids */
			delete_temp_file(instance, i);
	}
	return n;
}

static void delete_thread_data(void)
{
	struct buffer_instance *instance;
	int i = 0;

	for_all_instances(instance)
		i = delete_thread_instance(i, instance);
	/*
	 * Top instance temp files are still created even if it
	 * isn't used.
	 */
	if (no_top_instance()) {
		for (i = 0; i < local_cpu_count; i++)
			delete_temp_file(&top_instance, i);
	}
}

static void tell_guests_to_stop(void)
{
	struct buffer_instance *instance;

	/* Send close message to guests */
	for_all_instances(instance) {
		if (is_guest(instance))
			tracecmd_msg_send_close_msg(instance->msg_handle);
	}

	/* Wait for guests to acknowledge */
	for_all_instances(instance) {
		if (is_guest(instance)) {
			tracecmd_msg_wait_close_resp(instance->msg_handle);
			tracecmd_msg_handle_close(instance->msg_handle);
		}
	}
}

static void stop_threads(enum trace_type type)
{
	int ret;
	int i;

	if (!recorder_threads)
		return;

	/* Tell all threads to finish up */
	for (i = 0; i < recorder_threads; i++) {
		if (pids[i].pid > 0) {
			kill(pids[i].pid, SIGUSR1);
		}
	}

	/* Flush out the pipes */
	if (type & TRACE_TYPE_STREAM) {
		do {
			ret = trace_stream_read(pids, recorder_threads, NULL);
		} while (ret > 0);
	}
}

static void wait_threads()
{
	int i;

	for (i = 0; i < recorder_threads; i++) {
		if (pids[i].pid > 0) {
			waitpid(pids[i].pid, NULL, 0);
			pids[i].pid = -1;
		}
	}
}

static int create_recorder(struct buffer_instance *instance, int cpu,
			   enum trace_type type, int *brass);

static void flush_threads(void)
{
	struct buffer_instance *instance;
	long ret;
	int i;

	for_all_instances(instance) {
		for (i = 0; i < instance->cpu_count; i++) {
			/* Extract doesn't support sub buffers yet */
			ret = create_recorder(instance, i, TRACE_TYPE_EXTRACT, NULL);
			if (ret < 0)
				die("error reading ring buffer");
		}
	}
}

static int set_ftrace_enable(const char *path, int set)
{
	struct stat st;
	int fd;
	char *val = set ? "1" : "0";
	int ret;

	/* if ftace_enable does not exist, simply ignore it */
	fd = stat(path, &st);
	if (fd < 0)
		return -ENODEV;

	reset_save_file(path, RESET_DEFAULT_PRIO);

	ret = -1;
	fd = open(path, O_WRONLY);
	if (fd < 0)
		goto out;

	/* Now set or clear the function option */
	ret = write(fd, val, 1);
	close(fd);

 out:
	return ret < 0 ? ret : 0;
}

static int set_ftrace_proc(int set)
{
	const char *path = "/proc/sys/kernel/ftrace_enabled";
	int ret;

	ret = set_ftrace_enable(path, set);
	if (ret == -1)
		die ("Can't %s ftrace", set ? "enable" : "disable");
	return ret;
}

static int set_ftrace(int set, int use_proc)
{
	char *path;
	int ret;

	/* First check if the function-trace option exists */
	path = tracefs_get_tracing_file("options/function-trace");
	ret = set_ftrace_enable(path, set);
	tracefs_put_tracing_file(path);

	/* Always enable ftrace_enable proc file when set is true */
	if (ret < 0 || set || use_proc)
		ret = set_ftrace_proc(set);

	return 0;
}

static int write_file(const char *file, const char *str)
{
	int ret;
	int fd;

	fd = open(file, O_WRONLY | O_TRUNC);
	if (fd < 0)
		die("opening to '%s'", file);
	ret = write(fd, str, strlen(str));
	close(fd);
	return ret;
}

static void __clear_trace(struct buffer_instance *instance)
{
	FILE *fp;
	char *path;

	if (is_guest(instance))
		return;

	/* reset the trace */
	path = tracefs_instance_get_file(instance->tracefs, "trace");
	fp = fopen(path, "w");
	if (!fp)
		die("writing to '%s'", path);
	tracefs_put_tracing_file(path);
	fwrite("0", 1, 1, fp);
	fclose(fp);
}

static void clear_trace_instances(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		__clear_trace(instance);
}

static void clear_trace(void)
{
	FILE *fp;
	char *path;

	/* reset the trace */
	path = tracefs_get_tracing_file("trace");
	fp = fopen(path, "w");
	if (!fp)
		die("writing to '%s'", path);
	tracefs_put_tracing_file(path);
	fwrite("0", 1, 1, fp);
	fclose(fp);
}

static void reset_max_latency(struct buffer_instance *instance)
{
	tracefs_instance_file_write(instance->tracefs,
				    "tracing_max_latency", "0");
}

static void add_filter_pid(int pid, int exclude)
{
	struct filter_pids *p;
	char buf[100];

	for (p = filter_pids; p; p = p->next) {
		if (p->pid == pid) {
			p->exclude = exclude;
			return;
		}
	}

	p = malloc(sizeof(*p));
	if (!p)
		die("Failed to allocate pid filter");
	p->next = filter_pids;
	p->exclude = exclude;
	p->pid = pid;
	filter_pids = p;
	nr_filter_pids++;

	len_filter_pids += sprintf(buf, "%d", pid);
}

static void update_ftrace_pid(const char *pid, int reset)
{
	static char *path;
	int ret;
	static int fd = -1;
	static int first = 1;
	struct stat st;

	if (!pid) {
		if (fd >= 0)
			close(fd);
		if (path)
			tracefs_put_tracing_file(path);
		fd = -1;
		path = NULL;
		return;
	}

	/* Force reopen on reset */
	if (reset && fd >= 0) {
		close(fd);
		fd = -1;
	}

	if (fd < 0) {
		if (!path)
			path = tracefs_get_tracing_file("set_ftrace_pid");
		if (!path)
			return;
		ret = stat(path, &st);
		if (ret < 0)
			return;
		if (first) {
			first = 0;
			reset_save_file_cond(path, RESET_DEFAULT_PRIO, "no pid", "");
		}
		fd = open(path, O_WRONLY | O_CLOEXEC | (reset ? O_TRUNC : 0));
		if (fd < 0)
			return;
	}

	ret = write(fd, pid, strlen(pid));

	/*
	 * Older kernels required "-1" to disable pid
	 */
	if (ret < 0 && !strlen(pid))
		ret = write(fd, "-1", 2);

	if (ret < 0)
		die("error writing to %s", path);

	/* add whitespace in case another pid is written */
	write(fd, " ", 1);
}

static void update_ftrace_pids(int reset)
{
	char buf[100];
	struct filter_pids *pid;

	for (pid = filter_pids; pid; pid = pid->next) {
		if (pid->exclude)
			continue;
		snprintf(buf, 100, "%d ", pid->pid);
		update_ftrace_pid(buf, reset);
		/* Only reset the first entry */
		reset = 0;
	}
}

static void update_event_filters(struct buffer_instance *instance);
static void update_pid_event_filters(struct buffer_instance *instance);

static void append_filter_pid_range(char **filter, int *curr_len,
				    const char *field,
				    int start_pid, int end_pid, bool exclude)
{
	const char *op = "", *op1, *op2, *op3;
	int len;

	if (*filter && **filter)
		op = exclude ? "&&" : "||";

	/* Handle thus case explicitly so that we get `pid==3` instead of
	 * `pid>=3&&pid<=3` for singleton ranges
	 */
	if (start_pid == end_pid) {
#define FMT	"%s(%s%s%d)"
		len = snprintf(NULL, 0, FMT, op,
			       field, exclude ? "!=" : "==", start_pid);
		*filter = realloc(*filter, *curr_len + len + 1);
		if (!*filter)
			die("realloc");

		len = snprintf(*filter + *curr_len, len + 1, FMT, op,
			       field, exclude ? "!=" : "==", start_pid);
		*curr_len += len;

		return;
#undef FMT
	}

	if (exclude) {
		op1 = "<";
		op2 = "||";
		op3 = ">";
	} else {
		op1 = ">=";
		op2 = "&&";
		op3 = "<=";
	}

#define FMT	"%s(%s%s%d%s%s%s%d)"
	len = snprintf(NULL, 0, FMT, op,
		       field, op1, start_pid, op2,
		       field, op3, end_pid);
	*filter = realloc(*filter, *curr_len + len + 1);
	if (!*filter)
		die("realloc");

	len = snprintf(*filter + *curr_len, len + 1, FMT, op,
		       field, op1, start_pid, op2,
		       field, op3, end_pid);
	*curr_len += len;
}

/**
 * make_pid_filter - create a filter string to all pids against @field
 * @curr_filter: Append to a previous filter (may realloc). Can be NULL
 * @field: The field to compare the pids against
 *
 * Creates a new string or appends to an existing one if @curr_filter
 * is not NULL. The new string will contain a filter with all pids
 * in pid_filter list with the format (@field == pid) || ..
 * If @curr_filter is not NULL, it will add this string as:
 *  (@curr_filter) && ((@field == pid) || ...)
 */
static char *make_pid_filter(char *curr_filter, const char *field)
{
	int start_pid = -1, last_pid = -1;
	int last_exclude = -1;
	struct filter_pids *p;
	char *filter = NULL;
	int curr_len = 0;

	/* Use the new method if possible */
	if (have_set_event_pid)
		return NULL;

	if (!filter_pids)
		return curr_filter;

	for (p = filter_pids; p; p = p->next) {
		/*
		 * PIDs are inserted in `filter_pids` from the front and that's
		 * why we expect them in descending order here.
		 */
		if (p->pid == last_pid - 1 && p->exclude == last_exclude) {
			last_pid = p->pid;
			continue;
		}

		if (start_pid != -1)
			append_filter_pid_range(&filter, &curr_len, field,
						last_pid, start_pid,
						last_exclude);

		start_pid = last_pid = p->pid;
		last_exclude = p->exclude;

	}
	append_filter_pid_range(&filter, &curr_len, field,
				last_pid, start_pid, last_exclude);

	if (curr_filter) {
		char *save = filter;
		asprintf(&filter, "(%s)&&(%s)", curr_filter, filter);
		free(save);
	}

	return filter;
}

#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)

static int get_pid_addr_maps(int pid)
{
	struct buffer_instance *instance = &top_instance;
	struct pid_addr_maps *maps = instance->pid_maps;
	struct tracecmd_proc_addr_map *map;
	unsigned long long begin, end;
	struct pid_addr_maps *m;
	char mapname[PATH_MAX+1];
	char fname[PATH_MAX+1];
	char buf[PATH_MAX+100];
	FILE *f;
	int ret;
	int res;
	int i;

	sprintf(fname, "/proc/%d/exe", pid);
	ret = readlink(fname, mapname, PATH_MAX);
	if (ret >= PATH_MAX || ret < 0)
		return -ENOENT;
	mapname[ret] = 0;

	sprintf(fname, "/proc/%d/maps", pid);
	f = fopen(fname, "r");
	if (!f)
		return -ENOENT;

	while (maps) {
		if (pid == maps->pid)
			break;
		maps = maps->next;
	}

	ret = -ENOMEM;
	if (!maps) {
		maps = calloc(1, sizeof(*maps));
		if (!maps)
			goto out_fail;
		maps->pid = pid;
		maps->next = instance->pid_maps;
		instance->pid_maps = maps;
	} else {
		for (i = 0; i < maps->nr_lib_maps; i++)
			free(maps->lib_maps[i].lib_name);
		free(maps->lib_maps);
		maps->lib_maps = NULL;
		maps->nr_lib_maps = 0;
		free(maps->proc_name);
	}

	maps->proc_name = strdup(mapname);
	if (!maps->proc_name)
		goto out;

	while (fgets(buf, sizeof(buf), f)) {
		mapname[0] = '\0';
		res = sscanf(buf, "%llx-%llx %*s %*x %*s %*d %"STRINGIFY(PATH_MAX)"s",
			     &begin, &end, mapname);
		if (res == 3 && mapname[0] != '\0') {
			map = realloc(maps->lib_maps,
				      (maps->nr_lib_maps + 1) * sizeof(*map));
			if (!map)
				goto out_fail;
			map[maps->nr_lib_maps].end = end;
			map[maps->nr_lib_maps].start = begin;
			map[maps->nr_lib_maps].lib_name = strdup(mapname);
			if (!map[maps->nr_lib_maps].lib_name)
				goto out_fail;
			maps->lib_maps = map;
			maps->nr_lib_maps++;
		}
	}
out:
	fclose(f);
	return 0;

out_fail:
	fclose(f);
	if (maps) {
		for (i = 0; i < maps->nr_lib_maps; i++)
			free(maps->lib_maps[i].lib_name);
		if (instance->pid_maps != maps) {
			m = instance->pid_maps;
			while (m) {
				if (m->next == maps) {
					m->next = maps->next;
					break;
				}
				m = m->next;
			}
		} else
			instance->pid_maps = maps->next;
		free(maps->lib_maps);
		maps->lib_maps = NULL;
		maps->nr_lib_maps = 0;
		free(maps->proc_name);
		maps->proc_name = NULL;
		free(maps);
	}
	return ret;
}

static void get_filter_pid_maps(void)
{
	struct filter_pids *p;

	for (p = filter_pids; p; p = p->next) {
		if (p->exclude)
			continue;
		get_pid_addr_maps(p->pid);
	}
}

static void update_task_filter(void)
{
	struct buffer_instance *instance;
	int pid = getpid();

	if (no_filter)
		return;

	if (get_procmap && filter_pids)
		get_filter_pid_maps();

	if (filter_task)
		add_filter_pid(pid, 0);

	if (!filter_pids)
		return;

	common_pid_filter = make_pid_filter(NULL, "common_pid");

	update_ftrace_pids(1);
	for_all_instances(instance)
		update_pid_event_filters(instance);
}

void tracecmd_filter_pid(int pid, int exclude)
{
	struct buffer_instance *instance;

	add_filter_pid(pid, exclude);
	common_pid_filter = make_pid_filter(NULL, "common_pid");

	if (!filter_pids)
		return;

	update_ftrace_pids(1);
	for_all_instances(instance)
		update_pid_event_filters(instance);
}

static pid_t trace_waitpid(enum trace_type type, pid_t pid, int *status, int options)
{
	struct timeval tv = { 1, 0 };
	int ret;

	if (type & TRACE_TYPE_STREAM)
		options |= WNOHANG;

	do {
		ret = waitpid(pid, status, options);
		if (ret != 0)
			return ret;

		if (type & TRACE_TYPE_STREAM)
			trace_stream_read(pids, recorder_threads, &tv);
	} while (1);
}
#ifndef NO_PTRACE

/**
 * append_pid_filter - add a new pid to an existing filter
 * @curr_filter: the filter to append to. If NULL, then allocate one
 * @field: The fild to compare the pid to
 * @pid: The pid to add to.
 */
static char *append_pid_filter(char *curr_filter, const char *field, int pid)
{
	char *filter;
	int len;

	len = snprintf(NULL, 0, "(%s==%d)||", field, pid);

	if (!curr_filter) {
		/* No need for +1 as we don't use the "||" */
		filter = malloc(len);
		if (!filter)
			die("Failed to allocate pid filter");
		sprintf(filter, "(%s==%d)", field, pid);
	} else {
		int indx = strlen(curr_filter);

		len += indx;
		filter = realloc(curr_filter, len + indx + 1);
		if (!filter)
			die("realloc");
		sprintf(filter + indx, "||(%s==%d)", field, pid);
	}

	return filter;
}

static void append_sched_event(struct event_list *event, const char *field, int pid)
{
	if (!event || !event->pid_filter)
		return;

	event->pid_filter = append_pid_filter(event->pid_filter, field, pid);
}

static void update_sched_events(struct buffer_instance *instance, int pid)
{
	if (have_set_event_pid)
		return;
	/*
	 * Also make sure that the sched_switch to this pid
	 * and wakeups of this pid are also traced.
	 * Only need to do this if the events are active.
	 */
	append_sched_event(instance->sched_switch_event, "next_pid", pid);
	append_sched_event(instance->sched_wakeup_event, "pid", pid);
	append_sched_event(instance->sched_wakeup_new_event, "pid", pid);
}

static int open_instance_fd(struct buffer_instance *instance,
			    const char *file, int flags);

static void add_event_pid(const char *buf)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		tracefs_instance_file_write(instance->tracefs,
					    "set_event_pid", buf);
}

static void add_new_filter_pid(int pid)
{
	struct buffer_instance *instance;
	char buf[100];

	add_filter_pid(pid, 0);
	sprintf(buf, "%d", pid);
	update_ftrace_pid(buf, 0);

	if (have_set_event_pid)
		return add_event_pid(buf);

	common_pid_filter = append_pid_filter(common_pid_filter, "common_pid", pid);

	for_all_instances(instance) {
		update_sched_events(instance, pid);
		update_event_filters(instance);
	}
}

static void ptrace_attach(int pid)
{
	int ret;

	ret = ptrace(PTRACE_ATTACH, pid, NULL, 0);
	if (ret < 0) {
		warning("Unable to trace process %d children", pid);
		do_ptrace = 0;
		return;
	}
	add_filter_pid(pid, 0);
}

static void enable_ptrace(void)
{
	if (!do_ptrace || !filter_task)
		return;

	ptrace(PTRACE_TRACEME, 0, NULL, 0);
}

static void ptrace_wait(enum trace_type type)
{
	struct filter_pids *fpid;
	unsigned long send_sig;
	unsigned long child;
	siginfo_t sig;
	int main_pids;
	int cstatus;
	int status;
	int i = 0;
	int *pids;
	int event;
	int pid;
	int ret;

	pids = calloc(nr_filter_pids, sizeof(int));
	if (!pids) {
		warning("Unable to allocate array for %d PIDs", nr_filter_pids);
		return;
	}

	for (fpid = filter_pids; fpid; fpid = fpid->next) {
		if (fpid->exclude)
			continue;
		pids[i++] = fpid->pid;
		if (i >= nr_filter_pids)
			break;
	}
	main_pids = i;

	do {
		ret = trace_waitpid(type, -1, &status, WSTOPPED | __WALL);
		if (ret < 0)
			continue;

		pid = ret;

		if (WIFSTOPPED(status)) {
			event = (status >> 16) & 0xff;
			ptrace(PTRACE_GETSIGINFO, pid, NULL, &sig);
			send_sig = sig.si_signo;
			/* Don't send ptrace sigs to child */
			if (send_sig == SIGTRAP || send_sig == SIGSTOP)
				send_sig = 0;
			switch (event) {
			case PTRACE_EVENT_FORK:
			case PTRACE_EVENT_VFORK:
			case PTRACE_EVENT_CLONE:
				/* forked a child */
				ptrace(PTRACE_GETEVENTMSG, pid, NULL, &child);
				ptrace(PTRACE_SETOPTIONS, child, NULL,
				       PTRACE_O_TRACEFORK |
				       PTRACE_O_TRACEVFORK |
				       PTRACE_O_TRACECLONE |
				       PTRACE_O_TRACEEXIT);
				add_new_filter_pid(child);
				ptrace(PTRACE_CONT, child, NULL, 0);
				break;

			case PTRACE_EVENT_EXIT:
				if (get_procmap)
					get_pid_addr_maps(pid);
				ptrace(PTRACE_GETEVENTMSG, pid, NULL, &cstatus);
				ptrace(PTRACE_DETACH, pid, NULL, NULL);
				break;
			}
			ptrace(PTRACE_SETOPTIONS, pid, NULL,
			       PTRACE_O_TRACEFORK |
			       PTRACE_O_TRACEVFORK |
			       PTRACE_O_TRACECLONE |
			       PTRACE_O_TRACEEXIT);
			ptrace(PTRACE_CONT, pid, NULL, send_sig);
		}
		if (WIFEXITED(status) ||
		   (WIFSTOPPED(status) && event == PTRACE_EVENT_EXIT)) {
			for (i = 0; i < nr_filter_pids; i++) {
				if (pid == pids[i]) {
					pids[i] = 0;
					main_pids--;
					if (!main_pids)
						finished = 1;
					break;
				}
			}
		}
	} while (!finished && ret > 0);

	free(pids);
}
#else
static inline void ptrace_wait(enum trace_type type) { }
static inline void enable_ptrace(void) { }
static inline void ptrace_attach(int pid) { }
static inline void add_event_pid(const char *buf) { }

#endif /* NO_PTRACE */

static void trace_or_sleep(enum trace_type type)
{
	struct timeval tv = { 1 , 0 };

	if (do_ptrace && filter_pids)
		ptrace_wait(type);
	else if (type & TRACE_TYPE_STREAM)
		trace_stream_read(pids, recorder_threads, &tv);
	else
		sleep(10);
}

static int change_user(const char *user)
{
	struct passwd *pwd;

	if (!user)
		return 0;

	pwd = getpwnam(user);
	if (!pwd)
		return -1;
	if (initgroups(user, pwd->pw_gid) < 0)
		return -1;
	if (setgid(pwd->pw_gid) < 0)
		return -1;
	if (setuid(pwd->pw_uid) < 0)
		return -1;

	if (setenv("HOME", pwd->pw_dir, 1) < 0)
		return -1;
	if (setenv("USER", pwd->pw_name, 1) < 0)
		return -1;
	if (setenv("LOGNAME", pwd->pw_name, 1) < 0)
		return -1;

	return 0;
}

static void run_cmd(enum trace_type type, const char *user, int argc, char **argv)
{
	int status;
	int pid;

	if ((pid = fork()) < 0)
		die("failed to fork");
	if (!pid) {
		/* child */
		update_task_filter();
		tracecmd_enable_tracing();
		enable_ptrace();
		/*
		 * If we are using stderr for stdout, switch
		 * it back to the saved stdout for the code we run.
		 */
		if (save_stdout >= 0) {
			close(1);
			dup2(save_stdout, 1);
			close(save_stdout);
		}

		if (change_user(user) < 0)
			die("Failed to change user to %s", user);

		if (execvp(argv[0], argv)) {
			fprintf(stderr, "\n********************\n");
			fprintf(stderr, " Unable to exec %s\n", argv[0]);
			fprintf(stderr, "********************\n");
			die("Failed to exec %s", argv[0]);
		}
	}
	if (do_ptrace) {
		add_filter_pid(pid, 0);
		ptrace_attach(pid);
		ptrace_wait(type);
	} else
		trace_waitpid(type, pid, &status, 0);
}

static void
set_plugin_instance(struct buffer_instance *instance, const char *name)
{
	FILE *fp;
	char *path;
	char zero = '0';

	if (is_guest(instance))
		return;

	path = tracefs_instance_get_file(instance->tracefs, "current_tracer");
	fp = fopen(path, "w");
	if (!fp) {
		/*
		 * Legacy kernels do not have current_tracer file, and they
		 * always use nop. So, it doesn't need to try to change the
		 * plugin for those if name is "nop".
		 */
		if (!strncmp(name, "nop", 3)) {
			tracefs_put_tracing_file(path);
			return;
		}
		die("writing to '%s'", path);
	}
	tracefs_put_tracing_file(path);

	fwrite(name, 1, strlen(name), fp);
	fclose(fp);

	if (strncmp(name, "function", 8) != 0)
		return;

	/* Make sure func_stack_trace option is disabled */
	/* First try instance file, then top level */
	path = tracefs_instance_get_file(instance->tracefs, "options/func_stack_trace");
	fp = fopen(path, "w");
	if (!fp) {
		tracefs_put_tracing_file(path);
		path = tracefs_get_tracing_file("options/func_stack_trace");
		fp = fopen(path, "w");
		if (!fp) {
			tracefs_put_tracing_file(path);
			return;
		}
	}
	/*
	 * Always reset func_stack_trace to zero. Don't bother saving
	 * the original content.
	 */
	add_reset_file(path, "0", RESET_HIGH_PRIO);
	tracefs_put_tracing_file(path);
	fwrite(&zero, 1, 1, fp);
	fclose(fp);
}

static void set_plugin(const char *name)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		set_plugin_instance(instance, name);
}

static void save_option(const char *option)
{
	struct opt_list *opt;

	opt = malloc(sizeof(*opt));
	if (!opt)
		die("Failed to allocate option");
	opt->next = options;
	options = opt;
	opt->option = option;
}

static int set_option(const char *option)
{
	FILE *fp;
	char *path;

	path = tracefs_get_tracing_file("trace_options");
	fp = fopen(path, "w");
	if (!fp)
		warning("writing to '%s'", path);
	tracefs_put_tracing_file(path);

	if (!fp)
		return -1;

	fwrite(option, 1, strlen(option), fp);
	fclose(fp);

	return 0;
}

static void disable_func_stack_trace_instance(struct buffer_instance *instance)
{
	struct stat st;
	char *content;
	char *path;
	char *cond;
	int size;
	int ret;

	if (is_guest(instance))
		return;

	path = tracefs_instance_get_file(instance->tracefs, "current_tracer");
	ret = stat(path, &st);
	tracefs_put_tracing_file(path);
	if (ret < 0)
		return;

	content = tracefs_instance_file_read(instance->tracefs,
					     "current_tracer", &size);
	cond = strstrip(content);
	if (memcmp(cond, "function", size - (cond - content)) !=0)
		goto out;

	set_option("nofunc_stack_trace");
 out:
	free(content);
}

static void disable_func_stack_trace(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		disable_func_stack_trace_instance(instance);
}

static void add_reset_options(void)
{
	struct opt_list *opt;
	const char *option;
	char *content;
	char *path;
	char *ptr;
	int len;

	if (keep)
		return;

	path = tracefs_get_tracing_file("trace_options");
	content = get_file_content(path);

	for (opt = options; opt; opt = opt->next) {
		option = opt->option;
		len = strlen(option);
		ptr = content;
 again:
		ptr = strstr(ptr, option);
		if (ptr) {
			/* First make sure its the option we want */
			if (ptr[len] != '\n') {
				ptr += len;
				goto again;
			}
			if (ptr - content >= 2 && strncmp(ptr - 2, "no", 2) == 0) {
				/* Make sure this isn't ohno-option */
				if (ptr > content + 2 && *(ptr - 3) != '\n') {
					ptr += len;
					goto again;
				}
				/* we enabled it */
				ptr[len] = 0;
				add_reset_file(path, ptr-2, RESET_DEFAULT_PRIO);
				ptr[len] = '\n';
				continue;
			}
			/* make sure this is our option */
			if (ptr > content && *(ptr - 1) != '\n') {
				ptr += len;
				goto again;
			}
			/* this option hasn't changed, ignore it */
			continue;
		}

		/* ptr is NULL, not found, maybe option is a no */
		if (strncmp(option, "no", 2) != 0)
			/* option is really not found? */
			continue;

		option += 2;
		len = strlen(option);
		ptr = content;
 loop:
		ptr = strstr(content, option);
		if (!ptr)
			/* Really not found? */
			continue;

		/* make sure this is our option */
		if (ptr[len] != '\n') {
			ptr += len;
			goto loop;
		}

		if (ptr > content && *(ptr - 1) != '\n') {
			ptr += len;
			goto loop;
		}

		add_reset_file(path, option, RESET_DEFAULT_PRIO);
	}
	tracefs_put_tracing_file(path);
	free(content);
}

static void set_options(void)
{
	struct opt_list *opt;
	int ret;

	add_reset_options();

	while (options) {
		opt = options;
		options = opt->next;
		ret = set_option(opt->option);
		if (ret < 0)
			exit(-1);
		free(opt);
	}
}

static void set_saved_cmdlines_size(struct common_record_context *ctx)
{
	int fd, len, ret = -1;
	char *path, *str;

	if (!ctx->saved_cmdlines_size)
		return;

	path = tracefs_get_tracing_file("saved_cmdlines_size");
	if (!path)
		goto err;

	reset_save_file(path, RESET_DEFAULT_PRIO);

	fd = open(path, O_WRONLY);
	tracefs_put_tracing_file(path);
	if (fd < 0)
		goto err;

	len = asprintf(&str, "%d", ctx->saved_cmdlines_size);
	if (len < 0)
		die("%s couldn't allocate memory", __func__);

	if (write(fd, str, len) > 0)
		ret = 0;

	close(fd);
	free(str);
err:
	if (ret)
		warning("Couldn't set saved_cmdlines_size");
}

static int trace_check_file_exists(struct buffer_instance *instance, char *file)
{
	struct stat st;
	char *path;
	int ret;

	path = tracefs_instance_get_file(instance->tracefs, file);
	ret = stat(path, &st);
	tracefs_put_tracing_file(path);

	return ret < 0 ? 0 : 1;
}

static int use_old_event_method(void)
{
	static int old_event_method;
	static int processed;

	if (processed)
		return old_event_method;

	/* Check if the kernel has the events/enable file */
	if (!trace_check_file_exists(&top_instance, "events/enable"))
		old_event_method = 1;

	processed = 1;

	return old_event_method;
}

static void old_update_events(const char *name, char update)
{
	char *path;
	FILE *fp;
	int ret;

	if (strcmp(name, "all") == 0)
		name = "*:*";

	/* need to use old way */
	path = tracefs_get_tracing_file("set_event");
	fp = fopen(path, "w");
	if (!fp)
		die("opening '%s'", path);
	tracefs_put_tracing_file(path);

	/* Disable the event with "!" */
	if (update == '0')
		fwrite("!", 1, 1, fp);

	ret = fwrite(name, 1, strlen(name), fp);
	if (ret < 0)
		die("bad event '%s'", name);

	ret = fwrite("\n", 1, 1, fp);
	if (ret < 0)
		die("bad event '%s'", name);

	fclose(fp);

	return;
}

static void
reset_events_instance(struct buffer_instance *instance)
{
	glob_t globbuf;
	char *path;
	char c;
	int fd;
	int i;
	int ret;

	if (is_guest(instance))
		return;

	if (use_old_event_method()) {
		/* old way only had top instance */
		if (!is_top_instance(instance))
			return;
		old_update_events("all", '0');
		return;
	}

	c = '0';
	path = tracefs_instance_get_file(instance->tracefs, "events/enable");
	fd = open(path, O_WRONLY);
	if (fd < 0)
		die("opening to '%s'", path);
	ret = write(fd, &c, 1);
	close(fd);
	tracefs_put_tracing_file(path);

	path = tracefs_instance_get_file(instance->tracefs, "events/*/filter");
	globbuf.gl_offs = 0;
	ret = glob(path, 0, NULL, &globbuf);
	tracefs_put_tracing_file(path);
	if (ret < 0)
		return;

	for (i = 0; i < globbuf.gl_pathc; i++) {
		path = globbuf.gl_pathv[i];
		fd = open(path, O_WRONLY);
		if (fd < 0)
			die("opening to '%s'", path);
		ret = write(fd, &c, 1);
		close(fd);
	}
	globfree(&globbuf);
}

static void reset_events(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		reset_events_instance(instance);
}

enum {
	STATE_NEWLINE,
	STATE_SKIP,
	STATE_COPY,
};

static char *read_file(const char *file)
{
	char stbuf[BUFSIZ];
	char *buf = NULL;
	int size = 0;
	char *nbuf;
	int fd;
	int r;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return NULL;

	do {
		r = read(fd, stbuf, BUFSIZ);
		if (r <= 0)
			continue;
		nbuf = realloc(buf, size+r+1);
		if (!nbuf) {
			free(buf);
			buf = NULL;
			break;
		}
		buf = nbuf;
		memcpy(buf+size, stbuf, r);
		size += r;
	} while (r > 0);

	close(fd);
	if (r == 0 && size > 0)
		buf[size] = '\0';

	return buf;
}

static void read_error_log(const char *log)
{
	char *buf, *line;
	char *start = NULL;
	char *p;

	buf = read_file(log);
	if (!buf)
		return;

	line = buf;

	/* Only the last lines have meaning */
	while ((p = strstr(line, "\n")) && p[1]) {
		if (line[0] != ' ')
			start = line;
		line = p + 1;
	}

	if (start)
		printf("%s", start);

	free(buf);
}

static void show_error(const char *file, const char *type)
{
	struct stat st;
	char *path = strdup(file);
	char *p;
	int ret;

	if (!path)
		die("Could not allocate memory");

	p = strstr(path, "tracing");
	if (p) {
		if (strncmp(p + sizeof("tracing"), "instances", sizeof("instances") - 1) == 0) {
			p = strstr(p + sizeof("tracing") + sizeof("instances"), "/");
			if (!p)
				goto read_file;
		} else {
			p += sizeof("tracing") - 1;
		}
		ret = asprintf(&p, "%.*s/error_log", (int)(p - path), path);
		if (ret < 0)
			die("Could not allocate memory");
		ret = stat(p, &st);
		if (ret < 0) {
			free(p);
			goto read_file;
		}
		read_error_log(p);
		goto out;
	}

 read_file:
	p = read_file(path);
	if (p)
		printf("%s", p);

 out:
	printf("Failed %s of %s\n", type, file);
	free(path);
	return;
}

static void write_filter(const char *file, const char *filter)
{
	if (write_file(file, filter) < 0)
		show_error(file, "filter");
}

static void clear_filter(const char *file)
{
	write_filter(file, "0");
}

static void write_trigger(const char *file, const char *trigger)
{
	if (write_file(file, trigger) < 0)
		show_error(file, "trigger");
}

static int clear_trigger(const char *file)
{
	char trigger[BUFSIZ];
	char *save = NULL;
	char *line;
	char *buf;
	int len;
	int ret;

	buf = read_file(file);
	if (!buf) {
		perror(file);
		return 0;
	}

	trigger[0] = '!';

	for (line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		if (line[0] == '#')
			continue;
		len = strlen(line);
		if (len > BUFSIZ - 2)
			len = BUFSIZ - 2;
		strncpy(trigger + 1, line, len);
		trigger[len + 1] = '\0';
		/* We don't want any filters or extra on the line */
		strtok(trigger, " ");
		write_file(file, trigger);
	}

	free(buf);

	/*
	 * Some triggers have an order in removing them.
	 * They will not be removed if done in the wrong order.
	 */
	buf = read_file(file);
	if (!buf)
		return 0;

	ret = 0;
	for (line = strtok(buf, "\n"); line; line = strtok(NULL, "\n")) {
		if (line[0] == '#')
			continue;
		ret = 1;
		break;
	}
	free(buf);
	return ret;
}

static void clear_func_filter(const char *file)
{
	char filter[BUFSIZ];
	struct stat st;
	char *line;
	char *buf;
	char *p;
	int len;
	int ret;
	int fd;

	/* Function filters may not exist */
	ret = stat(file, &st);
	if (ret < 0)
		return;

	/*  First zero out normal filters */
	fd = open(file, O_WRONLY | O_TRUNC);
	if (fd < 0)
		die("opening to '%s'", file);
	close(fd);

	buf = read_file(file);
	if (!buf) {
		perror(file);
		return;
	}

	/* Now remove filters */
	filter[0] = '!';

	/*
	 * To delete a filter, we need to write a '!filter'
	 * to the file for each filter.
	 */
	for (line = strtok(buf, "\n"); line; line = strtok(NULL, "\n")) {
		if (line[0] == '#')
			continue;
		len = strlen(line);
		if (len > BUFSIZ - 2)
			len = BUFSIZ - 2;

		strncpy(filter + 1, line, len);
		filter[len + 1] = '\0';
		/*
		 * To remove "unlimited" filters, we must remove
		 * the ":unlimited" from what we write.
		 */
		if ((p = strstr(filter, ":unlimited"))) {
			*p = '\0';
			len = p - filter;
		}
		/*
		 * The write to this file expects white space
		 * at the end :-p
		 */
		filter[len] = '\n';
		filter[len+1] = '\0';
		write_file(file, filter);
	}
}

static void update_reset_triggers(void)
{
	struct reset_file *reset;

	while (reset_triggers) {
		reset = reset_triggers;
		reset_triggers = reset->next;

		clear_trigger(reset->path);
		free(reset->path);
		free(reset);
	}
}

static void update_reset_files(void)
{
	struct reset_file *reset;

	while (reset_files) {
		reset = reset_files;
		reset_files = reset->next;

		if (!keep)
			write_file(reset->path, reset->reset);
		free(reset->path);
		free(reset->reset);
		free(reset);
	}
}

static void
update_event(struct event_list *event, const char *filter,
	     int filter_only, char update)
{
	const char *name = event->event;
	FILE *fp;
	char *path;
	int ret;

	if (use_old_event_method()) {
		if (filter_only)
			return;
		old_update_events(name, update);
		return;
	}

	if (filter && event->filter_file) {
		add_reset_file(event->filter_file, "0", RESET_DEFAULT_PRIO);
		write_filter(event->filter_file, filter);
	}

	if (event->trigger_file) {
		add_reset_trigger(event->trigger_file);
		clear_trigger(event->trigger_file);
		write_trigger(event->trigger_file, event->trigger);
		/* Make sure we don't write this again */
		free(event->trigger_file);
		free(event->trigger);
		event->trigger_file = NULL;
		event->trigger = NULL;
	}

	if (filter_only || !event->enable_file)
		return;

	path = event->enable_file;

	fp = fopen(path, "w");
	if (!fp)
		die("writing to '%s'", path);
	ret = fwrite(&update, 1, 1, fp);
	fclose(fp);
	if (ret < 0)
		die("writing to '%s'", path);
}

/*
 * The debugfs file tracing_enabled needs to be deprecated.
 * But just in case anyone fiddled with it. If it exists,
 * make sure it is one.
 * No error checking needed here.
 */
static void check_tracing_enabled(void)
{
	static int fd = -1;
	char *path;

	if (fd < 0) {
		path = tracefs_get_tracing_file("tracing_enabled");
		fd = open(path, O_WRONLY | O_CLOEXEC);
		tracefs_put_tracing_file(path);

		if (fd < 0)
			return;
	}
	write(fd, "1", 1);
}

static int open_instance_fd(struct buffer_instance *instance,
			    const char *file, int flags)
{
	int fd;
	char *path;

	path = tracefs_instance_get_file(instance->tracefs, file);
	fd = open(path, flags);
	if (fd < 0) {
		/* instances may not be created yet */
		if (is_top_instance(instance))
			die("opening '%s'", path);
	}
	tracefs_put_tracing_file(path);

	return fd;
}

static int open_tracing_on(struct buffer_instance *instance)
{
	int fd = instance->tracing_on_fd;

	/* OK, we keep zero for stdin */
	if (fd > 0)
		return fd;

	fd = open_instance_fd(instance, "tracing_on", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		return fd;
	}
	instance->tracing_on_fd = fd;

	return fd;
}

static void write_tracing_on(struct buffer_instance *instance, int on)
{
	int ret;
	int fd;

	if (is_guest(instance))
		return;

	fd = open_tracing_on(instance);
	if (fd < 0)
		return;

	if (on)
		ret = write(fd, "1", 1);
	else
		ret = write(fd, "0", 1);

	if (ret < 0)
		die("writing 'tracing_on'");
}

static int read_tracing_on(struct buffer_instance *instance)
{
	int fd;
	char buf[10];
	int ret;

	if (is_guest(instance))
		return -1;

	fd = open_tracing_on(instance);
	if (fd < 0)
		return fd;

	ret = read(fd, buf, 10);
	if (ret <= 0)
		die("Reading 'tracing_on'");
	buf[9] = 0;
	ret = atoi(buf);

	return ret;
}

static void reset_max_latency_instance(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		reset_max_latency(instance);
}

void tracecmd_enable_tracing(void)
{
	struct buffer_instance *instance;

	check_tracing_enabled();

	for_all_instances(instance)
		write_tracing_on(instance, 1);

	if (latency)
		reset_max_latency_instance();
}

void tracecmd_disable_tracing(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		write_tracing_on(instance, 0);
}

void tracecmd_disable_all_tracing(int disable_tracer)
{
	tracecmd_disable_tracing();

	if (disable_tracer) {
		disable_func_stack_trace();
		set_plugin("nop");
	}

	reset_events();

	/* Force close and reset of ftrace pid file */
	update_ftrace_pid("", 1);
	update_ftrace_pid(NULL, 0);

	clear_trace_instances();
}

static void
update_sched_event(struct event_list *event, const char *field)
{
	if (!event)
		return;

	event->pid_filter = make_pid_filter(event->pid_filter, field);
}

static void update_event_filters(struct buffer_instance *instance)
{
	struct event_list *event;
	char *event_filter;
	int free_it;
	int len;
	int common_len = 0;

	if (common_pid_filter)
		common_len = strlen(common_pid_filter);

	for (event = instance->events; event; event = event->next) {
		if (!event->neg) {

			free_it = 0;
			if (event->filter) {
				if (!common_pid_filter)
					/*
					 * event->pid_filter is only created if
					 * common_pid_filter is. No need to check that.
					 * Just use the current event->filter.
					 */
					event_filter = event->filter;
				else if (event->pid_filter) {
					free_it = 1;
					len = common_len + strlen(event->pid_filter) +
						strlen(event->filter) + strlen("()&&(||)") + 1;
					event_filter = malloc(len);
					if (!event_filter)
						die("Failed to allocate event_filter");
					sprintf(event_filter, "(%s)&&(%s||%s)",
						event->filter, common_pid_filter,
						event->pid_filter);
				} else {
					free_it = 1;
					len = common_len + strlen(event->filter) +
						strlen("()&&()") + 1;
					event_filter = malloc(len);
					if (!event_filter)
						die("Failed to allocate event_filter");
					sprintf(event_filter, "(%s)&&(%s)",
						event->filter, common_pid_filter);
				}
			} else {
				/* event->pid_filter only exists when common_pid_filter does */
				if (!common_pid_filter)
					continue;

				if (event->pid_filter) {
					free_it = 1;
					len = common_len + strlen(event->pid_filter) +
						strlen("||") + 1;
					event_filter = malloc(len);
					if (!event_filter)
						die("Failed to allocate event_filter");
					sprintf(event_filter, "%s||%s",
						common_pid_filter, event->pid_filter);
				} else
					event_filter = common_pid_filter;
			}

			update_event(event, event_filter, 1, '1');
			if (free_it)
				free(event_filter);
		}
	}
}

static void update_pid_filters(struct buffer_instance *instance)
{
	struct filter_pids *p;
	char *filter;
	char *str;
	int len;
	int ret;
	int fd;

	if (is_guest(instance))
		return;

	fd = open_instance_fd(instance, "set_event_pid",
			      O_WRONLY | O_CLOEXEC | O_TRUNC);
	if (fd < 0)
		die("Failed to access set_event_pid");

	len = len_filter_pids + nr_filter_pids;
	filter = malloc(len);
	if (!filter)
		die("Failed to allocate pid filter");

	str = filter;

	for (p = filter_pids; p; p = p->next) {
		if (p->exclude)
			continue;
		len = sprintf(str, "%d ", p->pid);
		str += len;
	}

	if (filter == str)
		goto out;

	len = str - filter;
	str = filter;
	do {
		ret = write(fd, str, len);
		if (ret < 0)
			die("Failed to write to set_event_pid");
		str += ret;
		len -= ret;
	} while (ret >= 0 && len);

 out:
	close(fd);
}

static void update_pid_event_filters(struct buffer_instance *instance)
{
	if (have_set_event_pid)
		return update_pid_filters(instance);
	/*
	 * Also make sure that the sched_switch to this pid
	 * and wakeups of this pid are also traced.
	 * Only need to do this if the events are active.
	 */
	update_sched_event(instance->sched_switch_event, "next_pid");
	update_sched_event(instance->sched_wakeup_event, "pid");
	update_sched_event(instance->sched_wakeup_new_event, "pid");

	update_event_filters(instance);
}

#define MASK_STR_MAX 4096 /* Don't expect more than 32768 CPUS */

static char *alloc_mask_from_hex(struct buffer_instance *instance, const char *str)
{
	char *cpumask;

	if (strcmp(str, "-1") == 0) {
		/* set all CPUs */
		int bytes = (instance->cpu_count + 7) / 8;
		int last = instance->cpu_count % 8;
		int i;

		cpumask = malloc(MASK_STR_MAX);
		if (!cpumask)
			die("can't allocate cpumask");

		if (bytes > (MASK_STR_MAX-1)) {
			warning("cpumask can't handle more than 32768 CPUS!");
			bytes = MASK_STR_MAX-1;
		}

		sprintf(cpumask, "%x", (1 << last) - 1);

		for (i = 1; i < bytes; i++)
			cpumask[i] = 'f';

		cpumask[i+1] = 0;
	} else {
		cpumask = strdup(str);
		if (!cpumask)
			die("can't allocate cpumask");
	}

	return cpumask;
}

static void set_mask(struct buffer_instance *instance)
{
	struct stat st;
	char *path;
	int fd;
	int ret;

	if (is_guest(instance))
		return;

	if (!instance->cpumask)
		return;

	path = tracefs_instance_get_file(instance->tracefs, "tracing_cpumask");
	if (!path)
		die("could not allocate path");
	reset_save_file(path, RESET_DEFAULT_PRIO);

	ret = stat(path, &st);
	if (ret < 0) {
		warning("%s not found", path);
		goto out;
	}

	fd = open(path, O_WRONLY | O_TRUNC);
	if (fd < 0)
		die("could not open %s\n", path);

	write(fd, instance->cpumask, strlen(instance->cpumask));

	close(fd);
 out:
	tracefs_put_tracing_file(path);
	free(instance->cpumask);
	instance->cpumask = NULL;
}

static void enable_events(struct buffer_instance *instance)
{
	struct event_list *event;

	if (is_guest(instance))
		return;

	for (event = instance->events; event; event = event->next) {
		if (!event->neg)
			update_event(event, event->filter, 0, '1');
	}

	/* Now disable any events */
	for (event = instance->events; event; event = event->next) {
		if (event->neg)
			update_event(event, NULL, 0, '0');
	}
}

void tracecmd_enable_events(void)
{
	enable_events(first_instance);
}

static void set_clock(struct buffer_instance *instance)
{
	char *path;
	char *content;
	char *str;

	if (is_guest(instance))
		return;

	if (!instance->clock)
		return;

	/* The current clock is in brackets, reset it when we are done */
	content = tracefs_instance_file_read(instance->tracefs,
					     "trace_clock", NULL);

	/* check if first clock is set */
	if (*content == '[')
		str = strtok(content+1, "]");
	else {
		str = strtok(content, "[");
		if (!str)
			die("Can not find clock in trace_clock");
		str = strtok(NULL, "]");
	}
	path = tracefs_instance_get_file(instance->tracefs, "trace_clock");
	add_reset_file(path, str, RESET_DEFAULT_PRIO);

	free(content);
	tracefs_put_tracing_file(path);

	tracefs_instance_file_write(instance->tracefs,
				    "trace_clock", instance->clock);
}

static void set_max_graph_depth(struct buffer_instance *instance, char *max_graph_depth)
{
	char *path;
	int ret;

	if (is_guest(instance))
		return;

	path = tracefs_instance_get_file(instance->tracefs, "max_graph_depth");
	reset_save_file(path, RESET_DEFAULT_PRIO);
	tracefs_put_tracing_file(path);
	ret = tracefs_instance_file_write(instance->tracefs, "max_graph_depth",
					  max_graph_depth);
	if (ret < 0)
		die("could not write to max_graph_depth");
}


/**
 * create_event - create and event descriptor
 * @instance: instance to use
 * @path: path to event attribute
 * @old_event: event descriptor to use as base
 *
 * NOTE: the function purpose is to create a data structure to describe
 * an ftrace event. During the process it becomes handy to change the
 * string `path`. So, do not rely on the content of `path` after you
 * invoke this function.
 */
static struct event_list *
create_event(struct buffer_instance *instance, char *path, struct event_list *old_event)
{
	struct event_list *event;
	struct stat st;
	char *path_dirname;
	char *p;
	int ret;

	event = malloc(sizeof(*event));
	if (!event)
		die("Failed to allocate event");
	*event = *old_event;
	add_event(instance, event);

	if (event->filter || filter_task || filter_pids) {
		event->filter_file = strdup(path);
		if (!event->filter_file)
			die("malloc filter file");
	}

	path_dirname = dirname(path);

	ret = asprintf(&p, "%s/enable", path_dirname);
	if (ret < 0)
		die("Failed to allocate enable path for %s", path);
	ret = stat(p, &st);
	if (ret >= 0)
		event->enable_file = p;
	else
		free(p);

	if (event->trigger) {
		ret = asprintf(&p, "%s/trigger", path_dirname);
		if (ret < 0)
			die("Failed to allocate trigger path for %s", path);
		ret = stat(p, &st);
		if (ret > 0)
			die("trigger specified but not supported by this kernel");
		event->trigger_file = p;
	}

	return event;
}

static void make_sched_event(struct buffer_instance *instance,
			     struct event_list **event, struct event_list *sched,
			     const char *sched_path)
{
	char *path_dirname;
	char *tmp_file;
	char *path;
	int ret;

	/* Do nothing if the event already exists */
	if (*event)
		return;

	/* we do not want to corrupt sched->filter_file when using dirname() */
	tmp_file = strdup(sched->filter_file);
	if (!tmp_file)
		die("Failed to allocate path for %s", sched_path);
	path_dirname = dirname(tmp_file);

	ret = asprintf(&path, "%s/%s/filter", path_dirname, sched_path);
	free(tmp_file);
	if (ret < 0)
		die("Failed to allocate path for %s", sched_path);

	*event = create_event(instance, path, sched);
	free(path);
}

static void test_event(struct event_list *event, const char *path,
		       const char *name, struct event_list **save, int len)
{
	path += len - strlen(name);

	if (strcmp(path, name) != 0)
		return;

	*save = event;
}

static int expand_event_files(struct buffer_instance *instance,
			      const char *file, struct event_list *old_event)
{
	struct event_list **save_event_tail = instance->event_next;
	struct event_list *sched_event = NULL;
	struct event_list *event;
	glob_t globbuf;
	char *path;
	char *p;
	int ret;
	int i;

	ret = asprintf(&p, "events/%s/filter", file);
	if (ret < 0)
		die("Failed to allocate event filter path for %s", file);

	path = tracefs_instance_get_file(instance->tracefs, p);

	globbuf.gl_offs = 0;
	ret = glob(path, 0, NULL, &globbuf);
	tracefs_put_tracing_file(path);
	free(p);

	if (ret < 0)
		die("No filters found");

	for (i = 0; i < globbuf.gl_pathc; i++) {
		int len;

		path = globbuf.gl_pathv[i];

		event = create_event(instance, path, old_event);
		pr_stat("%s\n", path);

		len = strlen(path);

		test_event(event, path, "sched", &sched_event, len);
		test_event(event, path, "sched/sched_switch", &instance->sched_switch_event, len);
		test_event(event, path, "sched/sched_wakeup_new", &instance->sched_wakeup_new_event, len);
		test_event(event, path, "sched/sched_wakeup", &instance->sched_wakeup_event, len);
	}

	if (sched_event && sched_event->filter_file) {
		/* make sure all sched events exist */
		make_sched_event(instance, &instance->sched_switch_event,
				 sched_event, "sched_switch");
		make_sched_event(instance, &instance->sched_wakeup_event,
				 sched_event, "sched_wakeup");
		make_sched_event(instance, &instance->sched_wakeup_new_event,
				 sched_event, "sched_wakeup_new");

	}


	globfree(&globbuf);

	/* If the event list tail changed, that means events were added */
	return save_event_tail == instance->event_next;
}

static void expand_event(struct buffer_instance *instance, struct event_list *event)
{
	const char *name = event->event;
	char *str;
	char *ptr;
	int len;
	int ret;
	int ret2;

	/*
	 * We allow the user to use "all" to enable all events.
	 * Expand event_selection to all systems.
	 */
	if (strcmp(name, "all") == 0) {
		expand_event_files(instance, "*", event);
		return;
	}

	ptr = strchr(name, ':');

	if (ptr) {
		len = ptr - name;
		str = malloc(strlen(name) + 1); /* may add '*' */
		if (!str)
			die("Failed to allocate event for %s", name);
		strcpy(str, name);
		str[len] = '/';
		ptr++;
		if (!strlen(ptr)) {
			str[len + 1] = '*';
			str[len + 2] = '\0';
		}

		ret = expand_event_files(instance, str, event);
		if (!ignore_event_not_found && ret)
			die("No events enabled with %s", name);
		free(str);
		return;
	}

	/* No ':' so enable all matching systems and events */
	ret = expand_event_files(instance, name, event);

	len = strlen(name) + strlen("*/") + 1;
	str = malloc(len);
	if (!str)
		die("Failed to allocate event for %s", name);
	snprintf(str, len, "*/%s", name);
	ret2 = expand_event_files(instance, str, event);
	free(str);

	if (!ignore_event_not_found && ret && ret2)
		die("No events enabled with %s", name);
}

static void expand_event_instance(struct buffer_instance *instance)
{
	struct event_list *compressed_list = instance->events;
	struct event_list *event;

	if (is_guest(instance))
		return;

	reset_event_list(instance);

	while (compressed_list) {
		event = compressed_list;
		compressed_list = event->next;
		expand_event(instance, event);
		free(event);
	}
}

static void expand_event_list(void)
{
	struct buffer_instance *instance;

	if (use_old_event_method())
		return;

	for_all_instances(instance)
		expand_event_instance(instance);
}

static void finish(int sig)
{
	/* all done */
	if (recorder)
		tracecmd_stop_recording(recorder);
	finished = 1;
}

static int connect_port(const char *host, unsigned int port)
{
	struct addrinfo hints;
	struct addrinfo *results, *rp;
	int s, sfd;
	char buf[BUFSIZ];

	snprintf(buf, BUFSIZ, "%u", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = use_tcp ? SOCK_STREAM : SOCK_DGRAM;

	s = getaddrinfo(host, buf, &hints, &results);
	if (s != 0)
		die("connecting to %s server %s:%s",
		    use_tcp ? "TCP" : "UDP", host, buf);

	for (rp = results; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype,
			     rp->ai_protocol);
		if (sfd == -1)
			continue;
		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;
		close(sfd);
	}

	if (rp == NULL)
		die("Can not connect to %s server %s:%s",
		    use_tcp ? "TCP" : "UDP", host, buf);

	freeaddrinfo(results);

	return sfd;
}

#ifdef VSOCK
static int open_vsock(unsigned int cid, unsigned int port)
{
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_cid = cid,
		.svm_port = port,
	};
	int sd;

	sd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (sd < 0)
		return -errno;

	if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)))
		return -errno;

	return sd;
}

static int try_splice_read_vsock(void)
{
	int ret, sd, brass[2];

	sd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (sd < 0)
		return -errno;

	ret = pipe(brass);
	if (ret < 0)
		goto out_close_sd;

	/*
	 * On kernels that don't support splice reading from vsockets
	 * this will fail with EINVAL, or ENOTCONN otherwise.
	 * Technically, it should never succeed but if it does, claim splice
	 * reading is supported.
	 */
	ret = splice(sd, NULL, brass[1], NULL, 10, 0);
	if (ret < 0)
		ret = errno != EINVAL;
	else
		ret = 1;

	close(brass[0]);
	close(brass[1]);
out_close_sd:
	close(sd);
	return ret;
}

static bool can_splice_read_vsock(void)
{
	static bool initialized, res;

	if (initialized)
		return res;

	res = try_splice_read_vsock() > 0;
	initialized = true;
	return res;
}

#else
static inline int open_vsock(unsigned int cid, unsigned int port)
{
	die("vsock is not supported");
	return -1;
}

static bool can_splice_read_vsock(void)
{
	return false;
}
#endif

static int do_accept(int sd)
{
	int cd;

	for (;;) {
		cd = accept(sd, NULL, NULL);
		if (cd < 0) {
			if (errno == EINTR)
				continue;
			die("accept");
		}

		return cd;
	}

	return -1;
}

static bool is_digits(const char *s)
{
	for (; *s; s++)
		if (!isdigit(*s))
			return false;
	return true;
}

struct guest {
	char *name;
	int cid;
	int pid;
};

static struct guest *guests;
static size_t guests_len;

static char *get_qemu_guest_name(char *arg)
{
	char *tok, *end = arg;

	while ((tok = strsep(&end, ","))) {
		if (strncmp(tok, "guest=", 6) == 0)
			return tok + 6;
	}

	return arg;
}

static void read_qemu_guests(void)
{
	static bool initialized;
	struct dirent *entry;
	char path[PATH_MAX];
	DIR *dir;

	if (initialized)
		return;

	initialized = true;
	dir = opendir("/proc");
	if (!dir)
		die("Can not open /proc");

	while ((entry = readdir(dir))) {
		bool is_qemu = false, last_was_name = false;
		struct guest guest = {};
		char *p, *arg = NULL;
		size_t arg_size = 0;
		FILE *f;

		if (!(entry->d_type == DT_DIR && is_digits(entry->d_name)))
			continue;

		guest.pid = atoi(entry->d_name);
		snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
		f = fopen(path, "r");
		if (!f)
			continue;

		while (getdelim(&arg, &arg_size, 0, f) != -1) {
			if (!is_qemu && strstr(arg, "qemu-system-")) {
				is_qemu = true;
				continue;
			}

			if (!is_qemu)
				continue;

			if (strcmp(arg, "-name") == 0) {
				last_was_name = true;
				continue;
			}

			if (last_was_name) {
				guest.name = strdup(get_qemu_guest_name(arg));
				if (!guest.name)
					die("allocating guest name");
				last_was_name = false;
				continue;
			}

			p = strstr(arg, "guest-cid=");
			if (p) {
				guest.cid = atoi(p + 10);
				continue;
			}
		}

		if (!is_qemu)
			goto next;

		guests = realloc(guests, (guests_len + 1) * sizeof(*guests));
		if (!guests)
			die("Can not allocate guest buffer");
		guests[guests_len++] = guest;

next:
		free(arg);
		fclose(f);
	}

	closedir(dir);
}

static char *parse_guest_name(char *guest, int *cid, int *port)
{
	size_t i;
	char *p;

	*port = -1;
	p = strrchr(guest, ':');
	if (p) {
		*p = '\0';
		*port = atoi(p + 1);
	}

	*cid = -1;
	p = strrchr(guest, '@');
	if (p) {
		*p = '\0';
		*cid = atoi(p + 1);
	} else if (is_digits(guest))
		*cid = atoi(guest);

	read_qemu_guests();
	for (i = 0; i < guests_len; i++) {
		if ((*cid > 0 && *cid == guests[i].cid) ||
		    strcmp(guest, guests[i].name) == 0) {
			*cid = guests[i].cid;
			return guests[i].name;
		}
	}

	return guest;
}

static void set_prio(int prio)
{
	struct sched_param sp;

	memset(&sp, 0, sizeof(sp));
	sp.sched_priority = prio;
	if (sched_setscheduler(0, SCHED_FIFO, &sp) < 0)
		warning("failed to set priority");
}

static struct tracecmd_recorder *
create_recorder_instance_pipe(struct buffer_instance *instance,
			      int cpu, int *brass)
{
	struct tracecmd_recorder *recorder;
	unsigned flags = recorder_flags | TRACECMD_RECORD_BLOCK;
	char *path;

	path = tracefs_instance_get_dir(instance->tracefs);

	if (!path)
		die("malloc");

	/* This is already the child */
	close(brass[0]);

	recorder = tracecmd_create_buffer_recorder_fd(brass[1], cpu, flags, path);

	tracefs_put_tracing_file(path);

	return recorder;
}

static struct tracecmd_recorder *
create_recorder_instance(struct buffer_instance *instance, const char *file, int cpu,
			 int *brass)
{
	struct tracecmd_recorder *record;
	char *path;

	if (is_guest(instance)) {
		int fd;
		unsigned int flags;

		if (instance->use_fifos)
			fd = instance->fds[cpu];
		else
			fd = open_vsock(instance->cid, instance->client_ports[cpu]);
		if (fd < 0)
			die("Failed to connect to agent");

		flags = recorder_flags;
		if (instance->use_fifos)
			flags |= TRACECMD_RECORD_NOBRASS;
		else if (!can_splice_read_vsock())
			flags |= TRACECMD_RECORD_NOSPLICE;
		return tracecmd_create_recorder_virt(file, cpu, flags, fd);
	}

	if (brass)
		return create_recorder_instance_pipe(instance, cpu, brass);

	if (!tracefs_instance_get_name(instance->tracefs))
		return tracecmd_create_recorder_maxkb(file, cpu, recorder_flags, max_kb);

	path = tracefs_instance_get_dir(instance->tracefs);

	record = tracecmd_create_buffer_recorder_maxkb(file, cpu, recorder_flags,
						       path, max_kb);
	tracefs_put_tracing_file(path);

	return record;
}

/*
 * If extract is set, then this is going to set up the recorder,
 * connections and exit as the tracing is serialized by a single thread.
 */
static int create_recorder(struct buffer_instance *instance, int cpu,
			   enum trace_type type, int *brass)
{
	long ret;
	char *file;
	pid_t pid;

	if (type != TRACE_TYPE_EXTRACT) {

		pid = fork();
		if (pid < 0)
			die("fork");

		if (pid)
			return pid;

		signal(SIGINT, SIG_IGN);
		signal(SIGUSR1, finish);

		if (rt_prio)
			set_prio(rt_prio);

		/* do not kill tasks on error */
		instance->cpu_count = 0;
	}

	if ((instance->client_ports && !is_guest(instance)) || is_agent(instance)) {
		unsigned int flags = recorder_flags;
		char *path = NULL;
		int fd;

		if (is_agent(instance)) {
			if (instance->use_fifos)
				fd = instance->fds[cpu];
			else
				fd = do_accept(instance->fds[cpu]);
		} else {
			fd = connect_port(host, instance->client_ports[cpu]);
		}
		if (fd < 0)
			die("Failed connecting to client");
		if (tracefs_instance_get_name(instance->tracefs) && !is_agent(instance))
			path = tracefs_instance_get_dir(instance->tracefs);
		else
			path = tracefs_find_tracing_dir();
		recorder = tracecmd_create_buffer_recorder_fd(fd, cpu, flags, path);
		tracefs_put_tracing_file(path);
	} else {
		file = get_temp_file(instance, cpu);
		recorder = create_recorder_instance(instance, file, cpu, brass);
		put_temp_file(file);
	}

	if (!recorder)
		die ("can't create recorder");

	if (type == TRACE_TYPE_EXTRACT) {
		ret = tracecmd_flush_recording(recorder);
		tracecmd_free_recorder(recorder);
		recorder = NULL;
		return ret;
	}

	while (!finished) {
		if (tracecmd_start_recording(recorder, sleep_time) < 0)
			break;
	}
	tracecmd_free_recorder(recorder);
	recorder = NULL;

	exit(0);
}

static void check_first_msg_from_server(struct tracecmd_msg_handle *msg_handle)
{
	char buf[BUFSIZ];

	read(msg_handle->fd, buf, 8);

	/* Make sure the server is the tracecmd server */
	if (memcmp(buf, "tracecmd", 8) != 0)
		die("server not tracecmd server");
}

static void communicate_with_listener_v1(struct tracecmd_msg_handle *msg_handle,
					 unsigned int **client_ports)
{
	char buf[BUFSIZ];
	ssize_t n;
	int cpu, i;

	check_first_msg_from_server(msg_handle);

	/* write the number of CPUs we have (in ASCII) */
	sprintf(buf, "%d", local_cpu_count);

	/* include \0 */
	write(msg_handle->fd, buf, strlen(buf)+1);

	/* write the pagesize (in ASCII) */
	sprintf(buf, "%d", page_size);

	/* include \0 */
	write(msg_handle->fd, buf, strlen(buf)+1);

	/*
	 * If we are using IPV4 and our page size is greater than
	 * or equal to 64K, we need to punt and use TCP. :-(
	 */

	/* TODO, test for ipv4 */
	if (page_size >= UDP_MAX_PACKET) {
		warning("page size too big for UDP using TCP in live read");
		use_tcp = 1;
		msg_handle->flags |= TRACECMD_MSG_FL_USE_TCP;
	}

	if (use_tcp) {
		/* Send one option */
		write(msg_handle->fd, "1", 2);
		/* Size 4 */
		write(msg_handle->fd, "4", 2);
		/* use TCP */
		write(msg_handle->fd, "TCP", 4);
	} else
		/* No options */
		write(msg_handle->fd, "0", 2);

	*client_ports = malloc(local_cpu_count * sizeof(*client_ports));
	if (!*client_ports)
		die("Failed to allocate client ports for %d cpus", local_cpu_count);

	/*
	 * Now we will receive back a comma deliminated list
	 * of client ports to connect to.
	 */
	for (cpu = 0; cpu < local_cpu_count; cpu++) {
		for (i = 0; i < BUFSIZ; i++) {
			n = read(msg_handle->fd, buf+i, 1);
			if (n != 1)
				die("Error, reading server ports");
			if (!buf[i] || buf[i] == ',')
				break;
		}
		if (i == BUFSIZ)
			die("read bad port number");
		buf[i] = 0;
		(*client_ports)[cpu] = atoi(buf);
	}
}

static void communicate_with_listener_v3(struct tracecmd_msg_handle *msg_handle,
					 unsigned int **client_ports)
{
	if (tracecmd_msg_send_init_data(msg_handle, client_ports) < 0)
		die("Cannot communicate with server");
}

static void check_protocol_version(struct tracecmd_msg_handle *msg_handle)
{
	char buf[BUFSIZ];
	int fd = msg_handle->fd;
	int n;

	check_first_msg_from_server(msg_handle);

	/*
	 * Write the protocol version, the magic number, and the dummy
	 * option(0) (in ASCII). The client understands whether the client
	 * uses the v3 protocol or not by checking a reply message from the
	 * server. If the message is "V3", the server uses v3 protocol. On the
	 * other hands, if the message is just number strings, the server
	 * returned port numbers. So, in that time, the client understands the
	 * server uses the v1 protocol. However, the old server tells the
	 * client port numbers after reading cpu_count, page_size, and option.
	 * So, we add the dummy number (the magic number and 0 option) to the
	 * first client message.
	 */
	write(fd, V3_CPU, sizeof(V3_CPU));

	buf[0] = 0;

	/* read a reply message */
	n = read(fd, buf, BUFSIZ);

	if (n < 0 || !buf[0]) {
		/* the server uses the v1 protocol, so we'll use it */
		msg_handle->version = V1_PROTOCOL;
		tracecmd_plog("Use the v1 protocol\n");
	} else {
		if (memcmp(buf, "V3", n) != 0)
			die("Cannot handle the protocol %s", buf);
		/* OK, let's use v3 protocol */
		write(fd, V3_MAGIC, sizeof(V3_MAGIC));

		n = read(fd, buf, BUFSIZ - 1);
		if (n != 2 || memcmp(buf, "OK", 2) != 0) {
			if (n < 0)
				n  = 0;
			buf[n] = 0;
			die("Cannot handle the protocol %s", buf);
		}
	}
}

static struct tracecmd_msg_handle *setup_network(struct buffer_instance *instance)
{
	struct tracecmd_msg_handle *msg_handle = NULL;
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s;
	char *server;
	char *port;
	char *p;

	if (!strchr(host, ':')) {
		server = strdup("localhost");
		if (!server)
			die("alloctating server");
		port = host;
		host = server;
	} else {
		host = strdup(host);
		if (!host)
			die("alloctating server");
		server = strtok_r(host, ":", &p);
		port = strtok_r(NULL, ":", &p);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

again:
	s = getaddrinfo(server, port, &hints, &result);
	if (s != 0)
		die("getaddrinfo: %s", gai_strerror(s));

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype,
			     rp->ai_protocol);
		if (sfd == -1)
			continue;

		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;
		close(sfd);
	}

	if (!rp)
		die("Can not connect to %s:%s", server, port);

	freeaddrinfo(result);

	if (msg_handle) {
		msg_handle->fd = sfd;
	} else {
		msg_handle = tracecmd_msg_handle_alloc(sfd, 0);
		if (!msg_handle)
			die("Failed to allocate message handle");

		msg_handle->cpu_count = local_cpu_count;
		msg_handle->version = V3_PROTOCOL;
	}

	if (use_tcp)
		msg_handle->flags |= TRACECMD_MSG_FL_USE_TCP;

	if (msg_handle->version == V3_PROTOCOL) {
		check_protocol_version(msg_handle);
		if (msg_handle->version == V1_PROTOCOL) {
			/* reconnect to the server for using the v1 protocol */
			close(sfd);
			goto again;
		}
		communicate_with_listener_v3(msg_handle, &instance->client_ports);
	}

	if (msg_handle->version == V1_PROTOCOL)
		communicate_with_listener_v1(msg_handle, &instance->client_ports);

	return msg_handle;
}

static void add_options(struct tracecmd_output *handle, struct common_record_context *ctx);

static struct tracecmd_msg_handle *
setup_connection(struct buffer_instance *instance, struct common_record_context *ctx)
{
	struct tracecmd_msg_handle *msg_handle;
	struct tracecmd_output *network_handle;

	msg_handle = setup_network(instance);

	/* Now create the handle through this socket */
	if (msg_handle->version == V3_PROTOCOL) {
		network_handle = tracecmd_create_init_fd_msg(msg_handle, listed_events);
		tracecmd_set_quiet(network_handle, quiet);
		add_options(network_handle, ctx);
		tracecmd_write_cpus(network_handle, instance->cpu_count);
		tracecmd_write_options(network_handle);
		tracecmd_msg_finish_sending_data(msg_handle);
	} else {
		network_handle = tracecmd_create_init_fd_glob(msg_handle->fd,
							      listed_events);
		tracecmd_set_quiet(network_handle, quiet);
	}

	instance->network_handle = network_handle;

	/* OK, we are all set, let'r rip! */
	return msg_handle;
}

static void finish_network(struct tracecmd_msg_handle *msg_handle)
{
	if (msg_handle->version == V3_PROTOCOL)
		tracecmd_msg_send_close_msg(msg_handle);
	tracecmd_msg_handle_close(msg_handle);
	free(host);
}

static int open_guest_fifos(const char *guest, int **fds)
{
	char path[PATH_MAX];
	int i, fd, flags;

	for (i = 0; ; i++) {
		snprintf(path, sizeof(path), GUEST_FIFO_FMT ".out", guest, i);

		/* O_NONBLOCK so we don't wait for writers */
		fd = open(path, O_RDONLY | O_NONBLOCK);
		if (fd < 0)
			break;

		/* Success, now clear O_NONBLOCK */
		flags = fcntl(fd, F_GETFL);
		fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

		*fds = realloc(*fds, i + 1);
		(*fds)[i] = fd;
	}

	return i;
}

static void connect_to_agent(struct buffer_instance *instance)
{
	struct tracecmd_msg_handle *msg_handle;
	int sd, ret, nr_fifos, nr_cpus, page_size;
	unsigned int *ports;
	int i, *fds = NULL;
	bool use_fifos = false;
	char *name;

	name = tracefs_instance_get_name(instance->tracefs);
	if (!no_fifos) {
		nr_fifos = open_guest_fifos(name, &fds);
		use_fifos = nr_fifos > 0;
	}

	sd = open_vsock(instance->cid, instance->port);
	if (sd < 0)
		die("Failed to connect to vsocket @%u:%u",
		    instance->cid, instance->port);

	msg_handle = tracecmd_msg_handle_alloc(sd, 0);
	if (!msg_handle)
		die("Failed to allocate message handle");

	ret = tracecmd_msg_send_trace_req(msg_handle, instance->argc,
					  instance->argv, use_fifos);
	if (ret < 0)
		die("Failed to send trace request");

	ret = tracecmd_msg_recv_trace_resp(msg_handle, &nr_cpus, &page_size,
					   &ports, &use_fifos);
	if (ret < 0)
		die("Failed to receive trace response");

	if (use_fifos) {
		if (nr_cpus != nr_fifos) {
			warning("number of FIFOs (%d) for guest %s differs "
				"from number of virtual CPUs (%d)",
				nr_fifos, name, nr_cpus);
			nr_cpus = nr_cpus < nr_fifos ? nr_cpus : nr_fifos;
		}
		free(ports);
		instance->fds = fds;
	} else {
		for (i = 0; i < nr_fifos; i++)
			close(fds[i]);
		free(fds);
		instance->client_ports = ports;
	}

	instance->use_fifos = use_fifos;
	instance->cpu_count = nr_cpus;

	/* the msg_handle now points to the guest fd */
	instance->msg_handle = msg_handle;
}

static void setup_guest(struct buffer_instance *instance)
{
	struct tracecmd_msg_handle *msg_handle = instance->msg_handle;
	char *file;
	int fd;

	/* Create a place to store the guest meta data */
	file = get_guest_file(output_file,
			      tracefs_instance_get_name(instance->tracefs));
	if (!file)
		die("Failed to allocate memory");

	fd = open(file, O_CREAT|O_WRONLY|O_TRUNC, 0644);
	put_temp_file(file);
	if (fd < 0)
		die("Failed to open", file);

	/* Start reading tracing metadata */
	if (tracecmd_msg_read_data(msg_handle, fd))
		die("Failed receiving metadata");
	close(fd);
}

static void setup_agent(struct buffer_instance *instance, struct common_record_context *ctx)
{
	struct tracecmd_output *network_handle;

	network_handle = tracecmd_create_init_fd_msg(instance->msg_handle,
						     listed_events);
	add_options(network_handle, ctx);
	tracecmd_write_cpus(network_handle, instance->cpu_count);
	tracecmd_write_options(network_handle);
	tracecmd_msg_finish_sending_data(instance->msg_handle);
	instance->network_handle = network_handle;
}

void start_threads(enum trace_type type, struct common_record_context *ctx)
{
	struct buffer_instance *instance;
	int total_cpu_count = 0;
	int i = 0;
	int ret;

	for_all_instances(instance) {
		/* Start the connection now to find out how many CPUs we need */
		if (is_guest(instance))
			connect_to_agent(instance);
		total_cpu_count += instance->cpu_count;
	}

	/* make a thread for every CPU we have */
	pids = calloc(total_cpu_count * (buffers + 1), sizeof(*pids));
	if (!pids)
		die("Failed to allocate pids for %d cpus", total_cpu_count);

	for_all_instances(instance) {
		int *brass = NULL;
		int x, pid;

		if (is_agent(instance)) {
			setup_agent(instance, ctx);
		} else if (is_guest(instance)) {
			setup_guest(instance);
		} else if (host) {
			instance->msg_handle = setup_connection(instance, ctx);
			if (!instance->msg_handle)
				die("Failed to make connection");
		}

		for (x = 0; x < instance->cpu_count; x++) {
			if (type & TRACE_TYPE_STREAM) {
				brass = pids[i].brass;
				ret = pipe(brass);
				if (ret < 0)
					die("pipe");
				pids[i].stream = trace_stream_init(instance, x,
								   brass[0],
								   instance->cpu_count,
								   hooks, handle_init,
								   ctx->global);
				if (!pids[i].stream)
					die("Creating stream for %d", i);
			} else
				pids[i].brass[0] = -1;
			pids[i].cpu = x;
			pids[i].instance = instance;
			/* Make sure all output is flushed before forking */
			fflush(stdout);
			pid = pids[i++].pid = create_recorder(instance, x, type, brass);
			if (brass)
				close(brass[1]);
			if (pid > 0)
				add_filter_pid(pid, 1);
		}
	}
	recorder_threads = i;
}

static void touch_file(const char *file)
{
	int fd;

	fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		die("could not create file %s\n", file);
	close(fd);
}

static void append_buffer(struct tracecmd_output *handle,
			  struct tracecmd_option *buffer_option,
			  struct buffer_instance *instance,
			  char **temp_files)
{
	int cpu_count = instance->cpu_count;
	int i;

	/*
	 * Since we can record remote and virtual machines in the same file
	 * as the host, the buffers may no longer have matching number of
	 * CPU data as the host. For backward compatibility for older
	 * trace-cmd versions, which will blindly read the number of CPUs
	 * for each buffer instance as there are for the host, if there are
	 * fewer CPUs on the remote machine than on the host, an "empty"
	 * CPU is needed for each CPU that the host has that the remote does
	 * not. If there are more CPUs on the remote, older executables will
	 * simply ignore them (which is OK, we only need to guarantee that
	 * old executables don't crash).
	 */
	if (instance->cpu_count < local_cpu_count)
		cpu_count = local_cpu_count;

	for (i = 0; i < cpu_count; i++) {
		temp_files[i] = get_temp_file(instance, i);
		if (i >= instance->cpu_count)
			touch_file(temp_files[i]);
	}

	tracecmd_append_buffer_cpu_data(handle, buffer_option,
					cpu_count, temp_files);

	for (i = 0; i < instance->cpu_count; i++) {
		if (i >= instance->cpu_count)
			delete_temp_file(instance, i);
		put_temp_file(temp_files[i]);
	}
}


static void
add_pid_maps(struct tracecmd_output *handle, struct buffer_instance *instance)
{
	struct pid_addr_maps *maps = instance->pid_maps;
	struct trace_seq s;
	int i;

	trace_seq_init(&s);
	while (maps) {
		if (!maps->nr_lib_maps) {
			maps = maps->next;
			continue;
		}
		trace_seq_reset(&s);
		trace_seq_printf(&s, "%x %x %s\n",
				 maps->pid, maps->nr_lib_maps, maps->proc_name);
		for (i = 0; i < maps->nr_lib_maps; i++)
			trace_seq_printf(&s, "%llx %llx %s\n",
					maps->lib_maps[i].start,
					maps->lib_maps[i].end,
					maps->lib_maps[i].lib_name);
		trace_seq_terminate(&s);
		tracecmd_add_option(handle, TRACECMD_OPTION_PROCMAPS,
				    s.len + 1, s.buffer);
		maps = maps->next;
	}
	trace_seq_destroy(&s);
}

static void
add_buffer_stat(struct tracecmd_output *handle, struct buffer_instance *instance)
{
	struct trace_seq s;
	int i;

	trace_seq_init(&s);
	trace_seq_printf(&s, "\nBuffer: %s\n\n",
			tracefs_instance_get_name(instance->tracefs));
	tracecmd_add_option(handle, TRACECMD_OPTION_CPUSTAT,
			    s.len+1, s.buffer);
	trace_seq_destroy(&s);

	for (i = 0; i < instance->cpu_count; i++)
		tracecmd_add_option(handle, TRACECMD_OPTION_CPUSTAT,
				    instance->s_save[i].len+1,
				    instance->s_save[i].buffer);
}

static void add_option_hooks(struct tracecmd_output *handle)
{
	struct hook_list *hook;
	int len;

	for (hook = hooks; hook; hook = hook->next) {
		len = strlen(hook->hook);
		tracecmd_add_option(handle, TRACECMD_OPTION_HOOK,
				    len + 1, hook->hook);
	}
}

static void add_uname(struct tracecmd_output *handle)
{
	struct utsname buf;
	char *str;
	int len;
	int ret;

	ret = uname(&buf);
	/* if this fails for some reason, just ignore it */
	if (ret < 0)
		return;

	len = strlen(buf.sysname) + strlen(buf.nodename) +
		strlen(buf.release) + strlen(buf.machine) + 4;
	str = malloc(len);
	if (!str)
		return;
	sprintf(str, "%s %s %s %s", buf.sysname, buf.nodename, buf.release, buf.machine);
	tracecmd_add_option(handle, TRACECMD_OPTION_UNAME, len, str);
	free(str);
}

static void add_version(struct tracecmd_output *handle)
{
	char *str;
	int len;

	len = asprintf(&str, "%s %s", VERSION_STRING, VERSION_GIT);
	if (len < 0)
		return;

	tracecmd_add_option(handle, TRACECMD_OPTION_VERSION, len+1, str);
	free(str);
}

static void print_stat(struct buffer_instance *instance)
{
	int cpu;

	if (quiet)
		return;

	if (!is_top_instance(instance))
		printf("\nBuffer: %s\n\n",
			tracefs_instance_get_name(instance->tracefs));

	for (cpu = 0; cpu < instance->cpu_count; cpu++)
		trace_seq_do_printf(&instance->s_print[cpu]);
}

enum {
	DATA_FL_NONE		= 0,
	DATA_FL_DATE		= 1,
	DATA_FL_OFFSET		= 2,
};

static void add_options(struct tracecmd_output *handle, struct common_record_context *ctx)
{
	int type = 0;

	if (ctx->date2ts) {
		if (ctx->data_flags & DATA_FL_DATE)
			type = TRACECMD_OPTION_DATE;
		else if (ctx->data_flags & DATA_FL_OFFSET)
			type = TRACECMD_OPTION_OFFSET;
	}

	if (type)
		tracecmd_add_option(handle, type, strlen(ctx->date2ts)+1, ctx->date2ts);

	tracecmd_add_option(handle, TRACECMD_OPTION_TRACECLOCK, 0, NULL);
	add_option_hooks(handle);
	add_uname(handle);
	add_version(handle);
}

static void write_guest_file(struct buffer_instance *instance)
{
	struct tracecmd_output *handle;
	int cpu_count = instance->cpu_count;
	char *file;
	char **temp_files;
	int i, fd;

	file = get_guest_file(output_file,
			      tracefs_instance_get_name(instance->tracefs));
	if (!file)
		die("Failed to allocate memory");

	fd = open(file, O_RDWR);
	if (fd < 0)
		die("error opening %s", file);
	put_temp_file(file);

	handle = tracecmd_get_output_handle_fd(fd);
	if (!handle)
		die("error writing to %s", file);

	temp_files = malloc(sizeof(*temp_files) * cpu_count);
	if (!temp_files)
		die("failed to allocate temp_files for %d cpus",
		    cpu_count);

	for (i = 0; i < cpu_count; i++) {
		temp_files[i] = get_temp_file(instance, i);
		if (!temp_files[i])
			die("failed to allocate memory");
	}

	if (tracecmd_write_cpu_data(handle, cpu_count, temp_files) < 0)
		die("failed to write CPU data");
	tracecmd_output_close(handle);

	for (i = 0; i < cpu_count; i++)
		put_temp_file(temp_files[i]);
	free(temp_files);
}

static void record_data(struct common_record_context *ctx)
{
	struct tracecmd_option **buffer_options;
	struct tracecmd_output *handle;
	struct buffer_instance *instance;
	bool local = false;
	int max_cpu_count = local_cpu_count;
	char **temp_files;
	int i;

	for_all_instances(instance) {
		if (is_guest(instance))
			write_guest_file(instance);
		else if (host && instance->msg_handle)
			finish_network(instance->msg_handle);
		else
			local = true;
	}

	if (!local)
		return;

	if (latency) {
		handle = tracecmd_create_file_latency(output_file, local_cpu_count);
		tracecmd_set_quiet(handle, quiet);
	} else {
		if (!local_cpu_count)
			return;

		/* Allocate enough temp files to handle each instance */
		for_all_instances(instance) {
			if (instance->msg_handle)
				continue;
			if (instance->cpu_count > max_cpu_count)
				max_cpu_count = instance->cpu_count;
		}

		temp_files = malloc(sizeof(*temp_files) * max_cpu_count);
		if (!temp_files)
			die("Failed to allocate temp_files for %d cpus",
			    local_cpu_count);

		for (i = 0; i < max_cpu_count; i++)
			temp_files[i] = get_temp_file(&top_instance, i);

		/*
		 * If top_instance was not used, we still need to create
		 * empty trace.dat files for it.
		 */
		if (no_top_instance() || top_instance.msg_handle) {
			for (i = 0; i < local_cpu_count; i++)
				touch_file(temp_files[i]);
		}

		handle = tracecmd_create_init_file_glob(output_file, listed_events);
		if (!handle)
			die("Error creating output file");
		tracecmd_set_quiet(handle, quiet);

		add_options(handle, ctx);

		/* Only record the top instance under TRACECMD_OPTION_CPUSTAT*/
		if (!no_top_instance() && !top_instance.msg_handle) {
			struct trace_seq *s = top_instance.s_save;

			for (i = 0; i < local_cpu_count; i++)
				tracecmd_add_option(handle, TRACECMD_OPTION_CPUSTAT,
						    s[i].len+1, s[i].buffer);
		}

		if (buffers) {
			buffer_options = malloc(sizeof(*buffer_options) * buffers);
			if (!buffer_options)
				die("Failed to allocate buffer options");
			i = 0;
			for_each_instance(instance) {
				int cpus = instance->cpu_count != local_cpu_count ?
					instance->cpu_count : 0;

				if (instance->msg_handle)
					continue;

				buffer_options[i++] = tracecmd_add_buffer_option(handle,
										 tracefs_instance_get_name(instance->tracefs),
										 cpus);
				add_buffer_stat(handle, instance);
			}
		}

		if (!no_top_instance() && !top_instance.msg_handle)
			print_stat(&top_instance);

		for_all_instances(instance) {
			add_pid_maps(handle, instance);
		}

		tracecmd_append_cpu_data(handle, local_cpu_count, temp_files);

		for (i = 0; i < max_cpu_count; i++)
			put_temp_file(temp_files[i]);

		if (buffers) {
			i = 0;
			for_each_instance(instance) {
				if (instance->msg_handle)
					continue;
				print_stat(instance);
				append_buffer(handle, buffer_options[i++], instance, temp_files);
			}
		}

		free(temp_files);
	}
	if (!handle)
		die("could not write to file");
	tracecmd_output_close(handle);
}

static int write_func_file(struct buffer_instance *instance,
			    const char *file, struct func_list **list)
{
	struct func_list *item;
	const char *prefix = ":mod:";
	char *path;
	int fd;
	int ret = -1;

	if (!*list)
		return 0;

	path = tracefs_instance_get_file(instance->tracefs, file);

	fd = open(path, O_WRONLY | O_TRUNC);
	if (fd < 0)
		goto free;

	while (*list) {
		item = *list;
		*list = item->next;
		ret = write(fd, item->func, strlen(item->func));
		if (ret < 0)
			goto failed;
		if (item->mod) {
			ret = write(fd, prefix, strlen(prefix));
			if (ret < 0)
				goto failed;
			ret = write(fd, item->mod, strlen(item->mod));
			if (ret < 0)
				goto failed;
		}
		ret = write(fd, " ", 1);
		if (ret < 0)
			goto failed;
		free(item);
	}
	close(fd);
	ret = 0;
 free:
	tracefs_put_tracing_file(path);
	return ret;
 failed:
	die("Failed to write %s to %s.\n"
	    "Perhaps this function is not available for tracing.\n"
	    "run 'trace-cmd list -f %s' to see if it is.",
	    item->func, file, item->func);
	return ret;
}

static int functions_filtered(struct buffer_instance *instance)
{
	char buf[1] = { '#' };
	char *path;
	int fd;

	path = tracefs_instance_get_file(instance->tracefs, "set_ftrace_filter");
	fd = open(path, O_RDONLY);
	tracefs_put_tracing_file(path);
	if (fd < 0) {
		if (is_top_instance(instance))
			warning("Can not set set_ftrace_filter");
		else
			warning("Can not set set_ftrace_filter for %s",
				tracefs_instance_get_name(instance->tracefs));
		return 0;
	}

	/*
	 * If functions are not filtered, than the first character
	 * will be '#'. Make sure it is not an '#' and also not space.
	 */
	read(fd, buf, 1);
	close(fd);

	if (buf[0] == '#' || isspace(buf[0]))
		return 0;
	return 1;
}

static void set_funcs(struct buffer_instance *instance)
{
	int set_notrace = 0;
	int ret;

	if (is_guest(instance))
		return;

	ret = write_func_file(instance, "set_ftrace_filter", &instance->filter_funcs);
	if (ret < 0)
		die("set_ftrace_filter does not exist. Can not filter functions");

	/* graph tracing currently only works for top instance */
	if (is_top_instance(instance)) {
		ret = write_func_file(instance, "set_graph_function", &graph_funcs);
		if (ret < 0)
			die("set_graph_function does not exist.");
		if (instance->plugin && strcmp(instance->plugin, "function_graph") == 0) {
			ret = write_func_file(instance, "set_graph_notrace",
					      &instance->notrace_funcs);
			if (!ret)
				set_notrace = 1;
		}
		if (!set_notrace) {
			ret = write_func_file(instance, "set_ftrace_notrace",
					      &instance->notrace_funcs);
			if (ret < 0)
				die("set_ftrace_notrace does not exist. Can not filter functions");
		}
	} else
		write_func_file(instance, "set_ftrace_notrace", &instance->notrace_funcs);

	/* make sure we are filtering functions */
	if (func_stack && is_top_instance(instance)) {
		if (!functions_filtered(instance))
			die("Function stack trace set, but functions not filtered");
		save_option(FUNC_STACK_TRACE);
	}
	clear_function_filters = 1;
}

static void add_func(struct func_list **list, const char *mod, const char *func)
{
	struct func_list *item;

	item = malloc(sizeof(*item));
	if (!item)
		die("Failed to allocate function descriptor");
	item->func = func;
	item->mod = mod;
	item->next = *list;
	*list = item;
}

static int find_ts(struct tep_event *event, struct tep_record *record,
		   int cpu, void *context)
{
	unsigned long long *ts = (unsigned long long *)context;
	struct tep_format_field *field;

	if (!ts)
		return -1;

	field = tep_find_field(event, "buf");
	if (field && strcmp(STAMP"\n", record->data + field->offset) == 0) {
		*ts = record->ts;
		return 1;
	}

	return 0;
}

static unsigned long long find_time_stamp(struct tep_handle *tep)
{
	unsigned long long ts = 0;

	if (!tracefs_iterate_raw_events(tep, NULL, find_ts, &ts))
		return ts;

	return 0;
}


static char *read_top_file(char *file, int *psize)
{
	return tracefs_instance_file_read(top_instance.tracefs, file, psize);
}

/*
 * Try to write the date into the ftrace buffer and then
 * read it back, mapping the timestamp to the date.
 */
static char *get_date_to_ts(void)
{
	const char *systems[] = {"ftrace", NULL};
	unsigned long long min = -1ULL;
	unsigned long long diff;
	unsigned long long stamp;
	unsigned long long min_stamp;
	unsigned long long min_ts;
	unsigned long long ts;
	struct tep_handle *tep;
	struct timespec start;
	struct timespec end;
	char *date2ts = NULL;
	char *path;
	char *buf;
	int size;
	int tfd;
	int ret;
	int i;

	/* Set up a tep to read the raw format */
	tep = tracefs_local_events_system(NULL, systems);
	if (!tep) {
		warning("failed to alloc tep, --date ignored");
		return NULL;
	}

	tep_set_file_bigendian(tep, tracecmd_host_bigendian());

	buf = read_top_file("events/header_page", &size);
	if (!buf)
		goto out_pevent;
	ret = tep_parse_header_page(tep, buf, size, sizeof(unsigned long));
	free(buf);
	if (ret < 0) {
		warning("Can't parse header page, --date ignored");
		goto out_pevent;
	}

	path = tracefs_get_tracing_file("trace_marker");
	tfd = open(path, O_WRONLY);
	tracefs_put_tracing_file(path);
	if (tfd < 0) {
		warning("Can not open 'trace_marker', --date ignored");
		goto out_pevent;
	}

	for (i = 0; i < date2ts_tries; i++) {
		tracecmd_disable_tracing();
		clear_trace_instances();
		tracecmd_enable_tracing();

		clock_gettime(CLOCK_REALTIME, &start);
		write(tfd, STAMP, 5);
		clock_gettime(CLOCK_REALTIME, &end);

		tracecmd_disable_tracing();
		ts = find_time_stamp(tep);
		if (!ts)
			continue;

		diff = (unsigned long long)end.tv_sec * 1000000000LL;
		diff += (unsigned long long)end.tv_nsec;
		stamp = diff;
		diff -= (unsigned long long)start.tv_sec * 1000000000LL;
		diff -= (unsigned long long)start.tv_nsec;

		if (diff < min) {
			min_ts = ts;
			min_stamp = stamp - diff / 2;
			min = diff;
		}
	}

	close(tfd);

	if (min == -1ULL) {
		warning("Failed to make date offset, --date ignored");
		goto out_pevent;
	}

	/* 16 hex chars + 0x + \0 */
	date2ts = malloc(19);
	if (!date2ts)
		goto out_pevent;

	/*
	 * The difference between the timestamp and the gtod is
	 * stored as an ASCII string in hex.
	 */
	diff = min_stamp - min_ts;
	snprintf(date2ts, 19, "0x%llx", diff/1000);
 out_pevent:
	tep_free(tep);

	return date2ts;
}

static void set_buffer_size_instance(struct buffer_instance *instance)
{
	int buffer_size = instance->buffer_size;
	char buf[BUFSIZ];
	char *path;
	int ret;
	int fd;

	if (is_guest(instance))
		return;

	if (!buffer_size)
		return;

	if (buffer_size < 0)
		die("buffer size must be positive");

	snprintf(buf, BUFSIZ, "%d", buffer_size);

	path = tracefs_instance_get_file(instance->tracefs, "buffer_size_kb");
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		warning("can't open %s", path);
		goto out;
	}

	ret = write(fd, buf, strlen(buf));
	if (ret < 0)
		warning("Can't write to %s", path);
	close(fd);
 out:
	tracefs_put_tracing_file(path);
}

void set_buffer_size(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		set_buffer_size_instance(instance);
}

static int
process_event_trigger(char *path, struct event_iter *iter)
{
	const char *system = iter->system_dent->d_name;
	const char *event = iter->event_dent->d_name;
	struct stat st;
	char *trigger = NULL;
	char *file;
	int ret;

	path = append_file(path, system);
	file = append_file(path, event);
	free(path);

	ret = stat(file, &st);
	if (ret < 0 || !S_ISDIR(st.st_mode))
		goto out;

	trigger = append_file(file, "trigger");

	ret = stat(trigger, &st);
	if (ret < 0)
		goto out;

	ret = clear_trigger(trigger);
 out:
	free(trigger);
	free(file);
	return ret;
}

static void clear_instance_triggers(struct buffer_instance *instance)
{
	enum event_iter_type type;
	struct event_iter *iter;
	char *system;
	char *path;
	int retry = 0;
	int ret;

	path = tracefs_instance_get_file(instance->tracefs, "events");
	if (!path)
		die("malloc");

	iter = trace_event_iter_alloc(path);

	system = NULL;
	while ((type = trace_event_iter_next(iter, path, system))) {

		if (type == EVENT_ITER_SYSTEM) {
			system = iter->system_dent->d_name;
			continue;
		}

		ret = process_event_trigger(path, iter);
		if (ret > 0)
			retry++;
	}

	trace_event_iter_free(iter);

	if (retry) {
		int i;

		/* Order matters for some triggers */
		for (i = 0; i < retry; i++) {
			int tries = 0;

			iter = trace_event_iter_alloc(path);
			system = NULL;
			while ((type = trace_event_iter_next(iter, path, system))) {

				if (type == EVENT_ITER_SYSTEM) {
					system = iter->system_dent->d_name;
					continue;
				}

				ret = process_event_trigger(path, iter);
				if (ret > 0)
					tries++;
			}
			trace_event_iter_free(iter);
			if (!tries)
				break;
		}
	}

	tracefs_put_tracing_file(path);
}

static void
process_event_filter(char *path, struct event_iter *iter, enum event_process *processed)
{
	const char *system = iter->system_dent->d_name;
	const char *event = iter->event_dent->d_name;
	struct stat st;
	char *filter = NULL;
	char *file;
	int ret;

	path = append_file(path, system);
	file = append_file(path, event);
	free(path);

	ret = stat(file, &st);
	if (ret < 0 || !S_ISDIR(st.st_mode))
		goto out;

	filter = append_file(file, "filter");

	ret = stat(filter, &st);
	if (ret < 0)
		goto out;

	clear_filter(filter);
 out:
	free(filter);
	free(file);
}

static void clear_instance_filters(struct buffer_instance *instance)
{
	struct event_iter *iter;
	char *path;
	char *system;
	enum event_iter_type type;
	enum event_process processed = PROCESSED_NONE;

	path = tracefs_instance_get_file(instance->tracefs, "events");
	if (!path)
		die("malloc");

	iter = trace_event_iter_alloc(path);

	processed = PROCESSED_NONE;
	system = NULL;
	while ((type = trace_event_iter_next(iter, path, system))) {

		if (type == EVENT_ITER_SYSTEM) {
			system = iter->system_dent->d_name;
			continue;
		}

		process_event_filter(path, iter, &processed);
	}

	trace_event_iter_free(iter);

	tracefs_put_tracing_file(path);
}

static void clear_filters(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		clear_instance_filters(instance);
}

static void reset_clock(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		tracefs_instance_file_write(instance->tracefs,
					    "trace_clock", "local");
}

static void reset_cpu_mask(void)
{
	struct buffer_instance *instance;
	int cpus = tracecmd_count_cpus();
	int fullwords = (cpus - 1) / 32;
	int bits = (cpus - 1) % 32 + 1;
	int len = (fullwords + 1) * 9;
	char buf[len + 1];

	buf[0] = '\0';

	sprintf(buf, "%x", (unsigned int)((1ULL << bits) - 1));
	while (fullwords-- > 0)
		strcat(buf, ",ffffffff");

	for_all_instances(instance)
		tracefs_instance_file_write(instance->tracefs,
					    "tracing_cpumask", buf);
}

static void reset_event_pid(void)
{
	add_event_pid("");
}

static void clear_triggers(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		clear_instance_triggers(instance);
}

static void clear_all_synth_events(void)
{
	char sevent[BUFSIZ];
	char *save = NULL;
	char *line;
	char *file;
	char *buf;
	int len;

	file = tracefs_instance_get_file(NULL, "synthetic_events");
	if (!file)
		return;

	buf = read_file(file);
	if (!buf)
		goto out;

	sevent[0] = '!';

	for (line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		len = strlen(line);
		if (len > BUFSIZ - 2)
			len = BUFSIZ - 2;
		strncpy(sevent + 1, line, len);
		sevent[len + 1] = '\0';
		write_file(file, sevent);
	}
out:
	free(buf);
	tracefs_put_tracing_file(file);

}



static void clear_func_filters(void)
{
	struct buffer_instance *instance;
	char *path;
	int i;
	const char * const files[] = { "set_ftrace_filter",
				      "set_ftrace_notrace",
				      "set_graph_function",
				      "set_graph_notrace",
				      NULL };

	for_all_instances(instance) {
		for (i = 0; files[i]; i++) {
			path = tracefs_instance_get_file(instance->tracefs, files[i]);
			clear_func_filter(path);
			tracefs_put_tracing_file(path);
		}
	}
}

static void make_instances(void)
{
	struct buffer_instance *instance;

	for_each_instance(instance) {
		if (is_guest(instance))
			continue;
		if (tracefs_instance_create(instance->tracefs) > 0) {
			/* Don't delete instances that already exist */
			instance->flags |= BUFFER_FL_KEEP;
		}
	}
}

void tracecmd_remove_instances(void)
{
	struct buffer_instance *instance;

	for_each_instance(instance) {
		/* Only delete what we created */
		if (is_guest(instance) || (instance->flags & BUFFER_FL_KEEP))
			continue;
		if (instance->tracing_on_fd > 0) {
			close(instance->tracing_on_fd);
			instance->tracing_on_fd = 0;
		}
		tracefs_instance_destroy(instance->tracefs);
	}
}

/**
 * tracecmd_create_top_instance - create a top named instance
 * @name: name of the instance to use.
 *
 * This is a library function for tools that want to do their tracing inside of
 * an instance.  All it does is create an instance and set it as a top instance,
 * you don't want to call this more than once, and you want to call
 * tracecmd_remove_instances to undo your work.
 */
void tracecmd_create_top_instance(char *name)
{
	struct buffer_instance *instance;

	instance = create_instance(name);
	add_instance(instance, local_cpu_count);
	update_first_instance(instance, 0);
	make_instances();
}

static void check_plugin(const char *plugin)
{
	char *buf;
	char *str;
	char *tok;

	/*
	 * nop is special. We may want to just trace
	 * trace_printks, that are in the kernel.
	 */
	if (strcmp(plugin, "nop") == 0)
		return;

	buf = read_top_file("available_tracers", NULL);
	if (!buf)
		die("No plugins available");

	str = buf;
	while ((tok = strtok(str, " "))) {
		str = NULL;
		if (strcmp(tok, plugin) == 0)
			goto out;
	}
	die ("Plugin '%s' does not exist", plugin);
 out:
	if (!quiet)
		fprintf(stderr, "  plugin '%s'\n", plugin);
	free(buf);
}

static void check_function_plugin(void)
{
	const char *plugin;

	/* We only care about the top_instance */
	if (no_top_instance())
		return;

	plugin = top_instance.plugin;
	if (!plugin)
		return;

	if (plugin && strncmp(plugin, "function", 8) == 0 &&
	    func_stack && !top_instance.filter_funcs)
		die("Must supply function filtering with --func-stack\n");
}

static int __check_doing_something(struct buffer_instance *instance)
{
	return is_guest(instance) || (instance->flags & BUFFER_FL_PROFILE) ||
		instance->plugin || instance->events;
}

static void check_doing_something(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance) {
		if (__check_doing_something(instance))
			return;
	}

	die("no event or plugin was specified... aborting");
}

static void
update_plugin_instance(struct buffer_instance *instance,
		       enum trace_type type)
{
	const char *plugin = instance->plugin;

	if (is_guest(instance))
		return;

	if (!plugin)
		return;

	check_plugin(plugin);

	/*
	 * Latency tracers just save the trace and kill
	 * the threads.
	 */
	if (strcmp(plugin, "irqsoff") == 0 ||
	    strcmp(plugin, "preemptoff") == 0 ||
	    strcmp(plugin, "preemptirqsoff") == 0 ||
	    strcmp(plugin, "wakeup") == 0 ||
	    strcmp(plugin, "wakeup_rt") == 0) {
		latency = 1;
		if (host)
			die("Network tracing not available with latency tracer plugins");
		if (type & TRACE_TYPE_STREAM)
			die("Streaming is not available with latency tracer plugins");
	} else if (type == TRACE_TYPE_RECORD) {
		if (latency)
			die("Can not record latency tracer and non latency trace together");
	}

	if (fset < 0 && (strcmp(plugin, "function") == 0 ||
			 strcmp(plugin, "function_graph") == 0))
		die("function tracing not configured on this kernel");

	if (type != TRACE_TYPE_EXTRACT)
		set_plugin_instance(instance, plugin);
}

static void update_plugins(enum trace_type type)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		update_plugin_instance(instance, type);
}

static void allocate_seq(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance) {
		instance->s_save = malloc(sizeof(struct trace_seq) * instance->cpu_count);
		instance->s_print = malloc(sizeof(struct trace_seq) * instance->cpu_count);
		if (!instance->s_save || !instance->s_print)
			die("Failed to allocate instance info");
	}
}

/* Find the overrun output, and add it to the print seq */
static void add_overrun(int cpu, struct trace_seq *src, struct trace_seq *dst)
{
	const char overrun_str[] = "overrun: ";
	const char commit_overrun_str[] = "commit overrun: ";
	const char *p;
	int overrun;
	int commit_overrun;

	p = strstr(src->buffer, overrun_str);
	if (!p) {
		/* Warn? */
		trace_seq_printf(dst, "CPU %d: no overrun found?\n", cpu);
		return;
	}

	overrun = atoi(p + strlen(overrun_str));

	p = strstr(p + 9, commit_overrun_str);
	if (p)
		commit_overrun = atoi(p + strlen(commit_overrun_str));
	else
		commit_overrun = -1;

	if (!overrun && !commit_overrun)
		return;

	trace_seq_printf(dst, "CPU %d:", cpu);

	if (overrun)
		trace_seq_printf(dst, " %d events lost", overrun);

	if (commit_overrun)
		trace_seq_printf(dst, " %d events lost due to commit overrun",
				 commit_overrun);

	trace_seq_putc(dst, '\n');
}

static void record_stats(void)
{
	struct buffer_instance *instance;
	struct trace_seq *s_save;
	struct trace_seq *s_print;
	int cpu;

	for_all_instances(instance) {
		if (is_guest(instance))
			continue;

		s_save = instance->s_save;
		s_print = instance->s_print;
		for (cpu = 0; cpu < instance->cpu_count; cpu++) {
			trace_seq_init(&s_save[cpu]);
			trace_seq_init(&s_print[cpu]);
			trace_seq_printf(&s_save[cpu], "CPU: %d\n", cpu);
			tracecmd_stat_cpu_instance(instance, &s_save[cpu], cpu);
			add_overrun(cpu, &s_save[cpu], &s_print[cpu]);
		}
	}
}

static void print_stats(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		print_stat(instance);
}

static void destroy_stats(void)
{
	struct buffer_instance *instance;
	int cpu;

	for_all_instances(instance) {
		if (is_guest(instance))
			continue;

		for (cpu = 0; cpu < instance->cpu_count; cpu++) {
			trace_seq_destroy(&instance->s_save[cpu]);
			trace_seq_destroy(&instance->s_print[cpu]);
		}
	}
}

static void list_event(const char *event)
{
	struct tracecmd_event_list *list;

	list = malloc(sizeof(*list));
	if (!list)
		die("Failed to allocate list for event");
	list->next = listed_events;
	list->glob = event;
	listed_events = list;
}

#define ALL_EVENTS "*/*"

static void record_all_events(void)
{
	struct tracecmd_event_list *list;

	while (listed_events) {
		list = listed_events;
		listed_events = list->next;
		free(list);
	}
	list = malloc(sizeof(*list));
	if (!list)
		die("Failed to allocate list for all events");
	list->next = NULL;
	list->glob = ALL_EVENTS;
	listed_events = list;
}

static int recording_all_events(void)
{
	return listed_events && strcmp(listed_events->glob, ALL_EVENTS) == 0;
}

static void add_trigger(struct event_list *event, const char *trigger)
{
	int ret;

	if (event->trigger) {
		event->trigger = realloc(event->trigger,
					 strlen(event->trigger) + strlen("\n") +
					 strlen(trigger) + 1);
		strcat(event->trigger, "\n");
		strcat(event->trigger, trigger);
	} else {
		ret = asprintf(&event->trigger, "%s", trigger);
		if (ret < 0)
			die("Failed to allocate event trigger");
	}
}

static int test_stacktrace_trigger(struct buffer_instance *instance)
{
	char *path;
	int ret = 0;
	int fd;

	path = tracefs_instance_get_file(instance->tracefs,
					 "events/sched/sched_switch/trigger");

	clear_trigger(path);

	fd = open(path, O_WRONLY);
	if (fd < 0)
		goto out;

	ret = write(fd, "stacktrace", 10);
	if (ret != 10)
		ret = 0;
	else
		ret = 1;
	close(fd);
 out:
	tracefs_put_tracing_file(path);

	return ret;
}

static int
profile_add_event(struct buffer_instance *instance, const char *event_str, int stack)
{
	struct event_list *event;
	char buf[BUFSIZ];
	char *p;

	strcpy(buf, "events/");
	strncpy(buf + 7, event_str, BUFSIZ - 7);
	buf[BUFSIZ-1] = 0;

	if ((p = strstr(buf, ":"))) {
		*p = '/';
		p++;
	}

	if (!trace_check_file_exists(instance, buf))
		return -1;

	/* Only add event if it isn't already added */
	for (event = instance->events; event; event = event->next) {
		if (p && strcmp(event->event, p) == 0)
			break;
		if (strcmp(event->event, event_str) == 0)
			break;
	}

	if (!event) {
		event = malloc(sizeof(*event));
		if (!event)
			die("Failed to allocate event");
		memset(event, 0, sizeof(*event));
		event->event = event_str;
		add_event(instance, event);
	}

	if (!recording_all_events())
		list_event(event_str);

	if (stack) {
		if (!event->trigger || !strstr(event->trigger, "stacktrace"))
			add_trigger(event, "stacktrace");
	}

	return 0;
}

int tracecmd_add_event(const char *event_str, int stack)
{
	return profile_add_event(first_instance, event_str, stack);
}

static void enable_profile(struct buffer_instance *instance)
{
	int stacktrace = 0;
	int i;
	char *trigger_events[] = {
		"sched:sched_switch",
		"sched:sched_wakeup",
		NULL,
	};
	char *events[] = {
		"exceptions:page_fault_user",
		"irq:irq_handler_entry",
		"irq:irq_handler_exit",
		"irq:softirq_entry",
		"irq:softirq_exit",
		"irq:softirq_raise",
		"sched:sched_process_exec",
		"raw_syscalls",
		NULL,
	};

	if (!instance->plugin) {
		if (trace_check_file_exists(instance, "max_graph_depth")) {
			instance->plugin = "function_graph";
			set_max_graph_depth(instance, "1");
		} else
			warning("Kernel does not support max_graph_depth\n"
				" Skipping user/kernel profiling");
	}

	if (test_stacktrace_trigger(instance))
		stacktrace = 1;
	else
		/*
		 * The stacktrace trigger is not implemented with this
		 * kernel, then we need to default to the stack trace option.
		 * This is less efficient but still works.
		 */
		save_option("stacktrace");


	for (i = 0; trigger_events[i]; i++)
		profile_add_event(instance, trigger_events[i], stacktrace);

	for (i = 0; events[i]; i++)
		profile_add_event(instance, events[i], 0);
}

static struct event_list *
create_hook_event(struct buffer_instance *instance,
		  const char *system, const char *event)
{
	struct event_list *event_list;
	char *event_name;
	int len;

	if (!system)
		system = "*";

	len = strlen(event);
	len += strlen(system) + 2;

	event_name = malloc(len);
	if (!event_name)
		die("Failed to allocate %s/%s", system, event);
	sprintf(event_name, "%s:%s", system, event);

	event_list = malloc(sizeof(*event_list));
	if (!event_list)
		die("Failed to allocate event list for %s", event_name);
	memset(event_list, 0, sizeof(*event_list));
	event_list->event = event_name;
	add_event(instance, event_list);

	list_event(event_name);

	return event_list;
}

static void add_hook(struct buffer_instance *instance, const char *arg)
{
	struct event_list *event;
	struct hook_list *hook;

	hook = tracecmd_create_event_hook(arg);
	if (!hook)
		die("Failed to create event hook %s", arg);

	hook->instance = instance;
	hook->next = hooks;
	hooks = hook;

	/* Make sure the event is enabled */
	event = create_hook_event(instance, hook->start_system, hook->start_event);
	create_hook_event(instance, hook->end_system, hook->end_event);

	if (hook->stack) {
		if (!event->trigger || !strstr(event->trigger, "stacktrace"))
			add_trigger(event, "stacktrace");
	}
}

void update_first_instance(struct buffer_instance *instance, int topt)
{
	if (topt || instance == &top_instance)
		first_instance = &top_instance;
	else
		first_instance = buffer_instances;
}

void init_top_instance(void)
{
	if (!top_instance.tracefs)
		top_instance.tracefs = tracefs_instance_alloc(NULL);
	top_instance.cpu_count = tracecmd_count_cpus();
	top_instance.flags = BUFFER_FL_KEEP;
	init_instance(&top_instance);
}

enum {
	OPT_user		= 243,
	OPT_procmap		= 244,
	OPT_quiet		= 245,
	OPT_debug		= 246,
	OPT_no_filter		= 247,
	OPT_max_graph_depth	= 248,
	OPT_tsoffset		= 249,
	OPT_bycomm		= 250,
	OPT_stderr		= 251,
	OPT_profile		= 252,
	OPT_nosplice		= 253,
	OPT_funcstack		= 254,
	OPT_date		= 255,
	OPT_module		= 256,
	OPT_nofifos		= 257,
	OPT_cmdlines_size	= 258,
};

void trace_stop(int argc, char **argv)
{
	int topt = 0;
	struct buffer_instance *instance = &top_instance;

	init_top_instance();

	for (;;) {
		int c;

		c = getopt(argc-1, argv+1, "hatB:");
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'B':
			instance = create_instance(optarg);
			if (!instance)
				die("Failed to create instance");
			add_instance(instance, local_cpu_count);
			break;
		case 'a':
			add_all_instances();
			break;
		case 't':
			/* Force to use top instance */
			topt = 1;
			instance = &top_instance;
			break;
		default:
			usage(argv);
		}
	}
	update_first_instance(instance, topt);
	tracecmd_disable_tracing();
	exit(0);
}

void trace_restart(int argc, char **argv)
{
	int topt = 0;
	struct buffer_instance *instance = &top_instance;

	init_top_instance();

	for (;;) {
		int c;

		c = getopt(argc-1, argv+1, "hatB:");
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'B':
			instance = create_instance(optarg);
			if (!instance)
				die("Failed to create instance");
			add_instance(instance, local_cpu_count);
			break;
		case 'a':
			add_all_instances();
			break;
		case 't':
			/* Force to use top instance */
			topt = 1;
			instance = &top_instance;
			break;
		default:
			usage(argv);
		}

	}
	update_first_instance(instance, topt);
	tracecmd_enable_tracing();
	exit(0);
}

void trace_reset(int argc, char **argv)
{
	int c;
	int topt = 0;
	struct buffer_instance *instance = &top_instance;

	init_top_instance();

	/* if last arg is -a, then -b and -d apply to all instances */
	int last_specified_all = 0;
	struct buffer_instance *inst; /* iterator */

	while ((c = getopt(argc-1, argv+1, "hab:B:td")) >= 0) {

		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'b':
		{
			int size = atoi(optarg);
			/* Min buffer size is 1 */
			if (size <= 1)
				size = 1;
			if (last_specified_all) {
				for_each_instance(inst) {
					inst->buffer_size = size;
				}
			} else {
				instance->buffer_size = size;
			}
			break;
		}
		case 'B':
			last_specified_all = 0;
			instance = create_instance(optarg);
			if (!instance)
				die("Failed to create instance");
			add_instance(instance, local_cpu_count);
			/* -d will remove keep */
			instance->flags |= BUFFER_FL_KEEP;
			break;
		case 't':
			/* Force to use top instance */
			last_specified_all = 0;
			topt = 1;
			instance = &top_instance;
			break;
		case 'a':
			last_specified_all = 1;
			add_all_instances();
			for_each_instance(inst) {
				inst->flags |= BUFFER_FL_KEEP;
			}
			break;
		case 'd':
			if (last_specified_all) {
				for_each_instance(inst) {
					inst->flags &= ~BUFFER_FL_KEEP;
				}
			} else {
				if (is_top_instance(instance))
					die("Can not delete top level buffer");
				instance->flags &= ~BUFFER_FL_KEEP;
			}
			break;
		}
	}
	update_first_instance(instance, topt);
	tracecmd_disable_all_tracing(1);
	set_buffer_size();
	clear_filters();
	clear_triggers();
	clear_all_synth_events();
	/* set clock to "local" */
	reset_clock();
	reset_event_pid();
	reset_max_latency_instance();
	reset_cpu_mask();
	tracecmd_remove_instances();
	clear_func_filters();
	/* restore tracing_on to 1 */
	tracecmd_enable_tracing();
	exit(0);
}

static void init_common_record_context(struct common_record_context *ctx,
				       enum trace_cmd curr_cmd)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->instance = &top_instance;
	ctx->curr_cmd = curr_cmd;
	local_cpu_count = tracecmd_count_cpus();
	init_top_instance();
}

#define IS_EXTRACT(ctx) ((ctx)->curr_cmd == CMD_extract)
#define IS_START(ctx) ((ctx)->curr_cmd == CMD_start)
#define IS_STREAM(ctx) ((ctx)->curr_cmd == CMD_stream)
#define IS_PROFILE(ctx) ((ctx)->curr_cmd == CMD_profile)
#define IS_RECORD(ctx) ((ctx)->curr_cmd == CMD_record)
#define IS_RECORD_AGENT(ctx) ((ctx)->curr_cmd == CMD_record_agent)

static void add_argv(struct buffer_instance *instance, char *arg, bool prepend)
{
	instance->argv = realloc(instance->argv,
				 (instance->argc + 1) * sizeof(char *));
	if (!instance->argv)
		die("Can not allocate instance args");
	if (prepend) {
		memmove(instance->argv + 1, instance->argv,
			instance->argc * sizeof(*instance->argv));
		instance->argv[0] = arg;
	} else {
		instance->argv[instance->argc] = arg;
	}
	instance->argc++;
}

static void add_arg(struct buffer_instance *instance,
		    int c, const char *opts,
		    struct option *long_options, char *optarg)
{
	char *ptr, *arg;
	int i, ret;

	/* Short or long arg */
	if (!(c & 0x80)) {
		ptr = strchr(opts, c);
		if (!ptr)
			return; /* Not found? */
		ret = asprintf(&arg, "-%c", c);
		if (ret < 0)
			die("Can not allocate argument");
		add_argv(instance, arg, false);
		if (ptr[1] == ':') {
			arg = strdup(optarg);
			if (!arg)
				die("Can not allocate arguments");
			add_argv(instance, arg, false);
		}
		return;
	}
	for (i = 0; long_options[i].name; i++) {
		if (c != long_options[i].val)
			continue;
		ret = asprintf(&arg, "--%s", long_options[i].name);
		if (ret < 0)
			die("Can not allocate argument");
		add_argv(instance, arg, false);
		if (long_options[i].has_arg) {
			arg = strdup(optarg);
			if (!arg)
				die("Can not allocate arguments");
			add_argv(instance, arg, false);
		}
		return;
	}
	/* Not found? */
}

static void parse_record_options(int argc,
				 char **argv,
				 enum trace_cmd curr_cmd,
				 struct common_record_context *ctx)
{
	const char *plugin = NULL;
	const char *option;
	struct event_list *event = NULL;
	struct event_list *last_event = NULL;
	char *pids;
	char *pid;
	char *sav;
	int name_counter = 0;
	int neg_event = 0;

	init_common_record_context(ctx, curr_cmd);

	for (;;) {
		int option_index = 0;
		int ret;
		int c;
		const char *opts;
		static struct option long_options[] = {
			{"date", no_argument, NULL, OPT_date},
			{"func-stack", no_argument, NULL, OPT_funcstack},
			{"nosplice", no_argument, NULL, OPT_nosplice},
			{"nofifos", no_argument, NULL, OPT_nofifos},
			{"profile", no_argument, NULL, OPT_profile},
			{"stderr", no_argument, NULL, OPT_stderr},
			{"by-comm", no_argument, NULL, OPT_bycomm},
			{"ts-offset", required_argument, NULL, OPT_tsoffset},
			{"max-graph-depth", required_argument, NULL, OPT_max_graph_depth},
			{"cmdlines-size", required_argument, NULL, OPT_cmdlines_size},
			{"no-filter", no_argument, NULL, OPT_no_filter},
			{"debug", no_argument, NULL, OPT_debug},
			{"quiet", no_argument, NULL, OPT_quiet},
			{"help", no_argument, NULL, '?'},
			{"proc-map", no_argument, NULL, OPT_procmap},
			{"user", required_argument, NULL, OPT_user},
			{"module", required_argument, NULL, OPT_module},
			{NULL, 0, NULL, 0}
		};

		if (IS_EXTRACT(ctx))
			opts = "+haf:Fp:co:O:sr:g:l:n:P:N:tb:B:ksiT";
		else
			opts = "+hae:f:FA:p:cC:dDGo:O:s:r:vg:l:n:P:N:tb:R:B:ksSiTm:M:H:q";
		c = getopt_long (argc-1, argv+1, opts, long_options, &option_index);
		if (c == -1)
			break;

		/*
		 * If the current instance is to record a guest, then save
		 * all the arguments for this instance.
		 */
		if (c != 'B' && c != 'A' && is_guest(ctx->instance)) {
			add_arg(ctx->instance, c, opts, long_options, optarg);
			continue;
		}

		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'a':
			if (IS_EXTRACT(ctx)) {
				add_all_instances();
			} else {
				ctx->record_all = 1;
				record_all_events();
			}
			break;
		case 'e':
			ctx->events = 1;
			event = malloc(sizeof(*event));
			if (!event)
				die("Failed to allocate event %s", optarg);
			memset(event, 0, sizeof(*event));
			event->event = optarg;
			add_event(ctx->instance, event);
			event->neg = neg_event;
			event->filter = NULL;
			last_event = event;

			if (!ctx->record_all)
				list_event(optarg);
			break;
		case 'f':
			if (!last_event)
				die("filter must come after event");
			if (last_event->filter) {
				last_event->filter =
					realloc(last_event->filter,
						strlen(last_event->filter) +
						strlen("&&()") +
						strlen(optarg) + 1);
				strcat(last_event->filter, "&&(");
				strcat(last_event->filter, optarg);
				strcat(last_event->filter, ")");
			} else {
				ret = asprintf(&last_event->filter, "(%s)", optarg);
				if (ret < 0)
					die("Failed to allocate filter %s", optarg);
			}
			break;

		case 'R':
			if (!last_event)
				die("trigger must come after event");
			add_trigger(event, optarg);
			break;

		case 'A': {
			char *name = NULL;
			int cid = -1, port = -1;

			if (!IS_RECORD(ctx))
				die("-A is only allowed for record operations");

			name = parse_guest_name(optarg, &cid, &port);
			if (cid == -1)
				die("guest %s not found", optarg);
			if (port == -1)
				port = TRACE_AGENT_DEFAULT_PORT;
			if (!name || !*name) {
				ret = asprintf(&name, "unnamed-%d", name_counter++);
				if (ret < 0)
					die("Failed to allocate guest name");
			}

			ctx->instance = create_instance(name);
			ctx->instance->flags |= BUFFER_FL_GUEST;
			ctx->instance->cid = cid;
			ctx->instance->port = port;
			add_instance(ctx->instance, 0);
			break;
		}
		case 'F':
			test_set_event_pid();
			filter_task = 1;
			break;
		case 'G':
			ctx->global = 1;
			break;
		case 'P':
			test_set_event_pid();
			pids = strdup(optarg);
			if (!pids)
				die("strdup");
			pid = strtok_r(pids, ",", &sav);
			while (pid) {
				add_filter_pid(atoi(pid), 0);
				pid = strtok_r(NULL, ",", &sav);
			}
			free(pids);
			break;
		case 'c':
			test_set_event_pid();
			if (!have_event_fork) {
#ifdef NO_PTRACE
				die("-c invalid: ptrace not supported");
#endif
				do_ptrace = 1;
				do_children = 1;
			} else {
				save_option("event-fork");
				ctx->do_child = 1;
			}
			break;
		case 'C':
			ctx->instance->clock = optarg;
			break;
		case 'v':
			neg_event = 1;
			break;
		case 'l':
			add_func(&ctx->instance->filter_funcs,
				 ctx->instance->filter_mod, optarg);
			ctx->filtered = 1;
			break;
		case 'n':
			add_func(&ctx->instance->notrace_funcs,
				 ctx->instance->filter_mod, optarg);
			ctx->filtered = 1;
			break;
		case 'g':
			add_func(&graph_funcs, ctx->instance->filter_mod, optarg);
			ctx->filtered = 1;
			break;
		case 'p':
			if (ctx->instance->plugin)
				die("only one plugin allowed");
			for (plugin = optarg; isspace(*plugin); plugin++)
				;
			ctx->instance->plugin = plugin;
			for (optarg += strlen(optarg) - 1;
			     optarg > plugin && isspace(*optarg); optarg--)
				;
			optarg++;
			optarg[0] = '\0';
			break;
		case 'D':
			ctx->total_disable = 1;
			/* fall through */
		case 'd':
			ctx->disable = 1;
			break;
		case 'o':
			if (IS_RECORD_AGENT(ctx))
				die("-o incompatible with agent recording");
			if (host)
				die("-o incompatible with -N");
			if (IS_START(ctx))
				die("start does not take output\n"
				    "Did you mean 'record'?");
			if (IS_STREAM(ctx))
				die("stream does not take output\n"
				    "Did you mean 'record'?");
			if (ctx->output)
				die("only one output file allowed");
			ctx->output = optarg;

			if (IS_PROFILE(ctx)) {
				int fd;

				/* pipe the output to this file instead of stdout */
				save_stdout = dup(1);
				close(1);
				fd = open(optarg, O_WRONLY | O_CREAT | O_TRUNC, 0644);
				if (fd < 0)
					die("can't write to %s", optarg);
				if (fd != 1) {
					dup2(fd, 1);
					close(fd);
				}
			}
			break;
		case 'O':
			option = optarg;
			save_option(option);
			break;
		case 'T':
			save_option("stacktrace");
			break;
		case 'H':
			add_hook(ctx->instance, optarg);
			ctx->events = 1;
			break;
		case 's':
			if (IS_EXTRACT(ctx)) {
				if (optarg)
					usage(argv);
				recorder_flags |= TRACECMD_RECORD_SNAPSHOT;
				break;
			}
			if (!optarg)
				usage(argv);
			sleep_time = atoi(optarg);
			break;
		case 'S':
			ctx->manual = 1;
			/* User sets events for profiling */
			if (!event)
				ctx->events = 0;
			break;
		case 'r':
			rt_prio = atoi(optarg);
			break;
		case 'N':
			if (!IS_RECORD(ctx))
				die("-N only available with record");
			if (IS_RECORD_AGENT(ctx))
				die("-N incompatible with agent recording");
			if (ctx->output)
				die("-N incompatible with -o");
			host = optarg;
			break;
		case 'm':
			if (max_kb)
				die("-m can only be specified once");
			if (!IS_RECORD(ctx))
				die("only record take 'm' option");
			max_kb = atoi(optarg);
			break;
		case 'M':
			ctx->instance->cpumask = alloc_mask_from_hex(ctx->instance, optarg);
			break;
		case 't':
			if (IS_EXTRACT(ctx))
				ctx->topt = 1; /* Extract top instance also */
			else
				use_tcp = 1;
			break;
		case 'b':
			ctx->instance->buffer_size = atoi(optarg);
			break;
		case 'B':
			ctx->instance = create_instance(optarg);
			if (!ctx->instance)
				die("Failed to create instance");
			add_instance(ctx->instance, local_cpu_count);
			if (IS_PROFILE(ctx))
				ctx->instance->flags |= BUFFER_FL_PROFILE;
			break;
		case 'k':
			keep = 1;
			break;
		case 'i':
			ignore_event_not_found = 1;
			break;
		case OPT_user:
			ctx->user = strdup(optarg);
			if (!ctx->user)
				die("Failed to allocate user name");
			break;
		case OPT_procmap:
			get_procmap = 1;
			break;
		case OPT_date:
			ctx->date = 1;
			if (ctx->data_flags & DATA_FL_OFFSET)
				die("Can not use both --date and --ts-offset");
			ctx->data_flags |= DATA_FL_DATE;
			break;
		case OPT_funcstack:
			func_stack = 1;
			break;
		case OPT_nosplice:
			recorder_flags |= TRACECMD_RECORD_NOSPLICE;
			break;
		case OPT_nofifos:
			no_fifos = true;
			break;
		case OPT_profile:
			handle_init = trace_init_profile;
			ctx->instance->flags |= BUFFER_FL_PROFILE;
			ctx->events = 1;
			break;
		case OPT_stderr:
			/* if -o was used (for profile), ignore this */
			if (save_stdout >= 0)
				break;
			save_stdout = dup(1);
			close(1);
			dup2(2, 1);
			break;
		case OPT_bycomm:
			trace_profile_set_merge_like_comms();
			break;
		case OPT_tsoffset:
			ctx->date2ts = strdup(optarg);
			if (ctx->data_flags & DATA_FL_DATE)
				die("Can not use both --date and --ts-offset");
			ctx->data_flags |= DATA_FL_OFFSET;
			break;
		case OPT_max_graph_depth:
			free(ctx->instance->max_graph_depth);
			ctx->instance->max_graph_depth = strdup(optarg);
			if (!ctx->instance->max_graph_depth)
				die("Could not allocate option");
			break;
		case OPT_cmdlines_size:
			ctx->saved_cmdlines_size = atoi(optarg);
			break;
		case OPT_no_filter:
			no_filter = true;
			break;
		case OPT_debug:
			tracecmd_set_debug(true);
			break;
		case OPT_module:
			if (ctx->instance->filter_mod)
				add_func(&ctx->instance->filter_funcs,
					 ctx->instance->filter_mod, "*");
			ctx->instance->filter_mod = optarg;
			ctx->filtered = 0;
			break;
		case OPT_quiet:
		case 'q':
			quiet = true;
			break;
		default:
			usage(argv);
		}
	}

	/* If --date is specified, prepend it to all guest VM flags */
	if (ctx->date) {
		struct buffer_instance *instance;

		for_all_instances(instance) {
			if (is_guest(instance))
				add_argv(instance, "--date", true);
		}
	}

	if (!ctx->filtered && ctx->instance->filter_mod)
		add_func(&ctx->instance->filter_funcs,
			 ctx->instance->filter_mod, "*");

	if (do_children && !filter_task && !nr_filter_pids)
		die(" -c can only be used with -F (or -P with event-fork support)");
	if (ctx->do_child && !filter_task && !nr_filter_pids)
		die(" -c can only be used with -P or -F");

	if ((argc - optind) >= 2) {
		if (IS_START(ctx))
			die("Command start does not take any commands\n"
			    "Did you mean 'record'?");
		if (IS_EXTRACT(ctx))
			die("Command extract does not take any commands\n"
			    "Did you mean 'record'?");
		ctx->run_command = 1;
	}
	if (ctx->user && !ctx->run_command)
		warning("--user %s is ignored, no command is specified",
			ctx->user);
	if (get_procmap) {
		if (!ctx->run_command && !nr_filter_pids)
			warning("--proc-map is ignored, no command or filtered PIDs are specified.");
		else
			do_ptrace = 1;
	}
}

static enum trace_type get_trace_cmd_type(enum trace_cmd cmd)
{
	const static struct {
		enum trace_cmd cmd;
		enum trace_type ttype;
	} trace_type_per_command[] = {
		{CMD_record, TRACE_TYPE_RECORD},
		{CMD_stream, TRACE_TYPE_STREAM},
		{CMD_extract, TRACE_TYPE_EXTRACT},
		{CMD_profile, TRACE_TYPE_STREAM},
		{CMD_start, TRACE_TYPE_START},
		{CMD_record_agent, TRACE_TYPE_RECORD}
	};

	for (int i = 0; i < ARRAY_SIZE(trace_type_per_command); i++) {
		if (trace_type_per_command[i].cmd == cmd)
			return trace_type_per_command[i].ttype;
	}

	die("Trace type UNKNOWN for the given cmd_fun");
}

static void finalize_record_trace(struct common_record_context *ctx)
{
	struct buffer_instance *instance;

	if (keep)
		return;

	update_reset_files();
	update_reset_triggers();
	if (clear_function_filters)
		clear_func_filters();

	set_plugin("nop");

	tracecmd_remove_instances();

	/* If tracing_on was enabled before we started, set it on now */
	for_all_instances(instance) {
		if (instance->flags & BUFFER_FL_KEEP)
			write_tracing_on(instance,
					 instance->tracing_on_init_val);
		if (is_agent(instance)) {
			tracecmd_msg_send_close_resp_msg(instance->msg_handle);
			tracecmd_output_close(instance->network_handle);
		}
	}

	if (host)
		tracecmd_output_close(ctx->instance->network_handle);
}

static bool has_local_instances(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance) {
		if (is_guest(instance))
			continue;
		if (host && instance->msg_handle)
			continue;
		return true;
	}
	return false;
}

/*
 * This function contains common code for the following commands:
 * record, start, stream, profile.
 */
static void record_trace(int argc, char **argv,
			 struct common_record_context *ctx)
{
	enum trace_type type = get_trace_cmd_type(ctx->curr_cmd);
	struct buffer_instance *instance;
	struct filter_pids *pid;

	/*
	 * If top_instance doesn't have any plugins or events, then
	 * remove it from being processed.
	 */
	if (!__check_doing_something(&top_instance))
		first_instance = buffer_instances;
	else
		ctx->topt = 1;

	update_first_instance(ctx->instance, ctx->topt);
	check_doing_something();
	check_function_plugin();

	if (ctx->output)
		output_file = ctx->output;

	/* Save the state of tracing_on before starting */
	for_all_instances(instance) {
		if (!ctx->manual && instance->flags & BUFFER_FL_PROFILE)
			enable_profile(instance);

		instance->tracing_on_init_val = read_tracing_on(instance);
		/* Some instances may not be created yet */
		if (instance->tracing_on_init_val < 0)
			instance->tracing_on_init_val = 1;
	}

	make_instances();

	if (ctx->events)
		expand_event_list();

	page_size = getpagesize();

	if (!is_guest(ctx->instance))
		fset = set_ftrace(!ctx->disable, ctx->total_disable);
	tracecmd_disable_all_tracing(1);

	for_all_instances(instance)
		set_clock(instance);

	/* Record records the date first */
	if (ctx->date &&
	    ((IS_RECORD(ctx) && has_local_instances()) || IS_RECORD_AGENT(ctx)))
		ctx->date2ts = get_date_to_ts();

	for_all_instances(instance) {
		set_funcs(instance);
		set_mask(instance);
	}

	if (ctx->events) {
		for_all_instances(instance)
			enable_events(instance);
	}

	set_saved_cmdlines_size(ctx);
	set_buffer_size();
	update_plugins(type);
	set_options();

	for_all_instances(instance) {
		if (instance->max_graph_depth) {
			set_max_graph_depth(instance, instance->max_graph_depth);
			free(instance->max_graph_depth);
			instance->max_graph_depth = NULL;
		}
	}

	allocate_seq();

	if (type & (TRACE_TYPE_RECORD | TRACE_TYPE_STREAM)) {
		signal(SIGINT, finish);
		if (!latency)
			start_threads(type, ctx);
	} else {
		update_task_filter();
		tracecmd_enable_tracing();
		exit(0);
	}

	if (ctx->run_command) {
		run_cmd(type, ctx->user, (argc - optind) - 1, &argv[optind + 1]);
	} else if (ctx->instance && is_agent(ctx->instance)) {
		update_task_filter();
		tracecmd_enable_tracing();
		tracecmd_msg_wait_close(ctx->instance->msg_handle);
	} else {
		update_task_filter();
		tracecmd_enable_tracing();
		/* We don't ptrace ourself */
		if (do_ptrace && filter_pids) {
			for (pid = filter_pids; pid; pid = pid->next) {
				if (!pid->exclude)
					ptrace_attach(pid->pid);
			}
		}
		/* sleep till we are woken with Ctrl^C */
		printf("Hit Ctrl^C to stop recording\n");
		while (!finished)
			trace_or_sleep(type);
	}

	tell_guests_to_stop();
	tracecmd_disable_tracing();
	if (!latency)
		stop_threads(type);

	record_stats();

	if (!keep)
		tracecmd_disable_all_tracing(0);

	if (!latency)
		wait_threads();

	if (IS_RECORD(ctx)) {
		record_data(ctx);
		delete_thread_data();
	} else
		print_stats();

	destroy_stats();
	finalize_record_trace(ctx);
}

void trace_start(int argc, char **argv)
{
	struct common_record_context ctx;

	parse_record_options(argc, argv, CMD_start, &ctx);
	record_trace(argc, argv, &ctx);
	exit(0);
}

void trace_extract(int argc, char **argv)
{
	struct common_record_context ctx;
	struct buffer_instance *instance;
	enum trace_type type;

	parse_record_options(argc, argv, CMD_extract, &ctx);

	type = get_trace_cmd_type(ctx.curr_cmd);

	update_first_instance(ctx.instance, 1);
	check_function_plugin();

	if (ctx.output)
		output_file = ctx.output;

	/* Save the state of tracing_on before starting */
	for_all_instances(instance) {

		if (!ctx.manual && instance->flags & BUFFER_FL_PROFILE)
			enable_profile(ctx.instance);

		instance->tracing_on_init_val = read_tracing_on(instance);
		/* Some instances may not be created yet */
		if (instance->tracing_on_init_val < 0)
			instance->tracing_on_init_val = 1;
	}

	/* Extracting data records all events in the system. */
	if (!ctx.record_all)
		record_all_events();

	if (ctx.events)
		expand_event_list();

	page_size = getpagesize();
	update_plugins(type);
	set_options();

	for_all_instances(instance) {
		if (instance->max_graph_depth) {
			set_max_graph_depth(instance, instance->max_graph_depth);
			free(instance->max_graph_depth);
			instance->max_graph_depth = NULL;
		}
	}

	allocate_seq();
	flush_threads();
	record_stats();

	if (!keep)
		tracecmd_disable_all_tracing(0);

	/* extract records the date after extraction */
	if (ctx.date) {
		/*
		 * We need to start tracing, don't let other traces
		 * screw with our trace_marker.
		 */
		tracecmd_disable_all_tracing(1);
		ctx.date2ts = get_date_to_ts();
	}

	record_data(&ctx);
	delete_thread_data();
	destroy_stats();
	finalize_record_trace(&ctx);
	exit(0);
}

void trace_stream(int argc, char **argv)
{
	struct common_record_context ctx;

	parse_record_options(argc, argv, CMD_stream, &ctx);
	record_trace(argc, argv, &ctx);
	exit(0);
}

void trace_profile(int argc, char **argv)
{
	struct common_record_context ctx;

	parse_record_options(argc, argv, CMD_profile, &ctx);

	handle_init = trace_init_profile;
	ctx.events = 1;

	/*
	 * If no instances were set, then enable profiling on the top instance.
	 */
	if (!buffer_instances)
		top_instance.flags |= BUFFER_FL_PROFILE;

	record_trace(argc, argv, &ctx);
	do_trace_profile();
	exit(0);
}

void trace_clear(int argc, char **argv)
{
	if (argc > 2)
		usage(argv);
	else
		clear_trace();
	exit(0);
}

void trace_record(int argc, char **argv)
{
	struct common_record_context ctx;

	parse_record_options(argc, argv, CMD_record, &ctx);
	record_trace(argc, argv, &ctx);
	exit(0);
}

int trace_record_agent(struct tracecmd_msg_handle *msg_handle,
		       int cpus, int *fds,
		       int argc, char **argv,
		       bool use_fifos)
{
	struct common_record_context ctx;
	char **argv_plus;

	/* Reset optind for getopt_long */
	optind = 1;
	/*
	 * argc is the number of elements in argv, but we need to convert
	 * argc and argv into "trace-cmd", "record", argv.
	 * where argc needs to grow by two.
	 */
	argv_plus = calloc(argc + 2, sizeof(char *));
	if (!argv_plus)
		die("Failed to allocate record arguments");

	argv_plus[0] = "trace-cmd";
	argv_plus[1] = "record";
	memmove(argv_plus + 2, argv, argc * sizeof(char *));
	argc += 2;

	parse_record_options(argc, argv_plus, CMD_record_agent, &ctx);
	if (ctx.run_command)
		return -EINVAL;

	ctx.instance->fds = fds;
	ctx.instance->use_fifos = use_fifos;
	ctx.instance->flags |= BUFFER_FL_AGENT;
	ctx.instance->msg_handle = msg_handle;
	msg_handle->version = V3_PROTOCOL;
	record_trace(argc, argv, &ctx);

	free(argv_plus);
	return 0;
}
