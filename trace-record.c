/*
 * Copyright (C) 2008, 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
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
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <sched.h>
#include <glob.h>
#include <errno.h>

#include "trace-local.h"
#include "trace-msg.h"

#define _STR(x) #x
#define STR(x) _STR(x)
#define MAX_PATH 256

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

static const char *output_file = "trace.dat";

static int latency;
static int sleep_time = 1000;
static int recorder_threads;
static struct pid_record_data *pids;
static int buffers;

/* Clear all function filters */
static int clear_function_filters;

static char *host;
static int sfd;
static struct tracecmd_output *network_handle;

/* Max size to let a per cpu file get */
static int max_kb;

static int do_ptrace;

static int filter_task;
static int filter_pid = -1;

static int finished;

/* setting of /proc/sys/kernel/ftrace_enabled */
static int fset;

static unsigned recorder_flags;

/* Try a few times to get an accurate date */
static int date2ts_tries = 5;

static int proto_ver = V2_PROTOCOL;
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

struct buffer_instance top_instance = { .keep = 1 };
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
	add_reset_file(file, content, prio);
	free(content);
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
void add_instance(struct buffer_instance *instance)
{
	init_instance(instance);
	instance->next = buffer_instances;
	if (first_instance == buffer_instances)
		first_instance = instance;
	buffer_instances = instance;
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

	path = tracecmd_get_tracing_file("set_event_pid");
	ret = stat(path, &st);
	if (!ret) {
		have_set_event_pid = 1;
		reset_save_file(path, RESET_DEFAULT_PRIO);
	}
	tracecmd_put_tracing_file(path);

	path = tracecmd_get_tracing_file("options/event-fork");
	ret = stat(path, &st);
	if (!ret) {
		have_event_fork = 1;
		reset_save_file(path, RESET_DEFAULT_PRIO);
	}
	tracecmd_put_tracing_file(path);

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
	instance->name = name;

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
		add_instance(instance);
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
	char *tracing_dir = tracecmd_find_tracing_dir();
	if (!tracing_dir)
		die("malloc");

	__add_all_instances(tracing_dir);

	tracecmd_put_tracing_file(tracing_dir);
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

	path = get_instance_file(instance, file);
	free(file);
	fd = open(path, O_RDONLY);
	tracecmd_put_tracing_file(path);
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
	const char *name = instance->name;
	char *file = NULL;
	int size;

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

static void put_temp_file(char *file)
{
	free(file);
}

static void delete_temp_file(struct buffer_instance *instance, int cpu)
{
	const char *name = instance->name;
	char file[MAX_PATH];

	if (name)
		snprintf(file, MAX_PATH, "%s.%s.cpu%d", output_file, name, cpu);
	else
		snprintf(file, MAX_PATH, "%s.cpu%d", output_file, cpu);
	unlink(file);
}

static int kill_thread_instance(int start, struct buffer_instance *instance)
{
	int n = start;
	int i;

	for (i = 0; i < cpu_count; i++) {
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

	for (i = 0; i < cpu_count; i++) {
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
		for (i = 0; i < cpu_count; i++)
			delete_temp_file(&top_instance, i);
	}
}

static void stop_threads(enum trace_type type)
{
	struct timeval tv = { 0, 0 };
	int ret;
	int i;

	if (!cpu_count)
		return;

	/* Tell all threads to finish up */
	for (i = 0; i < recorder_threads; i++) {
		if (pids[i].pid > 0) {
			kill(pids[i].pid, SIGINT);
		}
	}

	/* Flush out the pipes */
	if (type & TRACE_TYPE_STREAM) {
		do {
			ret = trace_stream_read(pids, recorder_threads, &tv);
		} while (ret > 0);
	}

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

	if (!cpu_count)
		return;

	for_all_instances(instance) {
		for (i = 0; i < cpu_count; i++) {
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
	path = tracecmd_get_tracing_file("options/function-trace");
	ret = set_ftrace_enable(path, set);
	tracecmd_put_tracing_file(path);

	/* Always enable ftrace_enable proc file when set is true */
	if (ret < 0 || set || use_proc)
		ret = set_ftrace_proc(set);

	return 0;
}

/**
 * get_instance_file - return the path to a instance file.
 * @instance: buffer instance for the file
 * @file: name of file to return
 *
 * Returns the path name of the @file for the given @instance.
 *
 * Must use tracecmd_put_tracing_file() to free the returned string.
 */
char *
get_instance_file(struct buffer_instance *instance, const char *file)
{
	char *buf;
	char *path;

	if (instance->name) {
		buf = malloc(strlen(instance->name) +
			     strlen(file) + strlen("instances//") + 1);
		if (!buf)
			die("Failed to allocate name for %s/%s", instance->name, file);
		sprintf(buf, "instances/%s/%s", instance->name, file);

		path = tracecmd_get_tracing_file(buf);
		free(buf);
	} else
		path = tracecmd_get_tracing_file(file);

	return path;
}

static char *
get_instance_dir(struct buffer_instance *instance)
{
	char *buf;
	char *path;

	/* only works for instances */
	if (!instance->name)
		return NULL;

	buf = malloc(strlen(instance->name) +
		     strlen("instances/") + 1);
	if (!buf)
		die("Failed to allocate for instance %s", instance->name);
	sprintf(buf, "instances/%s", instance->name);

	path = tracecmd_get_tracing_file(buf);
	free(buf);

	return path;
}

static void __clear_trace(struct buffer_instance *instance)
{
	FILE *fp;
	char *path;

	/* reset the trace */
	path = get_instance_file(instance, "trace");
	fp = fopen(path, "w");
	if (!fp)
		die("writing to '%s'", path);
	tracecmd_put_tracing_file(path);
	fwrite("0", 1, 1, fp);
	fclose(fp);
}

static void clear_trace(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		__clear_trace(instance);
}

static void reset_max_latency(void)
{
	FILE *fp;
	char *path;

	/* reset the trace */
	path = tracecmd_get_tracing_file("tracing_max_latency");
	fp = fopen(path, "w");
	if (!fp)
		die("writing to '%s'", path);
	tracecmd_put_tracing_file(path);
	fwrite("0", 1, 1, fp);
	fclose(fp);
}

static void add_filter_pid(int pid, int exclude)
{
	struct filter_pids *p;
	char buf[100];

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
			tracecmd_put_tracing_file(path);
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
			path = tracecmd_get_tracing_file("set_ftrace_pid");
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

/**
 * make_pid_filter - create a filter string to all pids against @field
 * @curr_filter: Append to a previous filter (may realloc). Can be NULL
 * @field: The fild to compare the pids against
 *
 * Creates a new string or appends to an existing one if @curr_filter
 * is not NULL. The new string will contain a filter with all pids
 * in pid_filter list with the format (@field == pid) || ..
 * If @curr_filter is not NULL, it will add this string as:
 *  (@curr_filter) && ((@field == pid) || ...)
 */
static char *make_pid_filter(char *curr_filter, const char *field)
{
	struct filter_pids *p;
	char *filter;
	char *orit;
	char *match;
	char *str;
	int curr_len = 0;
	int len;

	/* Use the new method if possible */
	if (have_set_event_pid)
		return NULL;

	len = len_filter_pids + (strlen(field) + strlen("(==)||")) * nr_filter_pids;

	if (curr_filter) {
		curr_len = strlen(curr_filter);
		filter = realloc(curr_filter, curr_len + len + strlen("(&&())"));
		if (!filter)
			die("realloc");
		memmove(filter+1, curr_filter, curr_len);
		filter[0] = '(';
		strcat(filter, ")&&(");
		curr_len = strlen(filter);
	} else
		filter = malloc(len);
	if (!filter)
		die("Failed to allocate pid filter");

	/* Last '||' that is not used will cover the \0 */
	str = filter + curr_len;

	for (p = filter_pids; p; p = p->next) {
		if (p == filter_pids)
			orit = "";
		else
			orit = "||";
		if (p->exclude)
			match = "!=";
		else
			match = "==";
		len = sprintf(str, "%s(%s%s%d)", orit, field, match, p->pid);
		str += len;
	}

	if (curr_len)
		sprintf(str, ")");

	return filter;
}

static void update_task_filter(void)
{
	struct buffer_instance *instance;
	int pid = getpid();

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

static void add_event_pid(const char *buf, int len)
{
	struct buffer_instance *instance;
	int fd;

	for_all_instances(instance) {
		fd = open_instance_fd(instance, "set_event_pid", O_WRONLY);
		write(fd, buf, len);
		close(fd);
	}
}

static void add_new_filter_pid(int pid)
{
	struct buffer_instance *instance;
	char buf[100];
	int len;

	add_filter_pid(pid, 0);
	len = sprintf(buf, "%d", pid);
	update_ftrace_pid(buf, 0);

	if (have_set_event_pid)
		return add_event_pid(buf, len);

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

static void ptrace_wait(enum trace_type type, int main_pid)
{
	unsigned long send_sig;
	unsigned long child;
	siginfo_t sig;
	int cstatus;
	int status;
	int event;
	int pid;
	int ret;

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
	} while (!finished && ret > 0 &&
		 (!WIFEXITED(status) || pid != main_pid));
}
#else
static inline void ptrace_wait(enum trace_type type, int main_pid) { }
static inline void enable_ptrace(void) { }
static inline void ptrace_attach(int pid) { }

#endif /* NO_PTRACE */

static void trace_or_sleep(enum trace_type type)
{
	struct timeval tv = { 1 , 0 };

	if (do_ptrace && filter_pid >= 0)
		ptrace_wait(type, filter_pid);
	else if (type & TRACE_TYPE_STREAM)
		trace_stream_read(pids, recorder_threads, &tv);
	else
		sleep(10);
}

static void run_cmd(enum trace_type type, int argc, char **argv)
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
		if (execvp(argv[0], argv)) {
			fprintf(stderr, "\n********************\n");
			fprintf(stderr, " Unable to exec %s\n", argv[0]);
			fprintf(stderr, "********************\n");
			die("Failed to exec %s", argv[0]);
		}
	}
	if (do_ptrace) {
		add_filter_pid(pid, 0);
		ptrace_wait(type, pid);
	} else
		trace_waitpid(type, pid, &status, 0);
}

static void
set_plugin_instance(struct buffer_instance *instance, const char *name)
{
	FILE *fp;
	char *path;
	char zero = '0';

	path = get_instance_file(instance, "current_tracer");
	fp = fopen(path, "w");
	if (!fp) {
		/*
		 * Legacy kernels do not have current_tracer file, and they
		 * always use nop. So, it doesn't need to try to change the
		 * plugin for those if name is "nop".
		 */
		if (!strncmp(name, "nop", 3)) {
			tracecmd_put_tracing_file(path);
			return;
		}
		die("writing to '%s'", path);
	}
	tracecmd_put_tracing_file(path);

	fwrite(name, 1, strlen(name), fp);
	fclose(fp);

	if (strncmp(name, "function", 8) != 0)
		return;

	/* Make sure func_stack_trace option is disabled */
	/* First try instance file, then top level */
	path = get_instance_file(instance, "options/func_stack_trace");
	fp = fopen(path, "w");
	if (!fp) {
		tracecmd_put_tracing_file(path);
		path = tracecmd_get_tracing_file("options/func_stack_trace");
		fp = fopen(path, "w");
		if (!fp) {
			tracecmd_put_tracing_file(path);
			return;
		}
	}
	/*
	 * Always reset func_stack_trace to zero. Don't bother saving
	 * the original content.
	 */
	add_reset_file(path, "0", RESET_HIGH_PRIO);
	tracecmd_put_tracing_file(path);
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

	path = tracecmd_get_tracing_file("trace_options");
	fp = fopen(path, "w");
	if (!fp)
		warning("writing to '%s'", path);
	tracecmd_put_tracing_file(path);

	if (!fp)
		return -1;

	fwrite(option, 1, strlen(option), fp);
	fclose(fp);

	return 0;
}

static char *read_instance_file(struct buffer_instance *instance, char *file, int *psize);

static void disable_func_stack_trace_instance(struct buffer_instance *instance)
{
	struct stat st;
	char *content;
	char *path;
	char *cond;
	int size;
	int ret;

	path = get_instance_file(instance, "current_tracer");
	ret = stat(path, &st);
	tracecmd_put_tracing_file(path);
	if (ret < 0)
		return;

	content = read_instance_file(instance, "current_tracer", &size);
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

	path = tracecmd_get_tracing_file("trace_options");
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
	tracecmd_put_tracing_file(path);
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

static int trace_check_file_exists(struct buffer_instance *instance, char *file)
{
	struct stat st;
	char *path;
	int ret;

	path = get_instance_file(instance, file);
	ret = stat(path, &st);
	tracecmd_put_tracing_file(path);

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
	path = tracecmd_get_tracing_file("set_event");
	fp = fopen(path, "w");
	if (!fp)
		die("opening '%s'", path);
	tracecmd_put_tracing_file(path);

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

	if (use_old_event_method()) {
		/* old way only had top instance */
		if (!is_top_instance(instance))
			return;
		old_update_events("all", '0');
		return;
	}

	c = '0';
	path = get_instance_file(instance, "events/enable");
	fd = open(path, O_WRONLY);
	if (fd < 0)
		die("opening to '%s'", path);
	ret = write(fd, &c, 1);
	close(fd);
	tracecmd_put_tracing_file(path);

	path = get_instance_file(instance, "events/*/filter");
	globbuf.gl_offs = 0;
	ret = glob(path, 0, NULL, &globbuf);
	tracecmd_put_tracing_file(path);
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

static int write_file(const char *file, const char *str, const char *type)
{
	char buf[BUFSIZ];
	int fd;
	int ret;

	fd = open(file, O_WRONLY | O_TRUNC);
	if (fd < 0)
		die("opening to '%s'", file);
	ret = write(fd, str, strlen(str));
	close(fd);
	if (ret < 0 && type) {
		/* write failed */
		fd = open(file, O_RDONLY);
		if (fd < 0)
			die("writing to '%s'", file);
		/* the filter has the error */
		while ((ret = read(fd, buf, BUFSIZ)) > 0)
			fprintf(stderr, "%.*s", ret, buf);
		die("Failed %s of %s\n", type, file);
		close(fd);
	}
	return ret;
}

static int
write_instance_file(struct buffer_instance *instance,
		    const char *file, const char *str, const char *type)
{
	char *path;
	int ret;

	path = get_instance_file(instance, file);
	ret = write_file(path, str, type);
	tracecmd_put_tracing_file(path);

	return ret;
}

enum {
	STATE_NEWLINE,
	STATE_SKIP,
	STATE_COPY,
};

static int find_trigger(const char *file, char *buf, int size, int fields)
{
	FILE *fp;
	int state = STATE_NEWLINE;
	int ch;
	int len = 0;

	fp = fopen(file, "r");
	if (!fp)
		return 0;

	while ((ch = fgetc(fp)) != EOF) {
		if (ch == '\n') {
			if (state == STATE_COPY)
				break;
			state = STATE_NEWLINE;
			continue;
		}
		if (state == STATE_SKIP)
			continue;
		if (state == STATE_NEWLINE && ch == '#') {
			state = STATE_SKIP;
			continue;
		}
		if (state == STATE_COPY && ch == ':' && --fields < 1)
			break;

		state = STATE_COPY;
		buf[len++] = ch;
		if (len == size - 1)
			break;
	}
	buf[len] = 0;
	fclose(fp);

	return len;
}

static void write_filter(const char *file, const char *filter)
{
	write_file(file, filter, "filter");
}

static void clear_filter(const char *file)
{
	write_filter(file, "0");
}

static void write_trigger(const char *file, const char *trigger)
{
	write_file(file, trigger, "trigger");
}

static void write_func_filter(const char *file, const char *trigger)
{
	write_file(file, trigger, "function filter");
}

static void clear_trigger(const char *file)
{
	char trigger[BUFSIZ];
	int len;

	trigger[0] = '!';

	/*
	 * To delete a trigger, we need to write a '!trigger'
	 * to the file for each trigger.
	 */
	do {
		len = find_trigger(file, trigger+1, BUFSIZ-1, 1);
		if (len)
			write_trigger(file, trigger);
	} while (len);
}

static void clear_func_filter(const char *file)
{
	char trigger[BUFSIZ];
	struct stat st;
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

	/* Now remove triggers */
	trigger[0] = '!';

	/*
	 * To delete a trigger, we need to write a '!trigger'
	 * to the file for each trigger.
	 */
	do {
		len = find_trigger(file, trigger+1, BUFSIZ-1, 3);
		if (len) {
			/*
			 * To remove "unlimited" triggers, we must remove
			 * the ":unlimited" from what we write.
			 */
			if ((p = strstr(trigger, ":unlimited"))) {
				*p = '\0';
				len = p - trigger;
			}
			/*
			 * The write to this file expects white space
			 * at the end :-p
			 */
			trigger[len] = '\n';
			trigger[len+1] = '\0';
			write_func_filter(file, trigger);
		}
	} while (len > 0);
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
			write_file(reset->path, reset->reset, "reset");
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
		path = tracecmd_get_tracing_file("tracing_enabled");
		fd = open(path, O_WRONLY | O_CLOEXEC);
		tracecmd_put_tracing_file(path);

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

	path = get_instance_file(instance, file);
	fd = open(path, flags);
	if (fd < 0) {
		/* instances may not be created yet */
		if (is_top_instance(instance))
			die("opening '%s'", path);
	}
	tracecmd_put_tracing_file(path);

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

void tracecmd_enable_tracing(void)
{
	struct buffer_instance *instance;

	check_tracing_enabled();

	for_all_instances(instance)
		write_tracing_on(instance, 1);

	if (latency)
		reset_max_latency();
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

	clear_trace();
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

static char *alloc_mask_from_hex(const char *str)
{
	char *cpumask;

	if (strcmp(str, "-1") == 0) {
		/* set all CPUs */
		int bytes = (cpu_count + 7) / 8;
		int last = cpu_count % 8;
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

	if (!instance->cpumask)
		return;

	path = get_instance_file(instance, "tracing_cpumask");
	if (!path)
		die("could not allocate path");

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
	tracecmd_put_tracing_file(path);
	free(instance->cpumask);
	instance->cpumask = NULL;
}

static void enable_events(struct buffer_instance *instance)
{
	struct event_list *event;

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

	if (!instance->clock)
		return;

	/* The current clock is in brackets, reset it when we are done */
	content = read_instance_file(instance, "trace_clock", NULL);

	/* check if first clock is set */
	if (*content == '[')
		str = strtok(content+1, "]");
	else {
		str = strtok(content, "[");
		if (!str)
			die("Can not find clock in trace_clock");
		str = strtok(NULL, "]");
	}
	path = get_instance_file(instance, "trace_clock");
	add_reset_file(path, str, RESET_DEFAULT_PRIO);

	free(content);
	tracecmd_put_tracing_file(path);

	write_instance_file(instance, "trace_clock", instance->clock, "clock");
}

static void set_max_graph_depth(struct buffer_instance *instance, char *max_graph_depth)
{
	char *path;
	int ret;

	path = get_instance_file(instance, "max_graph_depth");
	reset_save_file(path, RESET_DEFAULT_PRIO);
	tracecmd_put_tracing_file(path);
	ret = write_instance_file(instance, "max_graph_depth", max_graph_depth,
				  NULL);
	if (ret < 0)
		die("could not write to max_graph_depth");
}

static struct event_list *
create_event(struct buffer_instance *instance, char *path, struct event_list *old_event)
{
	struct event_list *event;
	struct stat st;
	char *p;
	int ret;

	event = malloc(sizeof(*event));
	if (!event)
		die("Failed to allocate event");
	*event = *old_event;
	add_event(instance, event);

	if (event->filter || filter_task || filter_pid) {
		event->filter_file = strdup(path);
		if (!event->filter_file)
			die("malloc filter file");
	}
	for (p = path + strlen(path) - 1; p > path; p--)
		if (*p == '/')
			break;
	*p = '\0';
	p = malloc(strlen(path) + strlen("/enable") + 1);
	if (!p)
		die("Failed to allocate enable path for %s", path);
	sprintf(p, "%s/enable", path);
	ret = stat(p, &st);
	if (ret >= 0)
		event->enable_file = p;
	else
		free(p);

	if (event->trigger) {
		p = malloc(strlen(path) + strlen("/trigger") + 1);
		if (!p)
			die("Failed to allocate trigger path for %s", path);
		sprintf(p, "%s/trigger", path);
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
	char *path;
	char *p;

	/* Do nothing if the event already exists */
	if (*event)
		return;

	path = malloc(strlen(sched->filter_file) + strlen(sched_path) + 2);
	if (!path)
		die("Failed to allocate path for %s", sched_path);

	sprintf(path, "%s", sched->filter_file);

	/* Remove the /filter from filter file */
	p = path + strlen(path) - strlen("filter");
	sprintf(p, "%s/filter", sched_path);

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

	p = malloc(strlen(file) + strlen("events//filter") + 1);
	if (!p)
		die("Failed to allocate event filter path for %s", file);
	sprintf(p, "events/%s/filter", file);

	path = get_instance_file(instance, p);

	globbuf.gl_offs = 0;
	ret = glob(path, 0, NULL, &globbuf);
	tracecmd_put_tracing_file(path);
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

int count_cpus(void)
{
	FILE *fp;
	char buf[1024];
	int cpus = 0;
	char *pbuf;
	size_t *pn;
	size_t n;
	int r;

	cpus = sysconf(_SC_NPROCESSORS_CONF);
	if (cpus > 0)
		return cpus;

	warning("sysconf could not determine number of CPUS");

	/* Do the hack to figure out # of CPUS */
	n = 1024;
	pn = &n;
	pbuf = buf;

	fp = fopen("/proc/cpuinfo", "r");
	if (!fp)
		die("Can not read cpuinfo");

	while ((r = getline(&pbuf, pn, fp)) >= 0) {
		char *p;

		if (strncmp(buf, "processor", 9) != 0)
			continue;
		for (p = buf+9; isspace(*p); p++)
			;
		if (*p == ':')
			cpus++;
	}
	fclose(fp);

	return cpus;
}

static void finish(int sig)
{
	/* all done */
	if (recorder)
		tracecmd_stop_recording(recorder);
	finished = 1;
}

static void flush(int sig)
{
	if (recorder)
		tracecmd_stop_recording(recorder);
}

static void connect_port(int cpu)
{
	struct addrinfo hints;
	struct addrinfo *results, *rp;
	int s;
	char buf[BUFSIZ];

	snprintf(buf, BUFSIZ, "%d", client_ports[cpu]);

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

	client_ports[cpu] = sfd;
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

	if (instance->name)
		path = get_instance_dir(instance);
	else
		path = tracecmd_find_tracing_dir();

	if (!path)
		die("malloc");

	/* This is already the child */
	close(brass[0]);

	recorder = tracecmd_create_buffer_recorder_fd(brass[1], cpu, flags, path);

	if (instance->name)
		tracecmd_put_tracing_file(path);

	return recorder;
}

static struct tracecmd_recorder *
create_recorder_instance(struct buffer_instance *instance, const char *file, int cpu,
			 int *brass)
{
	struct tracecmd_recorder *record;
	char *path;

	if (brass)
		return create_recorder_instance_pipe(instance, cpu, brass);

	if (!instance->name)
		return tracecmd_create_recorder_maxkb(file, cpu, recorder_flags, max_kb);

	path = get_instance_dir(instance);

	record = tracecmd_create_buffer_recorder_maxkb(file, cpu, recorder_flags,
						       path, max_kb);
	tracecmd_put_tracing_file(path);

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
	int pid;

	/* network for buffer instances not supported yet */
	if (client_ports && instance->name)
		return 0;

	if (type != TRACE_TYPE_EXTRACT) {
		signal(SIGUSR1, flush);

		pid = fork();
		if (pid < 0)
			die("fork");

		if (pid)
			return pid;

		if (rt_prio)
			set_prio(rt_prio);

		/* do not kill tasks on error */
		cpu_count = 0;
	}

	if (client_ports) {
		connect_port(cpu);
		recorder = tracecmd_create_recorder_fd(client_ports[cpu], cpu, recorder_flags);
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
		return ret;
	}

	while (!finished) {
		if (tracecmd_start_recording(recorder, sleep_time) < 0)
			break;
	}
	tracecmd_free_recorder(recorder);

	exit(0);
}

static void check_first_msg_from_server(int fd)
{
	char buf[BUFSIZ];

	read(fd, buf, 8);

	/* Make sure the server is the tracecmd server */
	if (memcmp(buf, "tracecmd", 8) != 0)
		die("server not tracecmd server");
}

static void communicate_with_listener_v1(int fd)
{
	char buf[BUFSIZ];
	ssize_t n;
	int cpu, i;

	check_first_msg_from_server(fd);

	/* write the number of CPUs we have (in ASCII) */
	sprintf(buf, "%d", cpu_count);

	/* include \0 */
	write(fd, buf, strlen(buf)+1);

	/* write the pagesize (in ASCII) */
	sprintf(buf, "%d", page_size);

	/* include \0 */
	write(fd, buf, strlen(buf)+1);

	/*
	 * If we are using IPV4 and our page size is greater than
	 * or equal to 64K, we need to punt and use TCP. :-(
	 */

	/* TODO, test for ipv4 */
	if (page_size >= UDP_MAX_PACKET) {
		warning("page size too big for UDP using TCP in live read");
		use_tcp = 1;
	}

	if (use_tcp) {
		/* Send one option */
		write(fd, "1", 2);
		/* Size 4 */
		write(fd, "4", 2);
		/* use TCP */
		write(fd, "TCP", 4);
	} else
		/* No options */
		write(fd, "0", 2);

	client_ports = malloc(sizeof(int) * cpu_count);
	if (!client_ports)
		die("Failed to allocate client ports for %d cpus", cpu_count);

	/*
	 * Now we will receive back a comma deliminated list
	 * of client ports to connect to.
	 */
	for (cpu = 0; cpu < cpu_count; cpu++) {
		for (i = 0; i < BUFSIZ; i++) {
			n = read(fd, buf+i, 1);
			if (n != 1)
				die("Error, reading server ports");
			if (!buf[i] || buf[i] == ',')
				break;
		}
		if (i == BUFSIZ)
			die("read bad port number");
		buf[i] = 0;
		client_ports[cpu] = atoi(buf);
	}
}

static void communicate_with_listener_v2(int fd)
{
	if (tracecmd_msg_send_init_data(fd) < 0)
		die("Cannot communicate with server");
}

static void check_protocol_version(int fd)
{
	char buf[BUFSIZ];
	int n;

	check_first_msg_from_server(fd);

	/*
	 * Write the protocol version, the magic number, and the dummy
	 * option(0) (in ASCII). The client understands whether the client
	 * uses the v2 protocol or not by checking a reply message from the
	 * server. If the message is "V2", the server uses v2 protocol. On the
	 * other hands, if the message is just number strings, the server
	 * returned port numbers. So, in that time, the client understands the
	 * server uses the v1 protocol. However, the old server tells the
	 * client port numbers after reading cpu_count, page_size, and option.
	 * So, we add the dummy number (the magic number and 0 option) to the
	 * first client message.
	 */
	write(fd, V2_CPU, sizeof(V2_CPU));

	/* read a reply message */
	n = read(fd, buf, BUFSIZ);

	if (n < 0 || !buf[0]) {
		/* the server uses the v1 protocol, so we'll use it */
		proto_ver = V1_PROTOCOL;
		plog("Use the v1 protocol\n");
	} else {
		if (memcmp(buf, "V2", n) != 0)
			die("Cannot handle the protocol %s", buf);
		/* OK, let's use v2 protocol */
		write(fd, V2_MAGIC, sizeof(V2_MAGIC));

		n = read(fd, buf, BUFSIZ - 1);
		if (n != 2 || memcmp(buf, "OK", 2) != 0) {
			if (n < 0)
				n  = 0;
			buf[n] = 0;
			die("Cannot handle the protocol %s", buf);
		}
	}
}

static void setup_network(void)
{
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

	if (proto_ver == V2_PROTOCOL) {
		check_protocol_version(sfd);
		if (proto_ver == V1_PROTOCOL) {
			/* reconnect to the server for using the v1 protocol */
			close(sfd);
			goto again;
		}
		communicate_with_listener_v2(sfd);
	}

	if (proto_ver == V1_PROTOCOL)
		communicate_with_listener_v1(sfd);

	/* Now create the handle through this socket */
	network_handle = tracecmd_create_init_fd_glob(sfd, listed_events);

	if (proto_ver == V2_PROTOCOL)
		tracecmd_msg_finish_sending_metadata(sfd);

	/* OK, we are all set, let'r rip! */
}

static void finish_network(void)
{
	if (proto_ver == V2_PROTOCOL)
		tracecmd_msg_send_close_msg();
	close(sfd);
	free(host);
}

static void start_threads(enum trace_type type, int global)
{
	struct buffer_instance *instance;
	int *brass = NULL;
	int i = 0;
	int ret;

	if (host)
		setup_network();

	/* make a thread for every CPU we have */
	pids = malloc(sizeof(*pids) * cpu_count * (buffers + 1));
	if (!pids)
		die("Failed to allocat pids for %d cpus", cpu_count);

	memset(pids, 0, sizeof(*pids) * cpu_count * (buffers + 1));

	for_all_instances(instance) {
		int x, pid;
		for (x = 0; x < cpu_count; x++) {
			if (type & TRACE_TYPE_STREAM) {
				brass = pids[i].brass;
				ret = pipe(brass);
				if (ret < 0)
					die("pipe");
				pids[i].stream = trace_stream_init(instance, x,
								   brass[0], cpu_count,
								   hooks, handle_init,
								   global);
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

static void append_buffer(struct tracecmd_output *handle,
			  struct tracecmd_option *buffer_option,
			  struct buffer_instance *instance,
			  char **temp_files)
{
	int i;

	for (i = 0; i < cpu_count; i++)
		temp_files[i] = get_temp_file(instance, i);

	tracecmd_append_buffer_cpu_data(handle, buffer_option, cpu_count, temp_files);

	for (i = 0; i < cpu_count; i++)
		put_temp_file(temp_files[i]);
}

static void
add_buffer_stat(struct tracecmd_output *handle, struct buffer_instance *instance)
{
	struct trace_seq s;
	int i;

	trace_seq_init(&s);
	trace_seq_printf(&s, "\nBuffer: %s\n\n", instance->name);
	tracecmd_add_option(handle, TRACECMD_OPTION_CPUSTAT,
			    s.len+1, s.buffer);
	trace_seq_destroy(&s);

	for (i = 0; i < cpu_count; i++)
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

static void touch_file(const char *file)
{
	int fd;

	fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		die("could not create file %s\n", file);
	close(fd);
}

static void print_stat(struct buffer_instance *instance)
{
	int cpu;

	if (!is_top_instance(instance))
		printf("\nBuffer: %s\n\n", instance->name);

	for (cpu = 0; cpu < cpu_count; cpu++)
		trace_seq_do_printf(&instance->s_print[cpu]);
}

enum {
	DATA_FL_NONE		= 0,
	DATA_FL_DATE		= 1,
	DATA_FL_OFFSET		= 2,
};

static void record_data(char *date2ts, int flags)
{
	struct tracecmd_option **buffer_options;
	struct tracecmd_output *handle;
	struct buffer_instance *instance;
	char **temp_files;
	int i;

	if (host) {
		finish_network();
		return;
	}

	if (latency)
		handle = tracecmd_create_file_latency(output_file, cpu_count);
	else {
		if (!cpu_count)
			return;

		temp_files = malloc(sizeof(*temp_files) * cpu_count);
		if (!temp_files)
			die("Failed to allocate temp_files for %d cpus", cpu_count);

		for (i = 0; i < cpu_count; i++)
			temp_files[i] = get_temp_file(&top_instance, i);

		/*
		 * If top_instance was not used, we still need to create
		 * empty trace.dat files for it.
		 */
		if (no_top_instance()) {
			for (i = 0; i < cpu_count; i++)
				touch_file(temp_files[i]);
		}

		handle = tracecmd_create_init_file_glob(output_file, listed_events);
		if (!handle)
			die("Error creating output file");

		if (date2ts) {
			int type = 0;

			if (flags & DATA_FL_DATE)
				type = TRACECMD_OPTION_DATE;
			else if (flags & DATA_FL_OFFSET)
				type = TRACECMD_OPTION_OFFSET;

			if (type)
				tracecmd_add_option(handle, type,
						    strlen(date2ts)+1, date2ts);
		}

		/* Only record the top instance under TRACECMD_OPTION_CPUSTAT*/
		if (!no_top_instance()) {
			struct trace_seq *s = top_instance.s_save;

			for (i = 0; i < cpu_count; i++)
				tracecmd_add_option(handle, TRACECMD_OPTION_CPUSTAT,
						    s[i].len+1, s[i].buffer);
		}

		tracecmd_add_option(handle, TRACECMD_OPTION_TRACECLOCK,
				    0, NULL);

		add_option_hooks(handle);

		add_uname(handle);

		if (buffers) {
			buffer_options = malloc(sizeof(*buffer_options) * buffers);
			if (!buffer_options)
				die("Failed to allocate buffer options");
			i = 0;
			for_each_instance(instance) {
				buffer_options[i++] = tracecmd_add_buffer_option(handle, instance->name);
				add_buffer_stat(handle, instance);
			}
		}

		if (!no_top_instance())
			print_stat(&top_instance);

		tracecmd_append_cpu_data(handle, cpu_count, temp_files);

		for (i = 0; i < cpu_count; i++)
			put_temp_file(temp_files[i]);

		if (buffers) {
			i = 0;
			for_each_instance(instance) {
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
	char *path;
	int fd;
	int ret = -1;

	if (!*list)
		return 0;

	path = get_instance_file(instance, file);

	fd = open(path, O_WRONLY | O_TRUNC);
	if (fd < 0)
		goto free;

	while (*list) {
		item = *list;
		*list = item->next;
		ret = write(fd, item->func, strlen(item->func));
		if (ret < 0)
			goto failed;
		ret = write(fd, " ", 1);
		if (ret < 0)
			goto failed;
		free(item);
	}
	close(fd);
	ret = 0;
 free:
	tracecmd_put_tracing_file(path);
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

	path = get_instance_file(instance, "set_ftrace_filter");
	fd = open(path, O_RDONLY);
	tracecmd_put_tracing_file(path);
	if (fd < 0) {
		if (is_top_instance(instance))
			warning("Can not set set_ftrace_filter");
		else
			warning("Can not set set_ftrace_filter for %s",
				instance->name);
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

static void add_func(struct func_list **list, const char *func)
{
	struct func_list *item;

	item = malloc(sizeof(*item));
	if (!item)
		die("Failed to allocate function descriptor");
	item->func = func;
	item->next = *list;
	*list = item;
}

static unsigned long long
find_ts_in_page(struct pevent *pevent, void *page, int size)
{
	struct event_format *event;
	struct format_field *field;
	struct pevent_record *last_record = NULL;
	struct pevent_record *record;
	unsigned long long ts = 0;
	int id;

	if (size <= 0)
		return 0;

	while (!ts) {
		record = tracecmd_read_page_record(pevent, page, size,
						   last_record);
		if (!record)
			break;
		free_record(last_record);
		id = pevent_data_type(pevent, record);
		event = pevent_data_event_from_type(pevent, id);
		if (event) {
			/* Make sure this is our event */
			field = pevent_find_field(event, "buf");
			/* the trace_marker adds a '\n' */
			if (field && strcmp(STAMP"\n", record->data + field->offset) == 0)
				ts = record->ts;
		}
		last_record = record;
	}
	free_record(last_record);

	return ts;
}

static unsigned long long find_time_stamp(struct pevent *pevent)
{
	struct dirent *dent;
	unsigned long long ts = 0;
	void *page;
	char *path;
	char *file;
	DIR *dir;
	int len;
	int fd;
	int r;

	path = tracecmd_get_tracing_file("per_cpu");
	if (!path)
		return 0;

	dir = opendir(path);
	if (!dir)
		goto out;

	len = strlen(path);
	file = malloc(len + strlen("trace_pipe_raw") + 32);
	page = malloc(page_size);
	if (!file || !page)
		die("Failed to allocate time_stamp info");

	while ((dent = readdir(dir))) {
		const char *name = dent->d_name;

		if (strncmp(name, "cpu", 3) != 0)
			continue;

		sprintf(file, "%s/%s/trace_pipe_raw", path, name);
		fd = open(file, O_RDONLY | O_NONBLOCK);
		if (fd < 0)
			continue;
		do {
			r = read(fd, page, page_size);
			ts = find_ts_in_page(pevent, page, r);
			if (ts)
				break;
		} while (r > 0);
		if (ts)
			break;
	}
	free(file);
	free(page);
	closedir(dir);

 out:
	tracecmd_put_tracing_file(path);
	return ts;
}

static char *read_instance_file(struct buffer_instance *instance, char *file, int *psize)
{
	char buffer[BUFSIZ];
	char *path;
	char *buf;
	int size = 0;
	int fd;
	int r;

	path = get_instance_file(instance, file);
	fd = open(path, O_RDONLY);
	tracecmd_put_tracing_file(path);
	if (fd < 0) {
		warning("%s not found, --date ignored", file);
		return NULL;
	}
	do {
		r = read(fd, buffer, BUFSIZ);
		if (r <= 0)
			continue;
		if (size)
			buf = realloc(buf, size+r+1);
		else
			buf = malloc(r+1);
		if (!buf)
			die("Failed to allocate instance file buffer");
		memcpy(buf+size, buffer, r);
		size += r;
	} while (r);

	buf[size] = '\0';
	if (psize)
		*psize = size;
	return buf;
}

static char *read_file(char *file, int *psize)
{
	return read_instance_file(&top_instance, file, psize);
}

/*
 * Try to write the date into the ftrace buffer and then
 * read it back, mapping the timestamp to the date.
 */
static char *get_date_to_ts(void)
{
	unsigned long long min = -1ULL;
	unsigned long long diff;
	unsigned long long stamp;
	unsigned long long min_stamp;
	unsigned long long min_ts;
	unsigned long long ts;
	struct pevent *pevent;
	struct timeval start;
	struct timeval end;
	char *date2ts = NULL;
	char *path;
	char *buf;
	int size;
	int tfd;
	int ret;
	int i;

	/* Set up a pevent to read the raw format */
	pevent = pevent_alloc();
	if (!pevent) {
		warning("failed to alloc pevent, --date ignored");
		return NULL;
	}

	buf = read_file("events/header_page", &size);
	if (!buf)
		goto out_pevent;
	ret = pevent_parse_header_page(pevent, buf, size, sizeof(unsigned long));
	free(buf);
	if (ret < 0) {
		warning("Can't parse header page, --date ignored");
		goto out_pevent;
	}

	/* Find the format for ftrace:print. */
	buf = read_file("events/ftrace/print/format", &size);
	if (!buf)
		goto out_pevent;
	ret = pevent_parse_event(pevent, buf, size, "ftrace");
	free(buf);
	if (ret < 0) {
		warning("Can't parse print event, --date ignored");
		goto out_pevent;
	}

	path = tracecmd_get_tracing_file("trace_marker");
	tfd = open(path, O_WRONLY);
	tracecmd_put_tracing_file(path);
	if (tfd < 0) {
		warning("Can not open 'trace_marker', --date ignored");
		goto out_pevent;
	}

	for (i = 0; i < date2ts_tries; i++) {
		tracecmd_disable_tracing();
		clear_trace();
		tracecmd_enable_tracing();

		gettimeofday(&start, NULL);
		write(tfd, STAMP, 5);
		gettimeofday(&end, NULL);

		tracecmd_disable_tracing();
		ts = find_time_stamp(pevent);
		if (!ts)
			continue;

		diff = (unsigned long long)end.tv_sec * 1000000;
		diff += (unsigned long long)end.tv_usec;
		stamp = diff;
		diff -= (unsigned long long)start.tv_sec * 1000000;
		diff -= (unsigned long long)start.tv_usec;

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
	snprintf(date2ts, 19, "0x%llx", min_stamp - min_ts / 1000);

 out_pevent:
	pevent_free(pevent);

	return date2ts;
}

static void set_buffer_size_instance(struct buffer_instance *instance)
{
	int buffer_size = instance->buffer_size;
	char buf[BUFSIZ];
	char *path;
	int ret;
	int fd;

	if (!buffer_size)
		return;

	if (buffer_size < 0)
		die("buffer size must be positive");

	snprintf(buf, BUFSIZ, "%d", buffer_size);

	path = get_instance_file(instance, "buffer_size_kb");
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
	tracecmd_put_tracing_file(path);
}

void set_buffer_size(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		set_buffer_size_instance(instance);
}

static void
process_event_trigger(char *path, struct event_iter *iter, enum event_process *processed)
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

	clear_trigger(trigger);
 out:
	free(trigger);
	free(file);
}

static void clear_instance_triggers(struct buffer_instance *instance)
{
	struct event_iter *iter;
	char *path;
	char *system;
	enum event_iter_type type;
	enum event_process processed = PROCESSED_NONE;

	path = get_instance_file(instance, "events");
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

		process_event_trigger(path, iter, &processed);
	}

	trace_event_iter_free(iter);

	tracecmd_put_tracing_file(path);
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

	path = get_instance_file(instance, "events");
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

	tracecmd_put_tracing_file(path);
}

static void clear_filters(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		clear_instance_filters(instance);
}

static void clear_triggers(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		clear_instance_triggers(instance);
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
			path = get_instance_file(instance, files[i]);
			clear_func_filter(path);
			tracecmd_put_tracing_file(path);
		}
	}
}

static void make_instances(void)
{
	struct buffer_instance *instance;
	struct stat st;
	char *path;
	int ret;

	for_each_instance(instance) {
		path = get_instance_dir(instance);
		ret = stat(path, &st);
		if (ret < 0) {
			ret = mkdir(path, 0777);
			if (ret < 0)
				die("mkdir %s", path);
		} else
			/* Don't delete instances that already exist */
			instance->keep = 1;
		tracecmd_put_tracing_file(path);
	}
}

void tracecmd_remove_instances(void)
{
	struct buffer_instance *instance;
	char *path;
	int ret;

	for_each_instance(instance) {
		/* Only delete what we created */
		if (instance->keep)
			continue;
		if (instance->tracing_on_fd > 0) {
			close(instance->tracing_on_fd);
			instance->tracing_on_fd = 0;
		}
		path = get_instance_dir(instance);
		ret = rmdir(path);
		if (ret < 0)
			die("rmdir %s", path);
		tracecmd_put_tracing_file(path);
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
	add_instance(instance);
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

	buf = read_file("available_tracers", NULL);
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
	return instance->profile || instance->plugin || instance->events;
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
		instance->s_save = malloc(sizeof(struct trace_seq) * cpu_count);
		instance->s_print = malloc(sizeof(struct trace_seq) * cpu_count);
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

	overrun = atoi(p + sizeof(overrun_str));

	p = strstr(p + 9, commit_overrun_str);
	if (p)
		commit_overrun = atoi(p + sizeof(commit_overrun_str));
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
		s_save = instance->s_save;
		s_print = instance->s_print;
		for (cpu = 0; cpu < cpu_count; cpu++) {
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
		for (cpu = 0; cpu < cpu_count; cpu++) {
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
	if (event->trigger) {
		event->trigger = realloc(event->trigger,
					 strlen(event->trigger) + strlen("\n") +
					 strlen(trigger) + 1);
		strcat(event->trigger, "\n");
		strcat(event->trigger, trigger);
	} else {
		event->trigger = malloc(strlen(trigger) + 1);
		if (!event->trigger)
			die("Failed to allocate event trigger");
		sprintf(event->trigger, "%s", trigger);
	}
}

static int test_stacktrace_trigger(struct buffer_instance *instance)
{
	char *path;
	int ret = 0;
	int fd;

	path = get_instance_file(instance, "events/sched/sched_switch/trigger");

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
	tracecmd_put_tracing_file(path);

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

enum {

	OPT_debug		= 247,
	OPT_max_graph_depth	= 248,
	OPT_tsoffset		= 249,
	OPT_bycomm		= 250,
	OPT_stderr		= 251,
	OPT_profile		= 252,
	OPT_nosplice		= 253,
	OPT_funcstack		= 254,
	OPT_date		= 255,
};

void trace_record (int argc, char **argv)
{
	const char *plugin = NULL;
	const char *output = NULL;
	const char *option;
	struct event_list *event = NULL;
	struct event_list *last_event = NULL;
	struct buffer_instance *instance = &top_instance;
	enum trace_type type = 0;
	char *pids;
	char *pid;
	char *sav;
	char *date2ts = NULL;
	int record_all = 0;
	int total_disable = 0;
	int disable = 0;
	int events = 0;
	int record = 0;
	int extract = 0;
	int stream = 0;
	int profile = 0;
	int global = 0;
	int start = 0;
	int run_command = 0;
	int neg_event = 0;
	int date = 0;
	int manual = 0;
	char *max_graph_depth = NULL;
	int topt = 0;
	int do_child = 0;
	int data_flags = 0;

	int c;

	init_instance(instance);

	cpu_count = count_cpus();

	if ((record = (strcmp(argv[1], "record") == 0)))
		; /* do nothing */
	else if ((start = strcmp(argv[1], "start") == 0))
		; /* do nothing */
	else if ((extract = strcmp(argv[1], "extract") == 0))
		; /* do nothing */
	else if ((stream = strcmp(argv[1], "stream") == 0))
		; /* do nothing */
	else if ((profile = strcmp(argv[1], "profile") == 0)) {
		handle_init = trace_init_profile;
		events = 1;
	} else if (strcmp(argv[1], "stop") == 0) {
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
				add_instance(instance);
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
	} else if (strcmp(argv[1], "restart") == 0) {
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
				add_instance(instance);
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
	} else if (strcmp(argv[1], "reset") == 0) {
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
				add_instance(instance);
				/* -d will remove keep */
				instance->keep = 1;
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
				for_each_instance(instance) {
					instance->keep = 1;
				}
				break;
			case 'd':
				if (last_specified_all) {
					for_each_instance(inst) {
						inst->keep = 0;
					}
				} else {
					if (is_top_instance(instance))
						die("Can not delete top level buffer");
					instance->keep = 0;
				}
				break;
			}
		}
		update_first_instance(instance, topt);
		tracecmd_disable_all_tracing(1);
		set_buffer_size();
		clear_filters();
		clear_triggers();
		tracecmd_remove_instances();
		clear_func_filters();
		exit(0);
	} else
		usage(argv);

	for (;;) {
		int option_index = 0;
		const char *opts;
		static struct option long_options[] = {
			{"date", no_argument, NULL, OPT_date},
			{"func-stack", no_argument, NULL, OPT_funcstack},
			{"nosplice", no_argument, NULL, OPT_nosplice},
			{"profile", no_argument, NULL, OPT_profile},
			{"stderr", no_argument, NULL, OPT_stderr},
			{"by-comm", no_argument, NULL, OPT_bycomm},
			{"ts-offset", required_argument, NULL, OPT_tsoffset},
			{"max-graph-depth", required_argument, NULL, OPT_max_graph_depth},
			{"debug", no_argument, NULL, OPT_debug},
			{"help", no_argument, NULL, '?'},
			{NULL, 0, NULL, 0}
		};

		if (extract)
			opts = "+haf:Fp:co:O:sr:g:l:n:P:N:tb:B:ksiT";
		else
			opts = "+hae:f:Fp:cC:dDGo:O:s:r:vg:l:n:P:N:tb:R:B:ksSiTm:M:H:";
		c = getopt_long (argc-1, argv+1, opts, long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'a':
			if (extract) {
				add_all_instances();
			} else {
				record_all = 1;
				record_all_events();
			}
			break;
		case 'e':
			events = 1;
			event = malloc(sizeof(*event));
			if (!event)
				die("Failed to allocate event %s", optarg);
			memset(event, 0, sizeof(*event));
			event->event = optarg;
			add_event(instance, event);
			event->neg = neg_event;
			event->filter = NULL;
			last_event = event;

			if (!record_all)
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
				last_event->filter =
					malloc(strlen(optarg) +
					       strlen("()") + 1);
				if (!last_event->filter)
					die("Failed to allocate filter %s", optarg);
				sprintf(last_event->filter, "(%s)", optarg);
			}
			break;

		case 'R':
			if (!last_event)
				die("trigger must come after event");
			add_trigger(event, optarg);
			break;

		case 'F':
			test_set_event_pid();
			filter_task = 1;
			break;
		case 'G':
			global = 1;
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
			} else {
				save_option("event-fork");
				do_child = 1;
			}
			break;
		case 'C':
			instance->clock = optarg;
			break;
		case 'v':
			neg_event = 1;
			break;
		case 'l':
			add_func(&instance->filter_funcs, optarg);
			break;
		case 'n':
			add_func(&instance->notrace_funcs, optarg);
			break;
		case 'g':
			add_func(&graph_funcs, optarg);
			break;
		case 'p':
			if (instance->plugin)
				die("only one plugin allowed");
			for (plugin = optarg; isspace(*plugin); plugin++)
				;
			instance->plugin = plugin;
			for (optarg += strlen(optarg) - 1;
			     optarg > plugin && isspace(*optarg); optarg--)
				;
			optarg++;
			optarg[0] = '\0';
			break;
		case 'D':
			total_disable = 1;
			/* fall through */
		case 'd':
			disable = 1;
			break;
		case 'o':
			if (host)
				die("-o incompatible with -N");
			if (start)
				die("start does not take output\n"
				    "Did you mean 'record'?");
			if (stream)
				die("stream does not take output\n"
				    "Did you mean 'record'?");
			if (output)
				die("only one output file allowed");
			output = optarg;

			if (profile) {
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
			add_hook(instance, optarg);
			events = 1;
			break;
		case 's':
			if (extract) {
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
			manual = 1;
			/* User sets events for profiling */
			if (!event)
				events = 0;
			break;
		case 'r':
			rt_prio = atoi(optarg);
			break;
		case 'N':
			if (!record)
				die("-N only available with record");
			if (output)
				die("-N incompatible with -o");
			host = optarg;
			break;
		case 'm':
			if (max_kb)
				die("-m can only be specified once");
			if (!record)
				die("only record take 'm' option");
			max_kb = atoi(optarg);
			break;
		case 'M':
			instance->cpumask = alloc_mask_from_hex(optarg);
			break;
		case 't':
			if (extract)
				topt = 1; /* Extract top instance also */
			else
				use_tcp = 1;
			break;
		case 'b':
			instance->buffer_size = atoi(optarg);
			break;
		case 'B':
			instance = create_instance(optarg);
			if (!instance)
				die("Failed to create instance");
			add_instance(instance);
			if (profile)
				instance->profile = 1;
			break;
		case 'k':
			keep = 1;
			break;
		case 'i':
			ignore_event_not_found = 1;
			break;
		case OPT_date:
			date = 1;
			if (data_flags & DATA_FL_OFFSET)
				die("Can not use both --date and --ts-offset");
			data_flags |= DATA_FL_DATE;
			break;
		case OPT_funcstack:
			func_stack = 1;
			break;
		case OPT_nosplice:
			recorder_flags |= TRACECMD_RECORD_NOSPLICE;
			break;
		case OPT_profile:
			handle_init = trace_init_profile;
			instance->profile = 1;
			events = 1;
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
			date2ts = strdup(optarg);
			if (data_flags & DATA_FL_DATE)
				die("Can not use both --date and --ts-offset");
			data_flags |= DATA_FL_OFFSET;
			break;
		case OPT_max_graph_depth:
			free(max_graph_depth);
			max_graph_depth = strdup(optarg);
			if (!max_graph_depth)
				die("Could not allocate option");
			break;
		case OPT_debug:
			debug = 1;
			break;
		default:
			usage(argv);
		}
	}

	if (do_ptrace && !filter_task && (filter_pid < 0))
		die(" -c can only be used with -F (or -P with event-fork support)");
	if (do_child && !filter_task &&! filter_pid)
		die(" -c can only be used with -P or -F");

	if ((argc - optind) >= 2) {
		if (start)
			die("Command start does not take any commands\n"
			    "Did you mean 'record'?");
		if (extract)
			die("Command extract does not take any commands\n"
			    "Did you mean 'record'?");
		run_command = 1;
	}

	/*
	 * If this is a profile run, and no instances were set,
	 * then enable profiling on the top instance.
	 */
	if (profile && !buffer_instances)
		top_instance.profile = 1;

	/*
	 * If top_instance doesn't have any plugins or events, then
	 * remove it from being processed.
	 */
	if (!extract && !__check_doing_something(&top_instance)) {
		if (!buffer_instances)
			die("No instances reference??");
		first_instance = buffer_instances;
	} else
		topt = 1;

	update_first_instance(instance, topt);

	if (!extract)
		check_doing_something();
	check_function_plugin();

	if (output)
		output_file = output;

	/* Save the state of tracing_on before starting */
	for_all_instances(instance) {

		if (!manual && instance->profile)
			enable_profile(instance);

		instance->tracing_on_init_val = read_tracing_on(instance);
		/* Some instances may not be created yet */
		if (instance->tracing_on_init_val < 0)
			instance->tracing_on_init_val = 1;
	}

	/* Extracting data records all events in the system. */
	if (extract && !record_all)
		record_all_events();

	if (!extract)
		make_instances();

	if (events)
		expand_event_list();

	page_size = getpagesize();

	if (!extract) {
		fset = set_ftrace(!disable, total_disable);
		tracecmd_disable_all_tracing(1);

		for_all_instances(instance)
			set_clock(instance);

		/* Record records the date first */
		if (record && date)
			date2ts = get_date_to_ts();

		for_all_instances(instance) {
			set_funcs(instance);
			set_mask(instance);
		}

		if (events) {
			for_all_instances(instance)
				enable_events(instance);
		}
		set_buffer_size();
	}

	if (record)
		type = TRACE_TYPE_RECORD;
	else if (stream)
		type = TRACE_TYPE_STREAM;
	else if (extract)
		type = TRACE_TYPE_EXTRACT;
	else if (profile)
		type = TRACE_TYPE_STREAM;
	else
		type = TRACE_TYPE_START;

	update_plugins(type);

	set_options();

	if (max_graph_depth) {
		for_all_instances(instance)
			set_max_graph_depth(instance, max_graph_depth);
		free(max_graph_depth);
	}

	allocate_seq();

	if (type & (TRACE_TYPE_RECORD | TRACE_TYPE_STREAM)) {
		signal(SIGINT, finish);
		if (!latency)
			start_threads(type, global);
	}

	if (extract) {
		flush_threads();

	} else {
		if (!(type & (TRACE_TYPE_RECORD | TRACE_TYPE_STREAM))) {
			update_task_filter();
			tracecmd_enable_tracing();
			exit(0);
		}

		if (run_command)
			run_cmd(type, (argc - optind) - 1, &argv[optind + 1]);
		else {
			update_task_filter();
			tracecmd_enable_tracing();
			/* We don't ptrace ourself */
			if (do_ptrace && filter_pid >= 0)
				ptrace_attach(filter_pid);
			/* sleep till we are woken with Ctrl^C */
			printf("Hit Ctrl^C to stop recording\n");
			while (!finished)
				trace_or_sleep(type);
		}

		tracecmd_disable_tracing();
		if (!latency)
			stop_threads(type);
	}

	record_stats();

	if (!keep)
		tracecmd_disable_all_tracing(0);

	/* extract records the date after extraction */
	if (extract && date) {
		/*
		 * We need to start tracing, don't let other traces
		 * screw with our trace_marker.
		 */
		tracecmd_disable_all_tracing(1);
		date2ts = get_date_to_ts();
	}

	if (record || extract) {
		record_data(date2ts, data_flags);
		delete_thread_data();
	} else
		print_stats();

	destroy_stats();

	if (keep)
		exit(0);

	update_reset_files();
	update_reset_triggers();
	if (clear_function_filters)
		clear_func_filters();

	set_plugin("nop");

	tracecmd_remove_instances();

	/* If tracing_on was enabled before we started, set it on now */
	for_all_instances(instance) {
		if (instance->keep)
			write_tracing_on(instance, instance->tracing_on_init_val);
	}

	if (host)
		tracecmd_output_close(network_handle);

	if (profile)
		trace_profile();

	exit(0);
}
