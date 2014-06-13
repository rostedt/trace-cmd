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

#define UDP_MAX_PACKET (65536 - 20)

static int rt_prio;

static int use_tcp;

static unsigned int page_size;

static const char *output_file = "trace.dat";

static int latency;
static int sleep_time = 1000;
static int cpu_count;
static int recorder_threads;
static int *pids;
static int buffers;

static char *host;
static int *client_ports;
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

static struct func_list *graph_funcs;

static int func_stack;

struct filter_pids {
	struct filter_pids *next;
	int pid;
};

static struct filter_pids *filter_pids;
static int nr_filter_pids;
static int len_filter_pids;

struct opt_list {
	struct opt_list *next;
	const char	*option;
};

static struct opt_list *options;

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

struct buffer_instance top_instance = { .keep = 1 };
struct buffer_instance *buffer_instances;
struct buffer_instance *first_instance = &top_instance;

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

/**
 * add_instance - add a buffer instance to the internal list
 * @instance: The buffer instance to add
 */
void add_instance(struct buffer_instance *instance)
{
	init_instance(instance);
	instance->next = buffer_instances;
	buffer_instances = instance;
	buffers++;
}

/**
 * create_instance - allocate a new buffer instance
 * @name: The name of the instance (instance will point to this)
 *
 * Returns a newly allocated instance. Note that @name will not be
 * copied, and the instance buffer will point to the string itself.
 */
struct buffer_instance *create_instance(char *name)
{
	struct buffer_instance *instance;

	instance = malloc_or_die(sizeof(*instance));
	memset(instance, 0, sizeof(*instance));
	instance->name = optarg;

	return instance;
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
		file = malloc_or_die(size + 1);
		sprintf(file, "%s.%s.cpu%d", output_file, name, cpu);
	} else {
		size = snprintf(file, 0, "%s.cpu%d", output_file, cpu);
		file = malloc_or_die(size + 1);
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
		if (pids[n] > 0) {
			kill(pids[n], SIGKILL);
			delete_temp_file(instance, i);
			pids[n] = 0;
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
			if (pids[n]) {
				delete_temp_file(instance, i);
				if (pids[n] < 0)
					pids[n] = 0;
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

static void stop_threads(void)
{
	int i;

	if (!cpu_count)
		return;

	for (i = 0; i < recorder_threads; i++) {
		if (pids[i] > 0) {
			kill(pids[i], SIGINT);
			waitpid(pids[i], NULL, 0);
			pids[i] = -1;
		}
	}
}

static int create_recorder(struct buffer_instance *instance, int cpu, int extract);

static void flush_threads(void)
{
	long ret;
	int i;

	if (!cpu_count)
		return;

	for (i = 0; i < cpu_count; i++) {
		/* Extract doesn't support sub buffers yet */
		ret = create_recorder(&top_instance, i, 1);
		if (ret < 0)
			die("error reading ring buffer");
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
		buf = malloc_or_die(strlen(instance->name) +
			     strlen(file) + strlen("instances//") + 1);
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

	buf = malloc_or_die(strlen(instance->name) +
			    strlen("instances/") + 1);
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

static void add_filter_pid(int pid)
{
	struct filter_pids *p;
	char buf[100];

	p = malloc_or_die(sizeof(*p));
	p->next = filter_pids;
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
		snprintf(buf, 100, "%d ", pid->pid);
		update_ftrace_pid(buf, reset);
		/* Only reset the first entry */
		reset = 0;
	}
}

static void update_event_filters(struct buffer_instance *instance);
static void update_pid_event_filters(struct buffer_instance *instance);
static void enable_tracing(void);

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
	char *str;
	int curr_len = 0;
	int len;

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
		filter = malloc_or_die(len);

	/* Last '||' that is not used will cover the \0 */
	str = filter + curr_len;

	for (p = filter_pids; p; p = p->next) {
		if (p == filter_pids)
			orit = "";
		else
			orit = "||";
		len = sprintf(str, "%s(%s==%d)", orit, field, p->pid);
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
		add_filter_pid(pid);

	if (!filter_pids)
		return;

	common_pid_filter = make_pid_filter(NULL, "common_pid");

	update_ftrace_pids(1);
	for_all_instances(instance)
		update_pid_event_filters(instance);
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
		filter = malloc_or_die(len);
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
	/*
	 * Also make sure that the sched_switch to this pid
	 * and wakeups of this pid are also traced.
	 * Only need to do this if the events are active.
	 */
	append_sched_event(instance->sched_switch_event, "next_pid", pid);
	append_sched_event(instance->sched_wakeup_event, "pid", pid);
	append_sched_event(instance->sched_wakeup_new_event, "pid", pid);
}

static void add_new_filter_pid(int pid)
{
	struct buffer_instance *instance;
	char buf[100];

	add_filter_pid(pid);
	sprintf(buf, "%d", pid);
	update_ftrace_pid(buf, 0);

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
	add_filter_pid(pid);
}

static void enable_ptrace(void)
{
	if (!do_ptrace || !filter_task)
		return;

	ptrace(PTRACE_TRACEME, 0, NULL, 0);
}

static void ptrace_wait(int main_pid)
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
		ret = waitpid(-1, &status, WSTOPPED | __WALL);
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
static inline void ptrace_wait(int main_pid) { }
static inline void enable_ptrace(void) { }
static inline void ptrace_attach(int pid) { }

#endif /* NO_PTRACE */

void trace_or_sleep(void)
{
	if (do_ptrace && filter_pid >= 0)
		ptrace_wait(filter_pid);
	else
		sleep(10);
}

void run_cmd(int argc, char **argv)
{
	int status;
	int pid;

	if ((pid = fork()) < 0)
		die("failed to fork");
	if (!pid) {
		/* child */
		update_task_filter();
		enable_tracing();
		enable_ptrace();
		if (execvp(argv[0], argv)) {
			fprintf(stderr, "\n********************\n");
			fprintf(stderr, " Unable to exec %s\n", argv[0]);
			fprintf(stderr, "********************\n");
			die("Failed to exec %s", argv[0]);
		}
	}
	if (do_ptrace) {
		add_filter_pid(pid);
		ptrace_wait(pid);
	} else
		waitpid(pid, &status, 0);
}

static void
set_plugin_instance(struct buffer_instance *instance, const char *name)
{
	FILE *fp;
	char *path;
	char zero = '0';

	path = get_instance_file(instance, "current_tracer");
	fp = fopen(path, "w");
	if (!fp)
		die("writing to '%s'", path);
	tracecmd_put_tracing_file(path);

	fwrite(name, 1, strlen(name), fp);
	fclose(fp);

	if (strncmp(name, "function", 8) != 0)
		return;

	/* Make sure func_stack_trace option is disabled */
	/* First try instance file, then top level */
	path = get_instance_file(instance, "options/func_stack_trace");
	fp = fopen(path, "w");
	tracecmd_put_tracing_file(path);
	if (!fp) {
		path = tracecmd_get_tracing_file("options/func_stack_trace");
		fp = fopen(path, "w");
		tracecmd_put_tracing_file(path);
		if (!fp)
			return;
	}
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

	opt = malloc_or_die(sizeof(*opt));
	opt->next = options;
	options = opt;
	opt->option = option;
}

static void set_option(const char *option)
{
	FILE *fp;
	char *path;

	path = tracecmd_get_tracing_file("trace_options");
	fp = fopen(path, "w");
	if (!fp)
		die("writing to '%s'", path);
	tracecmd_put_tracing_file(path);

	fwrite(option, 1, strlen(option), fp);
	fclose(fp);
}

static void set_options(void)
{
	struct opt_list *opt;

	while (options) {
		opt = options;
		options = opt->next;
		set_option(opt->option);
		free(opt);
	}
}

static int use_old_event_method(void)
{
	static int old_event_method;
	static int processed;
	struct stat st;
	char *path;
	int ret;

	if (processed)
		return old_event_method;

	/* Check if the kernel has the events/enable file */
	path = tracecmd_get_tracing_file("events/enable");
	ret = stat(path, &st);
	tracecmd_put_tracing_file(path);
	if (ret < 0)
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

static void write_file(const char *file, const char *str, const char *type)
{
	char buf[BUFSIZ];
	int fd;
	int ret;

	fd = open(file, O_WRONLY);
	if (fd < 0)
		die("opening to '%s'", file);
	ret = write(fd, str, strlen(str));
	close(fd);
	if (ret < 0) {
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
}

static void write_filter(const char *file, const char *filter)
{
	write_file(file, filter, "filter");
}

static void write_trigger(const char *file, const char *trigger)
{
	write_file(file, trigger, "trigger");
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

	if (filter && event->filter_file)
		write_filter(event->filter_file, filter);

	if (event->trigger_file) {
		write_trigger(event->trigger_file, event->trigger);
		/* Make sure we don't write this again */
		free(event->trigger_file);
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

static int open_tracing_on(struct buffer_instance *instance)
{
	int fd = instance->tracing_on_fd;
	char *path;

	/* OK, we keep zero for stdin */
	if (fd > 0)
		return fd;

	path = get_instance_file(instance, "tracing_on");
	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		/* instances may not be created yet */
		if (is_top_instance(instance))
			die("opening '%s'", path);
		return fd;
	}
	tracecmd_put_tracing_file(path);
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

static void enable_tracing(void)
{
	struct buffer_instance *instance;

	check_tracing_enabled();

	for_all_instances(instance)
		write_tracing_on(instance, 1);

	if (latency)
		reset_max_latency();
}

static void disable_tracing(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance)
		write_tracing_on(instance, 0);
}

static void disable_all(int disable_tracer)
{
	disable_tracing();

	if (disable_tracer)
		set_plugin("nop");

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
					event_filter = malloc_or_die(len);
					sprintf(event_filter, "(%s)&&(%s||%s)",
						event->filter, common_pid_filter,
						event->pid_filter);
				} else {
					free_it = 1;
					len = common_len + strlen(event->filter) +
						strlen("()&&()") + 1;
					event_filter = malloc_or_die(len);
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
					event_filter = malloc_or_die(len);
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

static void update_pid_event_filters(struct buffer_instance *instance)
{
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

static void set_mask(struct buffer_instance *instance)
{
	const char *mask = instance->cpumask;
	struct stat st;
	char cpumask[4096]; /* Don't expect more than 32768 CPUS */
	char *path;
	int fd;
	int ret;

	if (!mask)
		return;

	if (strcmp(mask, "-1") == 0) {
		/* set all CPUs */
		int bytes = (cpu_count + 7) / 8;
		int last = cpu_count % 8;
		int i;

		if (bytes > 4095) {
			warning("cpumask can't handle more than 32768 CPUS!");
			bytes = 4095;
		}

		sprintf(cpumask, "%x", (1 << last) - 1);

		for (i = 1; i < bytes; i++)
			cpumask[i] = 'f';

		cpumask[i+1] = 0;

		mask = cpumask;
	}

	path = get_instance_file(instance, "tracing_cpumask");
	if (!path)
		die("could not allocate path");

	ret = stat(path, &st);
	if (ret < 0) {
		if (mask)
			warning("%s not found", path);
		goto out;
	}

	fd = open(path, O_WRONLY | O_TRUNC);
	if (fd < 0)
		die("could not open %s\n", path);

	if (mask)
		write(fd, mask, strlen(mask));
	
	close(fd);
 out:
	tracecmd_put_tracing_file(path);
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

static struct event_list *
create_event(struct buffer_instance *instance, char *path, struct event_list *old_event)
{
	struct event_list *event;
	struct stat st;
	char *p;
	int ret;

	event = malloc_or_die(sizeof(*event));
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
	p = malloc_or_die(strlen(path) + strlen("/enable") + 1);
	sprintf(p, "%s/enable", path);
	ret = stat(p, &st);
	if (ret >= 0)
		event->enable_file = p;
	else
		free(p);

	if (event->trigger) {
		p = malloc_or_die(strlen(path) + strlen("/trigger") + 1);
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

	path = malloc_or_die(strlen(sched->filter_file) + strlen(sched_path) + 1);

	sprintf(path, "%s", sched->filter_file);

	/* Remove the /filter from filter file */
	p = path + strlen(path) - strlen("filter");
	sprintf(p, "%s/filter", sched_path);

	*event = create_event(instance, path, sched);
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

	p = malloc_or_die(strlen(file) + strlen("events//filter") + 1);
	sprintf(p, "events/%s/filter", file);

	path = get_instance_file(instance, p);
	printf("%s\n", path);

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
		str = malloc_or_die(strlen(name) + 1); /* may add '*' */
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
	str = malloc_or_die(len);
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

static int count_cpus(void)
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
create_recorder_instance(struct buffer_instance *instance, const char *file, int cpu)
{
	struct tracecmd_recorder *record;
	char *path;

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
static int create_recorder(struct buffer_instance *instance, int cpu, int extract)
{
	long ret;
	char *file;
	int pid;

	/* network for buffer instances not supported yet */
	if (client_ports && instance->name)
		return 0;

	if (!extract) {
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
		recorder = create_recorder_instance(instance, file, cpu);
		put_temp_file(file);
	}

	if (!recorder)
		die ("can't create recorder");

	if (extract) {
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

static void communicate_with_listener(int fd)
{
	char buf[BUFSIZ];
	ssize_t n;
	int cpu, i;

	n = read(fd, buf, 8);

	/* Make sure the server is the tracecmd server */
	if (memcmp(buf, "tracecmd", 8) != 0)
		die("server not tracecmd server");

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

	client_ports = malloc_or_die(sizeof(int) * cpu_count);

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

	communicate_with_listener(sfd);

	/* Now create the handle through this socket */
	network_handle = tracecmd_create_init_fd_glob(sfd, listed_events);

	/* OK, we are all set, let'r rip! */
}

static void finish_network(void)
{
	close(sfd);
	free(host);
}

static void start_threads(void)
{
	struct buffer_instance *instance;
	int i = 0;

	if (host)
		setup_network();

	/* make a thread for every CPU we have */
	pids = malloc_or_die(sizeof(*pids) * cpu_count * (buffers + 1));

	memset(pids, 0, sizeof(*pids) * cpu_count * (buffers + 1));

	for_all_instances(instance) {
		int x;
		for (x = 0; x < cpu_count; x++)
			pids[i++] = create_recorder(instance, x, 0);
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
				    instance->s[i].len+1,
				    instance->s[i].buffer);
}

static void touch_file(const char *file)
{
	int fd;

	fd = open(file, O_WRONLY | O_CREAT | O_TRUNC);
	if (fd < 0)
		die("could not create file %s\n", file);
	close(fd);
}

static void record_data(char *date2ts)
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

		temp_files = malloc_or_die(sizeof(*temp_files) * cpu_count);

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

		if (date2ts)
			tracecmd_add_option(handle, TRACECMD_OPTION_DATE,
					    strlen(date2ts)+1, date2ts);

		/* Only record the top instance under TRACECMD_OPTION_CPUSTAT*/
		if (!no_top_instance()) {
			struct trace_seq *s = top_instance.s;

			for (i = 0; i < cpu_count; i++)
				tracecmd_add_option(handle, TRACECMD_OPTION_CPUSTAT,
						    s[i].len+1, s[i].buffer);
		}

		tracecmd_add_option(handle, TRACECMD_OPTION_TRACECLOCK,
				    0, NULL);

		if (buffers) {
			buffer_options = malloc_or_die(sizeof(*buffer_options) * buffers);
			i = 0;
			for_each_instance(instance) {
				buffer_options[i++] = tracecmd_add_buffer_option(handle, instance->name);
				add_buffer_stat(handle, instance);
			}
		}

		tracecmd_append_cpu_data(handle, cpu_count, temp_files);

		for (i = 0; i < cpu_count; i++)
			put_temp_file(temp_files[i]);

		if (buffers) {
			i = 0;
			for_each_instance(instance) {
				append_buffer(handle, buffer_options[i++], instance, temp_files);
			}
		}

		free(temp_files);
	}
	if (!handle)
		die("could not write to file");
	tracecmd_output_close(handle);
}

static void write_func_file(struct buffer_instance *instance,
			    const char *file, struct func_list **list)
{
	struct func_list *item;
	char *path;
	int fd;
	int ret;

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

 free:
	tracecmd_put_tracing_file(path);
	return;
 failed:
	die("Failed to write %s to %s.\n"
	    "Perhaps this function is not available for tracing.\n"
	    "run 'trace-cmd list -f %s' to see if it is.",
	    item->func, file, item->func);
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
	write_func_file(instance, "set_ftrace_filter", &instance->filter_funcs);
	write_func_file(instance, "set_ftrace_notrace", &instance->notrace_funcs);
	/* graph tracing currently only works for top instance */
	if (is_top_instance(instance))
		write_func_file(instance, "set_graph_function", &graph_funcs);

	/* make sure we are filtering functions */
	if (func_stack && is_top_instance(instance)) {
		if (!functions_filtered(instance))
			die("Function stack trace set, but functions not filtered");
		save_option(FUNC_STACK_TRACE);
	}
}

static void add_func(struct func_list **list, const char *func)
{
	struct func_list *item;

	item = malloc_or_die(sizeof(*item));
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
	file = malloc_or_die(len + strlen("trace_pipe_raw") + 32);
	page = malloc_or_die(page_size);

	while ((dent = readdir(dir))) {
		const char *name = dent->d_name;

		if (strncmp(name, "cpu", 3) != 0)
			continue;

		sprintf(file, "%s/%s/trace_pipe_raw", path, name);
		fd = open(file, O_RDONLY);
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

static char *read_file(char *file, int *psize)
{
	char buffer[BUFSIZ];
	char *path;
	char *buf;
	int size = 0;
	int fd;
	int r;

	path = tracecmd_get_tracing_file(file);
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
		if (size) {
			buf = realloc(buf, size+r+1);
			if (!buf)
				die("malloc");
		} else
			buf = malloc_or_die(r+1);
		memcpy(buf+size, buffer, r);
		size += r;
	} while (r);

	buf[size] = '\0';
	if (psize)
		*psize = size;
	return buf;
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
		disable_tracing();
		clear_trace();
		enable_tracing();

		gettimeofday(&start, NULL);
		write(tfd, STAMP, 5);
		gettimeofday(&end, NULL);

		disable_tracing();
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

static void remove_instances(void)
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

static void check_plugin(const char *plugin)
{
	char *buf;
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

	while ((tok = strtok(buf, " "))) {
		buf = NULL;
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

static void check_doing_something(void)
{
	struct buffer_instance *instance;

	for_all_instances(instance) {
		if (instance->plugin || instance->events)
			return;
	}

	die("no event or plugin was specified... aborting");
}

enum trace_type {
	TRACE_TYPE_RECORD,
	TRACE_TYPE_START,
	TRACE_TYPE_EXTRACT,
};

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

	for_all_instances(instance)
		instance->s = malloc_or_die(sizeof(struct trace_seq) * cpu_count);
}

static void record_stats(void)
{
	struct buffer_instance *instance;
	struct trace_seq *s;
	int cpu;

	for_all_instances(instance) {
		s = instance->s;
		for (cpu = 0; cpu < cpu_count; cpu++) {
			trace_seq_init(&s[cpu]);
			trace_seq_printf(&s[cpu], "CPU: %d\n", cpu);
			tracecmd_stat_cpu_instance(instance, &s[cpu], cpu);
		}
	}
}

static void print_stats(void)
{
	struct buffer_instance *instance;
	int cpu;

	for_all_instances(instance) {
		if (!is_top_instance(instance)) {
			if (instance != first_instance)
				printf("\n");
			printf("Buffer: %s\n\n", instance->name);
		}
		for (cpu = 0; cpu < cpu_count; cpu++) {
			trace_seq_do_printf(&instance->s[cpu]);
			printf("\n");
		}
	}
}

static void destroy_stats(void)
{
	struct buffer_instance *instance;
	int cpu;

	for_all_instances(instance) {
		for (cpu = 0; cpu < cpu_count; cpu++)
			trace_seq_destroy(&instance->s[cpu]);
	}
}

static void record_all_events(void)
{
	struct tracecmd_event_list *list;

	while (listed_events) {
		list = listed_events;
		listed_events = list->next;
		free(list);
	}
	list = malloc_or_die(sizeof(*list));
	list->next = NULL;
	list->glob = "*/*";
	listed_events = list;
}

enum {
	OPT_nosplice	= 253,
	OPT_funcstack	= 254,
	OPT_date	= 255,
};

void trace_record (int argc, char **argv)
{
	const char *plugin = NULL;
	const char *output = NULL;
	const char *option;
	struct event_list *event;
	struct event_list *last_event;
	struct tracecmd_event_list *list;
	struct buffer_instance *instance = &top_instance;
	enum trace_type type;
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
	int run_command = 0;
	int neg_event = 0;
	int keep = 0;
	int date = 0;

	int c;

	init_instance(instance);

	cpu_count = count_cpus();

	if ((record = (strcmp(argv[1], "record") == 0)))
		; /* do nothing */
	else if (strcmp(argv[1], "start") == 0)
		; /* do nothing */
	else if ((extract = strcmp(argv[1], "extract") == 0))
		; /* do nothing */
	else if (strcmp(argv[1], "stop") == 0) {
		int topt = 0;
		for (;;) {
			int c;

			c = getopt(argc-1, argv+1, "tB:");
			if (c == -1)
				break;
			switch (c) {
			case 'h':
				usage(argv);
				break;
			case 'B':
				instance = create_instance(optarg);
				add_instance(instance);
				/* top instance requires direct access */
				if (!topt && is_top_instance(first_instance))
					first_instance = instance;
				break;
			case 't':
				/* Force to use top instance */
				topt = 1;
				instance = &top_instance;
				first_instance = instance;
				break;
			default:
				usage(argv);
			}

		}
		disable_tracing();
		exit(0);
	} else if (strcmp(argv[1], "restart") == 0) {
		int topt = 0;
		for (;;) {
			int c;

			c = getopt(argc-1, argv+1, "tB:");
			if (c == -1)
				break;
			switch (c) {
			case 'h':
				usage(argv);
				break;
			case 'B':
				instance = create_instance(optarg);
				add_instance(instance);
				/* top instance requires direct access */
				if (!topt && is_top_instance(first_instance))
					first_instance = instance;
				break;
			case 't':
				/* Force to use top instance */
				topt = 1;
				instance = &top_instance;
				first_instance = instance;
				break;
			default:
				usage(argv);
			}

		}
		enable_tracing();
		exit(0);
	} else if (strcmp(argv[1], "reset") == 0) {
		int topt = 0;

		while ((c = getopt(argc-1, argv+1, "b:B:td")) >= 0) {
			switch (c) {
			case 'b':
				instance->buffer_size = atoi(optarg);
				/* Min buffer size is 1 */
				if (strcmp(optarg, "0") == 0)
					instance->buffer_size = 1;
				break;
			case 'B':
				instance = create_instance(optarg);
				add_instance(instance);
				/* -d will remove keep */
				instance->keep = 1;
				/* top instance requires direct access */
				if (!topt && is_top_instance(first_instance))
					first_instance = instance;
				break;
			case 't':
				/* Force to use top instance */
				topt = 1;
				instance = &top_instance;
				first_instance = instance;
				break;
			case 'd':
				if (is_top_instance(instance))
					die("Can not delete top level buffer");
				instance->keep = 0;
				break;
			}
		}
		disable_all(1);
		set_buffer_size();
		remove_instances();
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
			{"help", no_argument, NULL, '?'},
			{NULL, 0, NULL, 0}
		};

		if (extract)
			opts = "+haf:Fp:co:O:sr:g:l:n:P:N:tb:ksiT";
		else
			opts = "+hae:f:Fp:cdDo:O:s:r:vg:l:n:P:N:tb:R:B:ksiTm:M:";
		c = getopt_long (argc-1, argv+1, opts, long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'a':
			if (!extract) {
				record_all = 1;
				record_all_events();
			}
			break;
		case 'e':
			events = 1;
			event = malloc_or_die(sizeof(*event));
			memset(event, 0, sizeof(*event));
			event->event = optarg;
			add_event(instance, event);
			event->neg = neg_event;
			event->filter = NULL;
			last_event = event;

			if (!record_all) {
				list = malloc_or_die(sizeof(*list));
				list->next = listed_events;
				list->glob = optarg;
				listed_events = list;
			}

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
					malloc_or_die(strlen(optarg) +
						      strlen("()") + 1);
				sprintf(last_event->filter, "(%s)", optarg);
			}
			break;

		case 'R':
			if (!last_event)
				die("trigger must come after event");
			if (last_event->trigger) {
				last_event->trigger =
					realloc(last_event->trigger,
						strlen(last_event->trigger) +
						strlen("\n") +
						strlen(optarg) + 1);
				strcat(last_event->trigger, "\n");
				strcat(last_event->trigger, optarg);
			} else {
				last_event->trigger =
					malloc_or_die(strlen(optarg) + 1);
				sprintf(last_event->trigger, "%s", optarg);
			}
			break;

		case 'F':
			filter_task = 1;
			break;
		case 'P':
			pids = strdup(optarg);
			if (!pids)
				die("strdup");
			pid = strtok_r(pids, ",", &sav);
			while (pid) {
				add_filter_pid(atoi(pid));
				pid = strtok_r(NULL, ",", &sav);
			}
			free(pids);
			break;
		case 'c':
#ifdef NO_PTRACE
			die("-c invalid: ptrace not supported");
#endif
			do_ptrace = 1;
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
			if (!record && !extract)
				die("start does not take output\n"
				    "Did you mean 'record'?");
			if (output)
				die("only one output file allowed");
			output = optarg;
			break;
		case 'O':
			option = optarg;
			save_option(option);
			break;
		case 'T':
			save_option("stacktrace");
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
			instance->cpumask = optarg;
			break;
		case 't':
			use_tcp = 1;
			break;
		case 'b':
			instance->buffer_size = atoi(optarg);
			break;
		case 'B':
			instance = create_instance(optarg);
			add_instance(instance);
			break;
		case 'k':
			keep = 1;
			break;
		case 'i':
			ignore_event_not_found = 1;
			break;
		case OPT_date:
			date = 1;
			break;
		case OPT_funcstack:
			func_stack = 1;
			break;
		case OPT_nosplice:
			recorder_flags |= TRACECMD_RECORD_NOSPLICE;
			break;
		default:
			usage(argv);
		}
	}

	if (do_ptrace && !filter_task && (filter_pid < 0))
		die(" -c can only be used with -F or -P");

	if ((argc - optind) >= 2) {
		if (!record)
			die("Command start does not take any commands\n"
			    "Did you mean 'record'?");
		if (extract)
			die("Command extract does not take any commands\n"
			    "Did you mean 'record'?");
		run_command = 1;
	}

	/*
	 * If top_instance doesn't have any plugins or events, then
	 * remove it from being processed.
	 */
	if (!extract && !top_instance.plugin && !top_instance.events) {
		if (!buffer_instances)
			die("No instances reference??");
		first_instance = buffer_instances;
	}

	if (!extract)
		check_doing_something();
	check_function_plugin();

	if (output)
		output_file = output;

	/* Save the state of tracing_on before starting */
	for_all_instances(instance) {
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
		disable_all(1);

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
	else if (extract)
		type = TRACE_TYPE_EXTRACT;
	else
		type = TRACE_TYPE_START;
		
	update_plugins(type);

	set_options();

	allocate_seq();

	if (record) {
		signal(SIGINT, finish);
		if (!latency)
			start_threads();
	}

	if (extract) {
		flush_threads();

	} else {
		if (!record) {
			update_task_filter();
			enable_tracing();
			exit(0);
		}

		if (run_command)
			run_cmd((argc - optind) - 1, &argv[optind + 1]);
		else {
			update_task_filter();
			enable_tracing();
			/* We don't ptrace ourself */
			if (do_ptrace && filter_pid >= 0)
				ptrace_attach(filter_pid);
			/* sleep till we are woken with Ctrl^C */
			printf("Hit Ctrl^C to stop recording\n");
			while (!finished)
				trace_or_sleep();
		}

		disable_tracing();
		if (!latency)
			stop_threads();
	}

	record_stats();

	if (!keep)
		disable_all(0);

	printf("Kernel buffer statistics:\n"
	       "  Note: \"entries\" are the entries left in the kernel ring buffer and are not\n"
	       "        recorded in the trace data. They should all be zero.\n\n");

	print_stats();

	/* extract records the date after extraction */
	if (extract && date) {
		/*
		 * We need to start tracing, don't let other traces
		 * screw with our trace_marker.
		 */
		disable_all(1);
		date2ts = get_date_to_ts();
	}

	record_data(date2ts);
	delete_thread_data();

	destroy_stats();

	if (keep)
		exit(0);

	set_plugin("nop");

	remove_instances();

	/* If tracing_on was enabled before we started, set it on now */
	for_all_instances(instance) {
		if (instance->keep)
			write_tracing_on(instance, instance->tracing_on_init_val);
	}

	if (host)
		tracecmd_output_close(network_handle);

	exit(0);
}
