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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <glob.h>

#include "trace-local.h"
#include "version.h"

#define _STR(x) #x
#define STR(x) _STR(x)
#define MAX_PATH 256

#define TRACE_CTRL	"tracing_on"
#define TRACE		"trace"
#define AVAILABLE	"available_tracers"
#define CURRENT		"current_tracer"
#define ITER_CTRL	"trace_options"
#define MAX_LATENCY	"tracing_max_latency"

#define UDP_MAX_PACKET (65536 - 20)

static int use_tcp;

static unsigned int page_size;

static int buffer_size;

static const char *output_file = "trace.dat";

static int latency;
static int sleep_time = 1000;
static int cpu_count;
static int *pids;

static char *host;
static int *client_ports;
static int sfd;

static int filter_task;
static int filter_pid = -1;

struct func_list {
	struct func_list *next;
	const char *func;
};

static struct func_list *filter_funcs;
static struct func_list *notrace_funcs;
static struct func_list *graph_funcs;

struct event_list {
	struct event_list *next;
	const char *event;
	char *filter;
	int neg;
};

static struct event_list *event_selection;

struct events {
	struct events *sibling;
	struct events *children;
	struct events *next;
	char *name;
};

static struct tracecmd_recorder *recorder;

static char *get_temp_file(int cpu)
{
	char *file = NULL;
	int size;

	size = snprintf(file, 0, "%s.cpu%d", output_file, cpu);
	file = malloc_or_die(size + 1);
	sprintf(file, "%s.cpu%d", output_file, cpu);

	return file;
}

static void put_temp_file(char *file)
{
	free(file);
}

static void delete_temp_file(int cpu)
{
	char file[MAX_PATH];

	snprintf(file, MAX_PATH, "%s.cpu%d", output_file, cpu);
	unlink(file);
}

static void kill_threads(void)
{
	int i;

	if (!cpu_count || !pids)
		return;

	for (i = 0; i < cpu_count; i++) {
		if (pids[i] > 0) {
			kill(pids[i], SIGKILL);
			delete_temp_file(i);
			pids[i] = 0;
		}
	}
}

static void delete_thread_data(void)
{
	int i;

	if (!cpu_count)
		return;

	for (i = 0; i < cpu_count; i++) {
		if (pids[i]) {
			delete_temp_file(i);
			if (pids[i] < 0)
				pids[i] = 0;
		}
	}
}

static void stop_threads(void)
{
	int i;

	if (!cpu_count)
		return;

	for (i = 0; i < cpu_count; i++) {
		if (pids[i] > 0) {
			kill(pids[i], SIGINT);
			waitpid(pids[i], NULL, 0);
			pids[i] = -1;
		}
	}
}

static void flush_threads(void)
{
	int i;

	if (!cpu_count)
		return;

	for (i = 0; i < cpu_count; i++) {
		if (pids[i] > 0)
			kill(pids[i], SIGUSR1);
	}
}

void die(char *fmt, ...)
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

void warning(char *fmt, ...)
{
	va_list ap;

	if (errno)
		perror("trace-cmd");
	errno = 0;

	va_start(ap, fmt);
	fprintf(stderr, "  ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");
}

void *malloc_or_die(unsigned int size)
{
	void *data;

	data = malloc(size);
	if (!data)
		die("malloc");
	return data;
}

static int set_ftrace(int set)
{
	struct stat buf;
	char *path = "/proc/sys/kernel/ftrace_enabled";
	int fd;
	char *val = set ? "1" : "0";

	/* if ftace_enable does not exist, simply ignore it */
	fd = stat(path, &buf);
	if (fd < 0)
		return -ENODEV;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		die ("Can't %s ftrace", set ? "enable" : "disable");

	write(fd, val, 1);
	close(fd);

	return 0;
}

static char *get_tracing_file(const char *name);
static void put_tracing_file(char *file);

static void clear_trace(void)
{
	FILE *fp;
	char *path;

	/* reset the trace */
	path = get_tracing_file("trace");
	fp = fopen(path, "w");
	if (!fp)
		die("writing to '%s'", path);
	put_tracing_file(path);
	fwrite("0", 1, 1, fp);
	fclose(fp);
}

static void reset_max_latency(void)
{
	FILE *fp;
	char *path;

	/* reset the trace */
	path = get_tracing_file("tracing_max_latency");
	fp = fopen(path, "w");
	if (!fp)
		die("writing to '%s'", path);
	put_tracing_file(path);
	fwrite("0", 1, 1, fp);
	fclose(fp);
}

static void update_ftrace_pid(const char *pid)
{
	char *path;
	int ret;
	int fd;

	path = get_tracing_file("set_ftrace_pid");
	if (!path)
		return;

	fd = open(path, O_WRONLY | O_TRUNC);
	if (fd < 0)
		return;

	ret = write(fd, pid, strlen(pid));

	/*
	 * Older kernels required "-1" to disable pid
	 */
	if (ret < 0 && !strlen(pid))
		ret = write(fd, "-1", 2);

	if (ret < 0)
		die("error writing to %s", path);

	close(fd);
}

static void update_pid_event_filters(const char *pid);
static void enable_tracing(void);

static void update_task_filter(void)
{
	int pid = getpid();
	char spid[100];

	if (!filter_task && filter_pid < 0) {
		update_ftrace_pid("");
		enable_tracing();
		return;
	}

	if (filter_pid >= 0)
		pid = filter_pid;

	snprintf(spid, 100, "%d", pid);

	update_ftrace_pid(spid);

	update_pid_event_filters(spid);

	enable_tracing();
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
		if (execvp(argv[0], argv))
			exit(-1);
	}
	waitpid(pid, &status, 0);
}

static char *get_tracing_file(const char *name)
{
	static const char *tracing;
	char *file;

	if (!tracing) {
		tracing = tracecmd_find_tracing_dir();
		if (!tracing)
			die("Can't find tracing dir");
	}

	file = malloc_or_die(strlen(tracing) + strlen(name) + 2);
	if (!file)
		return NULL;

	sprintf(file, "%s/%s", tracing, name);
	return file;
}

static void put_tracing_file(char *file)
{
	free(file);
}

static void show_events(void)
{
	char buf[BUFSIZ];
	char *path;
	FILE *fp;
	size_t n;

	path = get_tracing_file("available_events");
	fp = fopen(path, "r");
	if (!fp)
		die("reading %s", path);
	put_tracing_file(path);

	do {
		n = fread(buf, 1, BUFSIZ, fp);
		if (n > 0)
			fwrite(buf, 1, n, stdout);
	} while (n > 0);
	fclose(fp);
}

static void show_plugins(void)
{
	char buf[BUFSIZ];
	char *path;
	FILE *fp;
	size_t n;

	path = get_tracing_file("available_tracers");
	fp = fopen(path, "r");
	if (!fp)
		die("reading %s", path);
	put_tracing_file(path);

	do {
		n = fread(buf, 1, BUFSIZ, fp);
		if (n > 0)
			fwrite(buf, 1, n, stdout);
	} while (n > 0);
	fclose(fp);
}

static void set_plugin(const char *name)
{
	FILE *fp;
	char *path;

	path = get_tracing_file("current_tracer");
	fp = fopen(path, "w");
	if (!fp)
		die("writing to '%s'", path);
	put_tracing_file(path);

	fwrite(name, 1, strlen(name), fp);
	fclose(fp);
}

static void show_options(void)
{
	char buf[BUFSIZ];
	char *path;
	FILE *fp;
	size_t n;

	path = get_tracing_file("trace_options");
	fp = fopen(path, "r");
	if (!fp)
		die("reading %s", path);
	put_tracing_file(path);

	do {
		n = fread(buf, 1, BUFSIZ, fp);
		if (n > 0)
			fwrite(buf, 1, n, stdout);
	} while (n > 0);
	fclose(fp);
}

static void set_option(const char *option)
{
	FILE *fp;
	char *path;

	path = get_tracing_file("trace_options");
	fp = fopen(path, "w");
	if (!fp)
		die("writing to '%s'", path);
	put_tracing_file(path);

	fwrite(option, 1, strlen(option), fp);
	fclose(fp);
}

static void old_update_events(const char *name, char update)
{
	char *path;
	FILE *fp;
	int ret;

	if (strcmp(name, "all") == 0)
		name = "*:*";

	/* need to use old way */
	path = get_tracing_file("set_event");
	fp = fopen(path, "w");
	if (!fp)
		die("opening '%s'", path);
	put_tracing_file(path);

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

static void write_filter(const char *file, const char *filter)
{
	char buf[BUFSIZ];
	int fd;
	int ret;

	fd = open(file, O_WRONLY);
	if (fd < 0)
		die("opening to '%s'", file);
	ret = write(fd, filter, strlen(filter));
	close(fd);
	if (ret < 0) {
		/* filter failed */
		fd = open(file, O_RDONLY);
		if (fd < 0)
			die("writing to '%s'", file);
		/* the filter has the error */
		while ((ret = read(fd, buf, BUFSIZ)) > 0)
			fprintf(stderr, "%.*s", ret, buf);
		die("Failed filter of %s\n", file);
		close(fd);
	}
}

static int update_glob(const char *name, const char *filter,
		       int filter_only, char update)
{
	glob_t globbuf;
	FILE *fp;
	char *filter_file;
	char *path;
	char *str;
	int len;
	int ret;
	int i;
	int count = 0;

	len = strlen(name) + strlen("events//enable") + 1;
	str = malloc_or_die(len);
	snprintf(str, len, "events/%s/enable", name);
	path = get_tracing_file(str);
	free(str);

	globbuf.gl_offs = 0;
	printf("path = %s\n", path);
	ret = glob(path, GLOB_ONLYDIR, NULL, &globbuf);
	put_tracing_file(path);
	if (ret < 0)
		return 0;

	for (i = 0; i < globbuf.gl_pathc; i++) {
		path = globbuf.gl_pathv[i];

		filter_file = strdup(path);
		if (!filter_file)
			die("Allocating memory");

		/* s/enable/filter/ */
		memcpy(filter_file + strlen(filter_file) - 6,
		       "filter", 6);
		if (filter)
			write_filter(filter_file, filter);
		else if (update == '1')
			write_filter(filter_file, "0");
		free(filter_file);
		count++;

		if (filter_only)
			continue;

		fp = fopen(path, "w");
		if (!fp)
			die("writing to '%s'", path);
		ret = fwrite(&update, 1, 1, fp);
		fclose(fp);
		if (ret < 0)
			die("writing to '%s'", path);
	}
	globfree(&globbuf);
	return count;
}

static void filter_all_systems(const char *filter)
{
	glob_t globbuf;
	char *path;
	int ret;
	int i;

	path = get_tracing_file("events/*/filter");

	globbuf.gl_offs = 0;
	ret = glob(path, 0, NULL, &globbuf);
	put_tracing_file(path);
	if (ret < 0)
		die("No filters found");

	for (i = 0; i < globbuf.gl_pathc; i++) {
		path = globbuf.gl_pathv[i];

		write_filter(path, filter);
	}
	globfree(&globbuf);
}

static void update_event(const char *name, const char *filter,
			 int filter_only, char update)
{
	struct stat st;
	FILE *fp;
	char *path;
	char *str;
	char *ptr;
	int len;
	int ret;
	int ret2;

	/* Check if the kernel has the events/enable file */
	path = get_tracing_file("events/enable");
	ret = stat(path, &st);
	if (ret < 0) {
		if (filter_only)
			return;
		put_tracing_file(path);
		/* old kernel */
		old_update_events(name, update);
		return;
	}

	if (!filter_only)
		fprintf(stderr, "%s %s\n",
			update == '1' ? "enable" : "disable", name);

	/* We allow the user to use "all" to enable all events */

	if (strcmp(name, "all") == 0) {
		if (filter)
			filter_all_systems(filter);
		else if (update == '1')
			filter_all_systems("0");

		if (filter_only) {
			put_tracing_file(path);
			return;
		}

		fp = fopen(path, "w");
		if (!fp)
			die("writing to '%s'", path);
		put_tracing_file(path);
		ret = fwrite(&update, 1, 1, fp);
		fclose(fp);
		if (ret < 0)
			die("writing to '%s'", path);
		return;
	}

	ptr = strchr(name, ':');

	if (ptr) {
		len = ptr - name;
		str = strdup(name);
		if (!str)
			die("could not allocate memory");
		str[len] = 0;
		ptr++;
		if (!strlen(ptr) || strcmp(ptr, "*") == 0) {
			ret = update_glob(str, filter, filter_only, update);
			free(str);
			put_tracing_file(path);
			if (!ret)
				goto fail;
			return;
		}

		str[len] = '/';

		ret = update_glob(str, filter, filter_only, update);
		free(str);
		if (!ret)
			die("No events enabled with %s", name);
		return;
	}

	/* No ':' so enable all matching systems and events */
	ret = update_glob(name, filter, filter_only, update);

	len = strlen(name) + strlen("*/") + 1;
	str = malloc_or_die(len);
	snprintf(str, len, "*/%s", name);
	ret2 = update_glob(str, filter, filter_only, update);
	free(str);

	if (!ret && !ret2)
		goto fail;

	return;
 fail:
	die("No events enabled with %s", name);

}

static void write_tracing_on(int on)
{
	static int fd = -1;
	char *path;
	int ret;

	if (fd < 0) {
		path = get_tracing_file("tracing_on");
		fd = open(path, O_WRONLY);
		if (fd < 0)
			die("opening '%s'", path);
		put_tracing_file(path);
	}

	if (on)
		ret = write(fd, "1", 1);
	else
		ret = write(fd, "0", 1);

	if (ret < 0)
		die("writing 'tracing_on'");
}

static void enable_tracing(void)
{
	write_tracing_on(1);

	if (latency)
		reset_max_latency();
}

static void disable_tracing(void)
{
	write_tracing_on(0);
}

static void disable_all(void)
{
	disable_tracing();

	set_plugin("nop");
	update_event("all", "0", 0, '0');
	update_ftrace_pid("");

	clear_trace();
}

static void update_filter(const char *event_name, const char *field,
			  const char *pid)
{
	char buf[BUFSIZ];
	char *filter_name;
	char *path;
	char *filter;
	int fd;
	int ret;

	filter_name = malloc_or_die(strlen(event_name) +
				    strlen("events//filter") + 1);
	sprintf(filter_name, "events/%s/filter", event_name);

	path = get_tracing_file(filter_name);
	free(filter_name);

	/* Ignore if file does not exist */
	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto out;

	ret = read(fd, buf, BUFSIZ);
	if (ret < 0)
		die("Can't read %s", path);
	close(fd);

	/* append unless there is currently no filter */
	if (strncmp(buf, "none", 4) == 0) {
		filter = malloc_or_die(strlen(pid) + strlen(field) +
				       strlen("(==)") + 1);
		sprintf(filter, "(%s==%s)", field, pid);
	} else {
		filter = malloc_or_die(strlen(pid) + strlen(field) +
				       strlen(buf) + strlen("()||(==)") + 1);
		sprintf(filter, "(%s)||(%s==%s)", buf, field, pid);
	}

	fd = open(path, O_WRONLY);
	if (fd < 0)
		die("can't open %s", path);

	ret = write(fd, filter, strlen(filter));
	if (ret < 0)
		warning("Can't write to %s", path);
	close(fd);

	free(filter);

 out:
	put_tracing_file(path);
}

static void update_pid_event_filters(const char *pid)
{
	struct event_list *event;
	char *filter;

	filter = malloc_or_die(strlen(pid) + strlen("(common_pid==)") + 1);
	sprintf(filter, "(common_pid==%s)", pid);

	for (event = event_selection; event; event = event->next) {
		if (!event->neg) {
			if (event->filter) {
				event->filter =
					realloc(event->filter,
						strlen(event->filter) +
						strlen("&&") +
						strlen(filter) + 1);
					strcat(event->filter, "&&");
					strcat(event->filter, filter);
			} else
				event->filter = strdup(filter);
			update_event(event->event, event->filter, 1, '1');
		}
	}

	free(filter);

	/*
	 * Also make sure that the sched_switch to this pid
	 * and wakeups of this pid are also traced.
	 */
	update_filter("sched/sched_switch", "next_pid", pid);
	update_filter("sched/sched_wakeup", "pid", pid);
}

static void enable_events(void)
{
	struct event_list *event;

	for (event = event_selection; event; event = event->next) {
		if (!event->neg)
			update_event(event->event, event->filter, 0, '1');
	}

	/* Now disable any events */
	for (event = event_selection; event; event = event->next) {
		if (event->neg)
			update_event(event->event, NULL, 0, '0');
	}
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

static int finished;

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
		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != 1)
			break;
		close(sfd);
	}

	if (rp == NULL)
		die("Can not connect to %s server %s:%s",
		    use_tcp ? "TCP" : "UDP", host, buf);

	freeaddrinfo(results);

	client_ports[cpu] = sfd;
}

static int create_recorder(int cpu)
{
	char *file;
	int pid;

	pid = fork();
	if (pid < 0)
		die("fork");

	if (pid)
		return pid;

	signal(SIGINT, finish);
	signal(SIGUSR1, flush);

	/* do not kill tasks on error */
	cpu_count = 0;

	if (client_ports) {
		connect_port(cpu);
		recorder = tracecmd_create_recorder_fd(client_ports[cpu], cpu);
	} else {
		file = get_temp_file(cpu);
		recorder = tracecmd_create_recorder(file, cpu);
		put_temp_file(file);
	}

	if (!recorder)
		die ("can't create recorder");
	while (!finished) {
		if (tracecmd_start_recording(recorder, sleep_time) < 0)
			break;
	}
	tracecmd_free_recorder(recorder);

	exit(0);
}

static void setup_network(void)
{
	struct tracecmd_output *handle;
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s;
	ssize_t n;
	char buf[BUFSIZ];
	char *server;
	char *port;
	char *p;
	int cpu;
	int i;

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
		die("Can not connect to %s:%d", server, port);

	freeaddrinfo(result);

	n = read(sfd, buf, 8);

	/* Make sure the server is the tracecmd server */
	if (memcmp(buf, "tracecmd", 8) != 0)
		die("server not tracecmd server");

	/* write the number of CPUs we have (in ASCII) */

	sprintf(buf, "%d", cpu_count);

	/* include \0 */
	write(sfd, buf, strlen(buf)+1);

	/* write the pagesize (in ASCII) */

	page_size = getpagesize();
	sprintf(buf, "%d", page_size);

	/* include \0 */
	write(sfd, buf, strlen(buf)+1);

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
		write(sfd, "1", 2);
		/* Size 4 */
		write(sfd, "4", 2);
		/* use TCP */
		write(sfd, "TCP", 4);
	} else
		/* No options */
		write(sfd, "0", 2);

	client_ports = malloc_or_die(sizeof(int) * cpu_count);

	/*
	 * Now we will receive back a comma deliminated list
	 * of client ports to connect to.
	 */
	for (cpu = 0; cpu < cpu_count; cpu++) {
		for (i = 0; i < BUFSIZ; i++) {
			n = read(sfd, buf+i, 1);
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

	/* Now create the handle through this socket */
	handle = tracecmd_create_init_fd(sfd, cpu_count);

	/* OK, we are all set, let'r rip! */
}

static void finish_network(void)
{
	close(sfd);
	free(host);
}

static void start_threads(void)
{
	int i;

	cpu_count = count_cpus();

	if (host)
		setup_network();

	/* make a thread for every CPU we have */
	pids = malloc_or_die(sizeof(*pids) * cpu_count);

	memset(pids, 0, sizeof(*pids) * cpu_count);

	for (i = 0; i < cpu_count; i++) {
		pids[i] = create_recorder(i);
	}
}

static void record_data(void)
{
	struct tracecmd_output *handle;
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
			temp_files[i] = get_temp_file(i);

		handle = tracecmd_create_file(output_file, cpu_count, temp_files);

		for (i = 0; i < cpu_count; i++)
			put_temp_file(temp_files[i]);
		free(temp_files);
	}
	if (!handle)
		die("could not write to file");
	tracecmd_output_close(handle);
}

static int trace_empty(void)
{
	char *path;
	FILE *fp;
	char *line = NULL;
	size_t size;
	ssize_t n;
	int ret = 1;
	
	/*
	 * Test if the trace file is empty.
	 *
	 * Yes, this is a heck of a hack. What is done here
	 * is to read the trace file and ignore the
	 * lines starting with '#', and if we get a line
	 * that is without a '#' the trace is not empty.
	 * Otherwise it is.
	 */
	path = get_tracing_file("trace");
	fp = fopen(path, "r");
	if (!fp)
		die("reading '%s'", path);

	do {
		n = getline(&line, &size, fp);
		if (n > 0 && line && line[0] != '#') {
			ret = 0;
			break;
		}
	} while (line && n > 0);

	put_tracing_file(path);

	fclose(fp);

	return ret;
}

static void write_func_file(const char *file, struct func_list **list)
{
	struct func_list *item;
	char *path;
	int fd;

	path = get_tracing_file(file);

	fd = open(path, O_WRONLY | O_TRUNC);
	if (fd < 0)
		goto free;

	while (*list) {
		item = *list;
		*list = item->next;
		write(fd, item->func, strlen(item->func));
		write(fd, " ", 1);
		free(item);
	}
	close(fd);

 free:
	put_tracing_file(path);
}

static void set_funcs(void)
{
	write_func_file("set_ftrace_filter", &filter_funcs);
	write_func_file("set_ftrace_notrace", &notrace_funcs);
	write_func_file("set_graph_function", &graph_funcs);
}

static void add_func(struct func_list **list, const char *func)
{
	struct func_list *item;

	item = malloc_or_die(sizeof(*item));
	item->func = func;
	item->next = *list;
	*list = item;
}

void set_buffer_size(void)
{
	char buf[BUFSIZ];
	char *path;
	int ret;
	int fd;

	if (!buffer_size)
		return;

	if (buffer_size < 0)
		die("buffer size must be positive");

	snprintf(buf, BUFSIZ, "%d", buffer_size);

	path = get_tracing_file("buffer_size_kb");
	fd = open(path, O_WRONLY);
	if (fd < 0)
		die("can't open %s", path);

	ret = write(fd, buf, strlen(buf));
	if (ret < 0)
		warning("Can't write to %s", path);
	close(fd);
}

void usage(char **argv)
{
	char *arg = argv[0];
	char *p = arg+strlen(arg);

	while (p >= arg && *p != '/')
		p--;
	p++;

	printf("\n"
	       "%s version %s\n\n"
	       "usage:\n"
	       " %s record [-v][-e event [-f filter]][-p plugin][-F][-d][-o file] \\\n"
	       "           [-s usecs][-O option ][-l func][-g func][-n func]\n"
	       "           [-P pid][-N host:port][-t][-b size][command ...]\n"
	       "          -e run command with event enabled\n"
	       "          -f filter for previous -e event\n"
	       "          -p run command with plugin enabled\n"
	       "          -F filter only on the given process\n"
	       "          -P trace the given pid like -F for the command\n"
	       "          -l filter function name\n"
	       "          -g set graph function\n"
	       "          -n do not trace function\n"
	       "          -v will negate all -e after it (disable those events)\n"
	       "          -d disable function tracer when running\n"
	       "          -o data output file [default trace.dat]\n"
	       "          -O option to enable (or disable)\n"
	       "          -s sleep interval between recording (in usecs) [default: 1000]\n"
	       "          -N host:port to connect to (see listen)\n"
	       "          -t used with -N, forces use of tcp in live trace\n"
	       "          -b change kernel buffersize (in kilobytes per CPU)\n"
	       "\n"
	       " %s start [-e event][-p plugin][-d][-O option ][-P pid]\n"
	       "          Uses same options as record, but does not run a command.\n"
	       "          It only enables the tracing and exits\n"
	       "\n"
	       " %s extract [-p plugin][-O option][-o file]\n"
	       "          Uses same options as record, but only reads an existing trace.\n"
	       "\n"
	       " %s stop\n"
	       "          Stops the tracer from recording more data.\n"
	       "          Used in conjunction with start\n"
	       "\n"
	       " %s reset [-b size]\n"
	       "          Disables the tracer (may reset trace file)\n"
	       "          Used in conjunction with start\n"
	       "          -b change the kernel buffer size (in kilobytes per CPU)\n"
	       "\n"
	       " %s report [-i file] [--cpu cpu] [-e][-f][-l][-P][-E][-F filter][-v]\n"
	       "          -i input file [default trace.dat]\n"
	       "          -e show file endianess\n"
	       "          -f show function list\n"
	       "          -P show printk list\n"
	       "          -E show event files stored\n"
	       "          -F filter to filter output on\n"
	       "          -v will negate all -F after it (Not show matches)\n"
	       "          -w show wakeup latencies\n"
	       "          -l show latency format (default with latency tracers)\n"
	       "\n"
	       " %s split [options] -o file [start [end]]\n"
	       "          -o output file to write to (file.1, file.2, etc)\n"
	       "          -s n  split file up by n seconds\n"
	       "          -m n  split file up by n milliseconds\n"
	       "          -u n  split file up by n microseconds\n"
	       "          -e n  split file up by n events\n"
	       "          -p n  split file up by n pages\n"
	       "          -r    repeat from start to end\n"
	       "          -c    per cpu, that is -p 2 will be 2 pages for each CPU\n"
	       "          if option is specified, it will split the file\n"
	       "           up starting at start, and ending at end\n"
	       "          start - decimal start time in seconds (ex: 75678.923853)\n"
	       "                  if left out, will start at beginning of file\n"
	       "          end   - decimal end time in seconds\n"
	       "\n"
	       " %s listen -p port[-D][-o file][-d dir]\n"
	       "          Creates a socket to listen for clients.\n"
	       "          -D create it in daemon mode.\n"
	       "          -o file name to use for clients.\n"
	       "          -d diretory to store client files.\n"
	       "\n"
	       " %s list [-e][-p]\n"
	       "          -e list available events\n"
	       "          -p list available plugins\n"
	       "          -o list available options\n"
	       "\n", p, VERSION_STRING, p, p, p, p, p, p, p, p, p);
	exit(-1);
}

int main (int argc, char **argv)
{
	const char *plugin = NULL;
	const char *output = NULL;
	const char *option;
	struct event_list *event;
	struct event_list *last_event;
	struct trace_seq s;
	int disable = 0;
	int plug = 0;
	int events = 0;
	int options = 0;
	int record = 0;
	int extract = 0;
	int run_command = 0;
	int neg_event = 0;
	int fset;
	int cpu;

	int c;

	errno = 0;

	if (argc < 2)
		usage(argv);

	if (strcmp(argv[1], "report") == 0) {
		trace_report(argc, argv);
		exit(0);
	} else if (strcmp(argv[1], "listen") == 0) {
		trace_listen(argc, argv);
		exit(0);
	} else if (strcmp(argv[1], "split") == 0) {
		trace_split(argc, argv);
		exit(0);
	} else if ((record = (strcmp(argv[1], "record") == 0)) ||
		   (strcmp(argv[1], "start") == 0) ||
		   ((extract = strcmp(argv[1], "extract") == 0))) {

		while ((c = getopt(argc-1, argv+1, "+he:f:Fp:do:O:s:vg:l:n:P:N:tb:")) >= 0) {
			switch (c) {
			case 'h':
				usage(argv);
				break;
			case 'e':
				if (extract)
					usage(argv);
				events = 1;
				event = malloc_or_die(sizeof(*event));
				event->event = optarg;
				event->next = event_selection;
				event->neg = neg_event;
				event_selection = event;
				event->filter = NULL;
				last_event = event;
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

			case 'F':
				if (filter_pid >= 0)
					die("-P and -F can not both be specified");
				filter_task = 1;
				break;
			case 'P':
				if (filter_task)
					die("-P and -F can not both be specified");
				if (filter_pid >= 0)
					die("only one -P pid can be filtered at a time");
				filter_pid = atoi(optarg);
				break;
			case 'v':
				if (extract)
					usage(argv);
				neg_event = 1;
				break;
			case 'l':
				add_func(&filter_funcs, optarg);
				break;
			case 'n':
				add_func(&notrace_funcs, optarg);
				break;
			case 'g':
				add_func(&graph_funcs, optarg);
				break;
			case 'p':
				if (plugin)
					die("only one plugin allowed");
				plugin = optarg;
				fprintf(stderr, "  plugin %s\n", plugin);
				break;
			case 'd':
				if (extract)
					usage(argv);
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
				set_option(option);
				break;
			case 's':
				if (extract)
					usage(argv);
				sleep_time = atoi(optarg);
				break;
			case 'N':
				if (!record)
					die("-N only available with record");
				if (output)
					die("-N incompatible with -o");
				host = optarg;
				break;
			case 't':
				use_tcp = 1;
				break;
			case 'b':
				buffer_size = atoi(optarg);
				break;
			}
		}

	} else if (strcmp(argv[1], "stop") == 0) {
		disable_tracing();
		exit(0);

	} else if (strcmp(argv[1], "reset") == 0) {
		while ((c = getopt(argc-1, argv+1, "b:")) >= 0) {
			switch (c) {
			case 'b':
				buffer_size = atoi(optarg);
				/* Min buffer size is 1 */
				if (strcmp(optarg, "0") == 0)
					buffer_size = 1;
				break;
			}
		}
		disable_all();
		set_buffer_size();
		exit(0);

	} else if (strcmp(argv[1], "list") == 0) {

		while ((c = getopt(argc-1, argv+1, "+hepo")) >= 0) {
			switch (c) {
			case 'h':
				usage(argv);
				break;
			case 'e':
				events = 1;
				break;
			case 'p':
				plug = 1;
				break;
			case 'o':
				options = 1;
				break;
			default:
				usage(argv);
			}
		}

		if (events)
			show_events();

		if (plug)
			show_plugins();

		if (options)
			show_options();

		if (!events && !plug && !options) {
			printf("events:\n");
			show_events();
			printf("\nplugins:\n");
			show_plugins();
			printf("\noptions:\n");
			show_options();
		}

		exit(0);

	} else {
		fprintf(stderr, "unknown command: %s\n", argv[1]);
		usage(argv);
	}

	if ((argc - optind) >= 2) {
		if (!record)
			die("Command start does not take any commands\n"
			    "Did you mean 'record'?");
		if (extract)
			die("Command extract does not take any commands\n"
			    "Did you mean 'record'?");
		run_command = 1;
	}

	if (!events && !plugin && !extract)
		die("no event or plugin was specified... aborting");

	if (output)
		output_file = output;

	if (!extract) {
		fset = set_ftrace(!disable);
		disable_all();
		set_funcs();

		if (events)
			enable_events();
		set_buffer_size();
	}

	if (plugin) {
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
		}
		if (fset < 0 && (strcmp(plugin, "function") == 0 ||
				 strcmp(plugin, "function_graph") == 0))
			die("function tracing not configured on this kernel");
		if (!extract)
			set_plugin(plugin);
	}

	if (record || extract) {
		if (!latency)
			start_threads();
		signal(SIGINT, finish);
	}

	if (extract) {
		while (!finished && !trace_empty()) {
			flush_threads();
			sleep(1);
		}
	} else {
		if (!record) {
			update_task_filter();
			exit(0);
		}

		if (run_command)
			run_cmd((argc - optind) - 1, &argv[optind + 1]);
		else {
			update_task_filter();
			/* sleep till we are woken with Ctrl^C */
			printf("Hit Ctrl^C to stop recording\n");
			while (!finished)
				sleep(10);
		}

		disable_tracing();
	}

	stop_threads();

	record_data();
	delete_thread_data();

	printf("Buffer statistics:\n\n");
	for (cpu = 0; cpu < cpu_count; cpu++) {
		trace_seq_init(&s);
		trace_seq_printf(&s, "CPU: %d\n", cpu);
		tracecmd_stat_cpu(&s, cpu);
		trace_seq_do_printf(&s);
		printf("\n");
	}

	exit(0);

	return 0;
}

