/*
 * Copyright (C) 2008,2009, Steven Rostedt <srostedt@redhat.com>
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
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "parse-events.h"


#define VERSION "0.5"

#define _STR(x) #x
#define STR(x) _STR(x)
#define MAX_PATH 256

#define TRACE_CTRL	"tracing_on"
#define TRACE		"trace"
#define AVAILABLE	"available_tracers"
#define CURRENT		"current_tracer"
#define ITER_CTRL	"trace_options"
#define MAX_LATENCY	"tracing_max_latency"

unsigned int page_size;

static const char *output_file = "trace.dat";
static int output_fd;

static int latency;

static int old_ftrace_name;

static int cpu_count;
static int *pids;

struct event_list {
	struct event_list *next;
	const char *event;
};

static struct event_list *event_selection;

struct events {
	struct events *sibling;
	struct events *children;
	struct events *next;
	char *name;
};

static void delete_temp_file(int cpu)
{
	char file[MAX_PATH];

	snprintf(file, MAX_PATH, "%s.cpu%d", output_file, cpu);
	unlink(file);
}

static void kill_threads(void)
{
	int i;

	if (!cpu_count)
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

static const char *find_debugfs(void)
{
	static char debugfs[MAX_PATH+1];
	static int debugfs_found;
	char type[100];
	FILE *fp;

	if (debugfs_found)
		return debugfs;

	if ((fp = fopen("/proc/mounts","r")) == NULL)
		die("Can't open /proc/mounts for read");

	while (fscanf(fp, "%*s %"
		      STR(MAX_PATH)
		      "s %99s %*s %*d %*d\n",
		      debugfs, type) == 2) {
		if (strcmp(type, "debugfs") == 0)
			break;
	}
	fclose(fp);

	if (strcmp(type, "debugfs") != 0)
		die("debugfs not mounted, please mount");

	debugfs_found = 1;

	return debugfs;
}

/*
 * Finds the path to the debugfs/tracing
 * Allocates the string and stores it.
 */
static const char *find_tracing_dir(void)
{
	static char *tracing;
	static int tracing_found;
	const char *debugfs;

	if (tracing_found)
		return tracing;

	debugfs = find_debugfs();

	tracing = malloc_or_die(strlen(debugfs) + 9);

	sprintf(tracing, "%s/tracing", debugfs);

	tracing_found = 1;
	return tracing;
}

static char *get_tracing_file(const char *name)
{
	const char *tracing;
	char *file;

	tracing = find_tracing_dir();
	if (!tracing)
		return NULL;

	file = malloc_or_die(strlen(tracing) + strlen(name) + 2);

	sprintf(file, "%s/%s", tracing, name);
	return file;
}

static void put_tracing_file(char *file)
{
	free(file);
}

static void write_trace(const char *file, const char *val)
{
	char *path;
	int fd;

	path = get_tracing_file(file);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		die("writing %s", path);
	put_tracing_file(path);
	write(fd, val, strlen(val));
	close(fd);

}

static int find_trace_type(const char *type)
{
	char scan[100];
	char *path;
	FILE *fp;
	int ret;

	path = get_tracing_file(type);
	fp = fopen(path, "r");
	if (!fp)
		die("reading %s", path);
	put_tracing_file(path);
	do {
		ret = fscanf(fp, "%99s", scan);
		if (ret > 0 && strcmp(scan, "ftrace"))
			old_ftrace_name = 1;
		if (ret > 0 && strcmp(scan, type) == 0)
			break;
	} while (ret > 0);
	fclose(fp);

	return ret > 0;
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

void run_cmd(int argc, char **argv)
{
	int status;
	int pid;

	if ((pid = fork()) < 0)
		die("failed to fork");
	if (!pid) {
		/* child */
		if (execvp(argv[0], argv))
			exit(-1);
	}
	waitpid(pid, &status, 0);
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

static void enable_event(const char *name)
{
	struct stat st;
	FILE *fp;
	char *path;
	int ret;

	fprintf(stderr, "enable %s\n", name);
	if (strcmp(name, "all") == 0) {
		path = get_tracing_file("events/enable");

		ret = stat(path, &st);
		if (ret < 0) {
			put_tracing_file(path);
			/* need to use old way */
			path = get_tracing_file("set_event");
			fp = fopen(path, "w");
			if (!fp)
				die("writing to '%s'", path);
			put_tracing_file(path);
			fwrite("*:*\n", 4, 1, fp);
			fclose(fp);
			return;
		}

		fp = fopen(path, "w");
		if (!fp)
			die("writing to '%s'", path);
		put_tracing_file(path);
		ret = fwrite("1", 1, 1, fp);
		fclose(fp);
		if (ret < 0)
			die("writing to '%s'", path);
		return;
	}

	path = get_tracing_file("set_event");
	fp = fopen(path, "a");
	if (!fp)
		die("writing to '%s'", path);
	put_tracing_file(path);
	ret = fwrite(name, 1, strlen(name), fp);
	if (ret < 0)
		die("bad event '%s'", name);
	ret = fwrite("\n", 1, 1, fp);
	if (ret < 0)
		die("bad event '%s'", name);
	fclose(fp);
}

static void disable_event(const char *name)
{
	struct stat st;
	FILE *fp;
	char *path;
	int ret;

	if (strcmp(name, "all") == 0) {
		path = get_tracing_file("events/enable");

		ret = stat(path, &st);
		if (ret < 0) {
			put_tracing_file(path);
			/* need to use old way */
			path = get_tracing_file("set_event");
			fp = fopen(path, "w");
			if (!fp)
				die("writing to '%s'", path);
			put_tracing_file(path);
			fwrite("\n", 1, 1, fp);
			fclose(fp);
			return;
		}

		fp = fopen(path, "w");
		if (!fp)
			die("writing to '%s'", path);
		put_tracing_file(path);
		fwrite("0", 1, 1, fp);
		fclose(fp);
	}
}

static void enable_tracing(void)
{
	FILE *fp;
	char *path;

	/* reset the trace */
	path = get_tracing_file("tracing_on");
	fp = fopen(path, "w");
	if (!fp)
		die("writing to '%s'", path);
	put_tracing_file(path);
	fwrite("1", 1, 1, fp);
	fclose(fp);
}

static void disable_tracing(void)
{
	FILE *fp;
	char *path;

	/* reset the trace */
	path = get_tracing_file("tracing_on");
	fp = fopen(path, "w");
	if (!fp)
		die("writing to '%s'", path);
	put_tracing_file(path);
	fwrite("0", 1, 1, fp);
	fclose(fp);
}

static void disable_all(void)
{
	FILE *fp;
	char *path;

	disable_tracing();

	set_plugin("nop");
	disable_event("all");

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

static void enable_events(void)
{
	struct event_list *event;

	for (event = event_selection; event; event = event->next) {
		enable_event(event->event);
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
	finished = 1;
}

static int create_recorder(int cpu)
{
	char file[MAX_PATH];
	const char *tracing;
	char *path;
	int out_fd;
	int in_fd;
	int brass[2];
	int pid;
	int ret;
	char buf[page_size];

	pid = fork();
	if (pid < 0)
		die("fork");

	if (pid)
		return pid;

	signal(SIGINT, finish);

	/* do not kill tasks on error */
	cpu_count = 0;

	snprintf(file, MAX_PATH, "%s.cpu%d", output_file, cpu);

	out_fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
	if (out_fd < 0)
		die("can't create file '%s'", file);

	tracing = find_tracing_dir();

	path = malloc_or_die(strlen(tracing) + 40);

	sprintf(path, "%s/per_cpu/cpu%d/trace_pipe_raw", tracing, cpu);
	in_fd = open(path, O_RDONLY);
	if (in_fd < 0)
		die("can not read '%s'", path);

	ret = pipe(brass);
	if (ret < 0)
		die("can not create pipe");

	do {
		ret = splice(in_fd, NULL, brass[1], NULL, page_size, 1 /* SPLICE_F_MOVE */);
		if (ret < 0)
			die("splice in");
		ret = splice(brass[0], NULL, out_fd, NULL, page_size, 3 /* and NON_BLOCK */);
		if (ret < 0 && errno != EAGAIN)
			die("splice out");
	} while (!finished);

	/* splice only reads full pages */
	do {
		ret = read(in_fd, buf, page_size);
		if (ret > 0)
			write(out_fd, buf, ret);
	} while (ret > 0);

	exit(0);
}

static void start_threads(void)
{
	int cpus;
	int i;

	cpus = count_cpus();

	/* make a thread for every CPU we have */
	pids = malloc_or_die(sizeof(*pids) * cpu_count);

	memset(pids, 0, sizeof(*pids) * cpu_count);

	cpu_count = cpus;

	for (i = 0; i < cpus; i++) {
		pids[i] = create_recorder(i);
	}
}

static ssize_t write_or_die(const void *buf, size_t len)
{
	int ret;

	ret = write(output_fd, buf, len);
	if (ret < 0)
		die("writing to '%s'", output_file);

	return ret;
}

int bigendian(void)
{
	unsigned char str[] = { 0x1, 0x2, 0x3, 0x4 };
	unsigned int *ptr;

	ptr = (unsigned int *)str;
	return *ptr == 0x01020304;
}

static unsigned long long copy_file_fd(int fd)
{
	unsigned long long size = 0;
	char buf[BUFSIZ];
	int r;

	do {
		r = read(fd, buf, BUFSIZ);
		if (r > 0) {
			size += r;
			write_or_die(buf, r);
		}
	} while (r > 0);

	return size;
}

static unsigned long long copy_file(const char *file)
{
	unsigned long long size = 0;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		die("Can't read '%s'", file);
	size = copy_file_fd(fd);
	close(fd);

	return size;
}

static unsigned long get_size_fd(int fd)
{
	unsigned long long size = 0;
	char buf[BUFSIZ];
	int r;

	do {
		r = read(fd, buf, BUFSIZ);
		if (r > 0)
			size += r;
	} while (r > 0);

	lseek(fd, 0, SEEK_SET);

	return size;
}

static unsigned long get_size(const char *file)
{
	unsigned long long size = 0;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		die("Can't read '%s'", file);
	size = get_size_fd(fd);
	close(fd);

	return size;
}

static void read_header_files(void)
{
	unsigned long long size, check_size;
	struct stat st;
	char *path;
	int fd;
	int ret;

	path = get_tracing_file("events/header_page");

	ret = stat(path, &st);
	if (ret < 0) {
		/* old style did not show this info, just add zero */
		put_tracing_file(path);
		write_or_die("header_page", 12);
		size = 0;
		write_or_die(&size, 8);
		write_or_die("header_event", 13);
		write_or_die(&size, 8);
		return;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0)
		die("can't read '%s'", path);

	/* unfortunately, you can not stat debugfs files for size */
	size = get_size_fd(fd);

	write_or_die("header_page", 12);
	write_or_die(&size, 8);
	check_size = copy_file_fd(fd);
	if (size != check_size)
		die("wrong size for '%s' size=%lld read=%lld",
		    path, size, check_size);
	put_tracing_file(path);

	path = get_tracing_file("events/header_event");
	fd = open(path, O_RDONLY);
	if (fd < 0)
		die("can't read '%s'", path);

	size = get_size_fd(fd);

	write_or_die("header_event", 13);
	write_or_die(&size, 8);
	check_size = copy_file_fd(fd);
	if (size != check_size)
		die("wrong size for '%s'", path);
	put_tracing_file(path);
}

static void copy_event_system(const char *sys)
{
	unsigned long long size, check_size;
	struct dirent *dent;
	struct stat st;
	char *format;
	DIR *dir;
	int count = 0;
	int ret;

	dir = opendir(sys);
	if (!dir)
		die("can't read directory '%s'", sys);

	while ((dent = readdir(dir))) {
		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;
		format = malloc_or_die(strlen(sys) + strlen(dent->d_name) + 10);
		sprintf(format, "%s/%s/format", sys, dent->d_name);
		ret = stat(format, &st);
		free(format);
		if (ret < 0)
			continue;
		count++;
	}

	write_or_die(&count, 4);
	
	rewinddir(dir);
	while ((dent = readdir(dir))) {
		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;
		format = malloc_or_die(strlen(sys) + strlen(dent->d_name) + 10);
		sprintf(format, "%s/%s/format", sys, dent->d_name);
		ret = stat(format, &st);

		if (ret >= 0) {
			/* unfortunately, you can not stat debugfs files for size */
			size = get_size(format);
			write_or_die(&size, 8);
			check_size = copy_file(format);
			if (size != check_size)
				die("error in size of file '%s'", format);
		}

		free(format);
	}
}

static void read_ftrace_files(void)
{
	char *path;

	path = get_tracing_file("events/ftrace");

	copy_event_system(path);

	put_tracing_file(path);
}

static void read_event_files(void)
{
	struct dirent *dent;
	struct stat st;
	char *path;
	char *sys;
	DIR *dir;
	int count = 0;
	int ret;

	path = get_tracing_file("events");

	dir = opendir(path);
	if (!dir)
		die("can't read directory '%s'", path);

	while ((dent = readdir(dir))) {
		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0 ||
		    strcmp(dent->d_name, "ftrace") == 0)
			continue;
		sys = malloc_or_die(strlen(path) + strlen(dent->d_name) + 2);
		sprintf(sys, "%s/%s", path, dent->d_name);
		ret = stat(sys, &st);
		free(sys);
		if (ret < 0)
			continue;
		if (S_ISDIR(st.st_mode))
			count++;
	}

	write_or_die(&count, 4);

	rewinddir(dir);
	while ((dent = readdir(dir))) {
		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0 ||
		    strcmp(dent->d_name, "ftrace") == 0)
			continue;
		sys = malloc_or_die(strlen(path) + strlen(dent->d_name) + 2);
		sprintf(sys, "%s/%s", path, dent->d_name);
		ret = stat(sys, &st);
		if (ret >= 0) {
			if (S_ISDIR(st.st_mode)) {
				write_or_die(dent->d_name, strlen(dent->d_name) + 1);
				copy_event_system(sys);
			}
		}
		free(sys);
	}

	put_tracing_file(path);
}

static void read_proc_kallsyms(void)
{
	unsigned int size, check_size;
	const char *path = "/proc/kallsyms";
	struct stat st;
	int ret;

	ret = stat(path, &st);
	if (ret < 0) {
		/* not found */
		size = 0;
		write_or_die(&size, 4);
		return;
	}
	size = get_size(path);
	write_or_die(&size, 4);
	check_size = copy_file(path);
	if (size != check_size)
		die("error in size of file '%s'", path);

}

static void read_ftrace_printk(void)
{
	unsigned int size, check_size;
	const char *path;
	struct stat st;
	int ret;

	path = get_tracing_file("printk_formats");
	ret = stat(path, &st);
	if (ret < 0) {
		/* not found */
		size = 0;
		write_or_die(&size, 4);
		return;
	}
	size = get_size(path);
	write_or_die(&size, 4);
	check_size = copy_file(path);
	if (size != check_size)
		die("error in size of file '%s'", path);

}

static void read_tracing_data(void)
{
	char buf[BUFSIZ];

	output_fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
	if (output_fd < 0)
		die("creating file '%s'", output_file);

	buf[0] = 23;
	buf[1] = 8;
	buf[2] = 68;
	memcpy(buf + 3, "tracing", 7);

	write_or_die(buf, 10);

	write_or_die(VERSION, strlen(VERSION) + 1);

	/* save endian */
	if (bigendian())
		buf[0] = 1;
	else
		buf[0] = 0;

	write_or_die(buf, 1);

	/* save size of long */
	buf[0] = sizeof(long);
	write_or_die(buf, 1);

	/* save page_size */
	page_size = getpagesize();
	write_or_die(&page_size, 4);

	read_header_files();
	read_ftrace_files();
	read_event_files();
	read_proc_kallsyms();
	read_ftrace_printk();
}

static unsigned long long read_thread_file(int cpu)
{
	unsigned long long size;
	char *file;

	file = malloc_or_die(strlen(output_file) + 20);
	snprintf(file, MAX_PATH, "%s.cpu%d", output_file, cpu);

	size = copy_file(file);
	free(file);
	return size;
}

static void read_trace_data(void)
{
	char *path;

	write_or_die("latency  ", 10);

	path = get_tracing_file("trace");

	copy_file(path);

	put_tracing_file(path);
}

static void read_thread_data(void)
{
	unsigned long long offset, check_size;
	unsigned long long *offsets;
	unsigned long long *sizes;
	unsigned long long size;
	long long ret;
	struct stat st;
	char *file;
	int i;
		
	if (!cpu_count)
		return;

	/*
	 * Save the command lines;
	 */
	file = get_tracing_file("saved_cmdlines");
	ret = stat(file, &st);
	if (ret >= 0) {
		size = get_size(file);
		write_or_die(&size, 8);
		check_size = copy_file(file);
		if (size != check_size)
			die("error in size of file '%s'", file);
	} else {
		size = 0;
		write_or_die(&size, 8);
	}
	put_tracing_file(file);

	write_or_die(&cpu_count, 4);

	if (latency) {
		read_trace_data();
		return;
	}

	write_or_die("flyrecord", 10);

	offsets = malloc_or_die(sizeof(*offsets) * cpu_count);
	sizes = malloc_or_die(sizeof(*sizes) * cpu_count);

	offset = lseek(output_fd, 0, SEEK_CUR);

	/* hold any extra data for data */
	offset += cpu_count * (16);
	offset = (offset + (page_size - 1)) & ~(PAGE_MASK);

	for (i = 0; i < cpu_count; i++) {
		file = malloc_or_die(strlen(output_file) + 20);
		sprintf(file, "%s.cpu%d", output_file, i);
		ret = stat(file, &st);
		if (ret < 0)
			die("can not stat '%s'", file);
		free(file);
		offsets[i] = offset;
		sizes[i] = st.st_size;
		offset += st.st_size;
		offset = (offset + (page_size - 1)) & ~(PAGE_MASK);

		write_or_die(&offsets[i], 8);
		write_or_die(&sizes[i], 8);
	}

	for (i = 0; i < cpu_count; i++) {
		fprintf(stderr, "offset=%llx\n", offsets[i]);
		ret = lseek64(output_fd, offsets[i], SEEK_SET);
		if (ret < 0)
			die("could not seek to %lld\n", offsets[i]);
		check_size = read_thread_file(i);
		if (check_size != sizes[i])
			die("did not match size of %lld to %lld",
			    check_size, sizes[i]);
	}
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
	       "usage: %s record [-e event][-p plugin] [-d] [-o file] [-O option ] command ...\n"
	       "          -e run command with event enabled\n"
	       "          -p run command with plugin enabled\n"
	       "          -d disable function tracer when running\n"
	       "          -o data output file [default trace.dat]\n"
	       "          -O option to enable (or disable)\n"
	       "\n"
	       " %s report [-i file] [--cpu cpu] [-e][-f][-l][-P][-E]\n"
	       "          -i input file [default trace.dat]\n"
	       "          -e show file endianess\n"
	       "          -f show function list\n"
	       "          -P show printk list\n"
	       "          -E show event files stored\n"
	       "          -l show latency format (default with latency tracers)\n"
	       "\n"
	       " %s list [-e][-p]\n"
	       "          -e list available events\n"
	       "          -p list available plugins\n"
	       "          -o list available options\n"
	       "\n", p, VERSION, p, p, p);
	exit(-1);
}

int main (int argc, char **argv)
{
	const char *plugin = NULL;
	const char *output = NULL;
	const char *option;
	struct event_list *event;
	int disable = 0;
	int plug = 0;
	int events = 0;
	int options = 0;
	int fset;

	int c;

	errno = 0;

	if (argc < 2)
		usage(argv);

	if (strcmp(argv[1], "report") == 0) {
		trace_report(argc, argv);
		exit(0);
	} else if (strcmp(argv[1], "record") == 0) {

		while ((c = getopt(argc-1, argv+1, "+he:p:do:O:")) >= 0) {
			switch (c) {
			case 'h':
				usage(argv);
				break;
			case 'e':
				events = 1;
				event = malloc_or_die(sizeof(*event));
				event->event = optarg;
				event->next = event_selection;
				event_selection = event;
				break;
			case 'p':
				if (plugin)
					die("only one plugin allowed");
				plugin = optarg;
				fprintf(stderr, "  plugin %s\n", plugin);
				break;
			case 'd':
				disable = 1;
				break;
			case 'o':
				if (output)
					die("only one output file allowed");
				output = optarg;
				break;
			case 'O':
				option = optarg;
				set_option(option);
				break;
			}
		}

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

	if ((argc - optind) < 2)
		usage(argv);

	if (output)
		output_file = output;

	read_tracing_data();

	fset = set_ftrace(!disable);

	disable_all();

	start_threads();

	signal(SIGINT, finish);

	if (events)
		enable_events();
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
			stop_threads();
			reset_max_latency();
		}
		if (fset < 0 && (strcmp(plugin, "function") == 0 ||
				 strcmp(plugin, "function_graph") == 0))
			die("function tracing not configured on this kernel");
		set_plugin(plugin);
	}

	enable_tracing();

	run_cmd((argc - optind) - 1, &argv[optind + 1]);

	disable_tracing();

	stop_threads();

	read_thread_data();
	delete_thread_data();

	exit(0);

	return 0;
}

