#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "trace-cmd.h"

extern int show_events;

struct tracecmd_handle {
	int		fd;
};

int file_bigendian;
int host_bigendian;
int long_size;

int read_or_die(void *data, int size)
{
	int r;

	r = read(input_fd, data, size);
	if (r != size)
		die("reading input file (size expected=%d received=%d)",
		    size, r);
	return r;
}

static char *read_string(void)
{
	char buf[BUFSIZ];
	char *str = NULL;
	int size = 0;
	int i;
	int r;

	for (;;) {
		r = read(input_fd, buf, BUFSIZ);
		if (r < 0)
			die("reading input file");

		if (!r)
			die("no data");

		for (i = 0; i < r; i++) {
			if (!buf[i])
				break;
		}
		if (i < r)
			break;
			
		if (str) {
			size += BUFSIZ;
			str = realloc(str, size);
			if (!str)
				die("malloc of size %d", size);
			memcpy(str + (size - BUFSIZ), buf, BUFSIZ);
		} else {
			size = BUFSIZ;
			str = malloc_or_die(size);
			memcpy(str, buf, size);	
		}
	}

	/* move the file descriptor to the end of the string */
	r = lseek(input_fd, -(r - (i+1)), SEEK_CUR);
	if (r < 0)
		die("lseek");

	if (str) {
		size += i + 1;
		str = realloc(str, size);
		if (!str)
			die("malloc of size %d", size);
		memcpy(str + (size - i), buf, i);
		str[size] = 0;
	} else {
		size = i + 1;
		str = malloc_or_die(i);
		memcpy(str, buf, i);
		str[i] = 0;
	}

	return str;
}

unsigned int read4(void)
{
	unsigned int data;

	read_or_die(&data, 4);
	return __data2host4(data);
}

unsigned long long read8(void)
{
	unsigned long long data;

	read_or_die(&data, 8);
	return __data2host8(data);
}

static void read_header_files(void)
{
	unsigned long long size;
	char *header_page;
	char *header_event;
	char buf[BUFSIZ];

	read_or_die(buf, 12);
	if (memcmp(buf, "header_page", 12) != 0)
		die("did not read header page");

	size = read8();
	header_page = malloc_or_die(size);
	read_or_die(header_page, size);
	pevent_parse_header_page(header_page, size);
	free(header_page);

	/*
	 * The size field in the page is of type long,
	 * use that instead, since it represents the kernel.
	 */
	long_size = header_page_size_size;

	read_or_die(buf, 13);
	if (memcmp(buf, "header_event", 13) != 0)
		die("did not read header event");

	size = read8();
	header_event = malloc_or_die(size);
	read_or_die(header_event, size);
	free(header_event);
}

static void read_ftrace_file(unsigned long long size)
{
	char *buf;

	buf = malloc_or_die(size);
	read_or_die(buf, size);
	pevent_parse_event(buf, size, "ftrace");
	free(buf);
}

static void read_event_file(char *system, unsigned long long size)
{
	char *buf;

	buf = malloc_or_die(size+1);
	read_or_die(buf, size);
	buf[size] = 0;
	if (show_events)
		printf("%s\n", buf);
	pevent_parse_event(buf, size, system);
	free(buf);
}

static void read_ftrace_files(void)
{
	unsigned long long size;
	int count;
	int i;

	count = read4();

	for (i = 0; i < count; i++) {
		size = read8();
		read_ftrace_file(size);
	}
}

static void read_event_files(void)
{
	unsigned long long size;
	char *system;
	int systems;
	int count;
	int i,x;

	systems = read4();

	for (i = 0; i < systems; i++) {
		system = read_string();

		count = read4();
		for (x=0; x < count; x++) {
			size = read8();
			read_event_file(system, size);
		}
	}
}

static void read_proc_kallsyms(void)
{
	unsigned int size;
	char *buf;

	size = read4();
	if (!size)
		return;

	buf = malloc_or_die(size);
	read_or_die(buf, size);

	parse_proc_kallsyms(buf, size);

	free(buf);
}

static void read_ftrace_printk(void)
{
	unsigned int size;
	char *buf;

	size = read4();
	if (!size)
		return;

	buf = malloc_or_die(size);
	read_or_die(buf, size);

	parse_ftrace_printk(buf, size);

	free(buf);
}

int read_trace_files(void)
{
	read_header_files();
	read_ftrace_files();
	read_event_files();
	read_proc_kallsyms();
	read_ftrace_printk();

	trace_load_plugins();

	return 0;
}

struct tracecmd_handle *tracecmd_open(int fd)
{
	struct tracecmd_handle *handle;
	char test[] = { 23, 8, 68 };
	char *version;
	char buf[BUFSIZ];

	handle = malloc(sizeof(*handle));
	if (!handle)
		return NULL;

	handle->fd = fd;

	input_fd = open(input_file, O_RDONLY);
	if (input_fd < 0)
		die("opening '%s'\n", input_file);

	read_or_die(buf, 3);
	if (memcmp(buf, test, 3) != 0)
		die("not an trace data file");

	read_or_die(buf, 7);
	if (memcmp(buf, "tracing", 7) != 0)
		die("not a trace file (missing tracing)");

	version = read_string();
	printf("version = %s\n", version);
	free(version);

	read_or_die(buf, 1);
	file_bigendian = buf[0];
	host_bigendian = bigendian();

	read_or_die(buf, 1);
	long_size = buf[0];

	page_size = read4();

	return 0;
}
