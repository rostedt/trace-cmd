/*
 * Copyright (C) 2009, Steven Rostedt <srostedt@redhat.com>
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

#include "parse-events.h"

static int input_fd;

static int read_page;

int file_bigendian;
int host_bigendian;
static int long_size;

static int filter_cpu = -1;

static int read_or_die(void *data, int size)
{
	int r;

	r = read(input_fd, data, size);
	if (r != size)
		die("reading input file (size expected=%d received=%d)",
		    size, r);
	return r;
}

static unsigned int read4(void)
{
	unsigned int data;

	read_or_die(&data, 4);
	return __data2host4(data);
}

static unsigned long long read8(void)
{
	unsigned long long data;

	read_or_die(&data, 8);
	return __data2host8(data);
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
		size += i;
		str = realloc(str, size);
		if (!str)
			die("malloc of size %d", size);
		memcpy(str + (size - i), buf, i);
	} else {
		size = i;
		str = malloc_or_die(i);
		memcpy(str, buf, i);
	}

	return str;
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
	free(header_page);

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
	parse_ftrace_file(buf, size);
	free(buf);
}

static void read_event_file(char *system, unsigned long long size)
{
	char *buf;

	buf = malloc_or_die(size);
	read_or_die(buf, size);
	parse_event_file(buf, size, system);
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

struct cpu_data {
	unsigned long long	offset;
	unsigned long long	size;
	unsigned long long	timestamp;
	struct record		*next;
	char			*page;
	int			cpu;
	int			index;
	int			page_size;
};

static int cpus;
static struct cpu_data *cpu_data;

static void init_read(int cpu)
{
	off64_t ret;
	off64_t save_seek;

	cpu_data[cpu].page = malloc_or_die(page_size);

	/* other parts of the code may expect the pointer to not move */
	save_seek = lseek64(input_fd, 0, SEEK_CUR);

	ret = lseek64(input_fd, (off64_t)cpu_data[cpu].offset, SEEK_SET);
	if (ret < 0)
		die("failed to lseek");
	ret = read(input_fd, cpu_data[cpu].page, page_size);
	if (ret < 0)
		die("failed to read page");

	/* reset the file pointer back */
	lseek64(input_fd, save_seek, SEEK_SET);
}

static void init_cpu(int cpu)
{
	if (!cpu_data[cpu].size) {
		printf("CPU %d is empty\n", cpu);
		return;
	}

	if (read_page) {
		init_read(cpu);
		return;
	}

	cpu_data[cpu].page = mmap(NULL, page_size, PROT_READ, MAP_PRIVATE,
				  input_fd, cpu_data[cpu].offset);
	if (cpu_data[cpu].page == MAP_FAILED) {
		/* fall back to just reading pages */
		fprintf(stderr, "Can not mmap file, will read instead\n");
		read_page = 1;

		init_read(cpu);
	}
}

static void update_cpu_data_index(int cpu)
{
	cpu_data[cpu].offset += page_size;
	cpu_data[cpu].size -= page_size;
	cpu_data[cpu].index = 0;
}

static void get_next_page(int cpu)
{
	off64_t save_seek;
	off64_t ret;

	if (!cpu_data[cpu].page)
		return;

	if (read_page) {
		if (cpu_data[cpu].size <= page_size) {
			free(cpu_data[cpu].page);
			cpu_data[cpu].page = NULL;
			return;
		}

		update_cpu_data_index(cpu);

		/* other parts of the code may expect the pointer to not move */
		save_seek = lseek64(input_fd, 0, SEEK_CUR);

		ret = lseek64(input_fd, cpu_data[cpu].offset, SEEK_SET);
		if (ret < 0)
			die("failed to lseek");
		ret = read(input_fd, cpu_data[cpu].page, page_size);
		if (ret < 0)
			die("failed to read page");

		/* reset the file pointer back */
		lseek64(input_fd, save_seek, SEEK_SET);

		return;
	}

	munmap(cpu_data[cpu].page, page_size);
	cpu_data[cpu].page = NULL;

	if (cpu_data[cpu].size <= page_size)
		return;

	update_cpu_data_index(cpu);
	
	cpu_data[cpu].page = mmap(NULL, page_size, PROT_READ, MAP_PRIVATE,
				  input_fd, cpu_data[cpu].offset);
	if (cpu_data[cpu].page == MAP_FAILED)
		die("failed to mmap cpu %d at offset 0x%llx",
		    cpu, cpu_data[cpu].offset);
}

static unsigned int type_len4host(unsigned int type_len_ts)
{
	return type_len_ts & ((1 << 5) - 1);
}

static unsigned int ts4host(unsigned int type_len_ts)
{
	return type_len_ts >> 5;
}

static int calc_index(void *ptr, int cpu)
{
	return (unsigned long)ptr - (unsigned long)cpu_data[cpu].page;
}

struct record *peak_data(int cpu)
{
	struct record *data;
	void *page = cpu_data[cpu].page;
	int index = cpu_data[cpu].index;
	void *ptr = page + index;
	unsigned long long extend;
	unsigned int type_len_ts;
	unsigned int type_len;
	unsigned int delta;
	unsigned int length;

	if (cpu_data[cpu].next)
		return cpu_data[cpu].next;

	if (!page)
		return NULL;

	if (!index) {
		/* FIXME: handle header page */
		cpu_data[cpu].timestamp = data2host8(ptr);
		ptr += 8;
		switch (long_size) {
		case 4:
			cpu_data[cpu].page_size = data2host4(ptr);
			ptr += 4;
			break;
		case 8:
			cpu_data[cpu].page_size = data2host8(ptr);
			ptr += 8;
			break;
		default:
			die("bad long size");
		}
	}

read_again:
	index = calc_index(ptr, cpu);

	if (index >= cpu_data[cpu].page_size) {
		get_next_page(cpu);
		return peak_data(cpu);
	}

	type_len_ts = data2host4(ptr);
	ptr += 4;

	type_len = type_len4host(type_len_ts);
	delta = ts4host(type_len_ts);

	switch (type_len) {
	case RINGBUF_TYPE_PADDING:
		if (!delta)
			die("error, hit unexpected end of page");
		length = data2host4(ptr);
		ptr += 4;
		length *= 4;
		ptr += length;
		goto read_again;

	case RINGBUF_TYPE_TIME_EXTEND:
		extend = data2host4(ptr);
		ptr += 4;
		extend <<= TS_SHIFT;
		extend += delta;
		cpu_data[cpu].timestamp += extend;
		goto read_again;

	case RINGBUF_TYPE_TIME_STAMP:
		ptr += 12;
		break;
	case 0:
		length = data2host4(ptr);
		ptr += 4;
		die("here! length=%d", length);
		break;
	default:
		length = type_len * 4;
		break;
	}

	cpu_data[cpu].timestamp += delta;

	data = malloc_or_die(sizeof(*data));
	memset(data, 0, sizeof(*data));

	data->ts = cpu_data[cpu].timestamp;
	data->size = length;
	data->data = ptr;
	ptr += length;

	cpu_data[cpu].index = calc_index(ptr, cpu);
	cpu_data[cpu].next = data;

	return data;
}

struct record *read_data(int cpu)
{
	struct record *data;

	data = peak_data(cpu);
	cpu_data[cpu].next = NULL;

	return data;
}

static void show_data(int cpu)
{
	struct record *record;

	record = read_data(cpu);

	print_event(cpu, record->data, record->size, record->ts);

	free(record);
}

static void read_rest(void)
{
	char buf[BUFSIZ + 1];
	int r;

	do {
		r = read(input_fd, buf, BUFSIZ);
		if (r > 0) {
			buf[r] = 0;
			printf(buf);
		}
	} while (r > 0);
}

static void read_data_info(void)
{
	unsigned long long ts;
	unsigned long long size;
	char *cmdlines;
	struct record *data;
	char buf[10];
	int cpu;
	int next;

	size = read8();
	cmdlines = malloc_or_die(size);
	read_or_die(cmdlines, size);
	parse_cmdlines(cmdlines, size);
	free(cmdlines);

	cpus = read4();
	printf("cpus=%d\n", cpus);

	parse_set_info(cpus, long_size);

	/*
	 * Check if this is a latency report or not.
	 */
	read_or_die(buf, 10);
	if (strncmp(buf, "latency", 7) == 0) {
		read_rest();
		return;
	}

	cpu_data = malloc_or_die(sizeof(*cpu_data) * cpus);
	memset(cpu_data, 0, sizeof(*cpu_data) * cpus);

	for (cpu = 0; cpu < cpus; cpu++) {
		cpu_data[cpu].cpu = cpu;
		cpu_data[cpu].offset = read8();
		cpu_data[cpu].size = read8();

		init_cpu(cpu);
	}

	do {
		next = -1;
		ts = 0;
		if (filter_cpu >= 0) {
			cpu = filter_cpu;
			data = peak_data(cpu);
			if (data)
				next = cpu;
		} else {
			for (cpu = 0; cpu < cpus; cpu++) {
				data = peak_data(cpu);
				if (data && (!ts || data->ts < ts)) {
					ts = data->ts;
					next = cpu;
				}
			}
		}
		if (next >= 0)
			show_data(next);

	} while (next >= 0);
}


void trace_report (int argc, char **argv)
{
	const char *input_file = "trace.dat";
	char buf[BUFSIZ];
	char test[] = { 23, 8, 68 };
	char *version;
	int show_funcs = 0;
	int show_endian = 0;
	int show_page_size = 0;
	int c;

	if (argc < 2)
		usage(argv);

	if (strcmp(argv[1], "report") != 0)
		usage(argv);

	for (;;) {
		int option_index = 0;
		static struct option long_options[] = {
			{"cpu", required_argument, NULL, 0},
			{"help", no_argument, NULL, '?'},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc-1, argv+1, "+hi:fep",
			long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'i':
			input_file = optarg;
			break;
		case 'f':
			show_funcs = 1;
			break;
		case 'e':
			show_endian = 1;
			break;
		case 'p':
			show_page_size = 1;
			break;
		case 0:
			switch(option_index) {
			case 0:
				filter_cpu = atoi(optarg);
				break;
			default:
				usage(argv);
			}
			break;
		default:
			usage(argv);
		}
	}

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
	if (show_page_size) {
		printf("file page size is %d, and host page size is %d\n",
		       page_size,
		       getpagesize());
		return;
	}

	if (show_endian) {
		printf("file is %s endian and host is %s endian\n",
		       file_bigendian ? "big" : "little",
		       host_bigendian ? "big" : "little");
		return;
	}

	read_header_files();
	read_ftrace_files();
	read_event_files();
	read_proc_kallsyms();

	if (show_funcs) {
		print_funcs();
		return;
	}
	read_data_info();

	return;
}
