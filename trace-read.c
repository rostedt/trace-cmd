/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
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
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "trace-local.h"
#include "trace-hash-local.h"

static struct filter {
	struct filter		*next;
	const char		*filter;
	int			neg;
} *filter_strings;
static struct filter **filter_next = &filter_strings;

static struct event_filter *event_filters;
static struct event_filter *event_filter_out;

static unsigned int page_size;
static int input_fd;
const char *default_input_file = "trace.dat";
const char *input_file;

static int filter_cpu = -1;
static int *filter_cpus;
static int nr_filter_cpus;

static int show_wakeup;
static int wakeup_id;
static int wakeup_new_id;
static int sched_id;

static struct format_field *wakeup_task;
static struct format_field *wakeup_success;
static struct format_field *wakeup_new_task;
static struct format_field *wakeup_new_success;
static struct format_field *sched_task;

static unsigned long long total_wakeup_lat;
static unsigned long wakeup_lat_count;

struct wakeup_info {
	struct wakeup_info	*next;
	unsigned long long	start;
	int			pid;
};

#define WAKEUP_HASH_SIZE 1024
static struct wakeup_info *wakeup_hash[WAKEUP_HASH_SIZE];

/* Debug variables for testing tracecmd_read_at */
#define TEST_READ_AT 0
#if TEST_READ_AT
#define DO_TEST
static off64_t test_read_at_offset;
static int test_read_at_copy = 100;
static int test_read_at_index;
static void show_test(struct tracecmd_input *handle)
{
	struct pevent *pevent;
	struct record *record;
	struct trace_seq s;
	int cpu;

	if (!test_read_at_offset) {
		printf("\nNO RECORD COPIED\n");
		return;
	}

	pevent = tracecmd_get_pevent(handle);

	record = tracecmd_read_at(handle, test_read_at_offset, &cpu);
	printf("\nHERE'S THE COPY RECORD\n");
	trace_seq_init(&s);
	pevent_print_event(pevent, &s, cpu, record->data, record->size, record->ts);
	trace_seq_do_printf(&s);
	trace_seq_destroy(&s);
	printf("\n");

	free_record(record);
}

static void test_save(struct record *record, int cpu)
{
	if (test_read_at_index++ == test_read_at_copy) {
		test_read_at_offset = record->offset;
		printf("\nUSING THIS RECORD\n");
	}
}
#endif /* TEST_READ_AT */

/* Debug variables for testing tracecmd_set_cpu_at_timestamp */
#define TEST_AT_TIMESTAMP 0
#if TEST_AT_TIMESTAMP
#define DO_TEST
static unsigned long long test_at_timestamp_ts;
static int test_at_timestamp_copy = 100;
static int test_at_timestamp_cpu = -1;
static int test_at_timestamp_index;
static void show_test(struct tracecmd_input *handle)
{
	struct pevent *pevent;
	struct record *record;
	struct trace_seq s;
	int cpu = test_at_timestamp_cpu;

	if (!test_at_timestamp_ts) {
		printf("\nNO RECORD COPIED\n");
		return;
	}

	pevent = tracecmd_get_pevent(handle);

	if (tracecmd_set_cpu_to_timestamp(handle, cpu, test_at_timestamp_ts))
		return;

	record = tracecmd_read_data(handle, cpu);
	printf("\nHERE'S THE COPY RECORD with page %p offset=%p\n",
	       (void *)(record->offset & ~(page_size - 1)),
	       (void *)record->offset);
	trace_seq_init(&s);
	pevent_print_event(pevent, &s, cpu, record->data, record->size, record->ts);
	trace_seq_do_printf(&s);
	trace_seq_destroy(&s);
	printf("\n");

	free_record(record);
}

static void test_save(struct record *record, int cpu)
{
	if (test_at_timestamp_index++ == test_at_timestamp_copy) {
		test_at_timestamp_ts = record->ts;
		test_at_timestamp_cpu = cpu;
		printf("\nUSING THIS RECORD page=%p offset=%p\n",
		       (void *)(record->offset & ~(page_size - 1)),
		       (void *)record->offset);
	}
}
#endif /* TEST_AT_TIMESTAMP */

#define TEST_FIRST_LAST 0
#if TEST_FIRST_LAST
#define DO_TEST
static void show_test(struct tracecmd_input *handle)
{
	struct pevent *pevent;
	struct record *record;
	struct trace_seq s;
	int cpu = 0;

	pevent = tracecmd_get_pevent(handle);

	record = tracecmd_read_cpu_first(handle, cpu);
	if (!record) {
		printf("No first record?\n");
		return;
	}

	printf("\nHERE'S THE FIRST RECORD with offset %p\n",
	       (void *)record->offset);
	trace_seq_init(&s);
	pevent_print_event(pevent, &s, cpu, record->data, record->size, record->ts);
	trace_seq_do_printf(&s);
	trace_seq_destroy(&s);
	printf("\n");

	free_record(record);

	record = tracecmd_read_cpu_last(handle, cpu);
	if (!record) {
		printf("No last record?\n");
		return;
	}

	printf("\nHERE'S THE LAST RECORD with offset %p\n",
	       (void *)record->offset);
	trace_seq_init(&s);
	pevent_print_event(pevent, &s, cpu, record->data, record->size, record->ts);
	trace_seq_do_printf(&s);
	trace_seq_destroy(&s);
	printf("\n");

	free_record(record);
}
static void test_save(struct record *record, int cpu)
{
}
#endif /* TEST_FIRST_LAST */

#ifndef DO_TEST
static void show_test(struct tracecmd_input *handle)
{
}
static void test_save(struct record *record, int cpu)
{
}
#endif

static void add_filter(const char *filter, int neg)
{
	struct filter *ftr;

	ftr = malloc_or_die(sizeof(*ftr));
	ftr->filter = filter;
	ftr->next = NULL;
	ftr->neg = neg;

	/* must maintain order of command line */
	*filter_next = ftr;
	filter_next = &ftr->next;
}

static void process_filters(struct tracecmd_input *handle)
{
	struct event_filter *event_filter;
	struct pevent *pevent;
	struct filter *filter;
	char *errstr;
	int ret;

	pevent = tracecmd_get_pevent(handle);
	event_filters = pevent_filter_alloc(pevent);
	event_filter_out = pevent_filter_alloc(pevent);

	while (filter_strings) {
		filter = filter_strings;
		filter_strings = filter->next;
		if (filter->neg)
			event_filter = event_filter_out;
		else
			event_filter = event_filters;

		ret = pevent_filter_add_filter_str(event_filter,
						   filter->filter,
						   &errstr);
		if (ret < 0)
			die("Error filtering: %s\n%s",
			    filter->filter, errstr);
		free(errstr);
		free(filter);
	}
}

static int filter_record(struct tracecmd_input *handle,
			 struct record *record)
{
	return 0;
}

static void init_wakeup(struct tracecmd_input *handle)
{
	struct event_format *event;
	struct pevent *pevent;

	if (!show_wakeup)
		return;

	pevent = tracecmd_get_pevent(handle);

	event = pevent_find_event_by_name(pevent, "sched", "sched_wakeup");
	if (!event)
		goto fail;
	wakeup_id = event->id;
	wakeup_task = pevent_find_field(event, "pid");
	if (!wakeup_task)
		goto fail;
	wakeup_success = pevent_find_field(event, "success");

	event = pevent_find_event_by_name(pevent, "sched", "sched_switch");
	if (!event)
		goto fail;
	sched_id = event->id;
	sched_task = pevent_find_field(event, "next_pid");
	if (!sched_task)
		goto fail;


	wakeup_new_id = -1;

	event = pevent_find_event_by_name(pevent, "sched", "sched_wakeup_new");
	if (!event)
		goto skip;
	wakeup_new_id = event->id;
	wakeup_new_task = pevent_find_field(event, "pid");
	if (!wakeup_new_task)
		goto fail;
	wakeup_new_success = pevent_find_field(event, "success");

 skip:
	return;

 fail:
	show_wakeup = 0;
}

static unsigned int calc_wakeup_key(unsigned long val)
{
	return trace_hash(val) % WAKEUP_HASH_SIZE;
}

static struct wakeup_info *
__find_wakeup(unsigned int key, unsigned int val)
{
	struct wakeup_info *info = wakeup_hash[key];

	while (info) {
		if (info->pid == val)
			return info;
		info = info->next;
	}

	return NULL;
}

static void add_wakeup(unsigned int val, unsigned long long start)
{
	unsigned int key = calc_wakeup_key(val);
	struct wakeup_info *info;

	info = __find_wakeup(key, val);
	if (info) {
		/* Hmm, double wakeup? */
		info->start = start;
		return;
	}

	info = malloc_or_die(sizeof(*info));
	info->pid = val;
	info->start = start;
	info->next = wakeup_hash[key];
	wakeup_hash[key] = info;
}

static unsigned long long max_lat = 0;
static unsigned long long max_time;
static unsigned long long min_lat = -1;
static unsigned long long min_time;

static void add_sched(unsigned int val, unsigned long long end)
{
	unsigned int key = calc_wakeup_key(val);
	struct wakeup_info *info;
	struct wakeup_info **next;
	unsigned long long cal;

	info = __find_wakeup(key, val);
	if (!info)
		return;

	cal = end - info->start;

	if (cal > max_lat) {
		max_lat = cal;
		max_time = end;
	}
	if (cal < min_lat) {
		min_lat = cal;
		min_time = end;
	}

	printf(" Latency: %llu.%03llu usecs", cal / 1000, cal % 1000);

	total_wakeup_lat += cal;
	wakeup_lat_count++;

	next = &wakeup_hash[key];
	while (*next) {
		if (*next == info) {
			*next = info->next;
			break;
		}
		next = &(*next)->next;
	}
	free(info);
}

static void process_wakeup(struct pevent *pevent, struct record *record)
{
	unsigned long long val;
	int id;

	if (!show_wakeup)
		return;

	id = pevent_data_type(pevent, record);
	if (id == wakeup_id) {
		if (pevent_read_number_field(wakeup_success, record->data, &val) == 0) {
			if (!val)
				return;
		}
		if (pevent_read_number_field(wakeup_task, record->data, &val))
			return;
		add_wakeup(val, record->ts);
	} else if (id == wakeup_new_id) {
		if (pevent_read_number_field(wakeup_new_success, record->data, &val) == 0) {
			if (!val)
				return;
		}
		if (pevent_read_number_field(wakeup_new_task, record->data, &val))
			return;
		add_wakeup(val, record->ts);
	} else if (id == sched_id) {
		if (pevent_read_number_field(sched_task, record->data, &val))
			return;
		add_sched(val, record->ts);
	}
}

static void finish_wakeup(void)
{
	struct wakeup_info *info;
	int i;

	if (!show_wakeup || !wakeup_lat_count)
		return;

	total_wakeup_lat /= wakeup_lat_count;

	printf("\nAverage wakeup latency: %llu.%03llu usecs\n",
	       total_wakeup_lat / 1000,
	       total_wakeup_lat % 1000);
	printf("Maximum Latency: %llu.%03llu usecs at ", max_lat / 1000, max_lat % 1000);
	printf("timestamp: %llu.%06llu\n",
	       max_time / 1000000000, ((max_time + 500) % 1000000000) / 1000);
	printf("Minimum Latency: %llu.%03llu usecs at ", min_lat / 1000, min_lat % 1000);
	printf("timestamp: %llu.%06llu\n\n", min_time / 1000000000,
	       ((min_time + 500) % 1000000000) / 1000);

	for (i = 0; i < WAKEUP_HASH_SIZE; i++) {
		while (wakeup_hash[i]) {
			info = wakeup_hash[i];
			wakeup_hash[i] = info->next;
			free(info);
		}
	}
}

static void show_data(struct tracecmd_input *handle,
		      struct record *record, int cpu)
{
	struct pevent *pevent;
	struct trace_seq s;

	if (filter_record(handle, record))
		return;

	pevent = tracecmd_get_pevent(handle);

	test_save(record, cpu);

	trace_seq_init(&s);
	if (record->missed_events > 0)
		trace_seq_printf(&s, "CPU:%d [%lld EVENTS DROPPED]\n",
				 record->cpu, record->missed_events);
	else if (record->missed_events < 0)
		trace_seq_printf(&s, "CPU:%d [EVENTS DROPPED]\n",
				 record->cpu);
	pevent_print_event(pevent, &s, record);
	if (s.len && *(s.buffer + s.len - 1) == '\n')
		s.len--;
	trace_seq_do_printf(&s);
	trace_seq_destroy(&s);

	process_wakeup(pevent, record);

	printf("\n");
}

static void read_rest(void)
{
	char buf[BUFSIZ + 1];
	int r;

	do {
		r = read(input_fd, buf, BUFSIZ);
		if (r > 0) {
			buf[r] = 0;
			printf("%s", buf);
		}
	} while (r > 0);
}

static void read_data_info(struct tracecmd_input *handle)
{
	unsigned long long ts;
	struct record *record;
	int cpus;
	int next;
	int cpu;
	int ret;

	ret = tracecmd_init_data(handle);
	if (ret < 0)
		die("failed to init data");

	cpus = tracecmd_cpus(handle);
	printf("cpus=%d\n", cpus);

	/* Latency trace is just all ASCII */
	if (ret > 0) {
		read_rest();
		return;
	}

	init_wakeup(handle);
	process_filters(handle);

	do {
		next = -1;
		ts = 0;
		if (filter_cpus) {
			unsigned long long last_stamp = 0;
			struct record *precord;
			int next_cpu = -1;
			int i;

			for (i = 0; (cpu = filter_cpus[i]) >= 0; i++) {
				precord = tracecmd_peek_data(handle, cpu);
				if (precord &&
				    (!last_stamp || precord->ts < last_stamp)) {
					next_cpu = cpu;
					last_stamp = precord->ts;
				}
			}
			if (last_stamp)
				record = tracecmd_read_data(handle, next_cpu);
			else
				record = NULL;

		} else if (filter_cpu >= 0) {
			cpu = filter_cpu;
			record = tracecmd_read_data(handle, cpu);
		} else
			record = tracecmd_read_next_data(handle, &cpu);

		if (record) {
			ret = pevent_filter_match(event_filters, record);
			switch (ret) {
			case FILTER_NONE:
			case FILTER_MATCH:
				ret = pevent_filter_match(event_filter_out, record);
				if (ret != FILTER_MATCH)
					show_data(handle, record, next);
				break;
			}
			free_record(record);
		}
	} while (record);

	pevent_filter_free(event_filters);
	pevent_filter_free(event_filter_out);

	show_test(handle);
}

struct tracecmd_input *read_trace_header(void)
{
	input_fd = open(input_file, O_RDONLY);
	if (input_fd < 0)
		die("opening '%s'\n", input_file);

	return tracecmd_alloc_fd(input_fd);
}

static void sig_end(int sig)
{
	fprintf(stderr, "trace-cmd: Received SIGINT\n");
	exit(0);
}

static const char *inc_and_test_char(const char *p, const char *cpu_str)
{
	p++;
	while (isspace(*p))
		p++;
	if (!isdigit(*p))
		die("invalid character '%c' in cpu string '%s'",
		    *p, cpu_str);
	return p;
}

static void __add_cpu(int cpu)
{
	filter_cpus = tracecmd_add_id(filter_cpus, cpu, nr_filter_cpus++);
}

static int process_cpu_str(const char *cpu_str)
{
	const char *p = cpu_str;
	int cpu, ncpu, ret_cpu = 1;

	do {
		while (isspace(*p))
			p++;

		cpu = atoi(p);
		__add_cpu(cpu);

 again:
		while (isdigit(*p))
			p++;
		while (isspace(*p))
			p++;

		if (*p) {
			ret_cpu = 0;
			switch (*p) {
			case '-':
				p = inc_and_test_char(p, cpu_str);
				ncpu = atoi(p);
				if (ncpu < cpu)
					die("range of cpu numbers must be lower to greater");
				for (; cpu <= ncpu; cpu++)
					__add_cpu(cpu);
				break;

			case ',':
			case ':':
				p = inc_and_test_char(p, cpu_str);
				ncpu = atoi(p);
				__add_cpu(ncpu);
				break;
			default:
				die("invalid character '%c' in cpu string '%s'",
				    *p, cpu_str);
			}
			goto again;
		}
	} while (*p);

	if (ret_cpu)
		return cpu;

	/* Return -1 if we added more than one CPU */
	return -1;
}

static void add_cpu(const char *cpu_str)
{
	int cpu;

	cpu = process_cpu_str(cpu_str);
	if (cpu >= 0)
		__add_cpu(cpu);
}

void trace_report (int argc, char **argv)
{
	struct tracecmd_input *handle;
	struct pevent *pevent;
	int show_funcs = 0;
	int show_endian = 0;
	int show_page_size = 0;
	int show_printk = 0;
	int latency_format = 0;
	int show_events = 0;
	int print_events = 0;
	int test_filters = 0;
	int raw = 0;
	int neg = 0;
	int c;

	if (argc < 2)
		usage(argv);

	if (strcmp(argv[1], "report") != 0)
		usage(argv);

	signal(SIGINT, sig_end);

	for (;;) {
		int option_index = 0;
		static struct option long_options[] = {
			{"cpu", required_argument, NULL, 0},
			{"events", no_argument, NULL, 0},
			{"filter-test", no_argument, NULL, 'T'},
			{"help", no_argument, NULL, '?'},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc-1, argv+1, "+hi:feprPNLlEwF:VvTq",
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
		case 'F':
			add_filter(optarg, neg);
			break;
		case 'T':
			test_filters = 1;
			break;
		case 'f':
			show_funcs = 1;
			break;
		case 'P':
			show_printk = 1;
			break;
		case 'L':
			tracecmd_disable_sys_plugins = 1;
			break;
		case 'N':
			tracecmd_disable_plugins = 1;
			break;
		case 'e':
			show_endian = 1;
			break;
		case 'p':
			show_page_size = 1;
			break;
		case 'E':
			show_events = 1;
			break;
		case 'r':
			raw = 1;
			break;
		case 'w':
			show_wakeup = 1;
			break;
		case 'l':
			latency_format = 1;
			break;
		case 'v':
			if (neg)
				die("Only 1 -v can be used");
			neg = 1;
			break;
		case 'V':
			show_status = 1;
			break;
		case 'q':
			silence_warnings = 1;
			break;
		case 0:
			switch(option_index) {
			case 0:
				if (filter_cpu)
					add_cpu(optarg);
				else
					filter_cpu = atoi(optarg);
				break;
			case 1:
				print_events = 1;
				break;
			default:
				usage(argv);
			}
			break;
		default:
			usage(argv);
		}
	}

	if ((argc - optind) >= 2) {
		if (input_file)
			usage(argv);
		input_file = argv[optind + 1];
	}

	if (!input_file)
		input_file = default_input_file;

	handle = read_trace_header();
	if (!handle)
		die("error reading header");

	page_size = tracecmd_page_size(handle);

	if (show_page_size) {
		printf("file page size is %d, and host page size is %d\n",
		       page_size,
		       getpagesize());
		return;
	}

	pevent = tracecmd_get_pevent(handle);

	if (raw)
		pevent->print_raw = 1;

	if (test_filters)
		pevent->test_filters = 1;

	if (show_endian) {
		printf("file is %s endian and host is %s endian\n",
		       pevent_is_file_bigendian(pevent) ? "big" : "little",
		       pevent_is_host_bigendian(pevent) ? "big" : "little");
		return;
	}

	if (print_events) {
		tracecmd_print_events(handle);
		return;
	}

	if (tracecmd_read_headers(handle) < 0)
		return;

	if (show_funcs) {
		pevent_print_funcs(pevent);
		return;
	}
	if (show_printk) {
		pevent_print_printk(pevent);
		return;
	}

	if (show_events) {
		struct event_format **events;
		struct event_format *event;
		int i;

		events = pevent_list_events(pevent, EVENT_SORT_SYSTEM);
		for (i = 0; events[i]; i++) {
			event = events[i];
			if (event->system)
				printf("%s:", event->system);
			printf("%s\n", event->name);
		}
		return;
	}

	if (latency_format)
		pevent_set_latency_format(pevent, latency_format);

	read_data_info(handle);

	tracecmd_close(handle);

	finish_wakeup();

	return;
}
