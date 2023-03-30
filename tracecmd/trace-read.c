// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
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
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "trace-local.h"
#include "trace-hash.h"
#include "trace-hash-local.h"
#include "kbuffer.h"
#include "list.h"

/*
 * tep_func_repeat_format is defined as a weak variable in the
 * libtraceevent library function plugin, to allow applications
 * to override the format of the timestamp it prints for the
 * last function that repeated.
 */
const char *tep_func_repeat_format;

static struct filter_str {
	struct filter_str	*next;
	char			*filter;
	int			neg;
} *filter_strings;
static struct filter_str **filter_next = &filter_strings;

struct event_str {
	struct event_str	*next;
	const char		*event;
};

struct input_files;

struct handle_list {
	struct list_head	list;
	struct tracecmd_input	*handle;
	struct input_files	*input_file;
	const char		*file;
	int			cpus;
};
static struct list_head handle_list;

struct input_files {
	struct list_head	list;
	const char		*file;
	struct filter_str	*filter_str;
	struct filter_str	**filter_str_next;
	long long		tsoffset;
	unsigned long long	ts2secs;
};
static struct list_head input_files;
static struct input_files *last_input_file;

struct pid_list {
	struct pid_list		*next;
	char			*pid;
	int			free;
} *pid_list;

struct pid_list *comm_list;

static unsigned int page_size;
static int input_fd;
static const char *default_input_file = DEFAULT_INPUT_FILE;
static const char *input_file;
static int multi_inputs;
static int max_file_size;

static int instances;

static int *filter_cpus;
static int nr_filter_cpus;
static int test_filters_mode;

static int show_wakeup;
static int wakeup_id;
static int wakeup_new_id;
static int sched_id;

static int profile;

static int buffer_breaks = 0;

static int no_irqs;
static int no_softirqs;

static int tsdiff;
static int tscheck;

static int latency_format;
static bool raw_format;
static const char *format_type = TEP_PRINT_INFO;

static struct tep_format_field *wakeup_task;
static struct tep_format_field *wakeup_success;
static struct tep_format_field *wakeup_new_task;
static struct tep_format_field *wakeup_new_success;
static struct tep_format_field *sched_task;
static struct tep_format_field *sched_prio;

static unsigned long long total_wakeup_lat;
static unsigned long wakeup_lat_count;

static unsigned long long total_wakeup_rt_lat;
static unsigned long wakeup_rt_lat_count;

struct wakeup_info {
	struct trace_hash_item	hash;
	unsigned long long	start;
	int			pid;
};

static struct hook_list *hooks;
static struct hook_list *last_hook;

#define WAKEUP_HASH_SIZE 1024
static struct trace_hash wakeup_hash;

static void print_event_name(struct trace_seq *s, struct tep_event *event)
{
	static const char *spaces = "                    "; /* 20 spaces */
	const char *name;
	int len;

	name = event ? event->name : "(NULL)";

	trace_seq_printf(s, " %s: ", name);

	/* Space out the event names evenly. */
	len = strlen(name);
	if (len < 20)
		trace_seq_printf(s, "%.*s", 20 - len, spaces);
}

enum time_fmt {
	TIME_FMT_LAT		= 1,
	TIME_FMT_NORMAL,
	TIME_FMT_TS,
};

static const char *time_format(struct tracecmd_input *handle, enum time_fmt tf)
{
	struct tep_handle *tep = tracecmd_get_tep(handle);

	switch (tf) {
	case TIME_FMT_LAT:
		if (latency_format)
			return "%8.8s-%-5d %3d";
		return "%16s-%-5d [%03d]";
	default:
		if (tracecmd_get_flags(handle) & TRACECMD_FL_IN_USECS) {
			if (tep_test_flag(tep, TEP_NSEC_OUTPUT))
				return tf == TIME_FMT_NORMAL ? " %9.1d:" : "%9.1d";
			else
				return tf == TIME_FMT_NORMAL ? " %6.1000d:" : "%6.1000d";
		} else
			return tf == TIME_FMT_NORMAL ? "%12d:" : "%12d";
	}
}

static void print_event(struct trace_seq *s, struct tracecmd_input *handle,
			struct tep_record *record)
{
	struct tep_handle *tep = tracecmd_get_tep(handle);
	struct tep_event *event;
	const char *lfmt = time_format(handle, TIME_FMT_LAT);
	const char *tfmt = time_format(handle, TIME_FMT_NORMAL);

	event = tep_find_event_by_record(tep, record);
	tep_print_event(tep, s, record, lfmt, TEP_PRINT_COMM,
			TEP_PRINT_PID, TEP_PRINT_CPU);
	tep_print_event(tep, s, record, tfmt, TEP_PRINT_TIME);
	print_event_name(s, event);
	tep_print_event(tep, s, record, "%s", format_type);
}

/* Debug variables for testing tracecmd_read_at */
#define TEST_READ_AT 0
#if TEST_READ_AT
#define DO_TEST
static off_t test_read_at_offset;
static int test_read_at_copy = 100;
static int test_read_at_index;
static void show_test(struct tracecmd_input *handle)
{
	struct tep_record *record;
	struct trace_seq s;

	if (!test_read_at_offset) {
		printf("\nNO RECORD COPIED\n");
		return;
	}

	record = tracecmd_read_at(handle, test_read_at_offset, NULL);
	printf("\nHERE'S THE COPY RECORD\n");
	trace_seq_init(&s);
	print_event(&s, handle, record);
	trace_seq_do_printf(&s);
	trace_seq_destroy(&s);
	printf("\n");

	tracecmd_free_record(record);
}

static void test_save(struct tep_record *record, int cpu)
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
	struct tep_record *record;
	struct trace_seq s;
	int cpu = test_at_timestamp_cpu;

	if (!test_at_timestamp_ts) {
		printf("\nNO RECORD COPIED\n");
		return;
	}

	if (tracecmd_set_cpu_to_timestamp(handle, cpu, test_at_timestamp_ts))
		return;

	record = tracecmd_read_data(handle, cpu);
	printf("\nHERE'S THE COPY RECORD with page %p offset=%p\n",
	       (void *)(record->offset & ~(page_size - 1)),
	       (void *)record->offset);
	trace_seq_init(&s);
	print_event(&s, handle, record);
	trace_seq_do_printf(&s);
	trace_seq_destroy(&s);
	printf("\n");

	tracecmd_free_record(record);
}

static void test_save(struct tep_record *record, int cpu)
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
	struct tep_record *record;
	struct trace_seq s;
	int cpu = 0;

	record = tracecmd_read_cpu_first(handle, cpu);
	if (!record) {
		printf("No first record?\n");
		return;
	}

	printf("\nHERE'S THE FIRST RECORD with offset %p\n",
	       (void *)record->offset);
	trace_seq_init(&s);
	print_event(&s, handle, record);
	trace_seq_do_printf(&s);
	trace_seq_destroy(&s);
	printf("\n");

	tracecmd_free_record(record);

	record = tracecmd_read_cpu_last(handle, cpu);
	if (!record) {
		printf("No last record?\n");
		return;
	}

	printf("\nHERE'S THE LAST RECORD with offset %p\n",
	       (void *)record->offset);
	trace_seq_init(&s);
	print_event(&s, handle, record);
	trace_seq_do_printf(&s);
	trace_seq_destroy(&s);
	printf("\n");

	tracecmd_free_record(record);
}
static void test_save(struct tep_record *record, int cpu)
{
}
#endif /* TEST_FIRST_LAST */

#ifndef DO_TEST
static void show_test(struct tracecmd_input *handle)
{
	/* quiet the compiler */
	if (0)
		print_event(NULL, NULL, NULL);
}
static void test_save(struct tep_record *record, int cpu)
{
}
#endif

static void free_filter_strings(struct filter_str *filter_str)
{
	struct filter_str *filter;

	while (filter_str) {
		filter = filter_str;
		filter_str = filter->next;
		free(filter->filter);
		free(filter);
	}
}

static struct input_files *add_input(const char *file)
{
	struct input_files *item;

	item = calloc(1, sizeof(*item));
	if (!item)
		die("Failed to allocate for %s", file);
	item->file = file;
	item->filter_str_next = &item->filter_str;
	list_add_tail(&item->list, &input_files);
	last_input_file = item;
	return item;
}

static void add_handle(struct tracecmd_input *handle, struct input_files *input_files)
{
	struct handle_list *item;
	const char *file = input_files ? input_files->file : input_file;

	item = calloc(1, sizeof(*item));
	if (!item)
		die("Failed ot allocate for %s", file);
	item->handle = handle;
	if (input_files) {
		item->file = file + strlen(file);
		/* we want just the base name */
		while (item->file >= file && *item->file != '/')
			item->file--;
		item->file++;
		if (strlen(item->file) > max_file_size)
			max_file_size = strlen(item->file);

		item->input_file = input_files;
	}
	list_add_tail(&item->list, &handle_list);
}

static void free_inputs(void)
{
	struct input_files *item;

	while (!list_empty(&input_files)) {
		item = container_of(input_files.next, struct input_files, list);
		list_del(&item->list);
		free_filter_strings(item->filter_str);
		free(item);
	}
}

static void free_handles(void)
{
	struct handle_list *item;

	while (!list_empty(&handle_list)) {
		item = container_of(handle_list.next, struct handle_list, list);
		list_del(&item->list);
		free(item);
	}
}

static void add_filter(struct input_files *input_file, const char *filter, int neg)
{
	struct filter_str *ftr;

	ftr = malloc(sizeof(*ftr));
	if (!ftr)
		die("Failed to allocate for filter %s", filter);
	ftr->filter = strdup(filter);
	if (!ftr->filter)
		die("malloc");
	ftr->next = NULL;
	ftr->neg = neg;

	/* must maintain order of command line */
	if (input_file) {
		*input_file->filter_str_next = ftr;
		input_file->filter_str_next = &ftr->next;
	} else {
		*filter_next = ftr;
		filter_next = &ftr->next;
	}
}

static void __add_filter(struct pid_list **head, const char *arg)
{
	struct pid_list *list;
	char *pids = strdup(arg);
	char *pid;
	char *sav;
	int free = 1;

	if (!pids)
		die("malloc");

	pid = strtok_r(pids, ",", &sav);
	while (pid) {
		list = malloc(sizeof(*list));
		if (!list)
			die("Failed to allocate for arg %s", arg);
		list->pid = pid;
		list->free = free;
		list->next = *head;
		*head = list;
		/* The first pid needs to be freed */
		free = 0;
		pid = strtok_r(NULL, ",", &sav);
	}
}

static void add_comm_filter(const char *arg)
{
	__add_filter(&comm_list, arg);
}

static void add_pid_filter(const char *arg)
{
	__add_filter(&pid_list, arg);
}

static char *append_pid_filter(char *curr_filter, char *pid)
{
	char *filter;
	int len, curr_len;

#define FILTER_FMT "(common_pid==" __STR ")||(pid==" __STR ")||(next_pid==" __STR ")"

#undef __STR
#define __STR ""

	/* strlen(".*:") > strlen("||") */
	len = strlen(".*:" FILTER_FMT) + strlen(pid) * 3 + 1;

#undef __STR
#define __STR "%s"

	if (!curr_filter) {
		filter = malloc(len);
		if (!filter)
			die("Failed to allocate for filter %s", curr_filter);
		sprintf(filter, ".*:" FILTER_FMT, pid, pid, pid);
	} else {
		curr_len = strlen(curr_filter);
		len += curr_len;

		filter = realloc(curr_filter, len);
		if (!filter)
			die("realloc");
		sprintf(filter + curr_len, "||" FILTER_FMT, pid, pid, pid);
	}

	return filter;
}

static void convert_comm_filter(struct tracecmd_input *handle)
{
	struct tep_cmdline *cmdline;
	struct tep_handle *pevent;
	struct pid_list *list;

	char pidstr[100];

	if (!comm_list)
		return;

	pevent = tracecmd_get_tep(handle);

	/* Seach for comm names and get their pids */
	for (list = comm_list; list; list = list->next) {
		cmdline = tep_data_pid_from_comm(pevent, list->pid, NULL);
		if (!cmdline) {
			warning("comm: %s not in cmdline list", list->pid);
			continue;
		}
		do {
			sprintf(pidstr, "%d", tep_cmdline_pid(pevent, cmdline));
			add_pid_filter(pidstr);
			cmdline = tep_data_pid_from_comm(pevent, list->pid,
							    cmdline);
		} while (cmdline);
	}

	while (comm_list) {
		list = comm_list;
		comm_list = comm_list->next;
		if (list->free)
			free(list->pid);
		free(list);
	}
}

static void make_pid_filter(struct tracecmd_input *handle,
			    struct input_files *input_files)
{
	struct pid_list *list;
	char *str = NULL;

	convert_comm_filter(handle);

	if (!pid_list)
		return;

	/* First do all common pids */
	for (list = pid_list; list; list = list->next) {
		str = append_pid_filter(str, list->pid);
	}

	add_filter(input_files, str, 0);
	free(str);

	while (pid_list) {
		list = pid_list;
		pid_list = pid_list->next;
		if (list->free)
			free(list->pid);
		free(list);
	}
}

static int __process_filters(struct tracecmd_input *handle,
			     struct filter_str *filters)
{
	struct tracecmd_filter *trace_filter;

	for (; filters; filters = filters->next) {
		trace_filter = tracecmd_filter_add(handle,
						   filters->filter,
						   filters->neg);
		if (!trace_filter)
			die("Failed to create event filter: %s",
			    filters->filter);
	}

	return !!filters;
}

static void process_filters(struct handle_list *handles)
{
	struct input_files *input_file = handles->input_file ?: last_input_file;
	int added = 0;

	make_pid_filter(handles->handle, input_file);

	/*
	 * Order of filter processing matters. Apply the global filters
	 * before file-specific ones.
	 */
	added += __process_filters(handles->handle, filter_strings);
	if (input_file)
		added += __process_filters(handles->handle,
					   input_file->filter_str);

	if (added && test_filters_mode)
		exit(0);
}

static void init_wakeup(struct tracecmd_input *handle)
{
	struct tep_handle *pevent;
	struct tep_event *event;

	if (!show_wakeup)
		return;

	pevent = tracecmd_get_tep(handle);

	trace_hash_init(&wakeup_hash, WAKEUP_HASH_SIZE);

	event = tep_find_event_by_name(pevent, "sched", "sched_wakeup");
	if (!event)
		goto fail;
	wakeup_id = event->id;
	wakeup_task = tep_find_field(event, "pid");
	if (!wakeup_task)
		goto fail;
	wakeup_success = tep_find_field(event, "success");

	event = tep_find_event_by_name(pevent, "sched", "sched_switch");
	if (!event)
		goto fail;
	sched_id = event->id;
	sched_task = tep_find_field(event, "next_pid");
	if (!sched_task)
		goto fail;

	sched_prio = tep_find_field(event, "next_prio");
	if (!sched_prio)
		goto fail;


	wakeup_new_id = -1;

	event = tep_find_event_by_name(pevent, "sched", "sched_wakeup_new");
	if (!event)
		goto skip;
	wakeup_new_id = event->id;
	wakeup_new_task = tep_find_field(event, "pid");
	if (!wakeup_new_task)
		goto fail;
	wakeup_new_success = tep_find_field(event, "success");

 skip:
	return;

 fail:
	show_wakeup = 0;
}

static void add_wakeup(unsigned int val, unsigned long long start)
{
	unsigned int key = trace_hash(val);
	struct wakeup_info *info;
	struct trace_hash_item *item;

	item = trace_hash_find(&wakeup_hash, key, NULL, NULL);
	if (item) {
		info = container_of(item, struct wakeup_info, hash);
		/* Hmm, double wakeup? */
		info->start = start;
		return;
	}

	info = malloc(sizeof(*info));
	if (!info)
		die("Failed to allocate wakeup info");
	info->hash.key = key;
	info->start = start;
	trace_hash_add(&wakeup_hash, &info->hash);
}

static unsigned long long max_lat = 0;
static unsigned long long max_time;
static unsigned long long min_lat = -1;
static unsigned long long min_time;

static unsigned long long max_rt_lat = 0;
static unsigned long long max_rt_time;
static unsigned long long min_rt_lat = -1;
static unsigned long long min_rt_time;

static void add_sched(unsigned int val, unsigned long long end, int rt)
{
	struct trace_hash_item *item;
	unsigned int key = trace_hash(val);
	struct wakeup_info *info;
	unsigned long long cal;

	item = trace_hash_find(&wakeup_hash, key, NULL, NULL);
	if (!item)
		return;

	info = container_of(item, struct wakeup_info, hash);

	cal = end - info->start;

	if (cal > max_lat) {
		max_lat = cal;
		max_time = end;
	}
	if (cal < min_lat) {
		min_lat = cal;
		min_time = end;
	}

	if (rt) {
		if (cal > max_rt_lat) {
			max_rt_lat = cal;
			max_rt_time = end;
		}
		if (cal < min_rt_lat) {
			min_rt_lat = cal;
			min_rt_time = end;
		}
	}

	printf(" Latency: %llu.%03llu usecs", cal / 1000, cal % 1000);

	total_wakeup_lat += cal;
	wakeup_lat_count++;

	if (rt) {
		total_wakeup_rt_lat += cal;
		wakeup_rt_lat_count++;
	}

	trace_hash_del(item);
	free(info);
}

static void process_wakeup(struct tep_handle *pevent, struct tep_record *record)
{
	unsigned long long val;
	int id;

	if (!show_wakeup)
		return;

	id = tep_data_type(pevent, record);
	if (id == wakeup_id) {
		if (tep_read_number_field(wakeup_success, record->data, &val) == 0) {
			if (!val)
				return;
		}
		if (tep_read_number_field(wakeup_task, record->data, &val))
			return;
		add_wakeup(val, record->ts);
	} else if (id == wakeup_new_id) {
		if (tep_read_number_field(wakeup_new_success, record->data, &val) == 0) {
			if (!val)
				return;
		}
		if (tep_read_number_field(wakeup_new_task, record->data, &val))
			return;
		add_wakeup(val, record->ts);
	} else if (id == sched_id) {
		int rt = 1;
		if (tep_read_number_field(sched_prio, record->data, &val))
			return;
		if (val > 99)
			rt = 0;
		if (tep_read_number_field(sched_task, record->data, &val))
			return;
		add_sched(val, record->ts, rt);
	}
}

static void
show_wakeup_timings(unsigned long long total, unsigned long count,
		    unsigned long long lat_max, unsigned long long time_max,
		    unsigned long long lat_min, unsigned long long time_min)
{

	total /= count;

	printf("\nAverage wakeup latency: %llu.%03llu usecs\n",
	       total / 1000,
	       total % 1000);
	printf("Maximum Latency: %llu.%03llu usecs at ", lat_max / 1000, lat_max % 1000);
	printf("timestamp: %llu.%06llu\n",
	       time_max / 1000000000, ((time_max + 500) % 1000000000) / 1000);
	printf("Minimum Latency: %llu.%03llu usecs at ", lat_min / 1000, lat_min % 1000);
	printf("timestamp: %llu.%06llu\n\n", time_min / 1000000000,
	       ((time_min + 500) % 1000000000) / 1000);
}

static void finish_wakeup(void)
{
	struct wakeup_info *info;
	struct trace_hash_item **bucket;
	struct trace_hash_item *item;

	if (!show_wakeup || !wakeup_lat_count)
		return;

	show_wakeup_timings(total_wakeup_lat, wakeup_lat_count,
			    max_lat, max_time,
			    min_lat, min_time);


	if (wakeup_rt_lat_count) {
		printf("RT task timings:\n");
		show_wakeup_timings(total_wakeup_rt_lat, wakeup_rt_lat_count,
				    max_rt_lat, max_rt_time,
				    min_rt_lat, min_rt_time);
	}

	trace_hash_for_each_bucket(bucket, &wakeup_hash) {
		trace_hash_while_item(item, bucket) {
			trace_hash_del(item);
			info = container_of(item, struct wakeup_info, hash);
			free(info);
		}
	}

	trace_hash_free(&wakeup_hash);
}

void trace_show_data(struct tracecmd_input *handle, struct tep_record *record)
{
	tracecmd_show_data_func func = tracecmd_get_show_data_func(handle);
	const char *tfmt = time_format(handle, TIME_FMT_NORMAL);
	const char *cfmt = latency_format ? "%8.8s-%-5d %3d" : "%16s-%-5d [%03d]";
	struct tep_handle *pevent;
	struct tep_event *event;
	struct trace_seq s;
	int cpu = record->cpu;
	bool use_trace_clock;
	static unsigned long long last_ts;
	unsigned long long diff_ts;
	unsigned long page_size;
	char buf[50];

	page_size = tracecmd_page_size(handle);

	test_save(record, cpu);

	if (func) {
		func(handle, record);
		return;
	}

	pevent = tracecmd_get_tep(handle);
	event = tep_find_event_by_record(pevent, record);
	use_trace_clock = tracecmd_get_use_trace_clock(handle);

	trace_seq_init(&s);
	if (record->missed_events > 0)
		trace_seq_printf(&s, "CPU:%d [%lld EVENTS DROPPED]\n",
				 cpu, record->missed_events);
	else if (record->missed_events < 0)
		trace_seq_printf(&s, "CPU:%d [EVENTS DROPPED]\n", cpu);
	if (buffer_breaks || tracecmd_get_debug()) {
		if (tracecmd_record_at_buffer_start(handle, record)) {
			trace_seq_printf(&s, "CPU:%d [SUBBUFFER START]", cpu);
			if (tracecmd_get_debug())
				trace_seq_printf(&s, " [%lld:0x%llx]",
						 tracecmd_page_ts(handle, record),
						 record->offset & ~(page_size - 1));
			trace_seq_putc(&s, '\n');
		}
	}

	tep_print_event(pevent, &s, record, cfmt,
			TEP_PRINT_COMM,
			TEP_PRINT_PID,
			TEP_PRINT_CPU);

	if (latency_format) {
		if (raw_format)
			trace_seq_printf(&s, "-0x%x",
					 tep_data_flags(pevent, record));
		else
			tep_print_event(pevent, &s, record, "%s",
					TEP_PRINT_LATENCY);
	}

	tep_print_event(pevent, &s, record, tfmt, TEP_PRINT_TIME);

	if (tsdiff) {
		unsigned long long rec_ts = record->ts;

		buf[0] = 0;
		if (use_trace_clock && !tep_test_flag(pevent, TEP_NSEC_OUTPUT))
			rec_ts = (rec_ts + 500) / 1000;
		if (last_ts) {
			diff_ts = rec_ts - last_ts;
			snprintf(buf, 50, "(+%lld)", diff_ts);
			buf[49] = 0;
		}
		last_ts = rec_ts;
		trace_seq_printf(&s, " %-8s", buf);
	}

	print_event_name(&s, event);
	tep_print_event(pevent, &s, record, "%s", format_type);

	if (s.len && *(s.buffer + s.len - 1) == '\n')
		s.len--;
	if (tracecmd_get_debug()) {
		struct kbuffer *kbuf;
		struct kbuffer_raw_info info;
		void *page;
		void *offset;

		trace_seq_printf(&s, " [%d:0x%llx:%d]",
				 tracecmd_record_ts_delta(handle, record),
				 record->offset & (page_size - 1), record->size);
		kbuf = tracecmd_record_kbuf(handle, record);
		page = tracecmd_record_page(handle, record);
		offset = tracecmd_record_offset(handle, record);

		if (kbuf && page && offset) {
			struct kbuffer_raw_info *pi = &info;

			/* We need to get the record raw data to get next */
			pi->next = offset;
			pi = kbuffer_raw_get(kbuf, page, pi);
			while ((pi = kbuffer_raw_get(kbuf, page, pi))) {
				if (pi->type < KBUFFER_TYPE_PADDING)
					break;
				switch (pi->type) {
				case KBUFFER_TYPE_PADDING:
					trace_seq_printf(&s, "\n PADDING: ");
					break;
				case KBUFFER_TYPE_TIME_EXTEND:
					trace_seq_printf(&s, "\n TIME EXTEND: ");
					break;
				case KBUFFER_TYPE_TIME_STAMP:
					trace_seq_printf(&s, "\n TIME STAMP: ");
					break;
				}
				if (pi->type == KBUFFER_TYPE_TIME_STAMP)
					trace_seq_printf(&s, "timestamp:%lld length:%d",
							 pi->delta,
							 pi->length);
				else
					trace_seq_printf(&s, "delta:%lld length:%d",
							 pi->delta,
							 pi->length);
			}
		}
	}

	trace_seq_do_printf(&s);
	trace_seq_destroy(&s);

	process_wakeup(pevent, record);

	printf("\n");
}

static void read_latency(struct tracecmd_input *handle)
{
	char *buf = NULL;
	size_t size = 0;
	int r;

	do {
		r = tracecmd_latency_data_read(handle, &buf, &size);
		if (r > 0)
			printf("%.*s", r, buf);
	} while (r > 0);

	printf("\n");
	free(buf);
}

static int
test_filters(struct tep_handle *pevent, struct tep_record *record)
{
	int ret = FILTER_NONE;
	int flags;

	if (no_irqs || no_softirqs) {
		flags = tep_data_flags(pevent, record);
		if (no_irqs && (flags & TRACE_FLAG_HARDIRQ))
			return FILTER_MISS;
		if (no_softirqs && (flags & TRACE_FLAG_SOFTIRQ))
			return FILTER_MISS;
	}

	return ret;
}

struct stack_info_cpu {
	int			cpu;
	int			last_printed;
};

struct stack_info {
	struct stack_info	*next;
	struct handle_list	*handles;
	struct stack_info_cpu	*cpus;
	int			nr_cpus;
};

static void print_handle_file(struct handle_list *handles)
{
	/* Only print file names if more than one file is read */
	if (!multi_inputs && !instances)
		return;
	if (handles->file && *handles->file != '\0')
		printf("%*s: ", max_file_size, handles->file);
	else
		printf("%*s  ", max_file_size, "");
}

static bool skip_record(struct handle_list *handles, struct tep_record *record, int cpu)
{
	struct tep_handle *tep;
	bool found = false;
	int ret;

	tep = tracecmd_get_tep(handles->handle);

	if (filter_cpus) {
		int i;

		for (i = 0; filter_cpus[i] >= 0; i++) {
			if (filter_cpus[i] == cpu) {
				found = true;
				break;
			}
		}

		if (!found)
			return true;
		found = false;
	}

	ret = test_filters(tep, record);
	switch (ret) {
	case FILTER_NOEXIST:
		break;
	case FILTER_NONE:
	case FILTER_MATCH:
		/* Test the negative filters (-v) */
		ret = test_filters(tep, record);
		if (ret != FILTER_MATCH) {
			found = true;
			break;
		}
	}

	return !found;
}

struct kvm_cpu_map {
	struct tracecmd_input		*guest_handle;
	int				guest_vcpu;
	int				host_pid;
};

static struct kvm_cpu_map *vcpu_maps;
static int nr_vcpu_maps;

static int cmp_map(const void *A, const void *B)
{
	const struct kvm_cpu_map *a = A;
	const struct kvm_cpu_map *b = B;

	if (a->host_pid < b->host_pid)
		return -1;
	return a->host_pid > b->host_pid;
}

static void map_vcpus(struct tracecmd_input **handles, int nr_handles)
{
	struct tracecmd_input *host_handle = handles[0];
	unsigned long long traceid;
	struct kvm_cpu_map *map;
	const int *cpu_pids;
	const char *name;
	int vcpu_count;
	int ret;
	int i, k;

	for (i = 1; i < nr_handles; i++) {
		traceid = tracecmd_get_traceid(handles[i]);
		ret = tracecmd_get_guest_cpumap(host_handle, traceid,
						&name, &vcpu_count, &cpu_pids);
		if (ret)
			continue;
		map = realloc(vcpu_maps, sizeof(*map) * (nr_vcpu_maps + vcpu_count));
		if (!map)
			die("Could not allocate vcpu maps");

		vcpu_maps = map;
		map += nr_vcpu_maps;
		nr_vcpu_maps += vcpu_count;

		for (k = 0; k < vcpu_count; k++) {
			map[k].guest_handle = handles[i];
			map[k].guest_vcpu = k;
			map[k].host_pid = cpu_pids[k];
		}
	}
	if (!vcpu_maps)
		return;

	qsort(vcpu_maps, nr_vcpu_maps, sizeof(*map), cmp_map);
}


const char *tep_plugin_kvm_get_func(struct tep_event *event,
				    struct tep_record *record,
				    unsigned long long *val)
{
	struct tep_handle *tep;
	struct kvm_cpu_map *map;
	struct kvm_cpu_map key;
	unsigned long long rip = *val;
	const char *func;
	int pid;

	if (!vcpu_maps || !nr_vcpu_maps)
		return NULL;

	/*
	 * A kvm event is referencing an address of the guest.
	 * get the PID of this event, and then find which guest
	 * it belongs to. Then return the function name from that guest's
	 * handle.
	 */
	pid = tep_data_pid(event->tep, record);

	key.host_pid = pid;
	map = bsearch(&key, vcpu_maps, nr_vcpu_maps, sizeof(*vcpu_maps), cmp_map);

	if (!map)
		return NULL;

	tep = tracecmd_get_tep(map->guest_handle);
	func = tep_find_function(tep, rip);
	if (func)
		*val = tep_find_function_address(tep, rip);
	return func;
}

static int process_record(struct tracecmd_input *handle, struct tep_record *record,
			  int cpu, void *data)
{
	struct handle_list *handles = tracecmd_get_private(handle);
	unsigned long long *last_timestamp = data;

	if (skip_record(handles, record, cpu))
		return 0;

	if (tscheck && *last_timestamp > record->ts) {
		errno = 0;
		warning("WARNING: Record on cpu %d went backwards: %lld to %lld delta: -%lld\n",
			cpu, *last_timestamp, record->ts, *last_timestamp - record->ts);
	}
	*last_timestamp = record->ts;

	print_handle_file(handles);
	trace_show_data(handle, record);
	return 0;
}

enum output_type {
	OUTPUT_NORMAL,
	OUTPUT_STAT_ONLY,
	OUTPUT_UNAME_ONLY,
	OUTPUT_VERSION_ONLY,
};

static void read_data_info(struct list_head *handle_list, enum output_type otype,
			   int global, int align_ts)
{
	unsigned long long ts, first_ts;
	struct handle_list *handles;
	struct tracecmd_input **handle_array;
	unsigned long long last_timestamp = 0;
	int nr_handles = 0;
	int first = 1;
	int ret;

	list_for_each_entry(handles, handle_list, list) {
		int cpus;

		nr_handles++;

		if (!tracecmd_is_buffer_instance(handles->handle)) {
			ret = tracecmd_init_data(handles->handle);
			if (ret < 0)
				die("failed to init data");
		}
		cpus = tracecmd_cpus(handles->handle);
		handles->cpus = cpus;

		process_filters(handles);

		/* Don't process instances that we added here */
		if (tracecmd_is_buffer_instance(handles->handle))
			continue;

		if (align_ts) {
			ts = tracecmd_get_first_ts(handles->handle);
			if (first || first_ts > ts)
				first_ts = ts;
			first = 0;
		}
		print_handle_file(handles);
		printf("cpus=%d\n", cpus);

		/* Latency trace is just all ASCII */
		if (ret > 0) {
			if (multi_inputs)
				die("latency traces do not work with multiple inputs");
			read_latency(handles->handle);
			return;
		}

		switch (otype) {
		case OUTPUT_NORMAL:
			break;
		case OUTPUT_STAT_ONLY:
			printf("\nKernel buffer statistics:\n"
			       "  Note: \"entries\" are the entries left in the kernel ring buffer and are not\n"
			       "        recorded in the trace data. They should all be zero.\n\n");
			tracecmd_print_stats(handles->handle);
			continue;
		case OUTPUT_UNAME_ONLY:
			tracecmd_print_uname(handles->handle);
		case OUTPUT_VERSION_ONLY:
			tracecmd_print_version(handles->handle);
			continue;
		}

		init_wakeup(handles->handle);
		if (last_hook)
			last_hook->next = tracecmd_hooks(handles->handle);
		else
			hooks = tracecmd_hooks(handles->handle);
		if (profile)
			trace_init_profile(handles->handle, hooks, global);

		/* If this file has buffer instances, get the handles for them */
		instances = tracecmd_buffer_instances(handles->handle);
		if (instances) {
			struct tracecmd_input *new_handle;
			struct input_files *file_input;
			const char *save_name;
			const char *name;
			int i;

			file_input = handles->input_file;

			for (i = 0; i < instances; i++) {
				name = tracecmd_buffer_instance_name(handles->handle, i);
				if (!name)
					die("error in reading buffer instance");
				new_handle = tracecmd_buffer_instance_handle(handles->handle, i);
				if (!new_handle) {
					warning("could not retrieve handle %s", name);
					continue;
				}
				if (file_input) {
					save_name = file_input->file;
					file_input->file = name;
				} else {
					save_name = NULL;
					file_input = add_input(name);
				}
				add_handle(new_handle, file_input);
				if (save_name)
					file_input->file = save_name;
			}
		}
	}

	if (otype != OUTPUT_NORMAL)
		return;

	if (align_ts) {
		list_for_each_entry(handles, handle_list, list) {
			tracecmd_add_ts_offset(handles->handle, -first_ts);
		}
	}

	handle_array = calloc(nr_handles, sizeof(*handle_array));
	if (!handle_array)
		die("Could not allocate memory for handle list");

	nr_handles = 0;
	list_for_each_entry(handles, handle_list, list) {
		tracecmd_set_private(handles->handle, handles);
		handle_array[nr_handles++] = handles->handle;
	}

	map_vcpus(handle_array, nr_handles);

	tracecmd_iterate_events_multi(handle_array, nr_handles,
				      process_record, &last_timestamp);

	free(handle_array);

	if (profile)
		do_trace_profile();

	list_for_each_entry(handles, handle_list, list) {
		show_test(handles->handle);
	}
}

struct tracecmd_input *read_trace_header(const char *file, int flags)
{
	input_fd = open(file, O_RDONLY);
	if (input_fd < 0)
		die("opening '%s'\n", file);

	return tracecmd_alloc_fd(input_fd, flags);
}

static void sig_end(int sig)
{
	struct handle_list *handles;

	fprintf(stderr, "trace-cmd: Received SIGINT\n");

	list_for_each_entry(handles, &handle_list, list) {
		tracecmd_close(handles->handle);
	}

	exit(0);
}

static const char *skip_space_and_test_digit(const char *p, const char *cpu_str)
{
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

static void parse_cpulist(const char *cpu_str)
{
	unsigned a, b;
	const char *s = cpu_str;

	do {
		s = skip_space_and_test_digit(s, cpu_str);
		b = a = strtoul(s, (char **)&s, 10);
		if (*s == '-') {
			s = skip_space_and_test_digit(s + 1, cpu_str);
			b = strtoul(s, (char **)&s, 10);
		}
		if (!(a <= b))
			die("range of cpu numbers must be lower to greater");
		while (a <= b) {
			__add_cpu(a);
			a++;
		}
		if (*s == ',' || *s == ':')
			s++;
	} while (*s != '\0');
}

static void read_file_fd(int fd, char *dst, int len)
{
	size_t size = 0;
	int r;

	do {
		r = read(fd, dst+size, len);
		if (r > 0) {
			size += r;
			len -= r;
		}
	} while (r > 0);
}

static void add_functions(struct tep_handle *pevent, const char *file)
{
	struct stat st;
	char *buf;
	int ret;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		die("Can't read file %s", file);

	ret = fstat(fd, &st);
	if (ret < 0)
		die("Can't stat file %s", file);

	buf = malloc(st.st_size + 1);
	if (!buf)
		die("Failed to allocate for function buffer");
	read_file_fd(fd, buf, st.st_size);
	buf[st.st_size] = '\0';
	close(fd);
	tep_parse_kallsyms(pevent, buf);
	free(buf);
}

static void process_plugin_option(char *option)
{
	char *name = option;
	char *val = NULL;
	char *p;

	if ((p = strstr(name, "="))) {
		*p = '\0';
		val = p+1;
	}
	tep_plugin_add_option(name, val);
}

static void set_event_flags(struct tep_handle *pevent, struct event_str *list,
			    unsigned int flag)
{
	struct tep_event **events;
	struct tep_event *event;
	struct event_str *str;
	regex_t regex;
	int ret;
	int i;

	if (!list)
		return;

	events = tep_list_events(pevent, 0);

	for (str = list; str; str = str->next) {
		char *match;

		match = malloc(strlen(str->event) + 3);
		if (!match)
			die("Failed to allocate for match string '%s'", str->event);
		sprintf(match, "^%s$", str->event);

		ret = regcomp(&regex, match, REG_ICASE|REG_NOSUB);
		if (ret < 0)
			die("Can't parse '%s'", str->event);
		free(match);
		for (i = 0; events[i]; i++) {
			event = events[i];
			if (!regexec(&regex, event->name, 0, NULL, 0) ||
			    !regexec(&regex, event->system, 0, NULL, 0))
				event->flags |= flag;
		}
	}
}

static void show_event_ts(struct tracecmd_input *handle,
			  struct tep_record *record)
{
	const char *tfmt = time_format(handle, TIME_FMT_TS);
	struct tep_handle *tep = tracecmd_get_tep(handle);
	struct trace_seq s;

	trace_seq_init(&s);
	tep_print_event(tep, &s, record, tfmt, TEP_PRINT_TIME);
	printf("%s", s.buffer);
	trace_seq_destroy(&s);
}

static void add_hook(const char *arg)
{
	struct hook_list *hook;

	hook = tracecmd_create_event_hook(arg);

	hook->next = hooks;
	hooks = hook;
	if (!last_hook)
		last_hook = hook;
}

static void add_first_input(const char *input_file, long long tsoffset)
{
	struct input_files *item;

	/* Copy filter strings to this input file */
	item = add_input(input_file);
	item->filter_str = filter_strings;
	if (filter_strings)
		item->filter_str_next = filter_next;
	else
		item->filter_str_next = &item->filter_str;
	/* Copy the tsoffset to this input file */
	item->tsoffset = tsoffset;
}

enum {
	OPT_verbose	= 234,
	OPT_align_ts	= 235,
	OPT_raw_ts	= 236,
	OPT_version	= 237,
	OPT_tscheck	= 238,
	OPT_tsdiff	= 239,
	OPT_ts2secs	= 240,
	OPT_tsoffset	= 241,
	OPT_bycomm	= 242,
	OPT_debug	= 243,
	OPT_uname	= 244,
	OPT_profile	= 245,
	OPT_event	= 246,
	OPT_comm	= 247,
	OPT_boundary	= 248,
	OPT_stat	= 249,
	OPT_pid		= 250,
	OPT_nodate	= 251,
	OPT_check_event_parsing	= 252,
	OPT_kallsyms	= 253,
	OPT_events	= 254,
	OPT_cpu		= 255,
	OPT_cpus	= 256,
	OPT_first	= 257,
	OPT_last	= 258,
};

void trace_report (int argc, char **argv)
{
	struct tracecmd_input *handle;
	struct tep_handle *pevent;
	struct event_str *raw_events = NULL;
	struct event_str *nohandler_events = NULL;
	struct event_str **raw_ptr = &raw_events;
	struct event_str **nohandler_ptr = &nohandler_events;
	const char *functions = NULL;
	const char *print_event = NULL;
	struct input_files *inputs;
	struct handle_list *handles;
	enum output_type otype;
	long long tsoffset = 0;
	unsigned long long ts2secs = 0;
	unsigned long long ts2sc;
	int open_flags = 0;
	int show_stat = 0;
	int show_funcs = 0;
	int show_endian = 0;
	int show_page_size = 0;
	int show_printk = 0;
	int show_uname = 0;
	int show_version = 0;
	int show_events = 0;
	int show_cpus = 0;
	int show_first = 0;
	int show_last = 0;
	int print_events = 0;
	int nanosec = 0;
	int no_date = 0;
	int raw_ts = 0;
	int align_ts = 0;
	int global = 0;
	int neg = 0;
	int ret = 0;
	int check_event_parsing = 0;
	int c;

	list_head_init(&handle_list);
	list_head_init(&input_files);

	if (argc < 2)
		usage(argv);

	if (strcmp(argv[1], "report") != 0)
		usage(argv);

	signal(SIGINT, sig_end);

	trace_set_loglevel(TEP_LOG_ERROR);

	for (;;) {
		int option_index = 0;
		static struct option long_options[] = {
			{"cpu", required_argument, NULL, OPT_cpu},
			{"cpus", no_argument, NULL, OPT_cpus},
			{"events", no_argument, NULL, OPT_events},
			{"event", required_argument, NULL, OPT_event},
			{"filter-test", no_argument, NULL, 'T'},
			{"first-event", no_argument, NULL, OPT_first},
			{"kallsyms", required_argument, NULL, OPT_kallsyms},
			{"pid", required_argument, NULL, OPT_pid},
			{"comm", required_argument, NULL, OPT_comm},
			{"check-events", no_argument, NULL,
				OPT_check_event_parsing},
			{"nodate", no_argument, NULL, OPT_nodate},
			{"stat", no_argument, NULL, OPT_stat},
			{"boundary", no_argument, NULL, OPT_boundary},
			{"debug", no_argument, NULL, OPT_debug},
			{"last-event", no_argument, NULL, OPT_last},
			{"profile", no_argument, NULL, OPT_profile},
			{"uname", no_argument, NULL, OPT_uname},
			{"version", no_argument, NULL, OPT_version},
			{"by-comm", no_argument, NULL, OPT_bycomm},
			{"ts-offset", required_argument, NULL, OPT_tsoffset},
			{"ts2secs", required_argument, NULL, OPT_ts2secs},
			{"ts-diff", no_argument, NULL, OPT_tsdiff},
			{"ts-check", no_argument, NULL, OPT_tscheck},
			{"raw-ts", no_argument, NULL, OPT_raw_ts},
			{"align-ts", no_argument, NULL, OPT_align_ts},
			{"verbose", optional_argument, NULL, OPT_verbose},
			{"help", no_argument, NULL, '?'},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc-1, argv+1, "+hSIi:H:feGpRr:tPNn:LlEwF:V::vTqO:",
			long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'i':
			if (input_file) {
				multi_inputs++;
				add_input(optarg);
			} else {
				input_file = optarg;
				add_first_input(input_file, tsoffset);
			}
			break;
		case 'F':
			add_filter(last_input_file, optarg, neg);
			break;
		case 'H':
			add_hook(optarg);
			break;
		case 'T':
			test_filters_mode = 1;
			break;
		case 'f':
			show_funcs = 1;
			break;
		case 'I':
			no_irqs = 1;
			break;
		case 'S':
			no_softirqs = 1;
			break;
		case 'P':
			show_printk = 1;
			break;
		case 'L':
			open_flags |= TRACECMD_FL_LOAD_NO_SYSTEM_PLUGINS;
			break;
		case 'N':
			open_flags |= TRACECMD_FL_LOAD_NO_PLUGINS;
			break;
		case 'n':
			*nohandler_ptr = malloc(sizeof(struct event_str));
			if (!*nohandler_ptr)
				die("Failed to allocate for '-n %s'", optarg);
			(*nohandler_ptr)->event = optarg;
			(*nohandler_ptr)->next = NULL;
			nohandler_ptr = &(*nohandler_ptr)->next;
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
		case 'G':
			global = 1;
			break;
		case 'R':
			raw_format = true;
			break;
		case 'r':
			*raw_ptr = malloc(sizeof(struct event_str));
			if (!*raw_ptr)
				die("Failed to allocate '-r %s'", optarg);
			(*raw_ptr)->event = optarg;
			(*raw_ptr)->next = NULL;
			raw_ptr = &(*raw_ptr)->next;
			break;
		case 't':
			nanosec = 1;
			break;
		case 'w':
			show_wakeup = 1;
			break;
		case 'l':
			latency_format = 1;
			break;
		case 'O':
			process_plugin_option(optarg);
			break;
		case 'v':
			if (neg)
				die("Only 1 -v can be used");
			neg = 1;
			break;
		case 'q':
			silence_warnings = 1;
			tracecmd_set_loglevel(TEP_LOG_NONE);
			break;
		case OPT_cpu:
			parse_cpulist(optarg);
			break;
		case OPT_cpus:
			show_cpus = 1;
			break;
		case OPT_events:
			print_events = 1;
			break;
		case OPT_event:
			print_event = optarg;
			break;
		case OPT_kallsyms:
			functions = optarg;
			break;
		case OPT_pid:
			add_pid_filter(optarg);
			break;
		case OPT_comm:
			add_comm_filter(optarg);
			break;
		case OPT_check_event_parsing:
			check_event_parsing = 1;
			break;
		case OPT_nodate:
			no_date = 1;
			break;
		case OPT_stat:
			show_stat = 1;
			break;
		case OPT_first:
			show_first = 1;
			show_cpus = 1;
			break;
		case OPT_last:
			show_last = 1;
			show_cpus = 1;
			break;
		case OPT_boundary:
			/* Debug to look at buffer breaks */
			buffer_breaks = 1;
			break;
		case OPT_debug:
			buffer_breaks = 1;
			tracecmd_set_debug(true);
			break;
		case OPT_profile:
			profile = 1;
			break;
		case OPT_uname:
			show_uname = 1;
			break;
		case OPT_version:
			show_version = 1;
			break;
		case OPT_bycomm:
			trace_profile_set_merge_like_comms();
			break;
		case OPT_ts2secs:
			ts2sc = atoll(optarg);
			if (multi_inputs)
				last_input_file->ts2secs = ts2sc;
			else
				ts2secs = ts2sc;
			break;
		case OPT_tsoffset:
			tsoffset = atoll(optarg);
			if (multi_inputs)
				last_input_file->tsoffset = tsoffset;
			if (!input_file)
				die("--ts-offset must come after -i");
			break;
		case OPT_tsdiff:
			tsdiff = 1;
			break;
		case OPT_tscheck:
			tscheck = 1;
			break;
		case OPT_raw_ts:
			raw_ts = 1;
			break;
		case OPT_align_ts:
			align_ts = 1;
			break;
		case 'V':
		case OPT_verbose:
			show_status = 1;
			if (trace_set_verbose(optarg) < 0)
				die("invalid verbose level %s", optarg);
			break;
		default:
			usage(argv);
		}
	}

	if ((argc - optind) >= 2) {
		if (input_file)
			usage(argv);
		input_file = argv[optind + 1];
		add_first_input(input_file, tsoffset);
	}

	if (!multi_inputs) {
		if (!input_file) {
			input_file = default_input_file;
			add_first_input(input_file, tsoffset);
		}
	} else if (show_wakeup)
		die("Wakeup tracing can only be done on a single input file");

	list_for_each_entry(inputs, &input_files, list) {
		handle = read_trace_header(inputs->file, open_flags);
		if (!handle)
			die("error reading header for %s", inputs->file);

		/* If used with instances, top instance will have no tag */
		add_handle(handle, multi_inputs ? inputs : NULL);

		if (no_date)
			tracecmd_set_flag(handle, TRACECMD_FL_IGNORE_DATE);
		if (raw_ts)
			tracecmd_set_flag(handle, TRACECMD_FL_RAW_TS);
		page_size = tracecmd_page_size(handle);

		if (show_page_size) {
			printf("file page size is %d, and host page size is %d\n",
			       page_size,
			       getpagesize());
			return;
		}

		if (inputs->tsoffset)
			tracecmd_set_ts_offset(handle, inputs->tsoffset);

		if (inputs->ts2secs)
			tracecmd_set_ts2secs(handle, inputs->ts2secs);
		else if (ts2secs)
			tracecmd_set_ts2secs(handle, ts2secs);

		pevent = tracecmd_get_tep(handle);

		if (nanosec)
			tep_set_flag(pevent, TEP_NSEC_OUTPUT);

		if (raw_format)
			format_type = TEP_PRINT_INFO_RAW;

		if (test_filters_mode)
			tep_set_test_filters(pevent, 1);

		if (functions)
			add_functions(pevent, functions);

		if (show_endian) {
			printf("file is %s endian and host is %s endian\n",
				tep_is_file_bigendian(pevent) ? "big" : "little",
				tep_is_local_bigendian(pevent) ? "big" : "little");
			return;
		}

		if (print_events) {
			tracecmd_print_events(handle, NULL);
			return;
		}

		if (print_event) {
			tracecmd_print_events(handle, print_event);
			return;
		}

		ret = tracecmd_read_headers(handle, 0);
		if (check_event_parsing) {
			if (ret || tracecmd_get_parsing_failures(handle))
				exit(EINVAL);
			else
				exit(0);
		} else {
			if (ret)
				return;
		}

		if (show_funcs) {
			tep_print_funcs(pevent);
			return;
		}
		if (show_printk) {
			tep_print_printk(pevent);
			return;
		}

		if (show_events) {
			struct tep_event **events;
			struct tep_event *event;
			int i;

			events = tep_list_events(pevent, TEP_EVENT_SORT_SYSTEM);
			for (i = 0; events[i]; i++) {
				event = events[i];
				if (event->system)
					printf("%s:", event->system);
				printf("%s\n", event->name);
			}
			return;
		}

		if (show_cpus) {
			struct tep_record *record;
			int cpus;
			int ret;
			int i;

			if (!tracecmd_is_buffer_instance(handle)) {
				ret = tracecmd_init_data(handle);
				if (ret < 0)
					die("failed to init data");
			}
			cpus = tracecmd_cpus(handle);
			printf("List of CPUs in %s with data:\n", inputs->file);
			for (i = 0; i < cpus; i++) {
				if ((record = tracecmd_read_cpu_first(handle, i))) {
					printf("  %d", i);
					if (show_first) {
						printf("\tFirst event:");
						show_event_ts(handle, record);
					}
					if (show_last) {
						tracecmd_free_record(record);
						record = tracecmd_read_cpu_last(handle, i);
						if (record) {
							printf("\tLast event:");
							show_event_ts(handle, record);
						}
					}
					tracecmd_free_record(record);
					printf("\n");
				}
			}
			continue;
		}

		set_event_flags(pevent, nohandler_events, TEP_EVENT_FL_NOHANDLE);
		set_event_flags(pevent, raw_events, TEP_EVENT_FL_PRINTRAW);
	}

	if (show_cpus)
		return;

	otype = OUTPUT_NORMAL;

	if (tracecmd_get_flags(handle) & TRACECMD_FL_RAW_TS) {
		tep_func_repeat_format = "%d";
	} else if (tracecmd_get_flags(handle) & TRACECMD_FL_IN_USECS) {
		if (tep_test_flag(tracecmd_get_tep(handle), TEP_NSEC_OUTPUT))
			tep_func_repeat_format = "%9.1d";
		else
			tep_func_repeat_format = "%6.1000d";
	} else {
		tep_func_repeat_format = "%12d";
	}


	if (show_stat)
		otype = OUTPUT_STAT_ONLY;
	/* yeah yeah, uname overrides stat */
	if (show_uname)
		otype = OUTPUT_UNAME_ONLY;
	/* and version overrides uname! */
	if (show_version)
		otype = OUTPUT_VERSION_ONLY;
	read_data_info(&handle_list, otype, global, align_ts);

	list_for_each_entry(handles, &handle_list, list) {
		tracecmd_close(handles->handle);
	}
	free_handles();
	free_inputs();

	finish_wakeup();

	return;
}
