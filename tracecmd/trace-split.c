// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <getopt.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "list.h"
#include "trace-local.h"

static unsigned int page_size;
static const char *default_input_file = DEFAULT_INPUT_FILE;
static const char *default_top_instance_name = "top";
static const char *input_file;

enum split_types {
	SPLIT_NONE,
	/* The order of these must be reverse of the case statement in the options */
	SPLIT_SECONDS,
	SPLIT_MSECS,
	SPLIT_USECS,
	SPLIT_EVENTS,
	SPLIT_PAGES,
	SPLIT_NR_TYPES,
};

struct cpu_data {
	unsigned long long		ts;
	unsigned long long		offset;
	unsigned long long		missed_events;
	struct tep_record		*record;
	int				cpu;
	int				fd;
	int				index;
	void				*commit;
	void				*page;
	char				*file;
};

struct handle_list {
	struct list_head		list;
	char				*name;
	int				index;
	struct tracecmd_input		*handle;

	/* Identify the top instance in the input trace. */
	bool				was_top_instance;
};

static struct list_head handle_list;

/**
 * get_handle - Obtain a handle that must be closed once finished.
 */
static struct tracecmd_input *get_handle(struct handle_list *item)
{
	struct tracecmd_input *top_handle, *handle;

	top_handle = tracecmd_open(input_file, 0);
	if (!top_handle)
		die("Error reading %s", input_file);

	if (item->was_top_instance) {
		return top_handle;
	} else {
		handle = tracecmd_buffer_instance_handle(top_handle, item->index);
		if (!handle)
			warning("Could not retrieve handle %s", item->name);

		tracecmd_close(top_handle);
		return handle;
	}
}

static void add_handle(const char *name, int index, bool was_top_instance)
{
	struct handle_list *item;

	item = calloc(1, sizeof(*item));
	if (!item)
		die("Failed to allocate handle item");

	item->name = strdup(name);
	if (!item->name)
		die("Failed to duplicate %s", name);

	item->index = index;
	item->was_top_instance = was_top_instance;
	item->handle = get_handle(item);
	list_add_tail(&item->list, &handle_list);
}

static void free_handles(struct list_head *list)
{
	struct handle_list *item, *n;

	list_for_each_entry_safe(item, n, list, list) {
		list_del(&item->list);
		free(item->name);
		tracecmd_close(item->handle);
		free(item);
	}
}

static struct list_head inst_list;

struct inst_list {
	struct list_head		list;
	char				*name;
	struct handle_list		*handle;

	/* Identify the top instance in the input trace. */
	bool				was_top_instance;

	/* Identify the top instance in the output trace. */
	bool				is_top_instance;
};

static void free_inst(struct list_head *list)
{
	struct inst_list *item, *n;

	list_for_each_entry_safe(item, n, list, list) {
		list_del(&item->list);
		free(item->name);
		free(item);
	}
}

static struct inst_list *add_inst(const char *name, bool was_top_instance,
				  bool is_top_instance)
{
	struct inst_list *item;

	item = calloc(1, sizeof(*item));
	if (!item)
		die("Failed to allocate output_file item");

	item->name = strdup(name);
	if (!item->name)
		die("Failed to duplicate %s", name);

	item->was_top_instance = was_top_instance;
	item->is_top_instance = is_top_instance;
	list_add_tail(&item->list, &inst_list);
	return item;
}

static int create_type_len(struct tep_handle *pevent, int time, int len)
{
	static int bigendian = -1;
	char *ptr;
	int test;

	if (bigendian < 0) {
		test = 0x4321;
		ptr = (char *)&test;
		if (*ptr == 0x21)
			bigendian = 0;
		else
			bigendian = 1;
	}

	if (tep_is_file_bigendian(pevent))
		time |= (len << 27);
	else
		time = (time << 5) | len;

	return tep_read_number(pevent, &time, 4);
}

static int write_record(struct tracecmd_input *handle,
			struct tep_record *record,
			struct cpu_data *cpu_data,
			enum split_types type)
{
	unsigned long long diff;
	struct tep_handle *pevent;
	void *page;
	int len = 0;
	char *ptr;
	int index = 0;
	int time;

	page = cpu_data->page;

	pevent = tracecmd_get_tep(handle);

	ptr = page + cpu_data->index;

	diff = record->ts - cpu_data->ts;
	if (diff > (1 << 27)) {
		/* Add a time stamp */
		len = RINGBUF_TYPE_TIME_EXTEND;
		time = (unsigned int)(diff & ((1ULL << 27) - 1));
		time = create_type_len(pevent, time, len);
		*(unsigned *)ptr = time;
		ptr += 4;
		time = (unsigned int)(diff >> 27);
		*(unsigned *)ptr = tep_read_number(pevent, &time, 4);
		cpu_data->ts = record->ts;
		cpu_data->index += 8;
		return 0;
	}

	if (record->size && (record->size <= 28 * 4))
		len = record->size / 4;

	time = (unsigned)diff;
	time = create_type_len(pevent, time, len);

	memcpy(ptr, &time, 4);
	ptr += 4;
	index = 4;

	if (!len) {
		len = record->size + 4;
		if ((len + 4) > record->record_size)
			die("Bad calculation of record len (expect:%d actual:%d)",
			    record->record_size, len + 4);
		*(unsigned *)ptr = tep_read_number(pevent, &len, 4);
		ptr += 4;
		index += 4;
	}

	len = (record->size + 3) & ~3;
	index += len;

	memcpy(ptr, record->data, len);

	cpu_data->index += index;
	cpu_data->ts = record->ts;

	return 1;
}

#define MISSING_EVENTS (1UL << 31)
#define MISSING_STORED (1UL << 30)

#define COMMIT_MASK ((1 << 27) - 1)

static void write_page(struct tep_handle *pevent,
		       struct cpu_data *cpu_data, int long_size)
{
	unsigned long long *ptr = NULL;
	unsigned int flags = 0;

	if (cpu_data->missed_events) {
		flags |= MISSING_EVENTS;
		if (cpu_data->missed_events > 0) {
			flags |= MISSING_STORED;
			ptr = cpu_data->page + cpu_data->index;
		}
	}

	if (long_size == 8) {
		unsigned long long index = cpu_data->index - 16 + flags;;
		*(unsigned long long *)cpu_data->commit =
				tep_read_number(pevent, &index, 8);
	} else {
		unsigned int index = cpu_data->index - 12 + flags;;
		*(unsigned int *)cpu_data->commit =
			tep_read_number(pevent, &index, 4);
	}
	if (ptr)
		*ptr = tep_read_number(pevent, &cpu_data->missed_events, 8);

	write(cpu_data->fd, cpu_data->page, page_size);
}

static struct tep_record *read_record(struct tracecmd_input *handle,
				      int percpu, int *cpu)
{
	if (percpu)
		return tracecmd_read_data(handle, *cpu);

	return tracecmd_read_next_data(handle, cpu);
}

static void set_cpu_time(struct tracecmd_input *handle,
			 int percpu, unsigned long long start, int cpu, int cpus)
{
	if (percpu) {
		tracecmd_set_cpu_to_timestamp(handle, cpu, start);
		return;
	}

	for (cpu = 0; cpu < cpus; cpu++)
		tracecmd_set_cpu_to_timestamp(handle, cpu, start);
	return;
}

static int parse_cpu(struct tracecmd_input *handle,
		     struct cpu_data *cpu_data,
		     unsigned long long start,
		     unsigned long long end,
		     int count_limit, int percpu, int cpu,
		     enum split_types type, bool *end_reached)
{
	struct tep_record *record;
	struct tep_handle *pevent;
	void *ptr;
	int page_size;
	int long_size = 0;
	int cpus;
	int count = 0;
	int pages = 0;

	cpus = tracecmd_cpus(handle);

	long_size = tracecmd_long_size(handle);
	page_size = tracecmd_page_size(handle);
	pevent = tracecmd_get_tep(handle);

	/* Force new creation of first page */
	if (percpu) {
		cpu_data[cpu].index = page_size + 1;
		cpu_data[cpu].page = NULL;
	} else {
		for (cpu = 0; cpu < cpus; cpu++) {
			cpu_data[cpu].index = page_size + 1;
			cpu_data[cpu].page = NULL;
		}
	}

	/*
	 * Get the cpu pointers up to the start of the
	 * start time stamp.
	 */

	record = read_record(handle, percpu, &cpu);

	if (start) {
		set_cpu_time(handle, percpu, start, cpu, cpus);
		while (record && record->ts < start) {
			tracecmd_free_record(record);
			record = read_record(handle, percpu, &cpu);
		}
	} else if (record)
		start = record->ts;

	while (record && (!end || record->ts <= end)) {
		if ((cpu_data[cpu].index + record->record_size > page_size) ||
		    record->missed_events) {

			if (type == SPLIT_PAGES && ++pages > count_limit)
				break;

			if (cpu_data[cpu].page)
				write_page(pevent, &cpu_data[cpu], long_size);
			else {
				cpu_data[cpu].page = malloc(page_size);
				if (!cpu_data[cpu].page)
					die("Failed to allocate page");
			}

			cpu_data[cpu].missed_events = record->missed_events;

			memset(cpu_data[cpu].page, 0, page_size);
			ptr = cpu_data[cpu].page;

			*(unsigned long long*)ptr =
				tep_read_number(pevent, &(record->ts), 8);
			cpu_data[cpu].ts = record->ts;
			ptr += 8;
			cpu_data[cpu].commit = ptr;
			ptr += long_size;
			cpu_data[cpu].index = 8 + long_size;
		}

		cpu_data[cpu].offset = record->offset;

		if (write_record(handle, record, &cpu_data[cpu], type)) {
			tracecmd_free_record(record);
			record = read_record(handle, percpu, &cpu);

			/* if we hit the end of the cpu, clear the offset */
			if (!record) {
				if (percpu)
					cpu_data[cpu].offset = 0;
				else
					for (cpu = 0; cpu < cpus; cpu++)
						cpu_data[cpu].offset = 0;
			}

			switch (type) {
			case SPLIT_NONE:
				break;
			case SPLIT_SECONDS:
				if (record &&
				    record->ts >
				    (start + (unsigned long long)count_limit * 1000000000ULL)) {
					tracecmd_free_record(record);
					record = NULL;
				}
				break;
			case SPLIT_MSECS:
				if (record &&
				    record->ts >
				    (start + (unsigned long long)count_limit * 1000000ULL)) {
					tracecmd_free_record(record);
					record = NULL;
				}
				break;
			case SPLIT_USECS:
				if (record &&
				    record->ts >
				    (start + (unsigned long long)count_limit * 1000ULL)) {
					tracecmd_free_record(record);
					record = NULL;
				}
				break;
			case SPLIT_EVENTS:
				if (++count >= count_limit) {
					tracecmd_free_record(record);
					record = NULL;
				}
				break;
			default:
				break;
			}
		}
	}

	if (record && (record->ts > end))
		*end_reached = true;
	else
		*end_reached = false;

	if (record)
		tracecmd_free_record(record);

	if (percpu) {
		if (cpu_data[cpu].page) {
			write_page(pevent, &cpu_data[cpu], long_size);
			free(cpu_data[cpu].page);
			cpu_data[cpu].page = NULL;
		}
	} else {
		for (cpu = 0; cpu < cpus; cpu++) {
			if (cpu_data[cpu].page) {
				write_page(pevent, &cpu_data[cpu], long_size);
				free(cpu_data[cpu].page);
				cpu_data[cpu].page = NULL;
			}
		}
	}

	return 0;
}

static char *get_temp_file(const char *output_file, const char *name, int cpu)
{
	const char *dot;
	char *file = NULL;
	char *output;
	char *base;
	char *dir;
	int ret;

	if (name)
		dot = ".";
	else
		dot = name = "";

	output = strdup(output_file);
	if (!output)
		die("Failed to duplicate %s", output_file);

	/* Extract basename() first, as dirname() truncates output */
	base = basename(output);
	dir = dirname(output);

	ret = asprintf(&file, "%s/.tmp.%s.%s%s%d", dir, base, name, dot, cpu);
	if (ret < 0)
		die("Failed to allocate file for %s %s %s %d", dir, base, name, cpu);
	free(output);
	return file;
}

static void delete_temp_file(const char *name)
{
	unlink(name);
}

static void put_temp_file(char *file)
{
	free(file);
}

static void touch_file(const char *file)
{
	int fd;

	fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		die("could not create file %s\n", file);
	close(fd);
}

static unsigned long long parse_file(struct tracecmd_input *handle,
				     const char *output_file,
				     unsigned long long start,
				     unsigned long long end, int percpu,
				     int only_cpu, int count,
				     enum split_types type,
				     bool *end_reached)
{
	unsigned long long current = 0;
	struct tracecmd_output *ohandle;
	struct inst_list *inst_entry;
	struct cpu_data *cpu_data;
	struct tep_record *record;
	bool all_end_reached = true;
	char **cpu_list;
	char *file;
	int cpus;
	int cpu;
	int ret;
	int fd;

	ohandle = tracecmd_copy(handle, output_file, TRACECMD_FILE_CMD_LINES, 0, NULL);
	tracecmd_set_out_clock(ohandle, tracecmd_get_trace_clock(handle));

	list_for_each_entry(inst_entry, &inst_list, list) {
		struct tracecmd_input *curr_handle;
		bool curr_end_reached = false;

		curr_handle = inst_entry->handle->handle;
		cpus = tracecmd_cpus(curr_handle);
		cpu_data = malloc(sizeof(*cpu_data) * cpus);
		if (!cpu_data)
			die("Failed to allocate cpu_data for %d cpus", cpus);

		for (cpu = 0; cpu < cpus; cpu++) {
			file = get_temp_file(output_file, inst_entry->name, cpu);
			touch_file(file);

			fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
			cpu_data[cpu].cpu = cpu;
			cpu_data[cpu].fd = fd;
			cpu_data[cpu].file = file;
			cpu_data[cpu].offset = 0;
			if (start)
				tracecmd_set_cpu_to_timestamp(curr_handle, cpu, start);
		}

		if (only_cpu >= 0) {
			parse_cpu(curr_handle, cpu_data, start, end, count,
				  1, only_cpu, type, &curr_end_reached);
		} else if (percpu) {
			for (cpu = 0; cpu < cpus; cpu++)
				parse_cpu(curr_handle, cpu_data, start,
					  end, count, percpu, cpu, type, &curr_end_reached);
		} else {
			parse_cpu(curr_handle, cpu_data, start,
				  end, count, percpu, -1, type, &curr_end_reached);
		}

		/* End is reached when all instances finished. */
		all_end_reached &= curr_end_reached;

		cpu_list = malloc(sizeof(*cpu_list) * cpus);
		if (!cpu_list)
			die("Failed to allocate cpu_list for %d cpus", cpus);
		for (cpu = 0; cpu < cpus; cpu++)
			cpu_list[cpu] = cpu_data[cpu].file;

		if (inst_entry->is_top_instance)
			ret = tracecmd_append_cpu_data(ohandle, cpus, cpu_list);
		else
			ret = tracecmd_append_buffer_cpu_data(ohandle, inst_entry->name, cpus,
							      cpu_list);
		if (ret < 0)
			die("Failed to append tracing data\n");

		for (cpu = 0; cpu < cpus; cpu++) {
			/* Set the tracecmd cursor to the next set of records */
			if (cpu_data[cpu].offset) {
				record = tracecmd_read_at(curr_handle, cpu_data[cpu].offset, NULL);
				if (record && (!current || record->ts > current))
					current = record->ts + 1;
				tracecmd_free_record(record);
			}
		}

		for (cpu = 0; cpu < cpus; cpu++) {
			close(cpu_data[cpu].fd);
			delete_temp_file(cpu_data[cpu].file);
			put_temp_file(cpu_data[cpu].file);
		}
		free(cpu_data);
		free(cpu_list);
	}

	tracecmd_output_close(ohandle);

	*end_reached = all_end_reached;
	return current;
}

/* Map the instance names to their handle. */
static void map_inst_handle(void)
{
	struct handle_list *handle_entry;
	struct inst_list *inst_entry;

	/*
	 * No specific instance was given for this output file.
	 * Add all the available instances.
	 */
	if (list_empty(&inst_list)) {
		list_for_each_entry(handle_entry, &handle_list, list) {
			add_inst(handle_entry->name, handle_entry->was_top_instance,
				 handle_entry->was_top_instance);
		}
	}

	list_for_each_entry(inst_entry, &inst_list, list) {
		list_for_each_entry(handle_entry, &handle_list, list) {
			if ((inst_entry->was_top_instance &&
			     handle_entry->was_top_instance) ||
			    (!inst_entry->was_top_instance &&
			     !strcmp(handle_entry->name, inst_entry->name))) {
				inst_entry->handle = handle_entry;
				goto found;
			}
		}

		warning("Requested instance %s was not found in trace.", inst_entry->name);
		break;
found:
		continue;
	}
}

static bool is_top_instance_unique(void)
{
	struct inst_list *inst_entry;
	bool has_top_buffer = false;

	/* Check there is at most one top buffer. */
	list_for_each_entry(inst_entry, &inst_list, list) {
		if (inst_entry->is_top_instance) {
			if (has_top_buffer)
				return false;
			has_top_buffer = true;
		}
	}

	return true;
}

enum {
	OPT_top = 237,
};

/*
 * Used to identify the arg. previously parsed.
 * E.g. '-b' can only follow '--top'.
 */
enum prev_arg_type {
	PREV_IS_NONE,
	PREV_IS_TOP,
	PREV_IS_BUFFER,
};

void trace_split (int argc, char **argv)
{
	struct tracecmd_input *handle;
	unsigned long long start_ns = 0, end_ns = 0;
	unsigned long long current;
	enum prev_arg_type prev_arg_type;
	struct inst_list *prev_inst = NULL;
	int prev_arg_idx;
	bool end_reached = false;
	double start, end;
	char *endptr;
	char *output = NULL;
	char *output_file;
	enum split_types split_type = SPLIT_NONE;
	enum split_types type = SPLIT_NONE;
	int instances;
	int count;
	int repeat = 0;
	int percpu = 0;
	int cpu = -1;
	int ac;
	int c;

	static struct option long_options[] = {
		{"top", optional_argument, NULL, OPT_top},
		{NULL, 0, NULL, 0},
	};
	int option_index = 0;

	prev_arg_type = PREV_IS_NONE;

	list_head_init(&handle_list);
	list_head_init(&inst_list);

	if (strcmp(argv[1], "split") != 0)
		usage(argv);

	while ((c = getopt_long(argc - 1, argv + 1, "+ho:i:s:m:u:e:p:rcC:B:b:t",
				long_options, &option_index)) >= 0) {
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'p':
			type++;
		case 'e':
			type++;
		case 'u':
			type++;
		case 'm':
			type++;
		case 's':
			type++;
			if (split_type != SPLIT_NONE)
				die("Only one type of split is allowed");
			count = atoi(optarg);
			if (count <= 0)
				die("Units must be greater than 0");
			split_type = type;

			/* Spliting by pages only makes sense per cpu */
			if (type == SPLIT_PAGES)
				percpu = 1;
			break;
		case 'r':
			repeat = 1;
			break;
		case 'c':
			percpu = 1;
			break;
		case 'C':
			cpu = atoi(optarg);
			break;
		case 'o':
			if (output)
				die("only one output file allowed");
			output = strdup(optarg);
			break;
		case 'i':
			input_file = optarg;
			break;
		case OPT_top:
			prev_arg_type = PREV_IS_TOP;
			prev_arg_idx = optind;
			prev_inst = add_inst(default_top_instance_name, true, true);
			break;
		case 'b':
			/* 1 as --top takes no argument. */
			if (prev_arg_type != PREV_IS_TOP &&
			    (prev_arg_idx != optind - 1))
				usage(argv);
			prev_arg_type = PREV_IS_NONE;

			prev_inst->is_top_instance = false;

			free(prev_inst->name);
			prev_inst->name = strdup(optarg);
			if (!prev_inst->name)
				die("Failed to duplicate %s", optarg);
			break;
		case 'B':
			prev_arg_type = PREV_IS_BUFFER;
			prev_arg_idx = optind;
			prev_inst = add_inst(optarg, false, false);
			break;
		case 't':
			/* 2 as -B takes an argument. */
			if (prev_arg_type != PREV_IS_BUFFER &&
			    (prev_arg_idx != optind - 2))
				usage(argv);
			prev_arg_type = PREV_IS_NONE;

			prev_inst->is_top_instance = true;
			break;
		default:
			usage(argv);
		}
	}

	if (!is_top_instance_unique())
		die("Can only have one top instance.");

	ac = (argc - optind);

	if (ac >= 2) {
		optind++;
		start = strtod(argv[optind], &endptr);
		if (ac > 3)
			usage(argv);

		/* Make sure a true start value was entered */
		if (*endptr != 0)
			die("Start value not floating point: %s", argv[optind]);

		start_ns = (unsigned long long)(start * 1000000000.0);
		optind++;
		if (ac == 3) {
			end = strtod(argv[optind], &endptr);

			/* Make sure a true end value was entered */
			if (*endptr != 0)
				die("End value not floating point: %s",
				    argv[optind]);

			end_ns = (unsigned long long)(end * 1000000000.0);
			if (end_ns < start_ns)
				die("Error: end is less than start");
		}
	}

	if (!input_file)
		input_file = default_input_file;

	handle = tracecmd_open(input_file, 0);
	if (!handle)
		die("error reading %s", input_file);

	if (tracecmd_get_file_state(handle) == TRACECMD_FILE_CPU_LATENCY)
		die("trace-cmd split does not work with latency traces\n");

	page_size = tracecmd_page_size(handle);

	if (!output)
		output = strdup(input_file);

	if (!repeat && strcmp(output, input_file) == 0) {
		output = realloc(output, strlen(output) + 3);
		strcat(output, ".1");
	}

	output_file = malloc(strlen(output) + 50);
	if (!output_file)
		die("Failed to allocate for %s", output);
	c = 1;

	add_handle(default_top_instance_name, -1, true);
	instances = tracecmd_buffer_instances(handle);
	if (instances) {
		const char *name;
		int i;

		for (i = 0; i < instances; i++) {
			name = tracecmd_buffer_instance_name(handle, i);
			if (!name)
				die("error in reading buffer instance");
			add_handle(name, i, false);
		}
	}

	map_inst_handle();

	do {
		if (repeat)
			sprintf(output_file, "%s.%04d", output, c++);
		else
			strcpy(output_file, output);
			
		current = parse_file(handle, output_file, start_ns, end_ns,
				     percpu, cpu, count, type, &end_reached);

		if (!repeat)
			break;
		start_ns = 0;
	} while (!end_reached && (current && (!end_ns || current < end_ns)));

	free(output);
	free(output_file);

	tracecmd_close(handle);
	free_handles(&handle_list);
	free_inst(&inst_list);

	return;
}
