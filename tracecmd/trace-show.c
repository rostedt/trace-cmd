// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>

#include "tracefs.h"
#include "trace-local.h"

enum {
	OPT_cpumask			= 240,
	OPT_graph_notrace,
	OPT_graph_function,
	OPT_ftrace_pid,
	OPT_ftrace_notrace,
	OPT_ftrace_filter,
	OPT_buffer_subbuf_size_kb,
	OPT_buffer_total_size_kb,
	OPT_buffer_size_kb,
	OPT_buffer_percent,
	OPT_current_tracer,
	OPT_tracing_on,
	OPT_hist,
	OPT_trigger,
};

void trace_show(int argc, char **argv)
{
	const char *buffer = NULL;
	const char *file = "trace";
	const char *cpu = NULL;
	struct buffer_instance *instance = &top_instance;
	char *hist = NULL;
	char *trigger = NULL;
	char cpu_path[128];
	char *path;
	int snap = 0;
	int pipe = 0;
	int show_name = 0;
	int option_index = 0;
	int stop = 0;
	int c;
	static struct option long_options[] = {
		{"hist", required_argument, NULL, OPT_hist},
		{"trigger", required_argument, NULL, OPT_trigger},
		{"tracing_on", no_argument, NULL, OPT_tracing_on},
		{"current_tracer", no_argument, NULL, OPT_current_tracer},
		{"buffer_size", no_argument, NULL, OPT_buffer_size_kb},
		{"buffer_total_size", no_argument, NULL, OPT_buffer_total_size_kb},
		{"buffer_subbuf_size", no_argument, NULL, OPT_buffer_subbuf_size_kb},
		{"buffer_percent", no_argument, NULL, OPT_buffer_percent},
		{"ftrace_filter", no_argument, NULL, OPT_ftrace_filter},
		{"ftrace_notrace", no_argument, NULL, OPT_ftrace_notrace},
		{"ftrace_pid", no_argument, NULL, OPT_ftrace_pid},
		{"graph_function", no_argument, NULL, OPT_graph_function},
		{"graph_notrace", no_argument, NULL, OPT_graph_notrace},
		{"cpumask", no_argument, NULL, OPT_cpumask},
		{"help", no_argument, NULL, '?'},
		{NULL, 0, NULL, 0}
	};

	init_top_instance();

	while ((c = getopt_long(argc-1, argv+1, "B:c:fsp",
				long_options, &option_index)) >= 0) {
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'B':
			if (buffer)
				die("Can only show one buffer at a time");
			buffer = optarg;
			instance = allocate_instance(optarg);
			if (!instance)
				die("Failed to create instance");
			break;
		case 'c':
			if (cpu)
				die("Can only show one CPU at a time");
			cpu = optarg;
			break;
		case 'f':
			show_name = 1;
			break;
		case 's':
			snap = 1;
			if (pipe)
				die("Can not have -s and -p together");
			break;
		case 'p':
			pipe = 1;
			if (snap)
				die("Can not have -s and -p together");
			break;
		case OPT_hist:
			hist = optarg;
			break;
		case OPT_trigger:
			trigger = optarg;
			break;

		case OPT_tracing_on:
			show_instance_file(instance, "tracing_on");
			stop = 1;
			break;
		case OPT_current_tracer:
			show_instance_file(instance, "current_tracer");
			stop = 1;
			break;
		case OPT_buffer_size_kb:
			show_instance_file(instance, "buffer_size_kb");
			stop = 1;
			break;
		case OPT_buffer_total_size_kb:
			show_instance_file(instance, "buffer_total_size_kb");
			stop = 1;
			break;
		case OPT_buffer_subbuf_size_kb:
			show_instance_file(instance, "buffer_subbuf_size_kb");
			stop = 1;
			break;
		case OPT_buffer_percent:
			show_instance_file(instance, "buffer_percent");
			stop = 1;
			break;
		case OPT_ftrace_filter:
			show_instance_file(instance, "set_ftrace_filter");
			stop = 1;
			break;
		case OPT_ftrace_notrace:
			show_instance_file(instance, "set_ftrace_notrace");
			stop = 1;
			break;
		case OPT_ftrace_pid:
			show_instance_file(instance, "set_ftrace_pid");
			stop = 1;
			break;
		case OPT_graph_function:
			show_instance_file(instance, "set_graph_function");
			stop = 1;
			break;
		case OPT_graph_notrace:
			show_instance_file(instance, "set_graph_notrace");
			stop = 1;
			break;
		case OPT_cpumask:
			show_instance_file(instance, "tracing_cpumask");
			stop = 1;
			break;
		default:
			usage(argv);
		}
	}
	if (stop)
		exit(0);
	if (pipe)
		file = "trace_pipe";
	else if (snap)
		file = "snapshot";

	if (hist || trigger) {
		char **systems = NULL;
		char *system = NULL;
		char *event = hist ? hist : trigger;
		char *file = hist ? "hist" : "trigger";
		char *p;

		if ((p = strstr(event, ":"))) {
			system = event;
			event = p + 1;
			*p = '\0';
		}

		if (!system) {
			systems = tracefs_event_systems(NULL);

			for (int i = 0; systems && systems[i]; i++) {
				system = systems[i];
				if (tracefs_event_file_exists(instance->tracefs,
							      system, event, file))
					break;
			}
			if (!system)
				die("Could not find system of event %s",
				    event);
		}

		path = tracefs_event_file_read(instance->tracefs,
					       system, event, file, NULL);
		tracefs_list_free(systems);
		if (!path)
			die("Could not find hist for %s%s%s",
			    system ? system : "", system ? ":":"", event);
		printf("%s\n", path);
		free(path);
		exit(0);
	}

	if (cpu) {
		char *endptr;
		long val;

		errno = 0;
		val = strtol(cpu, &endptr, 0);
		if (errno || cpu == endptr)
			die("Invalid CPU index '%s'", cpu);
		snprintf(cpu_path, 128, "per_cpu/cpu%ld/%s", val, file);
		file = cpu_path;
	}

	if (buffer) {
		int ret;

		ret = asprintf(&path, "instances/%s/%s", buffer, file);
		if (ret < 0)
			die("Failed to allocate instance path %s", file);
		file = path;
	}

	if (show_name) {
		char *name;
		name = tracefs_get_tracing_file(file);
		printf("%s\n", name);
		tracefs_put_tracing_file(name);
	}
	show_file(file);
	if (buffer)
		free(path);

	return;
}
