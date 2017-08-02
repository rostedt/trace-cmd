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
 * along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>

#include "trace-local.h"

enum {
	OPT_tracing_on			= 255,
	OPT_current_tracer		= 254,
	OPT_buffer_size_kb		= 253,
	OPT_buffer_total_size_kb	= 252,
	OPT_ftrace_filter		= 251,
	OPT_ftrace_notrace		= 250,
	OPT_ftrace_pid			= 249,
	OPT_graph_function		= 248,
	OPT_graph_notrace		= 247,
	OPT_cpumask			= 246,
};

void trace_show(int argc, char **argv)
{
	const char *buffer = NULL;
	const char *file = "trace";
	const char *cpu = NULL;
	struct buffer_instance *instance = &top_instance;
	char cpu_path[128];
	char *path;
	int snap = 0;
	int pipe = 0;
	int show_name = 0;
	int option_index = 0;
	int stop = 0;
	int c;
	static struct option long_options[] = {
		{"tracing_on", no_argument, NULL, OPT_tracing_on},
		{"current_tracer", no_argument, NULL, OPT_current_tracer},
		{"buffer_size", no_argument, NULL, OPT_buffer_size_kb},
		{"buffer_total_size", no_argument, NULL, OPT_buffer_total_size_kb},
		{"ftrace_filter", no_argument, NULL, OPT_ftrace_filter},
		{"ftrace_notrace", no_argument, NULL, OPT_ftrace_notrace},
		{"ftrace_pid", no_argument, NULL, OPT_ftrace_pid},
		{"graph_function", no_argument, NULL, OPT_graph_function},
		{"graph_notrace", no_argument, NULL, OPT_graph_notrace},
		{"cpumask", no_argument, NULL, OPT_cpumask},
		{"help", no_argument, NULL, '?'},
		{NULL, 0, NULL, 0}
	};

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
			instance = create_instance(optarg);
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

	if (cpu) {
		snprintf(cpu_path, 128, "per_cpu/cpu%d/%s", atoi(cpu), file);
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
		name = tracecmd_get_tracing_file(file);
		printf("%s\n", name);
		tracecmd_put_tracing_file(name);
	}
	show_file(file);
	if (buffer)
		free(path);

	return;
}
