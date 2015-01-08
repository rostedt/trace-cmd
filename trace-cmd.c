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
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#include "trace-local.h"

int silence_warnings;
int show_status;

void warning(const char *fmt, ...)
{
	va_list ap;

	if (silence_warnings)
		return;

	if (errno)
		perror("trace-cmd");
	errno = 0;

	va_start(ap, fmt);
	fprintf(stderr, "  ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");
}

void pr_stat(const char *fmt, ...)
{
	va_list ap;

	if (!show_status)
		return;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	printf("\n");
}

void *malloc_or_die(unsigned int size)
{
	void *data;

	data = malloc(size);
	if (!data)
		die("malloc");
	return data;
}

static void dump_file_content(const char *path)
{
	char buf[BUFSIZ];
	ssize_t n;
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp)
		die("reading %s", path);

	do {
		n = fread(buf, 1, BUFSIZ, fp);
		if (n > 0)
			fwrite(buf, 1, n, stdout);
	} while (n > 0);
	fclose(fp);
}

void show_file(const char *name)
{
	char *path;

	path = tracecmd_get_tracing_file(name);
	dump_file_content(path);
	tracecmd_put_tracing_file(path);
}

typedef int (*process_file_func)(char *buf, int len);

static void process_file_re(process_file_func func,
			    const char *name, const char *re)
{
	regex_t reg;
	char *path;
	char *buf = NULL;
	char *str;
	FILE *fp;
	ssize_t n;
	size_t l = strlen(re);

	/* Just in case :-p */
	if (!re || l == 0) {
		show_file(name);
		return;
	}

	/* Handle the newline at end of names for the user */
	str = malloc_or_die(l + 3);
	strcpy(str, re);
	if (re[l-1] == '$')
		strcpy(&str[l-1], "\n*$");
		
	if (regcomp(&reg, str, REG_ICASE|REG_NOSUB))
		die("invalid function regex '%s'", re);

	free(str);

	path = tracecmd_get_tracing_file(name);
	fp = fopen(path, "r");
	if (!fp)
		die("reading %s", path);
	tracecmd_put_tracing_file(path);

	do {
		n = getline(&buf, &l, fp);
		if (n > 0 && regexec(&reg, buf, 0, NULL, 0) == 0)
			func(buf, n);
	} while (n > 0);
	free(buf);
	fclose(fp);

	regfree(&reg);
}

static int show_file_write(char *buf, int len)
{
	return fwrite(buf, 1, len, stdout);
}

static void show_file_re(const char *name, const char *re)
{
	process_file_re(show_file_write, name, re);
}

static char *get_event_file(const char *type, char *buf, int len)
{
	char *system;
	char *event;
	char *path;
	char *file;

	if (buf[len-1] == '\n')
		buf[len-1] = '\0';

	system = strtok(buf, ":");
	if (!system)
		die("no system found in %s", buf);

	event = strtok(NULL, ":");
	if (!event)
		die("no event found in %s\n", buf);

	path = tracecmd_get_tracing_file("events");
	file = malloc_or_die(strlen(path) + strlen(system) + strlen(event) +
			     strlen(type) + strlen("///") + 1);
	sprintf(file, "%s/%s/%s/%s", path, system, event, type);
	tracecmd_put_tracing_file(path);

	return file;
}

static int event_filter_write(char *buf, int len)
{
	char *file;

	if (buf[len-1] == '\n')
		buf[len-1] = '\0';

	printf("%s\n", buf);

	file = get_event_file("filter", buf, len);
	dump_file_content(file);
	free(file);
	printf("\n");

	return 0;
}

static int event_trigger_write(char *buf, int len)
{
	char *file;

	if (buf[len-1] == '\n')
		buf[len-1] = '\0';

	printf("%s\n", buf);

	file = get_event_file("trigger", buf, len);
	dump_file_content(file);
	free(file);
	printf("\n");

	return 0;
}

static int event_format_write(char *fbuf, int len)
{
	char *file = get_event_file("format", fbuf, len);
	char *buf = NULL;
	size_t l;
	FILE *fp;
	int n;

	/* The get_event_file() crops system in fbuf */
	printf("system: %s\n", fbuf);

	/* Don't print the print fmt, it's ugly */

	fp = fopen(file, "r");
	if (!fp)
		die("reading %s", file);

	do {
		n = getline(&buf, &l, fp);
		if (n > 0) {
			if (strncmp(buf, "print fmt", 9) == 0)
				break;
			fwrite(buf, 1, n, stdout);
		}
	} while (n > 0);
	fclose(fp);
	free(buf);
	free(file);

	return 0;
}

static void show_event_filter_re(const char *re)
{
	process_file_re(event_filter_write, "available_events", re);
}

static void show_event_trigger_re(const char *re)
{
	process_file_re(event_trigger_write, "available_events", re);
}

static void show_event_format_re(const char *re)
{
	process_file_re(event_format_write, "available_events", re);
}

void show_instance_file(struct buffer_instance *instance, const char *name)
{
	char *path;

	path = get_instance_file(instance, name);
	dump_file_content(path);
	tracecmd_put_tracing_file(path);
}

enum {
	SHOW_EVENT_FORMAT		= 1 << 0,
	SHOW_EVENT_FILTER		= 1 << 1,
	SHOW_EVENT_TRIGGER		= 1 << 2,
};

static void show_events(const char *eventre, int flags)
{
	if (flags && !eventre)
		die("When specifying event files, an event must be named");

	if (eventre) {
		if (flags & SHOW_EVENT_FORMAT)
			show_event_format_re(eventre);

		else if (flags & SHOW_EVENT_FILTER)
			show_event_filter_re(eventre);

		else if (flags & SHOW_EVENT_TRIGGER)
			show_event_trigger_re(eventre);
		else
			show_file_re("available_events", eventre);
	} else
		show_file("available_events");
}

static void show_tracers(void)
{
	show_file("available_tracers");
}

static void show_options(void)
{
	show_file("trace_options");
}

static void show_clocks(void)
{
	show_file("trace_clock");
}

static void show_functions(const char *funcre)
{
	if (funcre)
		show_file_re("available_filter_functions", funcre);
	else
		show_file("available_filter_functions");
}

static void show_buffers(void)
{
	struct dirent *dent;
	DIR *dir;
	char *path;
	int printed = 0;

	path = tracecmd_get_tracing_file("instances");
	dir = opendir(path);
	tracecmd_put_tracing_file(path);
	if (!dir)
		die("Can not read instance directory");

	while ((dent = readdir(dir))) {
		const char *name = dent->d_name;

		if (strcmp(name, ".") == 0 ||
		    strcmp(name, "..") == 0)
			continue;

		printf("%s\n", name);
		printed = 1;
	}
	closedir(dir);

	if (!printed)
		printf("No buffer instances defined\n");
}

static void show_plugins(void)
{
	struct pevent *pevent;
	struct plugin_list *list;
	struct trace_seq s;

	pevent = pevent_alloc();
	if (!pevent)
		die("Can not allocate pevent\n");

	trace_seq_init(&s);

	list = tracecmd_load_plugins(pevent);
	trace_util_print_plugins(&s, "  ", "\n", list);
	trace_seq_do_printf(&s);
	tracecmd_unload_plugins(list, pevent);
	pevent_free(pevent);
}

static void show_plugin_options(void)
{
	struct pevent *pevent;
	struct plugin_list *list;
	struct trace_seq s;

	tracecmd_ftrace_load_options();

	pevent = pevent_alloc();
	if (!pevent)
		die("Can not allocate pevent\n");

	trace_seq_init(&s);

	list = tracecmd_load_plugins(pevent);
	trace_util_print_plugin_options(&s);
	trace_seq_do_printf(&s);
	tracecmd_unload_plugins(list, pevent);
	pevent_free(pevent);
}

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

int main (int argc, char **argv)
{
	int c;

	errno = 0;

	if (argc < 2)
		usage(argv);

	if (strcmp(argv[1], "report") == 0) {
		trace_report(argc, argv);
		exit(0);
	} else if (strcmp(argv[1], "snapshot") == 0) {
		trace_snapshot(argc, argv);
		exit(0);
	} else if (strcmp(argv[1], "hist") == 0) {
		trace_hist(argc, argv);
		exit(0);
	} else if (strcmp(argv[1], "mem") == 0) {
		trace_mem(argc, argv);
		exit(0);
	} else if (strcmp(argv[1], "listen") == 0) {
		trace_listen(argc, argv);
		exit(0);
	} else if (strcmp(argv[1], "split") == 0) {
		trace_split(argc, argv);
		exit(0);
	} else if (strcmp(argv[1], "restore") == 0) {
		trace_restore(argc, argv);
		exit(0);
	} else if (strcmp(argv[1], "stack") == 0) {
		trace_stack(argc, argv);
		exit(0);
	} else if (strcmp(argv[1], "check-events") == 0) {
		const char *tracing;
		int ret;
		struct pevent *pevent = NULL;
		struct plugin_list *list = NULL;

		while ((c = getopt(argc-1, argv+1, "+hN")) >= 0) {
			switch (c) {
			case 'h':
			default:
				usage(argv);
				break;
			case 'N':
				tracecmd_disable_plugins = 1;
				break;
			}
		}
		tracing = tracecmd_get_tracing_dir();

		if (!tracing) {
			printf("Can not find or mount tracing directory!\n"
				"Either tracing is not configured for this "
				"kernel\n"
				"or you do not have the proper permissions to "
				"mount the directory");
			exit(EINVAL);
		}

		pevent = pevent_alloc();
		if (!pevent)
			exit(EINVAL);
		list = tracecmd_load_plugins(pevent);
		ret = tracecmd_fill_local_events(tracing, pevent);
		if (ret || pevent->parsing_failures)
			ret = EINVAL;
		tracecmd_unload_plugins(list, pevent);
		pevent_free(pevent);
		exit(ret);

	} else if (strcmp(argv[1], "record") == 0 ||
		   strcmp(argv[1], "start") == 0 ||
		   strcmp(argv[1], "extract") == 0 ||
		   strcmp(argv[1], "stop") == 0 ||
		   strcmp(argv[1], "stream") == 0 ||
		   strcmp(argv[1], "profile") == 0 ||
		   strcmp(argv[1], "restart") == 0 ||
		   strcmp(argv[1], "reset") == 0) {
		trace_record(argc, argv);
		exit(0);

	} else if (strcmp(argv[1], "stat") == 0) {
		trace_stat(argc, argv);
		exit(0);

	} else if (strcmp(argv[1], "options") == 0) {
		show_plugin_options();
		exit(0);
	} else if (strcmp(argv[1], "show") == 0) {
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
			path = malloc_or_die(strlen(buffer) + strlen("instances//") +
					     strlen(file) + 1);
			sprintf(path, "instances/%s/%s", buffer, file);
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

		exit(0);
	} else if (strcmp(argv[1], "list") == 0) {
		int events = 0;
		int tracer = 0;
		int options = 0;
		int funcs = 0;
		int buffers = 0;
		int clocks = 0;
		int plug = 0;
		int plug_op = 0;
		int flags = 0;
		int show_all = 1;
		int i;
		const char *arg;
		const char *funcre = NULL;
		const char *eventre = NULL;

		for (i = 2; i < argc; i++) {
			arg = NULL;
			if (argv[i][0] == '-') {
				if (i < argc - 1) {
					if (argv[i+1][0] != '-')
						arg = argv[i+1];
				}
				switch (argv[i][1]) {
				case 'h':
					usage(argv);
					break;
				case 'e':
					events = 1;
					eventre = arg;
					show_all = 0;
					break;
				case 'B':
					buffers = 1;
					show_all = 0;
					break;
				case 'C':
					clocks = 1;
					show_all = 0;
					break;
				case 'F':
					flags |= SHOW_EVENT_FORMAT;
					break;
				case 'R':
					flags |= SHOW_EVENT_TRIGGER;
					break;
				case 'l':
					flags |= SHOW_EVENT_FILTER;
					break;
				case 'p':
				case 't':
					tracer = 1;
					show_all = 0;
					break;
				case 'P':
					plug = 1;
					show_all = 0;
					break;
				case 'O':
					plug_op = 1;
					show_all = 0;
					break;
				case 'o':
					options = 1;
					show_all = 0;
					break;
				case 'f':
					funcs = 1;
					funcre = arg;
					show_all = 0;
					break;
				default:
					fprintf(stderr, "list: invalid option -- '%c'\n",
						argv[optind][1]);
					usage(argv);
				}
			}
		}

		if (events)
			show_events(eventre, flags);

		if (tracer)
			show_tracers();

		if (options)
			show_options();

		if (plug)
			show_plugins();

		if (plug_op)
			show_plugin_options();

		if (funcs)
			show_functions(funcre);

		if (buffers)
			show_buffers();

		if (clocks)
			show_clocks();

		if (show_all) {
			printf("events:\n");
			show_events(NULL, 0);
			printf("\ntracers:\n");
			show_tracers();
			printf("\noptions:\n");
			show_options();
		}

		exit(0);

	} else if (strcmp(argv[1], "-h") == 0 ||
		   strcmp(argv[1], "help") == 0) {
		usage(argv);
	} else {
		fprintf(stderr, "unknown command: %s\n", argv[1]);
		usage(argv);
	}

	return 0;
}

