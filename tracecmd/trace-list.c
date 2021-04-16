// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */

#include <stdlib.h>
#include <sys/stat.h>

#include "tracefs.h"
#include "trace-local.h"


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



void show_instance_file(struct buffer_instance *instance, const char *name)
{
	char *path;

	path = tracefs_instance_get_file(instance->tracefs, name);
	dump_file_content(path);
	tracefs_put_tracing_file(path);
}

enum {
	SHOW_EVENT_FORMAT		= 1 << 0,
	SHOW_EVENT_FILTER		= 1 << 1,
	SHOW_EVENT_TRIGGER		= 1 << 2,
	SHOW_EVENT_FULL			= 1 << 3,
};


void show_file(const char *name)
{
	char *path;

	path = tracefs_get_tracing_file(name);
	dump_file_content(path);
	tracefs_put_tracing_file(path);
}

typedef int (*process_file_func)(char *buf, int len, int flags);

static void process_file_re(process_file_func func,
			    const char *name, const char *re, int flags)
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
	str = malloc(l + 3);
	if (!str)
		die("Failed to allocate reg ex %s", re);
	strcpy(str, re);
	if (re[l-1] == '$')
		strcpy(&str[l-1], "\n*$");

	if (regcomp(&reg, str, REG_ICASE|REG_NOSUB))
		die("invalid function regex '%s'", re);

	free(str);

	path = tracefs_get_tracing_file(name);
	fp = fopen(path, "r");
	if (!fp)
		die("reading %s", path);
	tracefs_put_tracing_file(path);

	do {
		n = getline(&buf, &l, fp);
		if (n > 0 && regexec(&reg, buf, 0, NULL, 0) == 0)
			func(buf, n, flags);
	} while (n > 0);
	free(buf);
	fclose(fp);

	regfree(&reg);
}

static void show_event(process_file_func func, const char *system,
		       const char *event, int flags)
{
	char *buf;
	int ret;

	ret = asprintf(&buf, "%s:%s", system, event);
	if (ret < 0)
		die("Can not allocate event");
	func(buf, strlen(buf), flags);
	free(buf);
}

static void show_system(process_file_func func, const char *system, int flags)
{
	char **events;
	int e;

	events = tracefs_system_events(NULL, system);
	if (!events) /* die? */
		return;

	for (e = 0; events[e]; e++)
		show_event(func, system, events[e], flags);
}

static void show_event_systems(process_file_func func, char **systems, int flags)
{
	int s;

	for (s = 0; systems[s]; s++)
		show_system(func, systems[s], flags);
}

static void match_system_events(process_file_func func, const char *system,
				regex_t *reg, int flags)
{
	char **events;
	int e;

	events = tracefs_system_events(NULL, system);
	if (!events) /* die? */
		return;
	for (e = 0; events[e]; e++) {
		if (regexec(reg, events[e], 0, NULL, 0) == 0)
			show_event(func, system, events[e], flags);
	}
	tracefs_list_free(events);
}

static void process_events(process_file_func func, const char *re, int flags)
{
	const char *ftrace = "ftrace";
	regex_t system_reg;
	regex_t event_reg;
	char *str;
	size_t l = strlen(re);
	bool just_systems = true;
	char **systems;
	char *system;
	char *event;
	int s;

	systems = tracefs_event_systems(NULL);
	if (!systems)
		return process_file_re(func, "available_events", re, flags);

	if (!re || l == 0) {
		show_event_systems(func, systems, flags);
		return;
	}

	str = strdup(re);
	if (!str)
		die("Can not allocate momory for regex");

	system = strtok(str, ":");
	event = strtok(NULL, "");

	if (regcomp(&system_reg, system, REG_ICASE|REG_NOSUB))
		die("invalid regex '%s'", system);

	if (event) {
		if (regcomp(&event_reg, event, REG_ICASE|REG_NOSUB))
			die("invalid regex '%s'", event);
	} else {
		/*
		 * If the regex ends with ":", then event would be null,
		 * but we do not want to match events.
		 */
		if (re[l-1] != ':')
			just_systems = false;
	}
	free(str);

	/*
	 * See if this matches the special ftrace system, as ftrace is not included
	 * in the systems list, but can get events from tracefs_system_events().
	 */
	if (regexec(&system_reg, ftrace, 0, NULL, 0) == 0) {
		if (!event)
			show_system(func, ftrace, flags);
		else
			match_system_events(func, ftrace, &event_reg, flags);
	} else if (!just_systems) {
		match_system_events(func, ftrace, &system_reg, flags);
	}

	for (s = 0; systems[s]; s++) {

		if (regexec(&system_reg, systems[s], 0, NULL, 0) == 0) {
			if (!event) {
				show_system(func, systems[s], flags);
				continue;
			}
			match_system_events(func, systems[s], &event_reg, flags);
			continue;
		}
		if (just_systems)
			continue;

		match_system_events(func, systems[s], &system_reg, flags);
	}
	tracefs_list_free(systems);

	regfree(&system_reg);
	if (event)
		regfree(&event_reg);
}

static int show_file_write(char *buf, int len, int flags)
{
	return fwrite(buf, 1, len, stdout);
}

static void show_file_re(const char *name, const char *re)
{
	process_file_re(show_file_write, name, re, 0);
}

static char *get_event_file(const char *type, char *buf, int len)
{
	char *system;
	char *event;
	char *path;
	char *file;
	int ret;

	if (buf[len-1] == '\n')
		buf[len-1] = '\0';

	system = strtok(buf, ":");
	if (!system)
		die("no system found in %s", buf);

	event = strtok(NULL, ":");
	if (!event)
		die("no event found in %s\n", buf);

	path = tracefs_get_tracing_file("events");
	ret = asprintf(&file, "%s/%s/%s/%s", path, system, event, type);
	if (ret < 0)
		die("Failed to allocate event file %s %s", system, event);

	tracefs_put_tracing_file(path);

	return file;
}

static int event_filter_write(char *buf, int len, int flags)
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

static int event_trigger_write(char *buf, int len, int flags)
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

static int event_format_write(char *fbuf, int len, int flags)
{
	char *file = get_event_file("format", fbuf, len);
	char *buf = NULL;
	size_t l;
	FILE *fp;
	bool full;
	int n;

	full = flags & SHOW_EVENT_FULL;

	/* The get_event_file() crops system in fbuf */
	printf("system: %s\n", fbuf);

	/* Don't print the print fmt, it's ugly */

	fp = fopen(file, "r");
	if (!fp)
		die("reading %s", file);

	do {
		n = getline(&buf, &l, fp);
		if (n > 0) {
			if (!full && strncmp(buf, "print fmt", 9) == 0)
				break;
			fwrite(buf, 1, n, stdout);
		}
	} while (n > 0);
	fclose(fp);
	free(buf);
	free(file);

	return 0;
}

static int event_name(char *buf, int len, int flags)
{
	printf("%s\n", buf);

	return 0;
}

static void show_event_filter_re(const char *re)
{
	process_events(event_filter_write, re, 0);
}


static void show_event_trigger_re(const char *re)
{
	process_events(event_trigger_write, re, 0);
}


static void show_event_format_re(const char *re, int flags)
{
	process_events(event_format_write, re, flags);
}

static void show_event_names_re(const char *re)
{
	process_events(event_name, re, 0);
}

static void show_events(const char *eventre, int flags)
{
	if (flags && !eventre)
		die("When specifying event files, an event must be named");

	if (eventre) {
		if (flags & SHOW_EVENT_FORMAT)
			show_event_format_re(eventre, flags);

		else if (flags & SHOW_EVENT_FILTER)
			show_event_filter_re(eventre);

		else if (flags & SHOW_EVENT_TRIGGER)
			show_event_trigger_re(eventre);
		else
			show_event_names_re(eventre);
	} else
		show_file("available_events");
}


static void show_tracers(void)
{
	show_file("available_tracers");
}

void show_options(const char *prefix, struct buffer_instance *buffer)
{
	struct tracefs_instance *instance = buffer ? buffer->tracefs : NULL;
	struct dirent *dent;
	struct stat st;
	char *path;
	DIR *dir;

	if (!prefix)
		prefix = "";

	path = tracefs_instance_get_file(instance, "options");
	if (!path)
		goto show_file;
	if (stat(path, &st) < 0)
		goto show_file;

	if ((st.st_mode & S_IFMT) != S_IFDIR)
		goto show_file;

	dir = opendir(path);
	if (!dir)
		die("Can not read instance directory");

	while ((dent = readdir(dir))) {
		const char *name = dent->d_name;
		long long val;
		char *file;
		int ret;

		if (strcmp(name, ".") == 0 ||
		    strcmp(name, "..") == 0)
			continue;

		ret = asprintf(&file, "options/%s", name);
		if (ret < 0)
			die("Failed to allocate file name");
		ret = tracefs_instance_file_read_number(instance, file, &val);
		if (!ret) {
			if (val)
				printf("%s%s\n", prefix, name);
			else
				printf("%sno%s\n", prefix, name);
		}
		free(file);
	}
	closedir(dir);
	tracefs_put_tracing_file(path);
	return;

 show_file:
	tracefs_put_tracing_file(path);
	show_file("trace_options");
}

static void show_clocks(void)
{
	char *clocks;
	int size;

	clocks = tracefs_instance_file_read(NULL, "trace_clock", &size);
	if (!clocks)
		die("getting clocks");
	if (clocks[size - 1] == '\n')
		clocks[size - 1] = 0;

	if (trace_tsc2nsec_is_supported())
		printf("%s %s\n", clocks, TSCNSEC_CLOCK);
	else
		printf("%s\n", clocks);

	free(clocks);
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

	path = tracefs_get_tracing_file("instances");
	dir = opendir(path);
	tracefs_put_tracing_file(path);
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


static void show_systems(void)
{
	struct dirent *dent;
	char *path;
	DIR *dir;

	path = tracefs_get_tracing_file("events");
	dir = opendir(path);

	if (!dir)
		die("Can not read events directory");

	while ((dent = readdir(dir))) {
		const char *name = dent->d_name;
		struct stat st;
		char *spath;
		int ret;

		if (strcmp(name, ".") == 0 ||
		    strcmp(name, "..") == 0)
			continue;

		if (asprintf(&spath, "%s/%s", path, name) < 0)
			continue;
		ret = stat(spath, &st);
		if (!ret && S_ISDIR(st.st_mode))
			printf("%s\n", name);

		free(spath);
	}

	printf("\n");
	closedir(dir);
	tracefs_put_tracing_file(path);
}

static void show_plugin_options(void)
{
	struct tep_handle *pevent;
	struct tep_plugin_list *list;
	struct trace_seq s;

	tracecmd_ftrace_load_options();

	pevent = tep_alloc();
	if (!pevent)
		die("Can not allocate pevent\n");

	trace_seq_init(&s);

	list = trace_load_plugins(pevent, 0);
	tep_plugin_print_options(&s);
	trace_seq_do_printf(&s);
	tep_unload_plugins(list, pevent);
	tep_free(pevent);
}


void trace_option(int argc, char **argv)
{
	show_plugin_options();
}


static void show_plugins(void)
{
	struct tep_handle *pevent;
	struct tep_plugin_list *list;
	struct trace_seq s;

	pevent = tep_alloc();
	if (!pevent)
		die("Can not allocate pevent\n");

	trace_seq_init(&s);

	list = trace_load_plugins(pevent, 0);
	tep_print_plugins(&s, "  ", "\n", list);

	trace_seq_do_printf(&s);
	tep_unload_plugins(list, pevent);
	tep_free(pevent);
}

static void show_compression(void)
{
	char **versions, **names;
	int c, i;

	c = tracecmd_compress_protos_get(&names, &versions);
	if (c <= 0) {
		printf("No compression algorithms are supported\n");
		return;
	}
	printf("Supported compression algorithms:\n");
	for (i = 0; i < c; i++)
		printf("\t%s, %s\n", names[i], versions[i]);

	free(names);
	free(versions);
}

void trace_list(int argc, char **argv)
{
	int events = 0;
	int tracer = 0;
	int options = 0;
	int funcs = 0;
	int buffers = 0;
	int clocks = 0;
	int plug = 0;
	int plug_op = 0;
	int flags = 0;
	int systems = 0;
	int show_all = 1;
	int compression = 0;
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
			case 's':
				systems = 1;
				show_all = 0;
				break;
			case 'c':
				compression = 1;
				show_all = 0;
				break;
			case '-':
				if (strcmp(argv[i], "--debug") == 0) {
					tracecmd_set_debug(true);
					break;
				}
				if (strcmp(argv[i], "--full") == 0) {
					flags |= SHOW_EVENT_FULL;
					break;
				}
				fprintf(stderr, "list: invalid option -- '%s'\n",
					argv[i]);
			default:
				fprintf(stderr, "list: invalid option -- '%c'\n",
					argv[i][1]);
				usage(argv);
			}
		}
	}

	if (events)
		show_events(eventre, flags);

	if (tracer)
		show_tracers();

	if (options)
		show_options(NULL, NULL);

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
	if (systems)
		show_systems();
	if (compression)
		show_compression();
	if (show_all) {
		printf("event systems:\n");
		show_systems();
		printf("events:\n");
		show_events(NULL, 0);
		printf("\ntracers:\n");
		show_tracers();
		printf("\noptions:\n");
		show_options(NULL, NULL);
		show_compression();
	}

	return;

}
