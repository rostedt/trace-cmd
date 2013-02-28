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
#include <unistd.h>
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

static void show_file(const char *name)
{
	char buf[BUFSIZ];
	char *path;
	FILE *fp;
	ssize_t n;

	path = tracecmd_get_tracing_file(name);
	fp = fopen(path, "r");
	if (!fp)
		die("reading %s", path);
	tracecmd_put_tracing_file(path);

	do {
		n = fread(buf, 1, BUFSIZ, fp);
		if (n > 0)
			fwrite(buf, 1, n, stdout);
	} while (n > 0);
	fclose(fp);
}

static void show_file_re(const char *name, const char *re)
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
			fwrite(buf, 1, n, stdout);
	} while (n > 0);
	free(buf);
	fclose(fp);

	regfree(&reg);
}

static void show_events(void)
{
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

static void show_functions(const char *funcre)
{
	if (funcre)
		show_file_re("available_filter_functions", funcre);
	else
		show_file("available_filter_functions");
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
	tracecmd_unload_plugins(list);
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
	tracecmd_unload_plugins(list);
	pevent_free(pevent);
}

int main (int argc, char **argv)
{
	int c;

	errno = 0;

	if (argc < 2)
		usage(argv);

	if (strcmp(argv[1], "report") == 0) {
		trace_report(argc, argv);
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
		char *tracing;
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
		tracing = tracecmd_find_tracing_dir();

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
		tracecmd_unload_plugins(list);
		pevent_free(pevent);
		exit(ret);

	} else if (strcmp(argv[1], "record") == 0 ||
		   strcmp(argv[1], "start") == 0 ||
		   strcmp(argv[1], "extract") == 0 ||
		   strcmp(argv[1], "stop") == 0 ||
		   strcmp(argv[1], "reset") == 0) {
		trace_record(argc, argv);
		exit(0);

	} else if (strcmp(argv[1], "options") == 0) {
		trace_option(argc, argv);
		exit(0);
	} else if (strcmp(argv[1], "list") == 0) {
		int events = 0;
		int tracer = 0;
		int options = 0;
		int funcs = 0;
		int plug = 0;
		int plug_op = 0;
		const char *funcre = NULL;

		while ((c = getopt(argc-1, argv+1, ":heptPOof:")) >= 0) {
 next:
			switch (c) {
			case 'h':
				usage(argv);
				break;
			case 'e':
				events = 1;
				break;
			case 'p':
			case 't':
				tracer = 1;
				break;
			case 'P':
				plug = 1;
				break;
			case 'O':
				plug_op = 1;
				break;
			case 'o':
				options = 1;
				break;
			case 'f':
				funcs = 1;
				if (optarg[0] == '-') {
					c = optarg[1];
					goto next;
				}
				funcre = optarg;
				break;
			default:
				/* -f can have an optional parameter */
				if (strcmp(argv[optind], "-f") == 0) {
					funcs = 1;
					break;
				}
				fprintf(stderr, "list: invalid option -- '%c'\n",
					argv[optind][1]);
				
				usage(argv);
			}
		}

		if (events)
			show_events();

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

		if (!events && !tracer && !options && !plug && !plug_op && !funcs) {
			printf("events:\n");
			show_events();
			printf("\tracers:\n");
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

