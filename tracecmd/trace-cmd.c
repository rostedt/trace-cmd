// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2008, 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>

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

void *malloc_or_die(unsigned int size)
{
	void *data;

	data = malloc(size);
	if (!data)
		die("malloc");
	return data;
}

static struct trace_log_severity {
	int		id;
	const char	*name;
} log_severity[] = {
	{ .id = TEP_LOG_NONE, .name = "none" },
	{ .id = TEP_LOG_CRITICAL, .name = "crit" },
	{ .id = TEP_LOG_ERROR, .name = "err" },
	{ .id = TEP_LOG_WARNING, .name = "warn" },
	{ .id = TEP_LOG_INFO, .name = "info" },
	{ .id = TEP_LOG_DEBUG, .name = "debug" },
	{ .id = TEP_LOG_ALL, .name = "all" },
};

int trace_set_verbose(char *level)
{
	int id;

	/* Default level is info */
	if (!level)
		level = "info";

	if (isdigit(level[0])) {
		id = atoi(level);
		if (id >= TEP_LOG_NONE) {
			if (id > TEP_LOG_ALL)
				id = TEP_LOG_ALL;
			tracecmd_set_loglevel(id);
			return 0;
		}
	} else {
		int size = ARRAY_SIZE(log_severity);
		int i;

		for (i = 0; i < size; i++) {
			if (!strncmp(level, log_severity[i].name, strlen(log_severity[i].name))) {
				tracecmd_set_loglevel(log_severity[i].id);
				return 0;
			}
		}
	}

	return -1;
}

/**
 * struct command
 * @name command name
 * @run function to execute on command `name`
 */
struct command {
	char *name;
	void (*run)(int argc, char **argv);
};


/**
 * Lookup table that maps command names to functions
 */
struct command commands[] = {
	{"report", trace_report},
	{"snapshot", trace_snapshot},
	{"hist", trace_hist},
	{"mem", trace_mem},
	{"listen", trace_listen},
#ifdef VSOCK
	{"agent", trace_agent},
	{"setup-guest", trace_setup_guest},
#endif
	{"split", trace_split},
	{"restore", trace_restore},
	{"stack", trace_stack},
	{"check-events", trace_check_events},
	{"record", trace_record},
	{"start", trace_start},
	{"set", trace_set},
	{"extract", trace_extract},
	{"stop", trace_stop},
	{"stream", trace_stream},
	{"profile", trace_profile},
	{"restart", trace_restart},
	{"clear", trace_clear},
	{"reset", trace_reset},
	{"stat", trace_stat},
	{"options", trace_option},
	{"show", trace_show},
	{"list", trace_list},
	{"help", trace_usage},
	{"dump", trace_dump},
	{"convert", trace_convert},
	{"-h", trace_usage},
};

int main (int argc, char **argv)
{
	int i;

	errno = 0;

	if (argc < 2)
		trace_usage(argc, argv);

	for (i = 0; i < ARRAY_SIZE(commands); ++i) {
		if (strcmp(argv[1], commands[i].name) == 0 ){
			commands[i].run(argc, argv);
			goto out;
		}
	}

	/* No valid command found, show help */
	trace_usage(argc, argv);
out:
	exit(0);
}
