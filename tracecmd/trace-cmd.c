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
#include <stdlib.h>

#include "trace-local.h"

int silence_warnings;
int show_status;

int debug;
int quiet;

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
	{"split", trace_split},
	{"restore", trace_restore},
	{"stack", trace_stack},
	{"check-events", trace_check_events},
	{"record", trace_record},
	{"start", trace_start},
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
