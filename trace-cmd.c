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


int main (int argc, char **argv)
{
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
		trace_check_events(argc, argv);
		exit(0);
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
		trace_show(argc, argv);
		exit(0);
	} else if (strcmp(argv[1], "list") == 0) {
		trace_list(argc, argv);
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

