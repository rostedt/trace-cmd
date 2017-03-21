/*
 * Copyright (C) 2013 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "trace-local.h"

static void write_file(const char *name, char *val)
{
	char *path;
	int fd;
	ssize_t n;

	path = tracecmd_get_tracing_file(name);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		die("writing %s", path);

	n = write(fd, val, strlen(val));
	if (n < 0)
		die("failed to write to %s\n", path);

	tracecmd_put_tracing_file(path);
	close(fd);
}

void trace_snapshot (int argc, char **argv)
{
	const char *buffer = NULL;
	const char *file = "snapshot";
	struct stat st;
	char *name;
	char cpu_path[128];
	int take_snap = 0;
	int reset_snap = 0;
	int free_snap = 0;
	int cpu = -1;
	int ret;
	int c;

	if (argc < 2)
		usage(argv);

	if (strcmp(argv[1], "snapshot") != 0)
		usage(argv);

	while ((c = getopt(argc-1, argv+1, "srfB:c:")) >= 0) {
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 's':
			take_snap = 1;
			if (free_snap)
				die("can't take snapshot and free it at the same time");
			break;
		case 'f':
			free_snap = 1;
			if (take_snap)
				die("can't take snapshot and free it at the same time");
			break;
		case 'r':
			reset_snap = 1;
			break;
		case 'B':
			if (buffer)
				die("Can only do one buffer at a time");
			buffer = optarg;
			break;
		case 'c':
			if (cpu >= 0)
				die("Can only do one CPU (or all) at a time");
			cpu = atoi(optarg);
			break;
		default:
			usage(argv);
		}
	}

	if (cpu >= 0) {
		snprintf(cpu_path, 128, "per_cpu/cpu%d/%s", cpu, file);
		file = cpu_path;
	}

	name = tracecmd_get_tracing_file(file);
	ret = stat(name, &st);
	if (ret < 0)
		die("Snapshot feature is not supported by this kernel");
	tracecmd_put_tracing_file(name);

	if (!reset_snap && !take_snap && !free_snap) {
		show_file(file);
		exit(0);
	}

	if (reset_snap)
		write_file(file, "2");

	if (free_snap)
		write_file(file, "0");

	if (take_snap)
		write_file(file, "1");
}
