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

void trace_check_events(int argc, char **argv)
{
	const char *tracing;
	int ret, c;
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

	return;
}
