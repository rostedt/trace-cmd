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
	OPT_verbose	= 255,
};

void trace_check_events(int argc, char **argv)
{
	const char *tracing;
	int ret, c;
	int parsing_failures = 0;
	struct tep_handle *pevent = NULL;
	struct tep_plugin_list *list = NULL;
	int open_flags = 0;
	int option_index = 0;
	static struct option long_options[] = {
		{"verbose", optional_argument, NULL, OPT_verbose},
		{NULL, 0, NULL, 0}
	};


	while ((c = getopt_long(argc-1, argv+1, "+hN", long_options, &option_index)) >= 0) {
		switch (c) {
		case 'h':
		default:
			usage(argv);
			break;
		case 'N':
			open_flags |= TRACECMD_FL_LOAD_NO_PLUGINS;
			break;
		case OPT_verbose:
			if (trace_set_verbose(optarg) < 0)
				die("invalid verbose level %s", optarg);
			break;
		}
	}
	tracing = tracefs_tracing_dir();

	if (!tracing) {
		printf("Can not find or mount tracing directory!\n"
		       "Either tracing is not configured for this "
		       "kernel\n"
		       "or you do not have the proper permissions to "
		       "mount the directory");
		exit(EINVAL);
	}

	pevent = tep_alloc();
	if (!pevent)
		exit(EINVAL);

	list = trace_load_plugins(pevent, open_flags);
	ret = tracefs_fill_local_events(tracing, pevent, &parsing_failures);
	if (ret || parsing_failures)
		ret = EINVAL;
	tep_unload_plugins(list, pevent);
	tep_free(pevent);

	return;
}
