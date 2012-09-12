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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "trace-local.h"

enum {
	OPT_kallsyms	= 253,
	OPT_events	= 254,
	OPT_cpu		= 255,
};

struct option_list {
	struct option_list	*next;
	struct plugin_option	*op;
};

static struct plugin_list {
	struct plugin_list	*next;
	const char		*name;
	struct option_list	*ops;
} *plugin_list;

static void add_option(struct plugin_option *option)
{
	struct plugin_list *pl;
	struct option_list *po;
	const char *name;

	name = option->plugin_alias ? : option->file;

	for (pl = plugin_list; pl; pl = pl->next) {
		if (strcmp(name, pl->name) == 0)
			break;
	}
	if (!pl) {
		pl = malloc_or_die(sizeof(*pl));
		memset(pl, 0, sizeof(*pl));
		pl->name = name;
		pl->next = plugin_list;
		plugin_list = pl;
	};
	po = malloc_or_die(sizeof(*po));
	po->next = pl->ops;
	pl->ops = po;
	po->op = option;
}

void trace_option (int argc, char **argv)
{
	struct plugin_option *options;
	struct plugin_option *op;
	struct plugin_list *pl;
	struct plugin_list *npl;
	struct option_list *po;
	struct option_list *npo;

	if (argc < 2)
		usage(argv);

	if (strcmp(argv[1], "options") != 0)
		usage(argv);

	options = trace_util_read_plugin_options();
	if (!options) {
		printf("No plugin options found\n");
		goto out;
	}

	/* Group them up according to aliases */
	for (op = options; op; op = op->next)
		add_option(op);

	for (pl = plugin_list; pl; pl = npl) {
		npl = pl->next;
		printf("%s\n", pl->name);
		for (po = pl->ops; po; po = npo) {
			npo = po->next;
			printf("  %s: %s\n",
			       po->op->name, po->op->description);
			free(po);
		}
		free(pl);
	}

 out:
	trace_util_free_options(options);
	return;
}
