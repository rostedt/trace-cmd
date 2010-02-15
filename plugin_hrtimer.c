/*
 * Copyright (C) 2009 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 * Copyright (C) 2009 Johannes Berg <johannes@sipsolutions.net>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse-events.h"

/* return -1 (field not found/not valid number), 0 (ok), 1 (buffer full) */
static int _print_field(struct trace_seq *s, const char *fmt,
			struct event_format *event, const char *name, const void *data)
{
	struct format_field *f = pevent_find_field(event, name);
	unsigned long long val;

	if (!f)
		return -1;

	if (pevent_read_number_field(f, data, &val))
		return -1;

	return trace_seq_printf(s, fmt, val);
}

/* return 0 (ok), 1 (buffer full) */
static void print_field(struct trace_seq *s, const char *fmt,
			struct event_format *event, const char *name, const void *data)
{
	int ret = _print_field(s, fmt, event, name, data);

	if (ret == -1)
		trace_seq_printf(s, "CAN'T FIND FIELD \"%s\"", name);
}

static int timer_expire_handler(struct trace_seq *s, struct record *record,
				struct event_format *event)
{
	void *data = record->data;

	trace_seq_printf(s, "hrtimer=");

	if (_print_field(s, "0x%llx", event, "timer", data) == -1)
		print_field(s, "0x%llx", event, "hrtimer", data);

	trace_seq_printf(s, " now=");

	print_field(s, "%llu", event, "now", data);

	return 0;
}

static int timer_start_handler(struct trace_seq *s, struct record *record,
			       struct event_format *event)
{
	struct pevent *pevent = event->pevent;
	struct format_field *fn = pevent_find_field(event, "function");
	void *data = record->data;

	trace_seq_printf(s, "hrtimer=");

	if (_print_field(s, "0x%llx", event, "timer", data) == -1)
		print_field(s, "0x%llx", event, "hrtimer", data);

	if (!fn) {
		trace_seq_printf(s, " function=MISSING");
	} else {
		unsigned long long function;
		const char *func;

		if (pevent_read_number_field(fn, data, &function))
			trace_seq_printf(s, " function=INVALID");

		func = pevent_find_function(pevent, function);

		trace_seq_printf(s, " function=%s", func);
	}

	trace_seq_printf(s, " expires=");
	print_field(s, "%llu", event, "expires", data);

	trace_seq_printf(s, " softexpires=");
	print_field(s, "%llu", event, "softexpires", data);

	return 0;
}

int PEVENT_PLUGIN_LOADER(struct pevent *pevent)
{
	pevent_register_event_handler(pevent, -1, "timer", "hrtimer_expire_entry",
				      timer_expire_handler);

	pevent_register_event_handler(pevent, -1, "timer", "hrtimer_start",
				      timer_start_handler);

	return 0;
}
