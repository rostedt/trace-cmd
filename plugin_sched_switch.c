/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
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

#include "trace-cmd.h"

static void write_state(struct trace_seq *s, int val)
{
	const char states[] = "SDTtZXxW";
	int found = 0;
	int i;

	for (i=0; i < (sizeof(states) - 1); i++) {
		if (!(val & (1 << i)))
			continue;

		if (found)
			trace_seq_putc(s, '|');

		found = 1;
		trace_seq_putc(s, states[i]);
	}

	if (!found)
		trace_seq_putc(s, 'R');
}

static int sched_wakeup_handler(struct trace_seq *s, struct record *record,
				struct event_format *event, void *context)
{
	struct format_field *field;
	unsigned long long val;

	if (pevent_get_common_field_val(s, event, "common_pid", record, &val, 1))
		return trace_seq_putc(s, '!');

	trace_seq_printf(s, "%lld:", val);

	if (pevent_get_field_val(s, event, "prev_prio", record, &val, 0))
		trace_seq_puts(s, "?:");
	else
		trace_seq_printf(s, "%lld:", val);

	if (pevent_get_field_val(s, event, "prev_state", record, &val, 0))
		trace_seq_putc(s, '?');
	else
		write_state(s, val);

	trace_seq_puts(s, " +   ");

	if (pevent_get_field_val(s, event, "pid", record, &val, 1))
		return trace_seq_putc(s, '!');

	trace_seq_printf(s, "%lld:", val);

	if (pevent_get_field_val(s, event, "prio", record, &val, 1))
		return trace_seq_putc(s, '!');

	trace_seq_printf(s, "%lld:", val);

	if (pevent_get_field_val(s, event, "state", record, &val, 0))
		trace_seq_putc(s, '?');
	else
		write_state(s, val);

	trace_seq_putc(s, ' ');

	field = pevent_find_field(event, "comm");
	if (!field) {
		trace_seq_printf(s, "<CANT FIND FIELD %s>", "next_comm");
		return trace_seq_putc(s, '!');
	}

	trace_seq_printf(s, "%.*s", field->size, (char *)(record->data + field->offset));

	if (pevent_get_field_val(s, event, "target_cpu", record, &val, 0) == 0)
		trace_seq_printf(s, " [%03llu]", val);

	if (pevent_get_field_val(s, event, "success", record, &val, 0) == 0)
		trace_seq_puts(s, val ? " Success" : " Failed");

	return 0;
}

static int sched_switch_handler(struct trace_seq *s, struct record *record,
				struct event_format *event, void *context)
{
	struct format_field *field;
	unsigned long long val;

	if (pevent_get_field_val(s, event, "prev_pid", record, &val, 1))
		return trace_seq_putc(s, '!');

	trace_seq_printf(s, "%lld:", val);

	if (pevent_get_field_val(s, event, "prev_prio", record, &val, 1))
		return trace_seq_putc(s, '!');

	trace_seq_printf(s, "%lld:", val);

	if (pevent_get_field_val(s,  event, "prev_state", record, &val, 1))
		return trace_seq_putc(s, '!');

	write_state(s, val);

	trace_seq_puts(s, " ==> ");

	if (pevent_get_field_val(s, event, "next_pid", record, &val, 1))
		return trace_seq_putc(s, '!');

	trace_seq_printf(s, "%lld:", val);

	if (pevent_get_field_val(s, event, "next_prio", record, &val, 1))
		return trace_seq_putc(s, '!');

	trace_seq_printf(s, "%lld:", val);

	trace_seq_putc(s, ' ');

	field = pevent_find_any_field(event, "next_comm");
	if (!field) {
		trace_seq_printf(s, "<CANT FIND FIELD %s>", "next_comm");
		return trace_seq_putc(s, '!');
	}

	trace_seq_printf(s, "%.*s", field->size, (char *)(record->data + field->offset));

	return 0;
}

int PEVENT_PLUGIN_LOADER(struct pevent *pevent)
{
	pevent_register_event_handler(pevent, -1, "sched", "sched_switch",
				      sched_switch_handler, NULL);

	pevent_register_event_handler(pevent, -1, "sched", "sched_wakeup",
				      sched_wakeup_handler, NULL);

	pevent_register_event_handler(pevent, -1, "sched", "sched_wakeup_new",
				      sched_wakeup_handler, NULL);

	return 0;
}
