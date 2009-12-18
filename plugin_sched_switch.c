#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trace-cmd.h"

static int get_field_val(struct trace_seq *s, void *data,
			 struct event_format *event, const char *name,
			 unsigned long long *val, int fail)
{
	struct format_field *field;

	field = pevent_find_any_field(event, name);
	if (!field) {
		if (fail)
			trace_seq_printf(s, "<CANT FIND FIELD %s>", name);
		return -1;
	}

	if (pevent_read_number_field(field, data, val)) {
		if (fail)
			trace_seq_printf(s, " %s=INVALID", name);
		return -1;
	}

	return 0;
}

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
				struct event_format *event, int cpu)
{
	struct format_field *field;
	unsigned long long val;
	void *data = record->data;

	if (get_field_val(s, data, event, "common_pid", &val, 1))
		return trace_seq_putc(s, '!');

	trace_seq_printf(s, "%lld:", val);

	if (get_field_val(s, data, event, "prev_prio", &val, 0))
		trace_seq_puts(s, "?:");
	else
		trace_seq_printf(s, "%lld:", val);

	if (get_field_val(s, data, event, "prev_state", &val, 0))
		trace_seq_putc(s, '?');
	else
		write_state(s, val);

	trace_seq_puts(s, " +   ");

	if (get_field_val(s, data, event, "pid", &val, 1))
		return trace_seq_putc(s, '!');

	trace_seq_printf(s, "%lld:", val);

	if (get_field_val(s, data, event, "prio", &val, 1))
		return trace_seq_putc(s, '!');

	trace_seq_printf(s, "%lld:", val);

	if (get_field_val(s, data, event, "state", &val, 0))
		trace_seq_putc(s, '?');
	else
		write_state(s, val);

	trace_seq_putc(s, ' ');

	field = pevent_find_any_field(event, "comm");
	if (!field) {
		trace_seq_printf(s, "<CANT FIND FIELD %s>", "next_comm");
		return trace_seq_putc(s, '!');
	}

	trace_seq_printf(s, "%.*s", field->size, (char *)(data + field->offset));

	if (get_field_val(s, data, event, "success", &val, 0) == 0)
		trace_seq_puts(s, val ? " Success" : " Failed");

	return 0;
}

static int sched_switch_handler(struct trace_seq *s, struct record *record,
				struct event_format *event, int cpu)
{
	struct format_field *field;
	unsigned long long val;
	void *data = record->data;

	if (get_field_val(s, data, event, "prev_pid", &val, 1))
		return trace_seq_putc(s, '!');

	trace_seq_printf(s, "%lld:", val);

	if (get_field_val(s, data, event, "prev_prio", &val, 1))
		return trace_seq_putc(s, '!');

	trace_seq_printf(s, "%lld:", val);

	if (get_field_val(s, data, event, "prev_state", &val, 1))
		return trace_seq_putc(s, '!');

	write_state(s, val);

	trace_seq_puts(s, " ==> ");

	if (get_field_val(s, data, event, "next_pid", &val, 1))
		return trace_seq_putc(s, '!');

	trace_seq_printf(s, "%lld:", val);

	if (get_field_val(s, data, event, "next_prio", &val, 1))
		return trace_seq_putc(s, '!');

	trace_seq_printf(s, "%lld:", val);

	trace_seq_putc(s, ' ');

	field = pevent_find_any_field(event, "next_comm");
	if (!field) {
		trace_seq_printf(s, "<CANT FIND FIELD %s>", "next_comm");
		return trace_seq_putc(s, '!');
	}

	trace_seq_printf(s, "%.*s", field->size, (char *)(data + field->offset));

	return 0;
}

int PEVENT_PLUGIN_LOADER(struct pevent *pevent)
{
	pevent_register_event_handler(pevent, -1, "sched", "sched_switch",
				      sched_switch_handler);

	pevent_register_event_handler(pevent, -1, "sched", "sched_wakeup",
				      sched_wakeup_handler);

	pevent_register_event_handler(pevent, -1, "sched", "sched_wakeup_new",
				      sched_wakeup_handler);

	return 0;
}
