#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse-events.h"

/* return -1 (field not found/not valid number), 0 (ok), 1 (buffer full) */
static int _print_field(struct trace_seq *s, const char *fmt,
			struct event *event, const char *name, const void *data)
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
			struct event *event, const char *name, const void *data)
{
	int ret = _print_field(s, fmt, event, name, data);

	if (ret == -1)
		trace_seq_printf(s, "CAN'T FIND FIELD \"%s\"", name);
}

static int timer_expire_handler(struct trace_seq *s, void *data, int size,
				struct event *event, int cpu)
{
	trace_seq_printf(s, "hrtimer=");

	if (_print_field(s, "0x%llx", event, "timer", data) == -1)
		print_field(s, "0x%llx", event, "hrtimer", data);

	trace_seq_printf(s, " now=");

	print_field(s, "%llu", event, "now", data);

	return 0;
}

static int timer_start_handler(struct trace_seq *s, void *data, int size,
			       struct event *event, int cpu)
{
	struct format_field *fn = pevent_find_field(event, "function");

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

		func = pevent_find_function(function);

		trace_seq_printf(s, " function=%s", func);
	}

	trace_seq_printf(s, " expires=");
	print_field(s, "%llu", event, "expires", data);

	trace_seq_printf(s, " softexpires=");
	print_field(s, "%llu", event, "softexpires", data);

	return 0;
}

int PEVENT_PLUGIN_LOADER(void)
{
	pevent_register_event_handler(-1, "timer", "hrtimer_expire_entry",
				      timer_expire_handler);

	pevent_register_event_handler(-1, "timer", "hrtimer_start",
				      timer_start_handler);

	return 0;
}
