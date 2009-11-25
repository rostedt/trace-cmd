#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse-events.h"

static int _print_field(struct trace_seq *s, const char *fmt,
			struct event *event, const char *name, const void *data)
{
	struct format_field *f = pevent_find_field(event, name);
	unsigned long long val;

	if (!f)
		return 0;

	if (pevent_read_number_field(f, data, &val))
		return 0;

	return trace_seq_printf(s, fmt, val);
}

static int print_field(struct trace_seq *s, const char *fmt,
		       struct event *event, const char *name, const void *data)
{
	int ret = _print_field(s, fmt, event, name, data);

	if (ret == 0)
		ret = trace_seq_printf(s, "CAN'T FIND FIELD \"%s\"", name);

	return ret;
}

static int timer_expire_handler(struct trace_seq *s, void *data, int size,
				struct event *event)
{
	int ret = 0, tmp;

	ret += trace_seq_printf(s, "hrtimer=");
	tmp = _print_field(s, "0x%llx", event, "timer", data);
	if (tmp)
		ret += tmp;
	else
		ret += print_field(s, "0x%llx", event, "hrtimer", data);

	ret += trace_seq_printf(s, " now=");

	ret += print_field(s, "%llu", event, "now", data);

	return ret;
}

static int timer_start_handler(struct trace_seq *s, void *data, int size,
			       struct event *event)
{
	struct format_field *fn = pevent_find_field(event, "function");
	int ret = 0, tmp;

	ret += trace_seq_printf(s, "hrtimer=");
	tmp = _print_field(s, "0x%llx", event, "timer", data);
	if (tmp)
		ret += tmp;
	else
		ret += print_field(s, "0x%llx", event, "hrtimer", data);

	if (!fn) {
		ret += trace_seq_printf(s, " function=MISSING");
	} else {
		unsigned long long function;
		const char *func;

		if (pevent_read_number_field(fn, data, &function))
			ret += trace_seq_printf(s, " function=INVALID");

		func = pevent_find_function(function);

		ret += trace_seq_printf(s, " function=%s", func);
	}

	ret += trace_seq_printf(s, " expires=");
	ret += print_field(s, "%llu", event, "expires", data);

	ret += trace_seq_printf(s, " softexpires=");
	ret += print_field(s, "%llu", event, "softexpires", data);

	return ret;
}

int PEVENT_PLUGIN_LOADER(void)
{
	pevent_register_event_handler(-1, "timer", "hrtimer_expire_entry",
				      timer_expire_handler);

	pevent_register_event_handler(-1, "timer", "hrtimer_start",
				      timer_start_handler);

	return 0;
}
