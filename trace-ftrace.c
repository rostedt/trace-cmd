#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse-events.h"

static int function_handler(struct trace_seq *s, void *data, int size,
			    struct event *event, int cpu)
{
	struct format_field *ip = pevent_find_field(event, "ip");
	struct format_field *pip = pevent_find_field(event, "parent_ip");
	unsigned long long function;
	const char *func;

	if (!ip)
		return trace_seq_printf(s, "CANT FIND FIELD IP");

	if (pevent_read_number_field(ip, data, &function))
		trace_seq_printf(s, " function=INVALID");
	else {
		func = pevent_find_function(function);
		if (func)
			trace_seq_printf(s, "%s <-- ", func);
		else
			trace_seq_printf(s, "0x%llx", function);
	}

	if (!pip)
		return trace_seq_printf(s, "CANT FIND FIELD PARENT_IP");

	if (pevent_read_number_field(pip, data, &function))
		trace_seq_printf(s, " function=INVALID");
	else {
		func = pevent_find_function(function);
		if (func)
			trace_seq_printf(s, "%s", func);
		else
			trace_seq_printf(s, "0x%llx", function);
	}

	return 0;
}

int tracecmd_ftrace_overrides(void)
{
	pevent_register_event_handler(-1, "ftrace", "function",
				      function_handler);

	return 0;
}
