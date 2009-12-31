#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trace-cmd.h"

static int call_site_handler(struct trace_seq *s, struct record *record,
			     struct event_format *event)
{
	struct format_field *field;
	unsigned long long val, addr;
	void *data = record->data;
	const char *func;

	field = pevent_find_field(event, "call_site");
	if (!field)
		return 1;

	if (pevent_read_number_field(field, data, &val))
		return 1;

	func = pevent_find_function(event->pevent, val);
	if (!func)
		return 1;
	addr = pevent_find_function_address(event->pevent, val);

	trace_seq_printf(s, "(%s+0x%x) ", func, (int)(val - addr));

	return 1;
}

int PEVENT_PLUGIN_LOADER(struct pevent *pevent)
{
	pevent_register_event_handler(pevent, -1, "kmem", "kfree",
				      call_site_handler);

	pevent_register_event_handler(pevent, -1, "kmem", "kmalloc",
				      call_site_handler);

	pevent_register_event_handler(pevent, -1, "kmem", "kmalloc_node",
				      call_site_handler);

	pevent_register_event_handler(pevent, -1, "kmem", "kmem_cache_alloc",
				      call_site_handler);

	pevent_register_event_handler(pevent, -1, "kmem", "kmem_cache_alloc_node",
				      call_site_handler);

	pevent_register_event_handler(pevent, -1, "kmem", "kfree",
				      call_site_handler);

	pevent_register_event_handler(pevent, -1, "kmem", "kmem_cache_free",
				      call_site_handler);

	return 0;
}
