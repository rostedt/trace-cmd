#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse-events.h"

static int get_offset(struct trace_seq *s, struct event *event, char *name)
{
	struct format_field *field;

	field = pevent_find_field(event, name);
	if (field)
		return field->offset;

	trace_seq_printf(s, "CAN'T FIND FIELD \"%s\"", name);
	return -1;
}

static int timer_expire_handler(struct trace_seq *s, void *data, int size,
				struct event *event)
{
	void *hrtimer;
	long long now;
	int offset;
	int ret;

	offset = get_offset(s, event, "hrtimer");
	if (offset < 0)
		return 0;
	hrtimer = *(void **)(data + offset);

	offset = get_offset(s, event, "now");
	if (offset < 0)
		return 0;
	now = *(long long *)(data + offset);

	ret = trace_seq_printf(s, "hrtimer=%p now=%llu",
			       hrtimer, now);
	return ret;
}

static int timer_start_handler(struct trace_seq *s, void *data, int size,
			       struct event *event)
{
	void *hrtimer;
	void *function;
	long long expires;
	long long soft;
	int offset;
	int ret;

	offset = get_offset(s, event, "hrtimer");
	if (offset < 0)
		return 0;
	hrtimer = *(void **)(data + offset);

	offset = get_offset(s, event, "function");
	if (offset < 0)
		return 0;
	function = *(void **)(data + offset);

	offset = get_offset(s, event, "expires");
	if (offset < 0)
		return 0;
	expires = *(long long *)(data + offset);

	offset = get_offset(s, event, "softexpires");
	if (offset < 0)
		return 0;
	soft = *(long long *)(data + offset);

	ret = trace_seq_printf(s, "hrtimer=%p function=%pf expires=%llu softexpires=%llu",
			       hrtimer, function,
			       expires, soft);
	return ret;
}

int PEVENT_PLUGIN_LOADER(void)
{
	printf("HELLO WORLD!!!\n");

	pevent_register_event_handler(-1, "timer", "hrtimer_expire_entry",
				      timer_expire_handler);

	pevent_register_event_handler(-1, "timer", "hrtimer_start",
				      timer_start_handler);

	return 0;
}
