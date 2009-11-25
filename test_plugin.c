#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse-events.h"

static int timer_expire_handler(struct trace_seq *s, void *data, int size,
				struct event *event)
{
	void *hrtimer = data + 16;
	long long now = *(long long *)(data + 24);
	int ret;

	ret = trace_seq_printf(s, "hrtimer=%p now=%llu",
			       hrtimer, now);
	return ret;
}

static int timer_start_handler(struct trace_seq *s, void *data, int size,
			       struct event *event)
{
	void *hrtimer = data + 16;
	void *function = data + 24;
	long long expires = *(long long *)(data + 32);
	long long soft = *(long long *)(data + 40);
	int ret;

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
