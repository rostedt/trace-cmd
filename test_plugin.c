#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse-events.h"

static int handler(struct trace_seq *s, void *data, int size)
{
	int ret;

	ret = trace_seq_printf(s, "COMM: %s state is %d next is %s",
			       (char *)(data+12), *(int *)(data + 40),
			       (char *)(data+48));
	return ret;
}

int PEVENT_PLUGIN_LOADER(void)
{
	printf("HELLO WORLD!!!\n");

	pevent_register_event_handler(-1, "sched", "sched_switch",
				      handler);
	return 0;
}
