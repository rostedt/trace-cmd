// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2015 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "event-parse.h"

enum tlb_flush_reason {
	TLB_FLUSH_ON_TASK_SWITCH,
	TLB_REMOTE_SHOOTDOWN,
	TLB_LOCAL_SHOOTDOWN,
	TLB_LOCAL_MM_SHOOTDOWN,
	NR_TLB_FLUSH_REASONS,
};

static int tlb_flush_handler(struct trace_seq *s, struct pevent_record *record,
			     struct event_format *event, void *context)
{
	unsigned long long val;

	trace_seq_printf(s, "pages=");

	pevent_print_num_field(s, "%ld", event, "pages", record, 1);

	if (pevent_get_field_val(s, event, "reason", record, &val, 1) < 0)
		return -1;

	trace_seq_puts(s, " reason=");

	switch (val) {
	case TLB_FLUSH_ON_TASK_SWITCH:
		trace_seq_puts(s, "flush on task switch");
		break;
	case TLB_REMOTE_SHOOTDOWN:
		trace_seq_puts(s, "remote shootdown");
		break;
	case TLB_LOCAL_SHOOTDOWN:
		trace_seq_puts(s, "local shootdown");
		break;
	case TLB_LOCAL_MM_SHOOTDOWN:
		trace_seq_puts(s, "local mm shootdown");
		break;
	}

	trace_seq_printf(s, " (%lld)", val);

	return 0;
}

int PEVENT_PLUGIN_LOADER(struct tep_handle *pevent)
{
	pevent_register_event_handler(pevent, -1, "tlb", "tlb_flush",
				      tlb_flush_handler, NULL);

	return 0;
}

void PEVENT_PLUGIN_UNLOADER(struct tep_handle *pevent)
{
	pevent_unregister_event_handler(pevent, -1,
					"tlb", "tlb_flush",
					tlb_flush_handler, NULL);
}
