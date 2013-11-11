#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <endian.h>
#include "event-parse.h"

unsigned long long process___le16_to_cpup(struct trace_seq *s,
					  unsigned long long *args)
{
	uint16_t *val = (uint16_t *) args[0];
	return (long long) le16toh(*val);
}

int PEVENT_PLUGIN_LOADER(struct pevent *pevent)
{
	pevent_register_print_function(pevent,
				       process___le16_to_cpup,
				       PEVENT_FUNC_ARG_INT,
				       "__le16_to_cpup",
				       PEVENT_FUNC_ARG_PTR,
				       PEVENT_FUNC_ARG_VOID);
	return 0;
}
