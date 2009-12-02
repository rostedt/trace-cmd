#ifndef __TRACE_LOCAL_H
#define __TRACE_LOCAL_H

#include "trace-cmd.h"

/* for local shared information with trace-cmd executable */

void usage(char **argv);

struct tracecmd_input *read_trace_header(void);
int read_trace_files(void);

void trace_report(int argc, char **argv);
void trace_view(int argc, char **argv);


/* GUI */

/* We use void because this can be used by non gtk files */
void trace_filter_event_dialog(void *traceview);
void trace_filter_cpu_dialog(void *trace_tree);

#endif /* __TRACE_LOCAL_H */
