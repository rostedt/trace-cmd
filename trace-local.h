#ifndef __TRACE_LOCAL_H
#define __TRACE_LOCAL_H

#include "trace-cmd.h"

/* fix stupid glib guint64 typecasts and printf formats */
typedef unsigned long long u64;

/* for local shared information with trace-cmd executable */

void usage(char **argv);

struct tracecmd_input *read_trace_header(void);
int read_trace_files(void);

void trace_report(int argc, char **argv);

void trace_split(int argc, char **argv);

#endif /* __TRACE_LOCAL_H */
