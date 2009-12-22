#ifndef _TRACE_VIEW_H
#define _TRACE_VIEW_H

#include "trace-view-store.h"

void
trace_view_load(GtkWidget *view, struct tracecmd_input *handle,
		GtkWidget *spin);

void trace_view(int argc, char **argv);


/* We use void because this can be used by non gtk files */
void trace_filter_event_dialog(void *traceview);
void trace_filter_cpu_dialog(void *trace_tree);

#endif /* _TRACE_VIEW_H */
