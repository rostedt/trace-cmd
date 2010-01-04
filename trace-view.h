#ifndef _TRACE_VIEW_H
#define _TRACE_VIEW_H

#include "trace-view-store.h"

void
trace_view_load(GtkWidget *view, struct tracecmd_input *handle,
		GtkWidget *spin);

void trace_view(int argc, char **argv);

void trace_view_update_task_filter(GtkWidget *treeview, struct filter_task *filter);
void trace_view_make_selection_visible(GtkWidget *treeview);

/* We use void because this can be used by non gtk files */
void trace_filter_event_dialog(void *traceview);
void trace_filter_cpu_dialog(void *trace_tree);

void trace_view_select(GtkWidget *treeview, guint64 time);

#endif /* _TRACE_VIEW_H */
