#ifndef _TRACE_VIEW_H
#define _TRACE_VIEW_H

#include "trace-view-store.h"
#include "trace-filter.h"

void
trace_view_load(GtkWidget *view, struct tracecmd_input *handle,
		GtkWidget *spin);

void trace_view(int argc, char **argv);

void trace_view_update_filters(GtkWidget *treeview,
			       struct filter_task *task_filter,
			       struct filter_task *hide_tasks);

void trace_view_make_selection_visible(GtkWidget *treeview);

void trace_view_select(GtkWidget *treeview, guint64 time);

void trace_view_event_filter_callback(gboolean accept,
				      gboolean all_events,
				      gchar **systems,
				      gint *events,
				      gpointer data);

void trace_view_cpu_filter_callback(gboolean accept,
				    gboolean all_cpus,
				    guint64 *selected_cpu_mask,
				    gpointer data);

void trace_view_search_setup(GtkBox *box, GtkTreeView *treeview);

#endif /* _TRACE_VIEW_H */
