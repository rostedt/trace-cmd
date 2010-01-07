#ifndef _TRACE_VIEW_H
#define _TRACE_VIEW_H

#include "trace-view-store.h"

void
trace_view_load(GtkWidget *view, struct tracecmd_input *handle,
		GtkWidget *spin);

void trace_view(int argc, char **argv);

void trace_view_update_task_filter(GtkWidget *treeview, struct filter_task *filter);
void trace_view_make_selection_visible(GtkWidget *treeview);

struct event_filter_list {
	struct event_filter_list	*next;
	struct event			*event;
};

/**
 * trace_filter_event_cb_func - callback type for event dialog
 * @accept: TRUE if the accept button was pressed, otherwise FALSE
 * @all_events: TRUE if "All Events" was checked
 * @systems: NULL or a string array of systems terminated with NULL
 * @events: NULL or a int array of event ids terminated with -1
 * @data: The data given passed in to the event dialog function
 *
 * If @accept is FALSE then @all_events, @systems, and @events
 * should be ignored. @data is still valid.
 *
 * If @all_events is TRUE then @systems and @events should be ignored.
 */
typedef void (*trace_filter_event_cb_func)(gboolean accept,
					   gboolean all_events,
					   char **systems,
					   gint *events,
					   gpointer data);

void trace_filter_event_dialog(struct tracecmd_input *handle,
			       gboolean all_events,
			       gchar **systems,
			       gint *events,
			       trace_filter_event_cb_func func,
			       gpointer data);

/**
 * trace_filter_cpu_cb_func - callback type for CPU dialog
 * @accept: TRUE if the accept button was pressed, otherwise FALSE
 * @all_cpus: TRUE if "All CPUS" was checked
 * @selected_cpus: NULL or a cpu_mask with the cpus that were checked set.
 * @data: The data given passed in to the CPU dialog function
 *
 * If @accept is FALSE then @all_cpus and @selected_cpus should be ignored.
 * @data is still valid.
 *
 * If @all_cpus is TRUE then @selected_cpus should be ignored.
 */
typedef void (*trace_filter_cpu_cb_func)(gboolean accept,
					 gboolean all_cpus,
					 guint64 *selected_cpus,
					 gpointer data);

void trace_filter_cpu_dialog(gboolean all_cpus, guint64 *cpu_mask_selected, gint cpus,
			     trace_filter_cpu_cb_func func, gpointer data);

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

#endif /* _TRACE_VIEW_H */
