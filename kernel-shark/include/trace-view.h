/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#ifndef _TRACE_VIEW_H
#define _TRACE_VIEW_H

#include "trace-view-store.h"
#include "trace-filter.h"
#include "trace-xml.h"

void
trace_view_load(GtkWidget *view, struct tracecmd_input *handle,
		GtkWidget *spin);

void trace_view_reload(GtkWidget *view, struct tracecmd_input *handle,
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

void trace_view_adv_filter_callback(gboolean accept,
				    const gchar *text,
				    gint *event_ids,
				    gpointer data);

void trace_view_cpu_filter_callback(gboolean accept,
				    gboolean all_cpus,
				    guint64 *selected_cpu_mask,
				    gpointer data);

void trace_view_copy_filter(GtkWidget *treeview,
			    gboolean all_events,
			    struct event_filter *event_filter);

void trace_view_search_setup(GtkBox *box, GtkTreeView *treeview);

gint trace_view_get_selected_row(GtkWidget *treeview);

int trace_view_save_filters(struct tracecmd_xml_handle *handle,
			    GtkTreeView *treeview);
int trace_view_load_filters(struct tracecmd_xml_handle *handle,
			    GtkTreeView *treeview);

#endif /* _TRACE_VIEW_H */
