/*
 * Copyright (C) 2009, Steven Rostedt <srostedt@redhat.com>
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <gtk/gtk.h>

#include "trace-cmd.h"
#include "trace-local.h"
#include "trace-view.h"

enum {
	COL_CPU,
	COL_TS,
	COL_COMM,
	COL_PID,
	COL_LAT,
	COL_EVENT,
	COL_INFO,
	NUM_COLS
};

static GtkTreeModel *
create_trace_view_model(struct tracecmd_input *handle)
{
	TraceViewStore *store;

	store = trace_view_store_new(handle);

	return GTK_TREE_MODEL(store);
}

static void
spin_changed(gpointer data, GtkWidget *spin)
{
	GtkTreeView *tree = data;
	GtkTreeModel *model;
	gint val, page;

	val = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(spin));

	model = gtk_tree_view_get_model(tree);
	/* This can be called when we NULL out the model */
	if (!model)
		return;
	page = trace_view_store_get_page(TRACE_VIEW_STORE(model));
	if (page == val)
		return;

	g_object_ref(model);
	gtk_tree_view_set_model(tree, NULL);

	trace_view_store_set_page(TRACE_VIEW_STORE(model), val);

	gtk_tree_view_set_model(tree, model);
	g_object_unref(model);
}

void
trace_view_load(GtkWidget *view, struct tracecmd_input *handle,
		GtkWidget *spin)
{
	GtkTreeViewColumn *col;
	GtkCellRenderer *renderer;
	GtkCellRenderer *fix_renderer;
	GtkTreeModel *model;


	/* --- CPU column --- */

	col = gtk_tree_view_column_new();

	renderer = gtk_cell_renderer_text_new();
	fix_renderer = gtk_cell_renderer_text_new();

	g_object_set(fix_renderer,
		     "family", "Monospace",
		     "family-set", TRUE,
		     NULL);

	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view),
					     -1,
					     "CPU",
					     renderer,
					     "text", COL_CPU,
					     NULL);

	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view),
					     -1,
					     "Time Stamp",
					     renderer,
					     "text", COL_TS,
					     NULL);

	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view),
					     -1,
					     "Task",
					     renderer,
					     "text", COL_COMM,
					     NULL);

	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view),
					     -1,
					     "PID",
					     renderer,
					     "text", COL_PID,
					     NULL);

	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view),
					     -1,
					     "Latency",
					     fix_renderer,
					     "text", COL_LAT,
					     NULL);

	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view),
					     -1,
					     "Event",
					     renderer,
					     "text", COL_EVENT,
					     NULL);

	
	gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(view),
					     -1,
					     "Info",
					     fix_renderer,
					     "text", COL_INFO,
					     NULL);

	model = create_trace_view_model(handle);

	trace_view_store_set_spin_button(TRACE_VIEW_STORE(model), spin);

	g_signal_connect_swapped (G_OBJECT (spin), "value-changed",
				  G_CALLBACK (spin_changed),
				  (gpointer) view);


	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);

	g_object_unref(model); /* destroy model automatically with view */
}

void trace_view_select(GtkWidget *treeview, guint64 time)
{
	GtkTreeView *tree = GTK_TREE_VIEW(treeview);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreePath *path;
	gint select_page, page;
	GtkWidget *spin;
	gchar buf[100];
	gint row;

	model = gtk_tree_view_get_model(tree);
	/* This can be called when we NULL out the model */
	if (!model)
		return;
	page = trace_view_store_get_page(TRACE_VIEW_STORE(model));
	select_page = trace_view_store_get_timestamp_page(TRACE_VIEW_STORE(model),
							  time);

	/* Make sure the page contains the selected event */
	if (page != select_page) {
		spin = trace_view_store_get_spin(TRACE_VIEW_STORE(model));
		/* If a spin button exists, it should update when changed */
		if (spin)
			gtk_spin_button_set_value(GTK_SPIN_BUTTON(spin), select_page);
		else {
			g_object_ref(model);
			gtk_tree_view_set_model(tree, NULL);

			trace_view_store_set_page(TRACE_VIEW_STORE(model), select_page);

			gtk_tree_view_set_model(tree, model);
			g_object_unref(model);
		}
	}

	/* Select the event */
	row = trace_view_store_get_timestamp_visible_row(TRACE_VIEW_STORE(model), time);
	snprintf(buf, 100, "%d", row);
	printf("row = %s\n", buf);
	path = gtk_tree_path_new_from_string(buf);

	selection = gtk_tree_view_get_selection(tree);
	gtk_tree_selection_select_path(selection, path);

	/* finally, make it visible */
	gtk_tree_view_scroll_to_cell(tree, path, NULL, TRUE, 0.5, 0.0);

	gtk_tree_path_free(path);
}
