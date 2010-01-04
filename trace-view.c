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
#include <glib-object.h>

#include "trace-cmd.h"
#include "trace-local.h"
#include "trace-view.h"
#include "trace-compat.h"

enum {
	COL_INDEX,
	COL_CPU,
	COL_TS,
	COL_COMM,
	COL_PID,
	COL_LAT,
	COL_EVENT,
	COL_INFO,
	NUM_COLS
};

static char* col_labels[] = {
	"#",
	"CPU",
	"Time Stamp",
	"Task",
	"PID",
	"Latency",
	"Event",
	"Info",
	NULL
};
static int col_chars[] = {
	0,	/* INDEX */
	0,	/* CPU */
	0,	/* TS */
	0,	/* COMM */
	0,	/* PID */
	0,	/* LAT */
	0,	/* EVENT */
	0,	/* INFO */
	0
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

void trace_view_data_func(GtkTreeViewColumn *column, GtkCellRenderer *renderer,
			  GtkTreeModel *model, GtkTreeIter *iter,
			  gpointer data)
{
	long col_num = (long)data;
	int str_len, label_len;
	gchar *text, *str;
	int new_w, x_pad;
	GValue val = {0};
	GtkWidget *view;

	PangoFontDescription *pfd;
	PangoLayout *playout;

	/* Put the text in the renderer. */
	gtk_tree_model_get_value(model, iter, col_num, &val);
	g_object_set_property(G_OBJECT(renderer), "text", &val);

	g_object_get(G_OBJECT(renderer),
			"text", &text,
			"font-desc", &pfd, /* apparently don't have to free this */
			NULL);

	if (!text)
		goto out;

	/* Make sure there is enough room to render the column label. */
	str = text;
	str_len = strlen(str);
	label_len = strlen(col_labels[col_num]);
	if (label_len > str_len) {
		str = col_labels[col_num];
		str_len = label_len;
	}

	/* Don't bother with pango unless we have more chars than the max. */
	if (str_len > col_chars[col_num]) {
		col_chars[col_num] = str_len;

		view = GTK_WIDGET(gtk_tree_view_column_get_tree_view(column));
		playout = gtk_widget_create_pango_layout(GTK_WIDGET(view), str);
		pango_layout_set_font_description(playout, pfd);
		pango_layout_get_pixel_size(playout, &new_w, NULL);
		gtk_cell_renderer_get_padding(renderer, &x_pad, NULL);
		/* +10 to avoid another adjustment for one char */
		new_w += 2*x_pad + 10;

		if (new_w > gtk_tree_view_column_get_width(column))
			gtk_tree_view_column_set_fixed_width(column, new_w);
	}

	g_free(text);
 out:
	g_value_unset(&val);
}

void
trace_view_load(GtkWidget *view, struct tracecmd_input *handle,
		GtkWidget *spin)
{
	GtkCellRenderer *renderer;
	GtkCellRenderer *fix_renderer;
	GtkTreeModel *model;


	/* --- CPU column --- */

	renderer = gtk_cell_renderer_text_new();
	fix_renderer = gtk_cell_renderer_text_new();

	g_object_set(fix_renderer,
		     "family", "Monospace",
		     "family-set", TRUE,
		     NULL);

	/*
	 * Set fixed height mode now which will cause all the columns below to
	 * be created with their sizing property to be set to
	 * GTK_TREE_VIEW_COLUMN_FIXED.
	 */
	gtk_tree_view_set_fixed_height_mode(GTK_TREE_VIEW(view), TRUE);

	for (long c = 0; c < NUM_COLS; c++)
	{
		gtk_tree_view_insert_column_with_data_func(GTK_TREE_VIEW(view),
				-1,
				col_labels[c],
				(c == COL_LAT || c == COL_INFO) ? fix_renderer : renderer,
				trace_view_data_func,
				(gpointer)c,
				NULL);
	}

	model = create_trace_view_model(handle);

	trace_view_store_set_spin_button(TRACE_VIEW_STORE(model), spin);

	g_signal_connect_swapped (G_OBJECT (spin), "value-changed",
				  G_CALLBACK (spin_changed),
				  (gpointer) view);


	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);

	g_object_unref(model); /* destroy model automatically with view */
}

/**
 * trace_view_get_selected_row - return the selected row
 * @treeview: The tree view
 *
 * Returns the selected row number (or -1 if none is selected)
 */
gint trace_view_get_selected_row(GtkWidget *treeview)
{
	GtkTreeView *tree = GTK_TREE_VIEW(treeview);
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreePath *path;
	gchar *spath;
	GList *glist;
	gint row;

	model = gtk_tree_view_get_model(tree);
	if (!model)
		return -1;

	selection = gtk_tree_view_get_selection(tree);
	glist = gtk_tree_selection_get_selected_rows(selection, &model);
	if (!glist)
		return -1;

	/* Only one row may be selected */
	path = glist->data;
	spath = gtk_tree_path_to_string(path);
	row = atoi(spath);
	g_free(spath);

	gtk_tree_path_free(path);
	g_list_free(glist);

	return row;
}

void trace_view_make_selection_visible(GtkWidget *treeview)
{
	GtkTreeView *tree = GTK_TREE_VIEW(treeview);
	GtkTreePath *path;
	gchar *spath;
	GString *gstr;
	gint row;

	row = trace_view_get_selected_row(treeview);
	if (row < 0)
		return;

	gstr = g_string_new("");
	g_string_printf(gstr, "%d", row);
	spath = g_string_free(gstr, FALSE);

	path = gtk_tree_path_new_from_string(spath);
	g_free(spath);

	gtk_tree_view_scroll_to_cell(tree, path, NULL, TRUE, 0.5, 0.0);

	gtk_tree_path_free(path);
}

void trace_view_update_task_filter(GtkWidget *treeview, struct filter_task *filter)
{
	GtkTreeView *tree = GTK_TREE_VIEW(treeview);
	GtkTreeModel *model;
	guint64 time;
	gint row;

	model = gtk_tree_view_get_model(tree);
	if (!model)
		return;

	/* Keep track of the currently selected row */
	row = trace_view_get_selected_row(treeview);
	if (row >= 0)
		time = trace_view_store_get_time_from_row(TRACE_VIEW_STORE(model), row);

	g_object_ref(model);
	gtk_tree_view_set_model(tree, NULL);

	trace_view_store_filter_tasks(TRACE_VIEW_STORE(model), filter);

	gtk_tree_view_set_model(tree, model);
	g_object_unref(model);

	/* Keep selection near previous selection */
	if (row >= 0)
		trace_view_select(treeview, time);
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
	gtk_tree_path_free(path);

	/* finally, make it visible */
	trace_view_make_selection_visible(treeview);	
}
