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
#include <gnome.h>

#include "trace-cmd.h"
#include "trace-local.h"
#include "trace-view-store.h"

#define version "0.1.1"

#define TRACE_WIDTH	800
#define TRACE_HEIGHT	600

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

GtkWidget *trace_tree;

/* Callback for the clicked signal of the Exit button */
static void
exit_clicked (GtkWidget *widget, gpointer data)
{
	gtk_widget_destroy (GTK_WIDGET (data)); /* the user data points to the main window */
	gtk_main_quit ();
}

/* Callback for the delete_event signal of the main application window */
static gint
delete_event (GtkWidget *widget, GdkEvent *event, gpointer data)
{
	gtk_widget_destroy (widget); /* destroy the main window */
	gtk_main_quit ();
	return TRUE;
}

/* Callback for the clicked signal of the Events filter button */
static void
events_clicked (gpointer data)
{
	GtkWidget *trace_tree = data;

	trace_filter_event_dialog(trace_tree);
}

static GtkTreeModel *
create_trace_view_model(struct tracecmd_input *handle)
{
	TraceViewStore *store;

	store = trace_view_store_new(handle);

	return GTK_TREE_MODEL(store);
}

static void
load_trace_view(GtkWidget *view, struct tracecmd_input *handle)
{
	GtkTreeViewColumn *col;
	GtkCellRenderer *renderer;
	GtkTreeModel *model;


	/* --- CPU column --- */

	col = gtk_tree_view_column_new();

	renderer = gtk_cell_renderer_text_new();

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
					     renderer,
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
					     renderer,
					     "text", COL_INFO,
					     NULL);

	model = create_trace_view_model(handle);

	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);

	g_object_unref(model); /* destroy model automatically with view */
}

void trace_view(int argc, char **argv)
{
	struct tracecmd_input *handle;
	GtkWidget *window;
	GtkWidget *vbox;
	GtkWidget *hbox;
	GtkWidget *menu_bar;
	GtkWidget *menu;
	GtkWidget *menu_item;
	GtkWidget *sub_item;
	GtkWidget *scrollwin;

	handle = read_trace_header();
	if (!handle)
		die("error reading header");

	if (tracecmd_read_headers(handle) < 0)
		return;

	if (tracecmd_init_data(handle) < 0)
		die("failed to init data");

	gnome_init("trace-cmd", version, argc, argv);

	/* --- Main window --- */

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

	/* --- Get handle for trace view first --- */

	trace_tree = gtk_tree_view_new();

	/* --- Top Level Vbox --- */

	vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER (window), vbox);
	gtk_widget_show(vbox);

	/* --- Menu Bar --- */

	menu_bar = gtk_menu_bar_new();
	gtk_box_pack_start(GTK_BOX (vbox), menu_bar, FALSE, FALSE, 0);
	gtk_widget_show(menu_bar);

	/* --- File Option --- */

	menu_item = gtk_menu_item_new_with_label("File");
	gtk_widget_show(menu_item);

	gtk_menu_bar_append(GTK_MENU_BAR (menu_bar), menu_item);

	menu = gtk_menu_new();    /* Don't need to show menus */


	/* --- File - Quit Option --- */

	sub_item = gtk_menu_item_new_with_label("Quit");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (exit_clicked),
				  (gpointer) window);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);

	gtk_menu_item_set_submenu(GTK_MENU_ITEM (menu_item), menu);

	/* --- end File options --- */


	/* --- Filter Option --- */

	menu_item = gtk_menu_item_new_with_label("Filter");
	gtk_widget_show(menu_item);

	gtk_menu_bar_append(GTK_MENU_BAR (menu_bar), menu_item);

	menu = gtk_menu_new();    /* Don't need to show menus */


	/* --- Filter - Events Option --- */

	sub_item = gtk_menu_item_new_with_label("events");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (events_clicked),
				  (gpointer) trace_tree);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);

	gtk_menu_item_set_submenu(GTK_MENU_ITEM (menu_item), menu);

	/* --- Top Level Hbox --- */

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, TRUE, TRUE, 0);
	gtk_widget_show(hbox);

	/* --- Scroll Window --- */
	scrollwin = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrollwin),
				       GTK_POLICY_AUTOMATIC,
				       GTK_POLICY_AUTOMATIC);
	gtk_box_pack_start(GTK_BOX (hbox), scrollwin, TRUE, TRUE, 0);
	gtk_widget_show(scrollwin);

	/* --- Set up Trace Tree --- */

	load_trace_view(trace_tree, handle);
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scrollwin),
					      trace_tree);
	gtk_widget_show(trace_tree);


	/**********************************************
	 *   Main Window
	 **********************************************/

	/* Connect to the delete_event signal and Run the application */

	gtk_signal_connect (GTK_OBJECT (window), "delete_event",
			    (GtkSignalFunc) delete_event,
			    NULL);

	gtk_widget_set_size_request(window, TRACE_WIDTH, TRACE_HEIGHT);

	gtk_widget_show (window);
	gtk_main ();
}
