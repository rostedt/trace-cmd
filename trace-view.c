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

#define version "0.1.1"

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

struct tracecmd_input *trace_handle;

GtkWidget *trace_tree;

static void add_data_to_model(GtkTreeModel *model,
			      struct tracecmd_input *handle,
			      int cpu)
{
	struct pevent *pevent;
	GtkTreeIter iter;
	struct record *record;
	struct event *event;
	struct trace_seq s;
	struct trace_seq l;
	unsigned long secs;
	unsigned long usecs;
	unsigned long nsecs;
	const char *comm;
	int pid, type;
	char *print;
	char buf[100];

	pevent = tracecmd_get_pevent(handle);

	record = tracecmd_read_data(handle, cpu);
	nsecs = record->ts;

	type = pevent_data_type(pevent, record->data);
	event = pevent_data_event_from_type(pevent, type);
	if (!event)
		return;

	pid = pevent_data_pid(pevent, record->data);
	comm = pevent_data_comm_from_pid(pevent, pid);

	trace_seq_init(&l);
	pevent_data_lat_fmt(pevent, &l, record->data, record->size);
	l.buffer[l.len] = 0;

	trace_seq_init(&s);
	pevent_event_info(&s, event, cpu, record->data, record->size, nsecs);
	if (s.full) {
		print = malloc(s.len + 1);
		memcpy(print, s.buffer, s.len);
	} else
		print = s.buffer;
	print[s.len] = 0;

	secs = nsecs / NSECS_PER_SEC;
	usecs = nsecs - secs * NSECS_PER_SEC;
	usecs = usecs / NSECS_PER_USEC;

	sprintf(buf, "%5lu.%06lu", secs, usecs);

	gtk_list_store_append(GTK_LIST_STORE(model), &iter);
	gtk_list_store_set(GTK_LIST_STORE(model), &iter,
			   COL_CPU, cpu,
			   COL_TS, buf,
			   COL_COMM, comm,
			   COL_PID, pid,
			   COL_LAT, l.buffer,
			   COL_EVENT, event->name,
			   COL_INFO, print,
			   -1);
	if (s.full)
		free(print);

	free(record);
}

static void trace_load_tree(struct tracecmd_input *handle, GtkWidget *trace_tree)
{
	GtkTreeModel *model;
	unsigned long long ts;
	struct record *data;
	int cpus;
	int next;
	int cpu;
	int filter_cpu = -1; /* TODO */

	cpus = tracecmd_cpus(handle);

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(trace_tree));
	g_object_ref(model);
	gtk_tree_view_set_model(GTK_TREE_VIEW(trace_tree), NULL);

	do {
		next = -1;
		ts = 0;
		if (filter_cpu >= 0) {
			cpu = filter_cpu;
			data = tracecmd_peek_data(handle, cpu);
			if (data)
				next = cpu;
		} else {
			for (cpu = 0; cpu < cpus; cpu++) {
				data = tracecmd_peek_data(handle, cpu);
				if (data && (!ts || data->ts < ts)) {
					ts = data->ts;
					next = cpu;
				}
			}
		}
		if (next >= 0)
			add_data_to_model(model, handle, next);

	} while (next >= 0);

	gtk_tree_view_set_model(GTK_TREE_VIEW(trace_tree), model);
	g_object_unref(model);
}

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

static GtkTreeModel *
create_trace_view_model(void)
{
	GtkListStore *store;

	store = gtk_list_store_new(NUM_COLS,
				   G_TYPE_UINT,
				   G_TYPE_STRING,
				   G_TYPE_STRING,
				   G_TYPE_UINT,
				   G_TYPE_STRING,
				   G_TYPE_STRING,
				   G_TYPE_STRING);

	return GTK_TREE_MODEL(store);
}

static GtkWidget *
create_trace_view(void)
{
	GtkTreeViewColumn *col;
	GtkCellRenderer *renderer;
	GtkWidget *view;
	GtkTreeModel *model;

	view = gtk_tree_view_new();

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

	model = create_trace_view_model();

	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);

	g_object_unref(model); /* destroy model automatically with view */

	return view;
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
	GtkWidget *quit_item;
	GtkWidget *scrollwin;

	handle = read_trace_header();
	if (!handle)
		die("error reading header");

	if (tracecmd_read_headers(handle) < 0)
		return;

	if (tracecmd_init_data(handle) < 0)
		die("failed to init data");

	trace_handle = handle;

	gnome_init("trace-cmd", version, argc, argv);

	/* --- Main window --- */

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

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


	/* --- Quit Option --- */

	quit_item = gtk_menu_item_new_with_label("Quit");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), quit_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (quit_item), "activate",
				  G_CALLBACK (exit_clicked),
				  (gpointer) window);

	/* We do need to show menu items */
	gtk_widget_show(quit_item);


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

	/* --- Trace Tree --- */

	trace_tree = create_trace_view();
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scrollwin),
					      trace_tree);
	gtk_widget_show(trace_tree);

	trace_load_tree(handle, trace_tree);

	/**********************************************
	 *   Main Window
	 **********************************************/

	/* Connect to the delete_event signal and Run the application */

	gtk_signal_connect (GTK_OBJECT (window), "delete_event",
			    (GtkSignalFunc) delete_event,
			    NULL);

	gtk_widget_show (window);
	gtk_main ();
}
