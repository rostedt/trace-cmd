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
#include <gtk/gtk.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "trace-cmd.h"
#include "trace-graph.h"
#include "trace-filter.h"
#include "trace-gui.h"

#include "version.h"

#define version "0.1.1"

#define TRACE_WIDTH	800
#define TRACE_HEIGHT	600

#define default_input_file "trace.dat"
static char *input_file;
static struct graph_info *ginfo;

void usage(char *prog)
{
	printf("Usage: %s\n", prog);
	printf("  -h	Display this help message\n");
	printf("  -i	input_file, default is %s\n", default_input_file);
}

/* Callback for the clicked signal of the Load button */
static void
load_clicked (gpointer data)
{
	struct graph_info *ginfo = data;
	struct tracecmd_input *handle;
	gchar *filename;

	filename = trace_get_file_dialog("Load File", NULL, FALSE);
	if (!filename)
		return;

	handle = tracecmd_open(filename);
	if (handle) {
		trace_graph_load_handle(ginfo, handle);
		/* Free handle when freeing graph */
		tracecmd_close(handle);
	}
	g_free(filename);
}

/* Callback for the clicked signal of the Exit button */
static void
exit_clicked (GtkWidget *widget, gpointer data)
{
	gtk_widget_destroy (GTK_WIDGET (data)); /* the user data points to the main window */
	tracecmd_close(ginfo->handle);
	gtk_main_quit ();
}

/* Callback for the delete_event signal of the main application window */
static gint
delete_event (GtkWidget *widget, GdkEvent *event, gpointer data)
{
	gtk_widget_destroy (widget); /* destroy the main window */
	tracecmd_close(ginfo->handle);
	gtk_main_quit ();
	return TRUE;
}

/* Callback for the clicked signal of the Events filter button */
static void
events_clicked (gpointer data)
{
	struct graph_info *ginfo = data;
	gboolean all_events = TRUE;

	if (!ginfo->handle)
		return;

	all_events = ginfo->all_events;

	trace_filter_event_filter_dialog(ginfo->handle, ginfo->event_filter,
					 all_events,
					 trace_graph_event_filter_callback, ginfo);
}

/* Callback for the clicked signal of the Advanced filter button */
static void
adv_filter_clicked (gpointer data)
{
	struct graph_info *ginfo = data;

	trace_adv_filter_dialog(ginfo->handle, ginfo->event_filter,
				trace_graph_adv_filter_callback, ginfo);
}

/* Callback for the clicked signal of the plot CPUs button */
static void
plot_cpu_clicked (gpointer data)
{
	struct graph_info *ginfo = data;
	gboolean all_cpus;
	guint64 *cpu_mask;

	if (!ginfo->handle)
		return;

	graph_plot_cpus_plotted(ginfo, &all_cpus, &cpu_mask);

	trace_filter_cpu_dialog(all_cpus, cpu_mask, ginfo->cpus,
				graph_plot_cpus_update_callback, ginfo);
	g_free(cpu_mask);
}

/* Callback for the clicked signal of the plot tasks button */
static void
plot_tasks_clicked (gpointer data)
{
	struct graph_info *ginfo = data;
	gint *selected;
	gint *tasks;

	if (!ginfo->handle)
		return;

	tasks = trace_graph_task_list(ginfo);
	graph_plot_task_plotted(ginfo, &selected);

	trace_task_dialog(ginfo->handle, tasks, selected,
			  graph_plot_task_update_callback, ginfo);
	free(tasks);
	free(selected);
}

/* Callback for the clicked signal of the Load Filters button */
static void
load_filters_clicked (gpointer data)
{
	struct graph_info *ginfo = data;
	struct tracecmd_xml_handle *handle;
	gchar *filename;

	filename = trace_get_file_dialog("Load Filters", NULL, FALSE);
	if (!filename)
		return;

	handle = tracecmd_xml_open(filename);
	if (!handle)
		warning("Could not open %s", filename);
	g_free(filename);

	trace_filter_load_filters(handle,
				  "GraphTaskFilter",
				  ginfo->task_filter,
				  ginfo->hide_tasks);

	trace_graph_load_filters(ginfo, handle);

	tracecmd_xml_close(handle);
}

/* Callback for the clicked signal of the Save Filters button */
static void
save_filters_clicked (gpointer data)
{
	struct graph_info *ginfo = data;
	struct tracecmd_xml_handle *handle;
	gchar *filename;

	filename = trace_get_file_dialog("Save Filters", "Save", TRUE);
	if (!filename)
		return;

	handle = tracecmd_xml_create(filename, VERSION_STRING);
	if (!handle)
		warning("Could not create %s", filename);
	g_free(filename);

	trace_filter_save_filters(handle,
				  "GraphTaskFilter",
				  ginfo->task_filter,
				  ginfo->hide_tasks);

	trace_graph_save_filters(ginfo, handle);

	tracecmd_xml_close(handle);
}

void trace_graph(int argc, char **argv)
{
	struct tracecmd_input *handle = NULL;
	struct stat st;
	GtkWidget *window;
	GtkWidget *vbox;
	GtkWidget *hbox;
	GtkWidget *menu_bar;
	GtkWidget *menu;
	GtkWidget *menu_item;
	GtkWidget *sub_item;
	GtkWidget *widget;
	GtkWidget *statusbar;
	int c;
	int ret;

	gtk_init(&argc, &argv);

	while ((c = getopt(argc, argv, "hi:")) != -1) {
		switch(c) {
		case 'h':
			usage(basename(argv[0]));
			return;
		case 'i':
			input_file = optarg;
			break;
		default:
			/* assume the other options are for gtk */
			break;
		}
	}

	if ((argc - optind) >= 1) {
		if (input_file)
			usage(basename(argv[0]));
		input_file = argv[optind];
	}

	if (!input_file) {
		ret = stat(default_input_file, &st);
		if (ret >= 0)
			input_file = default_input_file;
	}

	if (input_file)
		handle = tracecmd_open(input_file);

	/* graph struct is used by handlers */
	ginfo = trace_graph_create(handle);

	/* Free handle when freeing graph */
	if (handle)
		tracecmd_close(handle);

	/* --- Main window --- */

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

	trace_dialog_register_window(window);

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


	/* --- File - Load Option --- */

	sub_item = gtk_menu_item_new_with_label("Load info");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (load_clicked),
				  (gpointer) ginfo);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- File - Load Filter Option --- */

	sub_item = gtk_menu_item_new_with_label("Load filters");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (load_filters_clicked),
				  (gpointer) ginfo);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- File - Save Filter Option --- */

	sub_item = gtk_menu_item_new_with_label("Save filters");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (save_filters_clicked),
				  (gpointer) ginfo);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);

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
				  (gpointer) ginfo);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- Filter - Advanced Events Option --- */

	sub_item = gtk_menu_item_new_with_label("advanced event filter");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (adv_filter_clicked),
				  (gpointer) ginfo);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- End Filter Options --- */
	gtk_menu_item_set_submenu(GTK_MENU_ITEM (menu_item), menu);


	/* --- Plot Option --- */

	menu_item = gtk_menu_item_new_with_label("Plots");
	gtk_widget_show(menu_item);

	gtk_menu_bar_append(GTK_MENU_BAR (menu_bar), menu_item);

	menu = gtk_menu_new();    /* Don't need to show menus */


	/* --- Plot - CPUs Option --- */

	sub_item = gtk_menu_item_new_with_label("CPUs");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (plot_cpu_clicked),
				  (gpointer) ginfo);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- Plot - Tasks Option --- */

	sub_item = gtk_menu_item_new_with_label("Tasks");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (plot_tasks_clicked),
				  (gpointer) ginfo);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- End Plot Options --- */
	gtk_menu_item_set_submenu(GTK_MENU_ITEM (menu_item), menu);


	/* --- Top Level Hbox --- */

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, TRUE, TRUE, 0);
	gtk_widget_show(hbox);


	/* --- Set up the Graph --- */

	widget = trace_graph_get_window(ginfo);
	gtk_box_pack_start(GTK_BOX (hbox), widget, TRUE, TRUE, 0);
	gtk_widget_show(widget);


	/* --- Set up Status Bar --- */

	statusbar = trace_status_bar_new();

	gtk_box_pack_start(GTK_BOX(vbox), statusbar, FALSE, FALSE, 0);
	gtk_widget_show(statusbar);


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

int main(int argc, char **argv)
{
	trace_graph(argc, argv);
	return 0;
}
