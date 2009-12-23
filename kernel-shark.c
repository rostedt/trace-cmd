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
#include <fcntl.h>
#include <unistd.h>
#include <gtk/gtk.h>

#include "trace-compat.h"
#include "trace-cmd.h"
#include "kernel-shark.h"

#define version "0.1.1"

#define TRACE_WIDTH	800
#define TRACE_HEIGHT	600

#define input_file "trace.dat"

/* graph callbacks */

/* convert_nano() and print_time() are copied from trace-graph.c for debugging
   purposes, and should be deleted when this is complete (or merged with
   trace-graph.c */

static void convert_nano(unsigned long long time, unsigned long *sec,
			 unsigned long *usec)
{
	*sec = time / 1000000000ULL;
	*usec = (time / 1000) % 1000000;
}

static void print_time(unsigned long long time)
{
	unsigned long sec, usec;

	convert_nano(time, &sec, &usec);
	printf("%lu.%06lu", sec, usec);
}

static void ks_graph_select(struct graph_info *ginfo, guint64 cursor)
{
	struct graph_callbacks *cbs;
	struct shark_info *info;

	printf("Cursor: ");
	print_time(cursor);
	printf(" selected\n");

	cbs = trace_graph_get_callbacks(ginfo);
	info = container_of(cbs, struct shark_info, graph_cbs);

	trace_view_select(info->treeview, cursor);
}

/* Callback for the clicked signal of the Exit button */
static void
exit_clicked (gpointer data)
{
	struct shark_info *info = data;

	gtk_widget_destroy (info->window); /* the user data points to the main window */
	tracecmd_close(info->handle);
	gtk_main_quit ();
}

/* Callback for the delete_event signal of the main application window */
static gint
delete_event (GtkWidget *widget, GdkEvent *event, gpointer data)
{
	struct shark_info *info = data;

	gtk_widget_destroy (widget); /* destroy the main window */
	tracecmd_close(info->handle);
	gtk_main_quit ();
	return TRUE;
}

/* Callback for the clicked signal of the Events filter button */
static void
events_clicked (gpointer data)
{
	struct shark_info *info = data;

	trace_filter_event_dialog(info->treeview);
}

/* Callback for the clicked signal of the CPUs filter button */
static void
cpus_clicked (gpointer data)
{
	struct shark_info *info = data;

	trace_filter_cpu_dialog(info->treeview);
}

void kernel_shark(int argc, char **argv)
{
	struct tracecmd_input *handle;
	struct shark_info *info;
	GtkWidget *window;
	GtkWidget *vbox;
	GtkWidget *hbox;
	GtkWidget *menu_bar;
	GtkWidget *menu;
	GtkWidget *menu_item;
	GtkWidget *sub_item;
	GtkWidget *scrollwin;
	GtkWidget *draw;
	GtkWidget *label;
	GtkWidget *spin;

	info = g_new0(typeof(*info), 1);
	if (!info)
		die("Unable to allocate info");

	handle = tracecmd_open(input_file);
	if (!handle)
		die("error reading header");
	info->handle = handle;

	if (tracecmd_read_headers(handle) < 0)
		return;

	if (tracecmd_init_data(handle) < 0)
		die("failed to init data");

	gtk_init(&argc, &argv);

	/* --- Main window --- */

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	info->window = window;

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
				  (gpointer) info);

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
				  (gpointer) info);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- Filter - CPUs Option --- */

	sub_item = gtk_menu_item_new_with_label("CPUs");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (cpus_clicked),
				  (gpointer) info);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- End Filter Options --- */
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

	/* --- Set up Drawing --- */

	info->graph_cbs.select = ks_graph_select;

	info->ginfo = trace_graph_create_with_callbacks(handle, GTK_SCROLLED_WINDOW(scrollwin),
							&info->graph_cbs);
	draw = trace_graph_get_draw(info->ginfo);

	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scrollwin),
					      draw);
	gtk_widget_show(draw);



	/* --- Paging Hbox --- */

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
	gtk_widget_show(hbox);

	/* --- Page Spin Button --- */

	label = gtk_label_new("Page");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	spin = gtk_spin_button_new(NULL, 1.0, 0);
	gtk_spin_button_set_range(GTK_SPIN_BUTTON(spin), 1, 1);
	gtk_box_pack_start(GTK_BOX(hbox), spin, FALSE, FALSE, 0);
	gtk_widget_show(spin);

	/* --- Top Level Trace View Paging Hbox --- */

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

	info->treeview = gtk_tree_view_new();

	trace_view_load(info->treeview, handle, spin);

	gtk_container_add(GTK_CONTAINER(scrollwin), info->treeview);

	gtk_widget_show(info->treeview);


	/**********************************************
	 *   Main Window
	 **********************************************/

	/* Connect to the delete_event signal and Run the application */

	gtk_signal_connect (GTK_OBJECT (window), "delete_event",
			    (GtkSignalFunc) delete_event,
			    (gpointer) info);

	gtk_widget_set_size_request(window, TRACE_WIDTH, TRACE_HEIGHT);

	gtk_widget_show (window);
	gtk_main ();
}

int main(int argc, char **argv)
{
	kernel_shark(argc, argv);
	return 0;
}
