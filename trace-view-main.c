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
#include "trace-view.h"
#include "trace-xml.h"
#include "trace-filter.h"
#include "trace-gui.h"
#include "trace-compat.h"

#include "version.h"

#define version "0.1.1"

#define TRACE_WIDTH	800
#define TRACE_HEIGHT	600

#define default_input_file "trace.dat"
static char *input_file;

struct trace_tree_info {
	struct tracecmd_input	*handle;
	GtkWidget		*trace_tree;
	GtkWidget		*spin;
	gint			filter_enabled;
	gint			filter_task_selected;
	struct filter_task	*task_filter;
	struct filter_task	*hide_tasks;
};

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
	struct trace_tree_info *info = data;
	struct tracecmd_input *handle;
	gchar *filename;

	filename = trace_get_file_dialog("Load File", NULL, FALSE);
	if (!filename)
		return;

	handle = tracecmd_open(filename);
	if (handle) {
		trace_view_reload(info->trace_tree, handle, info->spin);
		/* Free handle when freeing the trace tree */
		tracecmd_close(handle);
		info->handle = handle;
	}
	g_free(filename);
}

/* Callback for the clicked signal of the Load Filters button */
static void
load_filters_clicked (gpointer data)
{
	struct trace_tree_info *info = data;
	GtkTreeView *trace_tree = GTK_TREE_VIEW(info->trace_tree);
	struct tracecmd_xml_handle *handle;
	gchar *filename;

	filename = trace_get_file_dialog("Load Filters", NULL, FALSE);
	if (!filename)
		return;

	handle = tracecmd_xml_open(filename);
	if (!handle) {
		warning("Could not open %s", filename);
		return;
	}
	g_free(filename);

	trace_filter_load_filters(handle,
				  "ListTaskFilter",
				  info->task_filter,
				  info->hide_tasks);

	trace_view_load_filters(handle, trace_tree);

	tracecmd_xml_close(handle);
}

/* Callback for the clicked signal of the Save Filters button */
static void
save_filters_clicked (gpointer data)
{
	struct trace_tree_info *info = data;
	GtkTreeView *trace_tree = GTK_TREE_VIEW(info->trace_tree);
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
				  "ListTaskFilter",
				  info->task_filter, info->hide_tasks);
	trace_view_save_filters(handle, trace_tree);

	tracecmd_xml_close(handle);
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

/* Callback for the clicked signal of the Events filter button */
static void
events_clicked (gpointer data)
{
	struct trace_tree_info *info = data;
	struct event_filter *event_filter;
	GtkTreeView *trace_tree = GTK_TREE_VIEW(info->trace_tree);
	GtkTreeModel *model;
	TraceViewStore *store;
	gboolean all_events;

	model = gtk_tree_view_get_model(trace_tree);
	if (!model)
		return;

	store = TRACE_VIEW_STORE(model);

	all_events = trace_view_store_get_all_events_enabled(store);
	event_filter = trace_view_store_get_event_filter(store);

	trace_filter_event_filter_dialog(store->handle, event_filter,
					 all_events,
					 trace_view_event_filter_callback,
					 trace_tree);
}

/* Callback for the clicked signal of the Advanced filter button */
static void
adv_filter_clicked (gpointer data)
{
	struct trace_tree_info *info = data;
	struct event_filter *event_filter;
	GtkTreeView *trace_tree = GTK_TREE_VIEW(info->trace_tree);
	GtkTreeModel *model;
	TraceViewStore *store;

	model = gtk_tree_view_get_model(trace_tree);
	if (!model)
		return;

	store = TRACE_VIEW_STORE(model);

	event_filter = trace_view_store_get_event_filter(store);

	trace_adv_filter_dialog(store->handle, event_filter,
				trace_view_adv_filter_callback, trace_tree);
}

/* Callback for the clicked signal of the CPUs filter button */
static void
cpus_clicked (gpointer data)
{
	struct trace_tree_info *info = data;
	GtkTreeView *trace_tree = GTK_TREE_VIEW(info->trace_tree);
	TraceViewStore *store;
	gboolean all_cpus;
	guint64 *cpu_mask;

	store = TRACE_VIEW_STORE(gtk_tree_view_get_model(trace_tree));

	all_cpus = trace_view_store_get_all_cpus(store);
	cpu_mask = trace_view_store_get_cpu_mask(store);

	trace_filter_cpu_dialog(all_cpus, cpu_mask,
				trace_view_store_get_cpus(store),
				trace_view_cpu_filter_callback, trace_tree);
}

static void
filter_list_clicked (gpointer data)
{
	struct trace_tree_info *info = data;

	if (!filter_task_count(info->task_filter) &&
	    !filter_task_count(info->hide_tasks))
		return;

	info->filter_enabled ^= 1;

	if (info->filter_enabled)
		trace_view_update_filters(info->trace_tree,
					  info->task_filter,
					  info->hide_tasks);
	else
		trace_view_update_filters(info->trace_tree, NULL, NULL);
}

static void update_task_filter(struct trace_tree_info *info,
			       struct filter_task *filter)
{
	struct filter_task_item *task;
	gint pid = info->filter_task_selected;

	task = filter_task_find_pid(filter, pid);

	if (task)
		filter_task_remove_pid(filter, pid);
	else
		filter_task_add_pid(filter, pid);

	if (info->filter_enabled)
		trace_view_update_filters(info->trace_tree,
					  info->task_filter,
					  info->hide_tasks);
}

static void filter_add_task_clicked(gpointer data)
{
	struct trace_tree_info *info = data;

	update_task_filter(info, info->task_filter);
}

static void filter_hide_task_clicked(gpointer data)
{
	struct trace_tree_info *info = data;

	update_task_filter(info, info->hide_tasks);
}

static void
filter_clear_tasks_clicked (gpointer data)
{
	struct trace_tree_info *info = data;

	trace_view_update_filters(info->trace_tree, NULL, NULL);
	info->filter_enabled = 0;
}

static gboolean
do_tree_popup(GtkWidget *widget, GdkEventButton *event, gpointer data)
{
	struct trace_tree_info *info = data;
	static GtkWidget *menu;
	static GtkWidget *menu_filter_enable;
	static GtkWidget *menu_filter_add_task;
	static GtkWidget *menu_filter_hide_task;
	static GtkWidget *menu_filter_clear_tasks;
	struct pevent *pevent;
	struct pevent_record *record;
	TraceViewRecord *vrec;
	GtkTreeModel *model;
	const char *comm;
	gchar *text;
	gint pid;
	gint len;
	guint64 offset;
	gint row;
	gint cpu;

	if (!menu) {
		menu = gtk_menu_new();

		menu_filter_enable = gtk_menu_item_new_with_label("Enable Filter");
		gtk_widget_show(menu_filter_enable);
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), menu_filter_enable);

		g_signal_connect_swapped (G_OBJECT (menu_filter_enable), "activate",
					  G_CALLBACK (filter_list_clicked),
					  data);

		menu_filter_add_task = gtk_menu_item_new_with_label("Add Task");
		gtk_widget_show(menu_filter_add_task);
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), menu_filter_add_task);

		g_signal_connect_swapped (G_OBJECT (menu_filter_add_task), "activate",
					  G_CALLBACK (filter_add_task_clicked),
					  data);

		menu_filter_hide_task = gtk_menu_item_new_with_label("Hide Task");
		gtk_widget_show(menu_filter_hide_task);
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), menu_filter_hide_task);

		g_signal_connect_swapped (G_OBJECT (menu_filter_hide_task), "activate",
					  G_CALLBACK (filter_hide_task_clicked),
					  data);

		menu_filter_clear_tasks = gtk_menu_item_new_with_label("Clear Task Filter");
		gtk_widget_show(menu_filter_clear_tasks);
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), menu_filter_clear_tasks);

		g_signal_connect_swapped (G_OBJECT (menu_filter_clear_tasks), "activate",
					  G_CALLBACK (filter_clear_tasks_clicked),
					  data);

	}

	row = trace_view_get_selected_row(GTK_WIDGET(info->trace_tree));
	if (row >= 0) {

		model = gtk_tree_view_get_model(GTK_TREE_VIEW(info->trace_tree));
		vrec = trace_view_store_get_row(TRACE_VIEW_STORE(model), row);
		offset = vrec->offset;

		record = tracecmd_read_at(info->handle, offset, &cpu);

		if (record) {
			pevent = tracecmd_get_pevent(info->handle);
			pid = pevent_data_pid(pevent, record);
			comm = pevent_data_comm_from_pid(pevent, pid);

			len = strlen(comm) + 50;

			text = g_malloc(len);
			g_assert(text);

			if (filter_task_find_pid(info->task_filter, pid))
				snprintf(text, len, "Remove %s-%d from filter", comm, pid);
			else
				snprintf(text, len, "Add %s-%d to filter", comm, pid);

			info->filter_task_selected = pid;

			gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_add_task),
						text);

			if (filter_task_find_pid(info->hide_tasks, pid))
				snprintf(text, len, "Show %s-%d", comm, pid);
			else
				snprintf(text, len, "Hide %s-%d", comm, pid);

			gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_hide_task),
						text);

			g_free(text);

			info->filter_task_selected = pid;

			gtk_widget_show(menu_filter_add_task);
			gtk_widget_show(menu_filter_hide_task);
			free_record(record);
		}
	} else {
		gtk_widget_hide(menu_filter_add_task);
		gtk_widget_hide(menu_filter_hide_task);
	}

	if (info->filter_enabled)
		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_enable),
					"Disable List Filter");
	else
		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_enable),
					"Enable List Filter");

	if (filter_task_count(info->task_filter) ||
	    filter_task_count(info->hide_tasks)) {
		gtk_widget_set_sensitive(menu_filter_clear_tasks, TRUE);
		gtk_widget_set_sensitive(menu_filter_enable, TRUE);
	} else {
		gtk_widget_set_sensitive(menu_filter_clear_tasks, FALSE);
		gtk_widget_set_sensitive(menu_filter_enable, FALSE);
	}

	gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL, 3,
		       gtk_get_current_event_time());

	return TRUE;
}

static gboolean
button_press_event(GtkWidget *widget, GdkEventButton *event, gpointer data)
{
	if (event->button == 3)
		return do_tree_popup(widget, event, data);

	return FALSE;
}

void trace_view(int argc, char **argv)
{
	static struct tracecmd_input *handle = NULL;
	struct trace_tree_info tree_info;
	struct stat st;
	GtkWidget *trace_tree;
	GtkWidget *window;
	GtkWidget *vbox;
	GtkWidget *hbox;
	GtkWidget *menu_bar;
	GtkWidget *menu;
	GtkWidget *menu_item;
	GtkWidget *sub_item;
	GtkWidget *scrollwin;
	GtkWidget *label;
	GtkWidget *spin;
	GtkWidget *statusbar;
	int ret;
	int c;

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

	memset(&tree_info, 0, sizeof(tree_info));
	tree_info.handle = handle;
	tree_info.task_filter = filter_task_hash_alloc();
	tree_info.hide_tasks = filter_task_hash_alloc();

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

	sub_item = gtk_menu_item_new_with_label("Load data");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (load_clicked),
				  (gpointer) &tree_info);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- File - Load Filter Option --- */

	sub_item = gtk_menu_item_new_with_label("Load filters");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (load_filters_clicked),
				  (gpointer) &tree_info);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- File - Save Filter Option --- */

	sub_item = gtk_menu_item_new_with_label("Save filters");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (save_filters_clicked),
				  (gpointer) &tree_info);

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
				  (gpointer) &tree_info);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- Filter - Advanced Events Option --- */

	sub_item = gtk_menu_item_new_with_label("advanced event filter");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (adv_filter_clicked),
				  (gpointer) &tree_info);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- Filter - CPUs Option --- */

	sub_item = gtk_menu_item_new_with_label("CPUs");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (cpus_clicked),
				  (gpointer) &tree_info);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- End Filter Options --- */
	gtk_menu_item_set_submenu(GTK_MENU_ITEM (menu_item), menu);


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

	/* --- Search --- */

	/* --- Get handle for trace view first --- */

	trace_tree = gtk_tree_view_new();

	/* The tree needs its columns loaded now */
	trace_view_load(trace_tree, handle, spin);

	/* Let the handle be freed when the trace_view is */
	if (handle)
		tracecmd_close(handle);

	label = gtk_label_new("      Search: ");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	gtk_signal_connect(GTK_OBJECT(trace_tree), "button_press_event",
			   (GtkSignalFunc) button_press_event,
			   (gpointer) &tree_info);

	trace_view_search_setup(GTK_BOX(hbox), GTK_TREE_VIEW(trace_tree));

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

	gtk_container_add(GTK_CONTAINER(scrollwin), trace_tree);
	gtk_widget_show(trace_tree);


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

	/* Set up info for call backs */
	tree_info.trace_tree = trace_tree;
	tree_info.spin = spin;

	gtk_widget_show (window);
	gtk_main ();
}

int main(int argc, char **argv)
{
	trace_view(argc, argv);
	return 0;
}
