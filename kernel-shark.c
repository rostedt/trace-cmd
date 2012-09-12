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
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <gtk/gtk.h>
#include <errno.h>
#include <getopt.h>

#include "trace-compat.h"
#include "trace-capture.h"
#include "trace-cmd.h"
#include "trace-gui.h"
#include "kernel-shark.h"
#include "event-utils.h"
#include "version.h"

#define ___stringify(X) #X
#define __stringify(X) ___stringify(X)

#define DEBUG_LEVEL	0
#if DEBUG_LEVEL > 0
# define dprintf(l, x...)			\
	do {					\
		if (l <= DEBUG_LEVEL)		\
			printf(x);		\
	} while (0)
#else
# define dprintf(l, x...)	do { if (0) printf(x); } while (0)
#endif

#define TRACE_WIDTH	800
#define TRACE_HEIGHT	600

#define default_input_file "trace.dat"
static char *input_file;

void usage(char *prog)
{
	printf("Usage: %s\n", prog);
	printf("  -h	Display this help message\n");
	printf("  -v	Display version and exit\n");
	printf("  -i	input_file, default is %s\n", default_input_file);
}

static gboolean display_warnings;

/*
 * trace_sync_select_menu - helper function to the syncing of list and graph filters
 *
 * Creates a pop up dialog with the selections given. The selections will be
 * radio buttons to the user. The keep is a value that will be set to the check
 * box (default on) if the user wants to keep the selection persistant.
 */
static int trace_sync_select_menu(const gchar *title,
				  gchar **selections, gboolean *keep)
{
	GtkWidget *dialog;
	GtkWidget *radio;
	GtkWidget *check;
	GSList *group;
	int result;
	int i;

	dialog = gtk_dialog_new_with_buttons(title,
					     NULL,
					     GTK_DIALOG_MODAL,
					     "OK", GTK_RESPONSE_ACCEPT,
					     GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					     NULL);

	radio = gtk_radio_button_new_with_label(NULL, selections[0]);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), radio, TRUE, TRUE, 0);
	gtk_widget_show(radio);

	group = gtk_radio_button_get_group(GTK_RADIO_BUTTON(radio));

	for (i = 1; selections[i]; i++) {
		radio = gtk_radio_button_new_with_label(group, selections[i]);
		gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), radio, TRUE, TRUE, 0);
		gtk_widget_show(radio);
	}

	check = gtk_check_button_new_with_label("Keep the filters in sync?");
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), check, TRUE, TRUE, 0);
	gtk_widget_show(check);

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check), TRUE);

	result = gtk_dialog_run(GTK_DIALOG(dialog));
	switch (result) {
	case GTK_RESPONSE_ACCEPT:
		i = 0;
		for (i = 0; group; i++, group = g_slist_next(group)) {
			radio = group->data;
			if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(radio)))
				break;
		}
		result = i;
		*keep = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(check));
		break;
	default:
		result = -1;
	}

	gtk_widget_destroy(dialog);
	return result;
}

static void update_tree_view_filters(struct shark_info *info,
				     struct filter_task *task_filter,
				     struct filter_task *hide_tasks)
{
	if (info->list_filter_enabled)
		trace_view_update_filters(info->treeview,
					  task_filter, hide_tasks);

	if (filter_task_count(task_filter) ||
	    filter_task_count(hide_tasks))
		info->list_filter_available = 1;
	else {
		info->list_filter_enabled = 0;
		info->list_filter_available = 0;
	}
}

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

	if (!DEBUG_LEVEL)
		return;

	convert_nano(time, &sec, &usec);
	printf("%lu.%06lu", sec, usec);
}

static void ks_graph_select(struct graph_info *ginfo, guint64 cursor)
{
	struct graph_callbacks *cbs;
	struct shark_info *info;

	dprintf(1, "Cursor: ");
	print_time(cursor);
	dprintf(1, " selected\n");

	cbs = trace_graph_get_callbacks(ginfo);
	info = container_of(cbs, struct shark_info, graph_cbs);

	trace_view_select(info->treeview, cursor);
}

static void ks_graph_filter(struct graph_info *ginfo,
			    struct filter_task *task_filter,
			    struct filter_task *hide_tasks)
{
	struct graph_callbacks *cbs;
	struct shark_info *info;

	cbs = trace_graph_get_callbacks(ginfo);
	info = container_of(cbs, struct shark_info, graph_cbs);

	if (!info->sync_task_filters)
		return;

	update_tree_view_filters(info, task_filter, hide_tasks);
}

static void free_info(struct shark_info *info)
{
	tracecmd_close(info->handle);
	trace_graph_free_info(info->ginfo);

	filter_task_hash_free(info->list_task_filter);
	filter_task_hash_free(info->list_hide_tasks);

	kernel_shark_clear_capture(info);

	free(info->current_filter);
	free(info->ginfo);
	free(info);
}

static void update_title(GtkWidget *window, const gchar *file)
{
	GString *gstr;
	gchar *str;

	gstr = g_string_new("kernelshark");
	g_string_append_printf(gstr, "(%s)", basename(file));
	str = g_string_free(gstr, FALSE);

	gtk_window_set_title(GTK_WINDOW(window), str);
	g_free(str);
}

static void unsync_task_filters(struct shark_info *info)
{
	info->sync_task_filters = 0;
	gtk_menu_item_set_label(GTK_MENU_ITEM(info->task_sync_menu),
				"Sync Graph and List Task Filters");

	gtk_menu_item_set_label(GTK_MENU_ITEM(info->graph_task_menu),
				"graph tasks");
	gtk_menu_item_set_label(GTK_MENU_ITEM(info->graph_hide_task_menu),
				"graph hide tasks");
	gtk_widget_show(info->list_task_menu);
	gtk_widget_show(info->list_hide_task_menu);

	/* The list now uses its own hash */
	info->list_task_filter = filter_task_hash_copy(info->ginfo->task_filter);
	info->list_hide_tasks = filter_task_hash_copy(info->ginfo->hide_tasks);
}

static void sync_task_filters(struct shark_info *info)
{
	info->sync_task_filters = 1;
	gtk_menu_item_set_label(GTK_MENU_ITEM(info->task_sync_menu),
				"Unsync Graph and List Task Filters");
	gtk_menu_item_set_label(GTK_MENU_ITEM(info->graph_task_menu),
				"tasks");
	gtk_menu_item_set_label(GTK_MENU_ITEM(info->graph_hide_task_menu),
				"hide tasks");
	gtk_widget_hide(info->list_task_menu);
	gtk_widget_hide(info->list_hide_task_menu);
}

static void unsync_event_filters(struct shark_info *info)
{
	info->sync_event_filters = 0;
	gtk_menu_item_set_label(GTK_MENU_ITEM(info->events_sync_menu),
				"Sync Graph and List Event Filters");

	gtk_menu_item_set_label(GTK_MENU_ITEM(info->graph_events_menu),
				"graph events");
	gtk_menu_item_set_label(GTK_MENU_ITEM(info->graph_adv_events_menu),
				"graph advanced events");
	gtk_widget_show(info->list_events_menu);
	gtk_widget_show(info->list_adv_events_menu);
}

static void sync_event_filters(struct shark_info *info)
{
	info->sync_event_filters = 1;
	gtk_menu_item_set_label(GTK_MENU_ITEM(info->events_sync_menu),
				"Unsync Graph and List Event Filters");
	gtk_menu_item_set_label(GTK_MENU_ITEM(info->graph_events_menu),
				"events");
	gtk_menu_item_set_label(GTK_MENU_ITEM(info->graph_adv_events_menu),
				"advanced events");
	gtk_widget_hide(info->list_events_menu);
	gtk_widget_hide(info->list_adv_events_menu);
}

static void alt_warn(const char *fmt, va_list ap)
{
	display_warnings = TRUE;
	vpr_stat(fmt, ap);
}

/**
 * kernelshark_load_file - load a new file into kernelshark
 * @info: the kernelshark descriptor
 * @file: the file to load
 *
 * Returns: 0 on success, -1 on error
 */
int kernelshark_load_file(struct shark_info *info, const char *file)
{
	struct tracecmd_input *handle;

	/*
	 * Have warnings go into the status bar. If we had any
	 * warnings, pop up a message at the end.
	 */
	display_warnings = 0;
	pr_stat("\nLoading file %s", file);
	trace_dialog_register_alt_warning(alt_warn);
	handle = tracecmd_open(file);
	trace_dialog_register_alt_warning(NULL);
	if (display_warnings) {
		errno = 0;
		warning("Warnings occurred on loading.\n"
			"See display status for details");
	}
	if (!handle)
		return -1;

	tracecmd_close(info->handle);
	info->handle = handle;
	trace_graph_load_handle(info->ginfo, handle);
	trace_view_reload(info->treeview, handle, info->spin);
	update_title(info->window, file);
	return 0;
}

static void
/* Callback for the clicked signal of the Load button */
load_clicked (gpointer data)
{
	struct shark_info *info = data;
	gchar *filename;

	filename = trace_get_file_dialog_filter("Load File", NULL,
					TRACE_DIALOG_FILTER_DATA, FALSE);
	if (!filename)
		return;

	kernelshark_load_file(info, filename);

	g_free(filename);
}

static GString *get_home_filters_new(void)
{
	char *path = getenv("HOME");
	GString *str;

	str = g_string_new(path);
	g_string_append(str, "/.trace-cmd/filters/");
	return str;
}

static int create_home_filters(void)
{
	char *path = getenv("HOME");
	GString *str;
	struct stat st;
	int ret;

	str = g_string_new(path);
	g_string_append(str, "/.trace-cmd");
	ret = stat(str->str, &st);
	if (ret < 0) {
		ret = mkdir(str->str, 0755);
		if (ret < 0) {
			warning("Can not create %s", str->str);
			goto out;
		}
	}

	g_string_append(str, "/filters");
	ret = stat(str->str, &st);
	if (ret < 0) {
		ret = mkdir(str->str, 0755);
		if (ret < 0) {
			warning("Can not create %s", str->str);
			goto out;
		}
	}

	ret = 0;
 out:
	g_string_free(str, TRUE);
	return ret;
}

static void load_filter(struct shark_info *info, const char *filename)
{
	struct graph_info *ginfo = info->ginfo;
	GtkTreeView *trace_tree = GTK_TREE_VIEW(info->treeview);
	GtkTreeModel *model;
	TraceViewStore *store;
	struct tracecmd_xml_handle *handle;
	struct filter_task *task_filter;
	struct filter_task *hide_tasks;
	struct event_filter *event_filter;
	int ret;

	handle = tracecmd_xml_open(filename);
	if (!handle) {
		warning("Could not open %s", filename);
		return;
	}

	/* Unsync the list and graph filters */
	if (info->sync_task_filters)
		unsync_task_filters(info);
	if (info->sync_event_filters)
		unsync_event_filters(info);

	ret = tracecmd_xml_system_exists(handle,
					 "GraphTaskFilter");
	if (ret) {
		filter_task_clear(ginfo->task_filter);
		filter_task_clear(ginfo->hide_tasks);

		trace_filter_load_filters(handle,
					  "GraphTaskFilter",
					  ginfo->task_filter,
					  ginfo->hide_tasks);
		trace_graph_refresh_filters(ginfo);
	}

	ret = tracecmd_xml_system_exists(handle,
					 "ListTaskFilter");
	if (ret) {
		task_filter = info->list_task_filter;
		hide_tasks = info->list_hide_tasks;
		filter_task_clear(task_filter);
		filter_task_clear(hide_tasks);

		trace_filter_load_filters(handle,
					  "ListTaskFilter",
					  task_filter,
					  hide_tasks);
		update_tree_view_filters(info, task_filter, hide_tasks);
	}

	trace_graph_load_filters(ginfo, handle);
	ret = trace_view_load_filters(handle, trace_tree);

	tracecmd_xml_close(handle);

	/*
	 * If the events or tasks filters are the same for both
	 * the list and graph, then sync them back.
	 */
	if (filter_task_compare(ginfo->task_filter,
				info->list_task_filter) &&
	    filter_task_compare(ginfo->hide_tasks,
				info->list_hide_tasks))
		sync_task_filters(info);

	model = gtk_tree_view_get_model(trace_tree);
	if (!model)
		return;

	store = TRACE_VIEW_STORE(model);
	event_filter = trace_view_store_get_event_filter(store);

	if (pevent_filter_compare(event_filter, ginfo->event_filter))
		sync_event_filters(info);
}

static void load_filter_clicked(GtkMenuItem *item, gpointer data)
{
	struct shark_info *info = data;
	const char *name;
	GString *path;

	name = gtk_menu_item_get_label(item);

	path = get_home_filters_new();
	g_string_append_printf(path, "/%s.ksf", name);

	load_filter(info, path->str);
	g_string_free(path, TRUE);

	free(info->current_filter);
	info->current_filter = strdup(name);
}

/* Callback for the clicked signal of the Load Filters button */
static void
import_filters_clicked (gpointer data)
{
	struct shark_info *info = data;
	gchar *filename;

	filename = trace_get_file_dialog_filter("Load Filters", NULL,
					 TRACE_DIALOG_FILTER_FILTER, FALSE);
	if (!filename)
		return;

	load_filter(info, filename);
}

static void save_filters(struct shark_info *info, const char *filename)
{
	struct graph_info *ginfo = info->ginfo;
	struct tracecmd_xml_handle *handle;
	GtkTreeView *trace_tree = GTK_TREE_VIEW(info->treeview);
	struct filter_task *task_filter;
	struct filter_task *hide_tasks;

	handle = tracecmd_xml_create(filename, VERSION_STRING);
	if (!handle) {
		warning("Could not create %s", filename);
		return;
	}

	trace_view_save_filters(handle, trace_tree);
	trace_graph_save_filters(ginfo, handle);

	trace_filter_save_filters(handle,
				  "GraphTaskFilter",
				  ginfo->task_filter,
				  ginfo->hide_tasks);

	if (info->sync_task_filters) {
		task_filter = ginfo->task_filter;
		hide_tasks = ginfo->hide_tasks;
	} else {
		task_filter = info->list_task_filter;
		hide_tasks = info->list_hide_tasks;
	}

	trace_filter_save_filters(handle,
				  "ListTaskFilter",
				  task_filter, hide_tasks);

	tracecmd_xml_close(handle);
}

/* Callback for the clicked signal of the Save Filters button */
static void
export_filters_clicked (gpointer data)
{
	struct shark_info *info = data;
	gchar *filename;

	filename = trace_get_file_dialog_filter("Save Filters", "Save",
					 TRACE_DIALOG_FILTER_FILTER, TRUE);
	if (!filename)
		return;

	save_filters(info, filename);
	g_free(filename);
}

static void update_load_filter(struct shark_info *info)
{
	struct dirent *dent;
	struct stat st;
	DIR *dir;
	GtkWidget *menu;
	GtkWidget *sub_item;
	GString *path;
	int ret;

	path = get_home_filters_new();

	menu = gtk_menu_new();

	ret = stat(path->str, &st);
	if (ret < 0 || !S_ISDIR(st.st_mode))
		goto update_rest;

	dir = opendir(path->str);
	if (!dir)
		goto update_rest;

	while ((dent = readdir(dir))) {
		const char *name = dent->d_name;
		GString *file;
		gchar *item;

		if (strcmp(name, ".") == 0 ||
		    strcmp(name, "..") == 0)
			continue;

		if (strcmp(name + strlen(name) - 4, ".ksf") != 0)
			continue;

		file = g_string_new(path->str);
		g_string_append_printf(file, "/%s", name);

		/* Save the file name but remove the .kss extention */
		item = g_strdup(name);
		item[strlen(name) - 4] = 0;

		sub_item = gtk_menu_item_new_with_label(item);
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);
		gtk_widget_show(sub_item);

		g_signal_connect(G_OBJECT (sub_item), "activate",
				 G_CALLBACK (load_filter_clicked),
				 (gpointer) info);

		g_free(item);
		g_string_free(file, TRUE);
	}

 update_rest:
	g_string_free(path, TRUE);

	/* --- File - Load Filter - Filters --- */

	sub_item = gtk_menu_item_new_with_label("Import Filter");

	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (import_filters_clicked),
				  (gpointer) info);

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);

	gtk_menu_item_set_submenu(GTK_MENU_ITEM (info->load_filter_menu), menu);

}

/* Callback for the clicked signal of the Save Filters button */
static void
save_filter_clicked (gpointer data)
{
	struct shark_info *info = data;
	struct stat st;
	GtkWidget *dialog;
	GtkWidget *hbox;
	GtkWidget *label;
	GtkWidget *entry;
	GString *file;
	const char *name;
	gint result;
	int ret;

	dialog = gtk_dialog_new_with_buttons("Save Filter",
					     NULL,
					     GTK_DIALOG_MODAL,
					     GTK_STOCK_OK,
					     GTK_RESPONSE_ACCEPT,
					     GTK_STOCK_CANCEL,
					     GTK_RESPONSE_REJECT,
					     NULL);

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), hbox, FALSE, FALSE, 0);
	gtk_widget_show(hbox);

	label = gtk_label_new("Filter Name: ");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	entry = gtk_entry_new();
	gtk_box_pack_start(GTK_BOX(hbox), entry, FALSE, FALSE, 0);
	gtk_widget_show(entry);

	if (info->current_filter)
		gtk_entry_set_text(GTK_ENTRY(entry), info->current_filter);

 again:
	result = gtk_dialog_run(GTK_DIALOG(dialog));
	switch (result) {
	case GTK_RESPONSE_ACCEPT:
		name = gtk_entry_get_text(GTK_ENTRY(entry));
		if (!name || !has_text(name)) {
			warning("Must enter a name");
			goto again;
		}
		/* Make sure home settings exists */
		if (create_home_filters() < 0)
			break;
		file = get_home_filters_new();
		g_string_append_printf(file, "/%s.ksf", name);
		ret = stat(file->str, &st);
		if (ret >= 0) {
			ret = trace_dialog(GTK_WINDOW(dialog), TRACE_GUI_ASK,
					   "The Filter '%s' already exists.\n"
					   "Are you sure you want to replace it",
					   name);
			if (ret == GTK_RESPONSE_NO) {
				g_string_free(file, TRUE);
				goto again;
			}
		}
		save_filters(info, file->str);

		free(info->current_filter);
		info->current_filter = strdup(name);

		update_load_filter(info);
		g_string_free(file, TRUE);
		break;

	case GTK_RESPONSE_REJECT:
		break;
	default:
		break;
	};

	gtk_widget_destroy(dialog);
}

/* Callback for the clicked signal of the Exit button */
static void
exit_clicked (gpointer data)
{
	struct shark_info *info = data;

	gtk_widget_destroy (info->window); /* the user data points to the main window */
	free_info(info);
	gtk_main_quit ();
}

/* Callback for the delete_event signal of the main application window */
static gint
delete_event (GtkWidget *widget, GdkEvent *event, gpointer data)
{
	struct shark_info *info = data;

	gtk_widget_destroy (widget); /* destroy the main window */
	free_info(info);
	gtk_main_quit ();
	return TRUE;
}

/* Callback for the clicked signal of the tasks sync filter button */
static void
sync_task_filter_clicked (GtkWidget *subitem, gpointer data)
{
	struct shark_info *info = data;
	struct filter_task *task_filter;
	struct filter_task *hide_tasks;
	GtkTreeView *trace_tree = GTK_TREE_VIEW(info->treeview);
	GtkTreeModel *model;
	TraceViewStore *store;
	gboolean keep;
	gchar *selections[] = { "Sync List Filter with Graph Filter",
				"Sync Graph Filter with List Filter",
				NULL };
	int result;

	if (info->sync_task_filters) {
		/* Separate the List and Graph filters */

		unsync_task_filters(info);
		return;
	}

	model = gtk_tree_view_get_model(trace_tree);
	if (!model)
		return;

	store = TRACE_VIEW_STORE(model);

	/* If they are already equal, then just perminently sync them */
	if (filter_task_compare(info->ginfo->task_filter,
				info->list_task_filter) &&
	    filter_task_compare(info->ginfo->hide_tasks,
				info->list_hide_tasks))
		result = 2;

	else
		/* Ask user which way to sync */
		result = trace_sync_select_menu("Sync Task Filters",
						selections, &keep);

	switch (result) {
	case 0:
		/* Sync List Filter with Graph Filter */
		filter_task_hash_free(info->list_task_filter);
		filter_task_hash_free(info->list_hide_tasks);

		info->list_task_filter = NULL;
		info->list_hide_tasks = NULL;

		task_filter = info->ginfo->task_filter;
		hide_tasks = info->ginfo->hide_tasks;

		if (!keep) {
			info->list_task_filter = filter_task_hash_copy(task_filter);
			info->list_hide_tasks = filter_task_hash_copy(hide_tasks);
		}

		update_tree_view_filters(info, task_filter, hide_tasks);

		break;
	case 1:
		/* Sync Graph Filter with List Filter */
		trace_graph_update_filters(info->ginfo,
					   info->list_task_filter,
					   info->list_hide_tasks);

		if (keep) {
			filter_task_hash_free(info->list_task_filter);
			filter_task_hash_free(info->list_hide_tasks);

			info->list_task_filter = NULL;
			info->list_hide_tasks = NULL;
		}
		break;
	case 2:
		keep = 1;
		break;
	default:
		keep = 0;
	}

	if (keep)
		sync_task_filters(info);
}

/* Callback for the clicked signal of the events sync filter button */
static void
sync_events_filter_clicked (GtkWidget *subitem, gpointer data)
{
	struct shark_info *info = data;
	struct graph_info *ginfo = info->ginfo;
	struct event_filter *event_filter;
	GtkTreeView *trace_tree = GTK_TREE_VIEW(info->treeview);
	GtkTreeModel *model;
	TraceViewStore *store;
	gboolean keep;
	gboolean all_events;
	gchar *selections[] = { "Sync List Filter with Graph Filter",
				"Sync Graph Filter with List Filter",
				NULL };
	int result;

	if (info->sync_event_filters) {
		/* Separate the List and Graph filters */
		unsync_event_filters(info);
		return;
	}

	model = gtk_tree_view_get_model(trace_tree);
	if (!model)
		return;

	store = TRACE_VIEW_STORE(model);
	event_filter = trace_view_store_get_event_filter(store);

	/* If they are already equal, then just perminently sync them */
	if (pevent_filter_compare(event_filter, ginfo->event_filter))
		result = 2;
	else
		/* Ask user which way to sync */
		result = trace_sync_select_menu("Sync Event Filters",
						selections, &keep);

	switch (result) {
	case 0:
		/* Sync List Filter with Graph Filter */
		all_events = ginfo->all_events;

		trace_view_copy_filter(info->treeview, all_events,
				       ginfo->event_filter);
		break;
	case 1:
		/* Sync Graph Filter with List Filter */
		all_events = trace_view_store_get_all_events_enabled(store);

		trace_graph_copy_filter(info->ginfo, all_events,
					event_filter);
		break;
	case 2:
		keep = 1;
		break;
	default:
		keep = 0;
	}

	if (keep)
		sync_event_filters(info);
}

static void filter_list_enable_clicked (gpointer data);

static void
__update_list_task_filter_callback(struct shark_info *info,
				   gboolean accept,
				   gint *selected,
				   struct filter_task *task_filter)
{
	GtkTreeView *trace_tree = GTK_TREE_VIEW(info->treeview);
	GtkTreeModel *model;
	TraceViewStore *store;
	int i;

	if (!accept)
		return;

	model = gtk_tree_view_get_model(trace_tree);
	if (!model)
		return;

	store = TRACE_VIEW_STORE(model);

	filter_task_clear(task_filter);

	if (selected) {
		for (i = 0; selected[i] >= 0; i++)
			filter_task_add_pid(task_filter, selected[i]);
	}

	update_tree_view_filters(info, info->list_task_filter, info->list_hide_tasks);

	/*
	 * The menu filters always enable the filters.
	 */
	if (info->list_filter_available && !info->list_filter_enabled)
		filter_list_enable_clicked(info);
}

static void
update_list_task_filter_callback(gboolean accept,
				 gint *selected,
				 gint *non_select,
				 gpointer data)
{
	struct shark_info *info = data;

	__update_list_task_filter_callback(info, accept, selected,
					   info->list_task_filter);
}

static void
update_list_hide_task_filter_callback(gboolean accept,
				      gint *selected,
				      gint *non_select,
				      gpointer data)
{
	struct shark_info *info = data;

	__update_list_task_filter_callback(info, accept, selected,
					   info->list_hide_tasks);
}

/* Callback for the clicked signal of the List Tasks filter button */
static void
__list_tasks_clicked (struct shark_info *info,
		      struct filter_task *task_filter,
		      trace_task_cb_func func)
{
	GtkTreeView *trace_tree = GTK_TREE_VIEW(info->treeview);
	struct graph_info *ginfo = info->ginfo;
	GtkTreeModel *model;
	TraceViewStore *store;
	gint *selected;
	gint *tasks;

	if (!ginfo->handle)
		return;

	model = gtk_tree_view_get_model(trace_tree);
	if (!model)
		return;

	store = TRACE_VIEW_STORE(model);

	tasks = trace_graph_task_list(ginfo);
	selected = filter_task_pids(task_filter);

	trace_task_dialog(info->handle, tasks, selected, func, info);

	free(tasks);
	free(selected);
}

static void
list_tasks_clicked (gpointer data)
{
	struct shark_info *info = data;

	__list_tasks_clicked(info, info->list_task_filter,
			     update_list_task_filter_callback);
}

static void
list_hide_tasks_clicked (gpointer data)
{
	struct shark_info *info = data;

	__list_tasks_clicked(info, info->list_hide_tasks,
			     update_list_hide_task_filter_callback);
}

static void
__update_graph_task_filter_callback(struct shark_info *info,
				  gboolean accept,
				  gint *selected,
				  struct filter_task *task_filter)
{
	struct graph_info *ginfo = info->ginfo;
	int i;

	if (!accept)
		return;

	filter_task_clear(task_filter);

	if (selected) {
		for (i = 0; selected[i] >= 0; i++)
			filter_task_add_pid(task_filter, selected[i]);
	}

	trace_graph_refresh_filters(ginfo);

	/*
	 * The menu filters always enable the filters.
	 */
	if (ginfo->filter_available) {
		if (!ginfo->filter_enabled)
			trace_graph_filter_toggle(info->ginfo);

		if (info->sync_task_filters && !info->list_filter_enabled)
			filter_list_enable_clicked(info);
	}
}

static void
update_graph_task_filter_callback(gboolean accept,
				  gint *selected,
				  gint *non_select,
				  gpointer data)
{
	struct shark_info *info = data;
	struct graph_info *ginfo = info->ginfo;

	__update_graph_task_filter_callback(info, accept, selected,
					    ginfo->task_filter);
}

static void
update_graph_hide_task_filter_callback(gboolean accept,
				       gint *selected,
				       gint *non_select,
				       gpointer data)
{
	struct shark_info *info = data;
	struct graph_info *ginfo = info->ginfo;

	__update_graph_task_filter_callback(info, accept, selected,
					    ginfo->hide_tasks);
}

/* Callback for the clicked signal of the Tasks filter button */
static void
__graph_tasks_clicked (struct shark_info *info,
		       struct filter_task *task_filter,
		       trace_task_cb_func func)
{
	struct graph_info *ginfo = info->ginfo;
	gint *selected;
	gint *tasks;

	if (!ginfo->handle)
		return;

	tasks = trace_graph_task_list(ginfo);
	selected = filter_task_pids(task_filter);

	trace_task_dialog(ginfo->handle, tasks, selected, func, info);

	free(tasks);
	free(selected);
}

static void
graph_tasks_clicked (gpointer data)
{
	struct shark_info *info = data;
	struct graph_info *ginfo = info->ginfo;

	__graph_tasks_clicked(info, ginfo->task_filter,
			      update_graph_task_filter_callback);
}

static void
graph_hide_tasks_clicked (gpointer data)
{
	struct shark_info *info = data;
	struct graph_info *ginfo = info->ginfo;

	__graph_tasks_clicked(info, ginfo->hide_tasks,
			      update_graph_hide_task_filter_callback);
}

/* Callback for the clicked signal of the Events filter button */
static void
list_events_clicked (gpointer data)
{
	struct shark_info *info = data;
	struct event_filter *event_filter;
	GtkTreeView *trace_tree = GTK_TREE_VIEW(info->treeview);
	GtkTreeModel *model;
	TraceViewStore *store;
	gboolean all_events;

	model = gtk_tree_view_get_model(trace_tree);
	if (!model)
		return;

	store = TRACE_VIEW_STORE(model);

	all_events = trace_view_store_get_all_events_enabled(store);
	event_filter = trace_view_store_get_event_filter(store);

	/*
	 * This menu is not available when in sync, so we
	 * can call the treeview callback directly.
	 */
	trace_filter_event_filter_dialog(store->handle, event_filter,
					 all_events,
					 trace_view_event_filter_callback,
					 info->treeview);
}

static void
graph_event_filter_callback(gboolean accept,
			    gboolean all_events,
			    gchar **systems,
			    gint *events,
			    gpointer data)
{
	struct shark_info *info = data;

	trace_graph_event_filter_callback(accept, all_events,
					  systems, events,
					  info->ginfo);

	if (info->sync_event_filters)
		trace_view_event_filter_callback(accept, all_events, systems,
						 events, info->treeview);
}

static void
graph_events_clicked (gpointer data)
{
	struct shark_info *info = data;
	struct graph_info *ginfo = info->ginfo;
	gboolean all_events;

	all_events = ginfo->all_events;

	trace_filter_event_filter_dialog(info->handle,
					 ginfo->event_filter,
					 all_events,
					 graph_event_filter_callback,
					 info);
}

/* Callback for the clicked signal of the List advanced filter button */
static void
adv_list_filter_clicked (gpointer data)
{
	struct shark_info *info = data;
	struct event_filter *event_filter;
	GtkTreeView *trace_tree = GTK_TREE_VIEW(info->treeview);
	GtkTreeModel *model;
	TraceViewStore *store;

	model = gtk_tree_view_get_model(trace_tree);
	if (!model)
		return;

	store = TRACE_VIEW_STORE(model);

	event_filter = trace_view_store_get_event_filter(store);

	/*
	 * This menu is not available when in sync, so we
	 * can call the treeview callback directly.
	 */
	trace_adv_filter_dialog(store->handle, event_filter,
				trace_view_adv_filter_callback, trace_tree);
}

static void
graph_adv_filter_callback(gboolean accept,
			  const gchar *text,
			  gint *event_ids,
			  gpointer data)
{
	struct shark_info *info = data;
	struct graph_info *ginfo = info->ginfo;

	trace_graph_adv_filter_callback(accept, text, event_ids, ginfo);

	if (info->sync_event_filters)
		trace_view_adv_filter_callback(accept, text, event_ids,
					       info->treeview);
}

/* Callback for the clicked signal of the Graph advanced filter button */
static void
adv_graph_filter_clicked (gpointer data)
{
	struct shark_info *info = data;
	struct graph_info *ginfo = info->ginfo;

	trace_adv_filter_dialog(ginfo->handle, ginfo->event_filter,
				graph_adv_filter_callback, info);
}

/* Callback for the clicked signal of the CPUs filter button */
static void
cpus_clicked (gpointer data)
{
	struct shark_info *info = data;
	GtkTreeView *trace_tree = GTK_TREE_VIEW(info->treeview);
	TraceViewStore *store;
	gboolean all_cpus;
	guint64 *cpu_mask;

	if (!info->handle)
		return;

	store = TRACE_VIEW_STORE(gtk_tree_view_get_model(trace_tree));

	all_cpus = trace_view_store_get_all_cpus(store);
	cpu_mask = trace_view_store_get_cpu_mask(store);

	trace_filter_cpu_dialog(all_cpus, cpu_mask,
				trace_view_store_get_cpus(store),
				trace_view_cpu_filter_callback, trace_tree);
}

/* Callback for the clicked signal of the plot CPUs button */
static void
plot_cpu_clicked (gpointer data)
{
	struct shark_info *info = data;
	struct graph_info *ginfo = info->ginfo;
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
	struct shark_info *info = data;
	struct graph_info *ginfo = info->ginfo;
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

/* Callback for the clicked signal of the help contents button */
static void
help_content_clicked (gpointer data)
{
	struct shark_info *info = data;
	GError *error = NULL;
	gchar *link;

	link = "file://" __stringify(HELP_DIR) "/index.html";

	trace_show_help(info->window, link, &error);
}


/* Callback for the clicked signal of the help about button */
static void
help_about_clicked (gpointer data)
{
	struct shark_info *info = data;

	trace_dialog(GTK_WINDOW(info->window), TRACE_GUI_INFO,
		     "KernelShark\n\n"
		     "version %s\n\n"
		     "Copyright (C) 2009, 2010 Red Hat Inc\n\n"
		     " Author: Steven Rostedt <srostedt@redhat.com>",
		     VERSION_STRING);
}

static void graph_follows_tree(struct shark_info *info,
			       GtkTreeView *treeview,
			       GtkTreePath *path)
{
	TraceViewRecord *rec;
	GtkTreeModel *model;
	gchar *spath;
	guint64 time;
	gint row;

	model = gtk_tree_view_get_model(treeview);
	/* This can be called when we NULL out the model */
	if (!model)
		return;

	spath = gtk_tree_path_to_string(path);
	row = atoi(spath);
	g_free(spath);

	rec = trace_view_store_get_visible_row(TRACE_VIEW_STORE(model), row);
	time = rec->timestamp;
	trace_graph_select_by_time(info->ginfo, time);
}

static void row_double_clicked(GtkTreeView        *treeview,
			       GtkTreePath        *path,
			       GtkTreeViewColumn  *col,
			       gpointer            data)
{
	struct shark_info *info = data;

	graph_follows_tree(info, treeview, path);
}

static void cursor_changed(GtkTreeView        *treeview,
			   gpointer            data)
{
	struct shark_info *info = data;
	GtkTreePath *path;

	if (!info->graph_follows)
		return;

	gtk_tree_view_get_cursor(treeview, &path, NULL);

	if (!path)
		return;

	graph_follows_tree(info, treeview, path);

	gtk_tree_path_free(path);
}

static void
filter_graph_enable_clicked (gpointer data)
{
	struct shark_info *info = data;

	trace_graph_filter_toggle(info->ginfo);
}

static void
filter_list_enable_clicked (gpointer data)
{
	struct shark_info *info = data;
	struct filter_task *task_filter;
	struct filter_task *hide_tasks;

	info->list_filter_enabled ^= 1;

	if (info->sync_task_filters) {
		task_filter = info->ginfo->task_filter;
		hide_tasks = info->ginfo->hide_tasks;
	} else {
		task_filter = info->list_task_filter;
		hide_tasks = info->list_hide_tasks;
	}

	if (info->list_filter_enabled)
		trace_view_update_filters(info->treeview,
					  task_filter, hide_tasks);
	else
		trace_view_update_filters(info->treeview, NULL, NULL);
}

static void
filter_update_list_filter(struct shark_info *info,
			  struct filter_task *filter,
			  struct filter_task *other_filter)
{
	struct filter_task_item *task;
	int pid = info->selected_task;

	task = filter_task_find_pid(filter, pid);
	if (task) {
		filter_task_remove_pid(filter, pid);
		if (!filter_task_count(filter) &&
		    !filter_task_count(other_filter)) {
			info->list_filter_enabled = 0;
			info->list_filter_available = 0;
		}
	} else {
		filter_task_add_pid(filter, pid);
		info->list_filter_available = 1;
	}
}

static void
filter_add_task_clicked (gpointer data)
{
	struct shark_info *info = data;
	int pid = info->selected_task;

	if (info->sync_task_filters) {
		trace_graph_filter_add_remove_task(info->ginfo, pid);
		return;
	}

	filter_update_list_filter(info, info->list_task_filter, info->list_hide_tasks);
	trace_view_update_filters(info->treeview,
				  info->list_task_filter, info->list_hide_tasks);
}

static void
filter_graph_add_task_clicked (gpointer data)
{
	struct shark_info *info = data;

	trace_graph_filter_add_remove_task(info->ginfo, info->selected_task);
}

static void
filter_hide_task_clicked (gpointer data)
{
	struct shark_info *info = data;

	if (info->sync_task_filters) {
		trace_graph_filter_hide_show_task(info->ginfo, info->selected_task);
		return;
	}

	filter_update_list_filter(info, info->list_hide_tasks, info->list_task_filter);
	trace_view_update_filters(info->treeview,
				  info->list_task_filter, info->list_hide_tasks);
}

static void
filter_graph_hide_task_clicked (gpointer data)
{
	struct shark_info *info = data;

	trace_graph_filter_hide_show_task(info->ginfo, info->selected_task);
}

static void
filter_clear_tasks_clicked (gpointer data)
{
	struct shark_info *info = data;

	if (info->sync_task_filters) {
		trace_graph_clear_tasks(info->ginfo);
		return;
	}

	filter_task_clear(info->list_task_filter);
	filter_task_clear(info->list_hide_tasks);
	trace_view_update_filters(info->treeview, NULL, NULL);

	info->list_filter_available = 0;
	info->list_filter_enabled = 0;
}

static void
filter_graph_clear_tasks_clicked (gpointer data)
{
	struct shark_info *info = data;

	trace_graph_clear_tasks(info->ginfo);
}

static void graph_check_toggle(gpointer data, GtkWidget *widget)
{
	struct shark_info *info = data;

	info->graph_follows = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));
}

static void set_menu_label(GtkWidget *menu, const char *comm, int pid,
			   const char *fmt)
{
	int len = strlen(comm) + strlen(fmt) + 50;
	char text[len];

	snprintf(text, len, fmt, comm, pid);

	gtk_menu_item_set_label(GTK_MENU_ITEM(menu), text);
}

static gboolean
do_tree_popup(GtkWidget *widget, GdkEventButton *event, gpointer data)
{
	struct shark_info *info = data;
	struct graph_info *ginfo = info->ginfo;
	static GtkWidget *menu;
	static GtkWidget *menu_filter_graph_enable;
	static GtkWidget *menu_filter_list_enable;
	static GtkWidget *menu_filter_add_task;
	static GtkWidget *menu_filter_hide_task;
	static GtkWidget *menu_filter_clear_tasks;
	static GtkWidget *menu_filter_graph_add_task;
	static GtkWidget *menu_filter_graph_hide_task;
	static GtkWidget *menu_filter_graph_clear_tasks;
	struct pevent_record *record;
	TraceViewRecord *vrec;
	GtkTreeModel *model;
	const char *comm;
	gint pid;
	gint len;
	guint64 offset;
	gint row;
	gint cpu;

	if (!menu) {
		menu = gtk_menu_new();
		menu_filter_graph_enable = gtk_menu_item_new_with_label("Enable Graph Task Filter");
		gtk_widget_show(menu_filter_graph_enable);
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), menu_filter_graph_enable);

		g_signal_connect_swapped (G_OBJECT (menu_filter_graph_enable), "activate",
					  G_CALLBACK (filter_graph_enable_clicked),
					  data);

		menu_filter_list_enable = gtk_menu_item_new_with_label("Enable List Task Filter");
		gtk_widget_show(menu_filter_list_enable);
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), menu_filter_list_enable);

		g_signal_connect_swapped (G_OBJECT (menu_filter_list_enable), "activate",
					  G_CALLBACK (filter_list_enable_clicked),
					  data);

		menu_filter_add_task = gtk_menu_item_new_with_label("Add Task");
		gtk_widget_show(menu_filter_add_task);
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), menu_filter_add_task);

		g_signal_connect_swapped (G_OBJECT (menu_filter_add_task), "activate",
					  G_CALLBACK (filter_add_task_clicked),
					  data);

		menu_filter_graph_add_task = gtk_menu_item_new_with_label("Add Task to Graph");
		gtk_widget_show(menu_filter_graph_add_task);
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), menu_filter_graph_add_task);

		g_signal_connect_swapped (G_OBJECT (menu_filter_graph_add_task), "activate",
					  G_CALLBACK (filter_graph_add_task_clicked),
					  data);

		menu_filter_hide_task = gtk_menu_item_new_with_label("Hide Task");
		gtk_widget_show(menu_filter_hide_task);
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), menu_filter_hide_task);

		g_signal_connect_swapped (G_OBJECT (menu_filter_hide_task), "activate",
					  G_CALLBACK (filter_hide_task_clicked),
					  data);

		menu_filter_graph_hide_task = gtk_menu_item_new_with_label("Hide Task from Graph");
		gtk_widget_show(menu_filter_graph_hide_task);
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), menu_filter_graph_hide_task);

		g_signal_connect_swapped (G_OBJECT (menu_filter_graph_hide_task), "activate",
					  G_CALLBACK (filter_graph_hide_task_clicked),
					  data);

		menu_filter_clear_tasks = gtk_menu_item_new_with_label("Clear Task Filter");
		gtk_widget_show(menu_filter_clear_tasks);
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), menu_filter_clear_tasks);

		g_signal_connect_swapped (G_OBJECT (menu_filter_clear_tasks), "activate",
					  G_CALLBACK (filter_clear_tasks_clicked),
					  data);

		menu_filter_graph_clear_tasks =
			gtk_menu_item_new_with_label("Clear Graph Task Filter");
		gtk_widget_show(menu_filter_graph_clear_tasks);
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), menu_filter_graph_clear_tasks);

		g_signal_connect_swapped (G_OBJECT (menu_filter_graph_clear_tasks), "activate",
					  G_CALLBACK (filter_graph_clear_tasks_clicked),
					  data);

	}

	row = trace_view_get_selected_row(GTK_WIDGET(info->treeview));
	if (row >= 0) {

		model = gtk_tree_view_get_model(GTK_TREE_VIEW(info->treeview));
		vrec = trace_view_store_get_row(TRACE_VIEW_STORE(model), row);
		offset = vrec->offset;

		record = tracecmd_read_at(info->handle, offset, &cpu);

		if (record) {
			pid = pevent_data_pid(ginfo->pevent, record);
			comm = pevent_data_comm_from_pid(ginfo->pevent, pid);

			len = strlen(comm) + 50;

			if (info->sync_task_filters) {
				if (trace_graph_filter_task_find_pid(ginfo, pid))
					set_menu_label(menu_filter_add_task, comm, pid,
						       "Remove %s-%d from filters");
				else
					set_menu_label(menu_filter_add_task, comm, pid,
						       "Add %s-%d to filters");

				if (trace_graph_hide_task_find_pid(ginfo, pid))
					set_menu_label(menu_filter_hide_task, comm, pid,
						       "Show %s-%d");
				else
					set_menu_label(menu_filter_hide_task, comm, pid,
						       "Hide %s-%d");

				gtk_widget_hide(menu_filter_graph_add_task);
				gtk_widget_hide(menu_filter_graph_hide_task);

			} else {
				if (filter_task_find_pid(info->list_task_filter, pid))
					set_menu_label(menu_filter_add_task, comm, pid,
						       "Remove %s-%d from List filter");
				else
					set_menu_label(menu_filter_add_task, comm, pid,
						       "Add %s-%d to List filter");

				if (filter_task_find_pid(info->list_hide_tasks, pid))
					set_menu_label(menu_filter_hide_task, comm, pid,
						       "Show %s-%d in List");
				else
					set_menu_label(menu_filter_hide_task, comm, pid,
						       "Hide %s-%d from List");

				if (trace_graph_filter_task_find_pid(ginfo, pid))
					set_menu_label(menu_filter_graph_add_task, comm, pid,
						       "Remove %s-%d from Graph filter");
				else
					set_menu_label(menu_filter_graph_add_task, comm, pid,
						       "Add %s-%d to Graph filter");

				if (trace_graph_hide_task_find_pid(ginfo, pid))
					set_menu_label(menu_filter_graph_hide_task, comm, pid,
						       "Show %s-%d in Graph");
				else
					set_menu_label(menu_filter_graph_hide_task, comm, pid,
						       "Hide %s-%d from Graph");

				gtk_widget_show(menu_filter_graph_add_task);
				gtk_widget_show(menu_filter_graph_hide_task);
			}

			ginfo->filter_task_selected = pid;

			info->selected_task = pid;

			gtk_widget_show(menu_filter_add_task);
			gtk_widget_show(menu_filter_hide_task);
			free_record(record);
		}
	} else {
		gtk_widget_hide(menu_filter_add_task);
		gtk_widget_hide(menu_filter_hide_task);
		gtk_widget_hide(menu_filter_graph_add_task);
		gtk_widget_hide(menu_filter_graph_hide_task);
	}

	if (ginfo->filter_enabled)
		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_graph_enable),
					"Disable Graph Task Filter");
	else
		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_graph_enable),
					"Enable Graph Task Filter");

	if (info->list_filter_enabled)
		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_list_enable),
					"Disable List Task Filter");
	else
		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_list_enable),
					"Enable List Task Filter");

	if (ginfo->filter_available)
		gtk_widget_set_sensitive(menu_filter_graph_enable, TRUE);
	else
		gtk_widget_set_sensitive(menu_filter_graph_enable, FALSE);

	if ((info->sync_task_filters && ginfo->filter_available) ||
	    (!info->sync_task_filters && info->list_filter_available))
		gtk_widget_set_sensitive(menu_filter_list_enable, TRUE);
	else
		gtk_widget_set_sensitive(menu_filter_list_enable, FALSE);

	if (info->sync_task_filters) {
		if (filter_task_count(ginfo->task_filter) ||
		    filter_task_count(ginfo->hide_tasks))
			gtk_widget_set_sensitive(menu_filter_clear_tasks, TRUE);
		else
			gtk_widget_set_sensitive(menu_filter_clear_tasks, FALSE);

		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_clear_tasks),
					"Clear Task Filter");
		gtk_widget_hide(menu_filter_graph_clear_tasks);
	} else {
		if (filter_task_count(ginfo->task_filter) ||
		    filter_task_count(ginfo->hide_tasks))
			gtk_widget_set_sensitive(menu_filter_graph_clear_tasks, TRUE);
		else
			gtk_widget_set_sensitive(menu_filter_graph_clear_tasks, FALSE);

		if (filter_task_count(info->list_task_filter) ||
		    filter_task_count(info->list_hide_tasks))
			gtk_widget_set_sensitive(menu_filter_clear_tasks, TRUE);
		else
			gtk_widget_set_sensitive(menu_filter_clear_tasks, FALSE);

		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_clear_tasks),
					"Clear List Task Filter");
		gtk_widget_show(menu_filter_graph_clear_tasks);
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

static void sig_end(int sig)
{
	fprintf(stderr, "kernelshark: Received SIGINT\n");
	exit(0);
}

void kernel_shark(int argc, char **argv)
{
	struct tracecmd_input *handle;
	struct shark_info *info;
	struct stat st;
	GtkWidget *window;
	GtkWidget *vbox;
	GtkWidget *vbox2;
	GtkWidget *vpaned;
	GtkWidget *hbox;
	GtkWidget *menu_bar;
	GtkWidget *menu;
	GtkWidget *menu_item;
	GtkWidget *sub_item;
	GtkWidget *scrollwin;
	GtkWidget *widget;
	GtkWidget *label;
	GtkWidget *spin;
	GtkWidget *check;
	GtkWidget *statusbar;
	int ret;
	int c;

	g_thread_init(NULL);
	gdk_threads_init();

	gtk_init(&argc, &argv);

	while ((c = getopt(argc, argv, "hvi:")) != -1) {
		switch(c) {
		case 'h':
			usage(basename(argv[0]));
			return;
		case 'v':
			printf("%s - %s\n",
			       basename(argv[0]),
			       VERSION_STRING);
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

	/* The python plugin overrides ^C */
	signal(SIGINT, sig_end);

	info = g_new0(typeof(*info), 1);
	if (!info)
		die("Unable to allocate info");

	if (!input_file) {
		ret = stat(default_input_file, &st);
		if (ret >= 0)
			input_file = default_input_file;
	}

	if (input_file)
		handle = tracecmd_open(input_file);
	else
		handle = NULL;

	info->handle = handle;
	info->sync_task_filters = TRUE;
	info->sync_event_filters = TRUE;

	/* --- Main window --- */

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	info->window = window;

	trace_dialog_register_window(window);

	if (input_file)
		update_title(window, input_file);

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
				  (gpointer) info);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- File - Load Filter --- */

	sub_item = gtk_menu_item_new_with_label("Load filter");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	info->load_filter_menu = sub_item;

	/* We do need to show menu items */
	gtk_widget_show(sub_item);

	update_load_filter(info);


	/* --- File - Save Filter Option --- */

	sub_item = gtk_menu_item_new_with_label("Save filter");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);

	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (save_filter_clicked),
				  (gpointer) info);


	/* --- File - Export Filter Option --- */

	sub_item = gtk_menu_item_new_with_label("Export filters");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (export_filters_clicked),
				  (gpointer) info);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);

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



	/* --- Filter - Sync task Option --- */

	sub_item = gtk_menu_item_new_with_label("Unsync Graph and List Task Filters");

	info->task_sync_menu = sub_item;

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect (G_OBJECT (sub_item), "activate",
			  G_CALLBACK (sync_task_filter_clicked),
			  (gpointer) info);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- Filter - Sync events Option --- */

	sub_item = gtk_menu_item_new_with_label("Unsync Graph and List Event Filters");

	info->events_sync_menu = sub_item;

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect (G_OBJECT (sub_item), "activate",
			  G_CALLBACK (sync_events_filter_clicked),
			  (gpointer) info);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- Filter - Graph Tasks Option --- */

	sub_item = gtk_menu_item_new_with_label("tasks");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (graph_tasks_clicked),
				  (gpointer) info);

	info->graph_task_menu = sub_item;

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- Filter - Graph Hide Tasks Option --- */

	sub_item = gtk_menu_item_new_with_label("hide tasks");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (graph_hide_tasks_clicked),
				  (gpointer) info);

	info->graph_hide_task_menu = sub_item;

	/* We do need to show menu items */
	gtk_widget_show(sub_item);



	/* --- Filter - Events Option --- */

	/* The list and graph events start off insync */
	sub_item = gtk_menu_item_new_with_label("events");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (graph_events_clicked),
				  (gpointer) info);

	info->graph_events_menu = sub_item;

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- Filter - Graph Advanced Events Option --- */

	/* The list and graph events start off in sync */
	sub_item = gtk_menu_item_new_with_label("advanced events");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (adv_graph_filter_clicked),
				  (gpointer) info);

	info->graph_adv_events_menu = sub_item;

	/* We do need to show menu items */
	gtk_widget_show(sub_item);

	/* --- Filter - List Tasks Option --- */

	sub_item = gtk_menu_item_new_with_label("list tasks");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (list_tasks_clicked),
				  (gpointer) info);

	info->list_task_menu = sub_item;

	/* Only show this item when list and graph tasks are not synced */


	/* --- Filter - List Hide Tasks Option --- */

	sub_item = gtk_menu_item_new_with_label("list hide tasks");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (list_hide_tasks_clicked),
				  (gpointer) info);

	info->list_hide_task_menu = sub_item;

	/* Only show this item when list and graph tasks are not synced */

	/* --- Filter - List Events Option --- */

	sub_item = gtk_menu_item_new_with_label("list events");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (list_events_clicked),
				  (gpointer) info);

	info->list_events_menu = sub_item;

	/* We do not show this menu (yet) */


	/* --- Filter - List Advanced Events Option --- */

	sub_item = gtk_menu_item_new_with_label("list advanced event");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (adv_list_filter_clicked),
				  (gpointer) info);

	info->list_adv_events_menu = sub_item;
	/* We do not show this menu (yet) */


	/* --- Filter - CPUs Option --- */

	sub_item = gtk_menu_item_new_with_label("list CPUs");

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
				  (gpointer) info);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- Plot - Tasks Option --- */

	sub_item = gtk_menu_item_new_with_label("Tasks");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (plot_tasks_clicked),
				  (gpointer) info);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- End Plot Options --- */
	gtk_menu_item_set_submenu(GTK_MENU_ITEM (menu_item), menu);



	/* --- Capture Option --- */

	menu_item = gtk_menu_item_new_with_label("Capture");
	gtk_widget_show(menu_item);

	gtk_menu_bar_append(GTK_MENU_BAR (menu_bar), menu_item);

	menu = gtk_menu_new();    /* Don't need to show menus */



	/* --- Capture - Record Option --- */

	sub_item = gtk_menu_item_new_with_label("Record");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (tracecmd_capture_clicked),
				  (gpointer) info);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);

	/* --- End Capture Options --- */
	gtk_menu_item_set_submenu(GTK_MENU_ITEM (menu_item), menu);


	/* --- Help Option --- */

	menu_item = gtk_menu_item_new_with_label("Help");
	gtk_widget_show(menu_item);

	gtk_menu_bar_append(GTK_MENU_BAR (menu_bar), menu_item);

	menu = gtk_menu_new();    /* Don't need to show menus */


	/* --- Help - Contents Option --- */

	sub_item = gtk_menu_item_new_with_label("Contents");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (help_content_clicked),
				  (gpointer) info);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- Help - About Option --- */

	sub_item = gtk_menu_item_new_with_label("About");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (help_about_clicked),
				  (gpointer) info);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- End Help Options --- */
	gtk_menu_item_set_submenu(GTK_MENU_ITEM (menu_item), menu);


	/* --- Top Level Vpaned --- */

	vpaned = gtk_vpaned_new();
	gtk_box_pack_start(GTK_BOX(vbox), vpaned, TRUE, TRUE, 0);
	gtk_widget_show(vpaned);
	gtk_paned_set_position(GTK_PANED(vpaned), TRACE_HEIGHT / 2);


	/* --- Set up Graph --- */

	info->graph_cbs.select = ks_graph_select;
	info->graph_cbs.filter = ks_graph_filter;

	info->ginfo = trace_graph_create_with_callbacks(handle, &info->graph_cbs);
	widget = trace_graph_get_window(info->ginfo);
	gtk_paned_add1(GTK_PANED(vpaned), widget);
	gtk_widget_show(widget);


	/* --- Tree View Vbox --- */

	vbox2 = gtk_vbox_new(FALSE, 0);
	gtk_paned_add2(GTK_PANED(vpaned), vbox2);
	gtk_widget_show(vbox2);

	/* --- Paging Hbox --- */

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox2), hbox, FALSE, FALSE, 0);
	gtk_widget_show(hbox);

	/* --- Page Spin Button --- */

	label = gtk_label_new("Page");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	spin = gtk_spin_button_new(NULL, 1.0, 0);
	gtk_spin_button_set_range(GTK_SPIN_BUTTON(spin), 1, 1);
	gtk_box_pack_start(GTK_BOX(hbox), spin, FALSE, FALSE, 0);
	gtk_widget_show(spin);

	info->spin = spin;

	/* --- Search --- */

	/* The tree needs its columns loaded now */
	info->treeview = gtk_tree_view_new();
	trace_view_load(info->treeview, handle, spin);

	label = gtk_label_new("      Search: ");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	trace_view_search_setup(GTK_BOX(hbox), GTK_TREE_VIEW(info->treeview));

	check = gtk_check_button_new_with_label("graph follows");
	gtk_box_pack_start(GTK_BOX(hbox), check, TRUE, TRUE, 0);
	gtk_widget_show(check);

	g_signal_connect_swapped (check, "toggled",
				  G_CALLBACK (graph_check_toggle),
				  (gpointer) info);


	/* --- Top Level Trace View Paging Hbox --- */

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox2), hbox, TRUE, TRUE, 0);
	gtk_widget_show(hbox);

	/* --- Scroll Window --- */
	scrollwin = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrollwin),
				       GTK_POLICY_AUTOMATIC,
				       GTK_POLICY_AUTOMATIC);
	gtk_box_pack_start(GTK_BOX (hbox), scrollwin, TRUE, TRUE, 0);
	gtk_widget_show(scrollwin);

	/* --- Set up Trace Tree --- */

	g_signal_connect(info->treeview, "row-activated",
			 (GCallback)row_double_clicked, info);

	g_signal_connect(info->treeview, "cursor-changed",
			 (GCallback)cursor_changed, info);

	gtk_container_add(GTK_CONTAINER(scrollwin), info->treeview);

	gtk_signal_connect(GTK_OBJECT(info->treeview), "button_press_event",
			   (GtkSignalFunc) button_press_event, info);

	gtk_widget_show(info->treeview);

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
			    (gpointer) info);

	gtk_widget_set_size_request(window, TRACE_WIDTH, TRACE_HEIGHT);

	gdk_threads_enter();
	gtk_widget_show (window);

	gtk_main ();
	gdk_threads_leave();
}

int main(int argc, char **argv)
{
	kernel_shark(argc, argv);
	return 0;
}
