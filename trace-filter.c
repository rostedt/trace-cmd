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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "trace-cmd.h"
#include "trace-local.h"
#include "trace-view-store.h"
#include "trace-view.h"

#include "cpu.h"
#include "util.h"
#include "list.h"

#define DIALOG_WIDTH	400
#define DIALOG_HEIGHT	600

#define TEXT_DIALOG_WIDTH	600
#define TEXT_DIALOG_HEIGHT	400

int str_cmp(const void *a, const void *b)
{
	char * const * sa = a;
	char * const * sb = b;

	return strcmp(*sa, *sb);
}

int id_cmp(const void *a, const void *b)
{
	const gint *ia = a;
	const gint *ib = b;

	if (*ia > *ib)
		return 1;
	if (*ia < *ib)
		return -1;
	return 0;
}

struct dialog_helper {
	GtkWidget		*dialog;
	gpointer		data;
};

/**
 * trace_array_add - allocate and add an int to an array.
 * @array: address of array to allocate
 * @count: address of the current count of array data
 * @val:  the value to append to the array.
 *
 * The first call to this, @array should be uninitialized
 * and @count should be zero. @array will be malloced and
 * val will be added to it. If count is greater than zero,
 * then array will be realloced, and val will be appened
 * to it.
 *
 * This also always ends the array with -1, so the values are
 * assumed to always be positive.
 *
 * @array must be freed with free().
 */
void trace_array_add(gint **array, gint *count, gint val)
{
	if (*count)
		*array = realloc(*array, sizeof(val) * (*count + 2));
	else
		*array = malloc(sizeof(val) * 2);
	(*array)[(*count)++] = val;
	(*array)[*count] = -1;
}

/* --- event info box --- */

struct event_combo_info {
	struct pevent		*pevent;
	GtkWidget		*event_combo;
	GtkWidget		*op_combo;
	GtkWidget		*field_combo;
};

struct adv_event_filter_helper {
	trace_adv_filter_cb_func	func;
	GtkTreeView			*view;
	GtkWidget			*entry;
	struct event_combo_info		combo_info;
	gpointer			data;
};

static GtkTreeModel *create_event_combo_model(struct pevent *pevent)
{
	GtkTreeStore *tree;
	GtkTreeIter sys_iter;
	GtkTreeIter iter;
	struct event_format **events;
	struct event_format *event;
	const char *last_sys = NULL;
	int i;

	events = pevent_list_events(pevent, EVENT_SORT_SYSTEM);
	if (!events)
		return NULL;

	tree = gtk_tree_store_new(1, G_TYPE_STRING);


	for (i = 0; events[i]; i++) {
		event = events[i];
		if (!last_sys || strcmp(last_sys, event->system) != 0) {
			last_sys = event->system;

			gtk_tree_store_append(tree, &sys_iter, NULL);
			gtk_tree_store_set(tree, &sys_iter,
					   0, last_sys,
					   -1);
		}
		gtk_tree_store_append(tree, &iter, &sys_iter);
		gtk_tree_store_set(tree, &iter,
				   0, event->name,
				   -1);
	}

	return GTK_TREE_MODEL(tree);
}

static GtkTreeModel *create_op_combo_model(struct pevent *pevent)
{
	GtkListStore *list;
	GtkTreeIter iter;
	int i;
	const gchar *ops[] = {":", ",", "==", "!=", "<", ">", "<=",
			      ">=", "=~", "!~", "!", "(", ")", "+",
			      "-", "*", "/", "<<", ">>", "&&", "||",
			      "&", "|", NULL};

	list = gtk_list_store_new(1, G_TYPE_STRING);

	for (i = 0; ops[i]; i++) {
		gtk_list_store_append(list, &iter);
		gtk_list_store_set(list, &iter,
				   0, ops[i],
				   -1);
	}

	return GTK_TREE_MODEL(list);
}

static GtkTreeModel *create_field_combo_model(struct pevent *pevent)
{
	GtkListStore *list;
	GtkTreeIter iter;
	struct event_format **events;
	struct format_field **fields;
	struct format_field *field;
	int i;

	events = pevent_list_events(pevent, EVENT_SORT_SYSTEM);
	if (!events)
		return NULL;

	list = gtk_list_store_new(1, G_TYPE_STRING);

	/* use any event for common fields */
	fields = pevent_event_common_fields(events[0]);

	for (i = 0; fields[i]; i++) {
		field = fields[i];
		gtk_list_store_append(list, &iter);
		gtk_list_store_set(list, &iter,
				   0, field->name,
				   -1);
	}

	free(fields);

	return GTK_TREE_MODEL(list);
}

static void update_field_combo(struct pevent *pevent,
			       GtkWidget *combo,
			       const char *system,
			       const char *event_name)
{
	struct event_format **events;
	struct event_format *event;
	struct format_field **fields;
	struct format_field *field;
	GtkTreeModel *model;
	GtkListStore *list;
	GtkTreeIter iter;
	int i;

	model = gtk_combo_box_get_model(GTK_COMBO_BOX(combo));
	if (!model)
		return;

	if (!gtk_tree_model_get_iter_first(model, &iter))
		return;

	if (event_name) {
		event = pevent_find_event_by_name(pevent, system, event_name);
		if (!event)
			return;
	} else {
		/* use any event */
		events = pevent_list_events(pevent, EVENT_SORT_SYSTEM);
		if (!events)
			return;
		event = events[0];
	}

	/* Remove all the objects and reset it */
	g_object_ref(model);
	gtk_combo_box_set_model(GTK_COMBO_BOX(combo), NULL);

	list = GTK_LIST_STORE(model);

	while (gtk_list_store_remove(list, &iter))
		;

	/* always load the common fields first */
	fields = pevent_event_common_fields(event);
	for (i = 0; fields[i]; i++) {
		field = fields[i];
		gtk_list_store_append(list, &iter);
		gtk_list_store_set(list, &iter,
				   0, field->name,
				   -1);
	}
	free(fields);

	/* Now add event specific events */
	if (event_name) {
		fields = pevent_event_fields(event);
		for (i = 0; fields[i]; i++) {
			field = fields[i];
			gtk_list_store_append(list, &iter);
			gtk_list_store_set(list, &iter,
					   0, field->name,
					   -1);
		}
		free(fields);
	}
	gtk_combo_box_set_model(GTK_COMBO_BOX(combo), model);
	g_object_unref(model);

	if (!gtk_tree_model_get_iter_first(model, &iter))
		return;
	gtk_combo_box_set_active_iter(GTK_COMBO_BOX(combo), &iter);
}

static void event_combo_changed(GtkComboBox *combo, gpointer data)
{
	struct event_combo_info *info = data;
	GtkWidget *field_combo = info->field_combo;
	GtkTreeIter parent_iter;
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkTreePath *path;
	gchar *system_name = NULL;
	gchar *event_name = NULL;
	gint depth;

	model = gtk_combo_box_get_model(combo);
	if (!model)
		return;

	if (!gtk_combo_box_get_active_iter(combo, &iter))
		return;

	path = gtk_tree_model_get_path(model, &iter);
	if (!path)
		return;

	depth = gtk_tree_path_get_depth(path);

	if (depth > 1) {
		gtk_tree_model_get(model, &iter,
				   0, &event_name,
				   -1);
		gtk_tree_model_iter_parent(model, &parent_iter,
					   &iter);
		gtk_tree_model_get(model, &parent_iter,
				   0, &system_name,
				   -1);
	} else
		gtk_tree_model_get(model, &iter,
				   0, &system_name,
				   -1);

	update_field_combo(info->pevent, field_combo,
			   system_name, event_name);

	g_free(system_name);
	g_free(event_name);
	gtk_tree_path_free(path);
}

static void insert_combo_text(struct event_combo_info *info,
			      GtkComboBox *combo)
{
	struct adv_event_filter_helper *event_helper;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkWidget *entry;
	gchar *text;
	gint pos;

	model = gtk_combo_box_get_model(combo);
	if (!model)
		return;

	if (!gtk_combo_box_get_active_iter(combo, &iter))
		return;

	gtk_tree_model_get(model, &iter,
			   0, &text,
			   -1);

	event_helper = container_of(info, typeof(*event_helper), combo_info);
	entry = event_helper->entry;

	pos = gtk_editable_get_position(GTK_EDITABLE(entry));
	gtk_editable_insert_text(GTK_EDITABLE(entry), text, strlen(text), &pos);
	gtk_editable_set_position(GTK_EDITABLE(entry), pos);
	gtk_editable_insert_text(GTK_EDITABLE(entry), " ", 1, &pos);
	gtk_editable_set_position(GTK_EDITABLE(entry), pos);

	g_free(text);
}

static void event_insert_pressed(GtkButton *button,
				 gpointer data)
{
	struct event_combo_info *info = data;

	insert_combo_text(info, GTK_COMBO_BOX(info->event_combo));
}

static void op_insert_pressed(GtkButton *button,
				 gpointer data)
{
	struct event_combo_info *info = data;

	insert_combo_text(info, GTK_COMBO_BOX(info->op_combo));
}

static void field_insert_pressed(GtkButton *button,
				 gpointer data)
{
	struct event_combo_info *info = data;

	insert_combo_text(info, GTK_COMBO_BOX(info->field_combo));
}

static GtkWidget *
create_combo_box(struct event_combo_info *info, GtkWidget *hbox, const gchar *text,
		 GtkTreeModel *(*combo_model_create)(struct pevent *pevent),
		 void (*insert_pressed)(GtkButton *button, gpointer data))
{
	GtkCellRenderer *renderer;
	GtkTreeModel *model;
	GtkWidget *label;
	GtkWidget *hbox2;
	GtkWidget *combo;
	GtkWidget *button;

	hbox2 = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), hbox2, TRUE, TRUE, 0);
	gtk_widget_show(hbox2);

	label = gtk_label_new(text);
	gtk_box_pack_start(GTK_BOX(hbox2), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	/* --- Set up the selection combo box --- */

	model = combo_model_create(info->pevent);

	renderer = gtk_cell_renderer_text_new();

	combo = gtk_combo_box_new_with_model(model);
	gtk_box_pack_start(GTK_BOX(hbox2), combo, FALSE, FALSE, 0);
	gtk_widget_show(combo);

	/* Free model with combobox */
	g_object_unref(model);

	gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(combo),
				   renderer,
				   TRUE);
	gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(combo),
				       renderer,
				       "text", 0,
				       NULL);

	gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);


	/* --- add insert button --- */

	button = gtk_button_new_with_label("Insert");
	gtk_box_pack_start(GTK_BOX(hbox2), button, FALSE, FALSE, 0);
	gtk_widget_show(button);

	g_signal_connect (button, "pressed",
			  G_CALLBACK (insert_pressed),
			  (gpointer) info);

	return combo;
}

static GtkWidget *event_info_box(struct event_combo_info *info)
{
	GtkWidget *hbox;
	GtkWidget *event_combo;
	GtkWidget *op_combo;
	GtkWidget *field_combo;

	hbox = gtk_hbox_new(FALSE, 0);

	event_combo = create_combo_box(info, hbox, "Event:",
				       create_event_combo_model,
				       event_insert_pressed);

	op_combo = create_combo_box(info, hbox, "Op:",
				    create_op_combo_model,
				    op_insert_pressed);

	field_combo = create_combo_box(info, hbox, "Field:",
				       create_field_combo_model,
				       field_insert_pressed);


	g_signal_connect (event_combo, "changed",
			  G_CALLBACK (event_combo_changed),
			  (gpointer) info);

	info->event_combo = event_combo;
	info->op_combo = op_combo;
	info->field_combo = field_combo;

	return hbox;
}


/* --- advance filter --- */

enum {
	ADV_COL_DELETE,
	ADV_COL_EVENT,
	ADV_COL_FILTER,
	ADV_COL_ID,
	NUM_ADV_FILTER_COLS,
};

static gint *get_event_ids(GtkTreeView *treeview)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	gboolean active;
	gint *ids = NULL;
	gint id;
	int count = 0;

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(treeview));
	if (!model)
		return NULL;

	if (!gtk_tree_model_iter_children(model, &iter, NULL))
		return NULL;

	for (;;) {
		gtk_tree_model_get(GTK_TREE_MODEL(model), &iter,
				   ADV_COL_DELETE, &active,
				   ADV_COL_ID, &id,
				   -1);

		if (active)
			trace_array_add(&ids, &count, id);

		if (!gtk_tree_model_iter_next(model, &iter))
			break;
	}

	return ids;
}

/* Callback for the clicked signal of the advanced filter button */
static void
adv_filter_dialog_response (gpointer data, gint response_id)
{
	struct dialog_helper *helper = data;
	struct adv_event_filter_helper *event_helper = helper->data;
	const gchar *text;
	gint *event_ids;

	switch (response_id) {
	case GTK_RESPONSE_ACCEPT:
		text = gtk_entry_get_text(GTK_ENTRY(event_helper->entry));
		event_ids = get_event_ids(event_helper->view);
		event_helper->func(TRUE, text, event_ids, event_helper->data);
		free(event_ids);
		break;
	case GTK_RESPONSE_REJECT:
		event_helper->func(FALSE, NULL, NULL, event_helper->data);
		break;
	default:
		break;
	};

	gtk_widget_destroy(GTK_WIDGET(helper->dialog));

	g_free(event_helper);
	g_free(helper);
}

static GtkTreeModel *
create_tree_filter_model(struct tracecmd_input *handle,
		       struct event_filter *event_filter)
{
	GtkTreeStore *treestore;
	GtkTreeIter iter_events;
	struct pevent *pevent;
	struct event_format **events;
	char *str;
	gint i;

	pevent = tracecmd_get_pevent(handle);

	treestore = gtk_tree_store_new(NUM_ADV_FILTER_COLS, G_TYPE_BOOLEAN,
				       G_TYPE_STRING, G_TYPE_STRING,
				       G_TYPE_INT);

	events = pevent_list_events(pevent, EVENT_SORT_SYSTEM);
	if (!events)
		return GTK_TREE_MODEL(treestore);

	for (i = 0; events[i]; i++) {
		str = pevent_filter_make_string(event_filter, events[i]->id);
		if (!str)
			continue;

		/* We only want to show advanced filters */
		if (strcmp(str, "TRUE") == 0 || strcmp(str, "FALSE") == 0) {
			free(str);
			continue;
		}

		gtk_tree_store_append(treestore, &iter_events, NULL);
		gtk_tree_store_set(treestore, &iter_events,
				   ADV_COL_DELETE, FALSE,
				   ADV_COL_EVENT, events[i]->name,
				   ADV_COL_FILTER, str,
				   ADV_COL_ID, events[i]->id,
				   -1);
		free(str);
	}

	return GTK_TREE_MODEL(treestore);
}

#define DELETE_FILTER "Delete Filter"

static void adv_filter_cursor_changed(GtkTreeView *treeview, gpointer data)
{
	GtkTreeViewColumn *col;
	GtkTreeModel *model;
	GtkTreePath *path;
	GtkTreeIter iter;
	gboolean active;
	const gchar *title;

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(treeview));
	if (!model)
		return;

	gtk_tree_view_get_cursor(treeview, &path, &col);
	if (!path)
		return;

	if (!col)
		goto free;

	title = gtk_tree_view_column_get_title(col);

	if (strcmp(title, DELETE_FILTER) != 0)
		goto free;

	if (!gtk_tree_model_get_iter(model, &iter, path))
		goto free;

	gtk_tree_model_get(model, &iter,
			   ADV_COL_DELETE, &active,
			   -1);

	active = active ? FALSE : TRUE;

	gtk_tree_store_set(GTK_TREE_STORE(model), &iter,
			   ADV_COL_DELETE, active,
			   -1);

 free:
	gtk_tree_path_free(path);
}

static GtkWidget *
create_adv_filter_view(struct tracecmd_input *handle,
		       struct event_filter *event_filter)
{
	GtkTreeViewColumn *col;
	GtkCellRenderer *renderer;
	GtkCellRenderer *togrend;
	GtkWidget *view;
	GtkTreeModel *model;

	view = gtk_tree_view_new();

	renderer = gtk_cell_renderer_text_new();

	togrend = gtk_cell_renderer_toggle_new();

	/* --- delete column --- */

	col = gtk_tree_view_column_new();

	gtk_tree_view_column_set_title(col, DELETE_FILTER);

	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);

	gtk_tree_view_column_pack_start(col, togrend, FALSE);
	gtk_tree_view_column_add_attribute(col, togrend, "active", ADV_COL_DELETE);

	/* --- events column --- */

	col = gtk_tree_view_column_new();

	gtk_tree_view_column_set_title(col, "Event");

	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);

	gtk_tree_view_column_pack_start(col, renderer, FALSE);

	gtk_tree_view_column_add_attribute(col, renderer, "text", ADV_COL_EVENT);


	/* --- filter column --- */

	col = gtk_tree_view_column_new();

	gtk_tree_view_column_set_title(col, "Filter");

	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);

	gtk_tree_view_column_pack_start(col, renderer, FALSE);

	gtk_tree_view_column_add_attribute(col, renderer, "text", ADV_COL_FILTER);


	model = create_tree_filter_model(handle, event_filter);

	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);

	g_object_unref(model);

	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(GTK_TREE_VIEW(view)),
				    GTK_SELECTION_NONE);


	g_signal_connect_swapped (view, "cursor-changed",
				  G_CALLBACK (adv_filter_cursor_changed),
				  (gpointer) view);

	return view;
}

/**
 * trace_adv_filter_dialog - make dialog for text
 * @handle: the handle to the tracecmd data file
 * @event_filter: advanced filters
 * @func: The function to call when accept or cancel is pressed
 * @data: data to pass to the function @func
 */
void trace_adv_filter_dialog(struct tracecmd_input *handle,
			     struct event_filter *event_filter,
			       trace_adv_filter_cb_func func,
			       gpointer data)
{
	struct pevent *pevent;
	struct dialog_helper *helper;
	struct adv_event_filter_helper *event_helper;
	GtkWidget *dialog;
	GtkWidget *hbox;
	GtkWidget *label;
	GtkWidget *entry;
	GtkWidget *scrollwin;
	GtkWidget *view;
	GtkWidget *event_box;

	helper = g_malloc(sizeof(*helper));
	g_assert(helper);

	/* --- Make dialog window --- */

	dialog = gtk_dialog_new_with_buttons("Advanced Filters",
					     NULL,
					     GTK_DIALOG_MODAL,
					     "Apply",
					     GTK_RESPONSE_ACCEPT,
					     GTK_STOCK_CANCEL,
					     GTK_RESPONSE_REJECT,
					     NULL);

	event_helper = g_new0(typeof(*event_helper), 1);
	g_assert(event_helper);

	helper->dialog = dialog;
	helper->data = event_helper;

	event_helper->func = func;
	event_helper->data = data;

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (dialog, "response",
				  G_CALLBACK (adv_filter_dialog_response),
				  (gpointer) helper);

	scrollwin = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrollwin),
				       GTK_POLICY_AUTOMATIC,
				       GTK_POLICY_AUTOMATIC);
	view = create_adv_filter_view(handle, event_filter);
	event_helper->view = GTK_TREE_VIEW(view);
	gtk_container_add(GTK_CONTAINER(scrollwin), view);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), scrollwin, TRUE, TRUE, 0);

	label = gtk_label_new(" <event>[,<event>] : [!][(]<field><op><val>[)]"
			      "[&&/|| [(]<field><op><val>[)]]\n\n"
			      "Examples:\n"
			      "   sched_switch : next_prio < 100 && (prev_prio > 100"
			      "&& prev_pid != 0)\n"
			      "   irq.* : irq != 38\n"
			      "   .* : common_pid == 1234");
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), label, TRUE, FALSE, 0);
	gtk_widget_show(label);

	pevent = tracecmd_get_pevent(handle);

	event_helper->combo_info.pevent = pevent;

	event_box = event_info_box(&event_helper->combo_info);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), event_box, FALSE, FALSE, 0);
	gtk_widget_show(event_box);

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), hbox, TRUE, FALSE, 0);
	gtk_widget_show(hbox);

	label = gtk_label_new("Filter:");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	entry = gtk_entry_new();
	gtk_box_pack_start(GTK_BOX(hbox), entry, TRUE, TRUE, 0);
	gtk_widget_show(entry);

	event_helper->entry = entry;

	gtk_widget_set_size_request(GTK_WIDGET(dialog),
				    TEXT_DIALOG_WIDTH, TEXT_DIALOG_HEIGHT);

	gtk_widget_show_all(dialog);
}

/* --- task list dialog --- */

struct task_helper {
	trace_task_cb_func		func;
	GtkTreeView			*view;
	gboolean			start;
	gpointer			data;
};

enum {
	TASK_COL_SELECT,
	TASK_COL_PID,
	TASK_COL_COMM,
	NUM_TASK_COLS,
};

static void get_tasks(GtkTreeView *treeview,
		      gint **selected,
		      gint **non_selected)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	gboolean active;
	gint *pids = NULL;
	gint *non_pids = NULL;
	gint pid;
	int pid_count = 0;
	int non_count = 0;

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(treeview));
	if (!model)
		return;

	if (!gtk_tree_model_iter_children(model, &iter, NULL))
		return;

	for (;;) {
		gtk_tree_model_get(GTK_TREE_MODEL(model), &iter,
				   TASK_COL_SELECT, &active,
				   TASK_COL_PID, &pid,
				   -1);

		if (active)
			trace_array_add(&pids, &pid_count, pid);
		else
			trace_array_add(&non_pids, &non_count, pid);

		if (!gtk_tree_model_iter_next(model, &iter))
			break;
	}

	*selected = pids;
	*non_selected = non_pids;
}

/* Callback for the clicked signal of the task filter button */
static void
task_dialog_response (gpointer data, gint response_id)
{
	struct dialog_helper *helper = data;
	struct task_helper *event_helper = helper->data;
	gint *selected;
	gint *non_select;

	switch (response_id) {
	case GTK_RESPONSE_ACCEPT:
		get_tasks(event_helper->view, &selected, &non_select);
		event_helper->func(TRUE, selected, non_select, event_helper->data);
		free(selected);
		free(non_select);
		break;
	case GTK_RESPONSE_REJECT:
		event_helper->func(FALSE, NULL, NULL, event_helper->data);
		break;
	default:
		break;
	};

	gtk_widget_destroy(GTK_WIDGET(helper->dialog));

	g_free(event_helper);
	g_free(helper);
}

static GtkTreeModel *
create_task_model(struct tracecmd_input *handle,
		  gint *tasks,
		  gint *selected)
{
	GtkTreeStore *treestore;
	GtkTreeIter iter;
	struct pevent *pevent;
	const char *comm;
	gboolean select;
	gint *ret;
	gint *list;
	gint count;
	gint i;

	if (!tasks)
		return NULL;

	pevent = tracecmd_get_pevent(handle);

	treestore = gtk_tree_store_new(NUM_TASK_COLS, G_TYPE_BOOLEAN,
				       G_TYPE_INT, G_TYPE_STRING);

	/* sort our tasks */
	for (i = 0; tasks[i] >= 0; i++)
		;
	count = i;

	/* Don't assume we can modify the array passed in. */
	list = malloc_or_die(sizeof(gint) * (count + 1));
	memcpy(list, tasks, sizeof(gint) * (count + 1));
	qsort(list, count, sizeof(gint), id_cmp);

	/* Now that we have our own copy, use it instead */
	tasks = list;

	if (selected) {
		/* do the same for selected */
		for (i = 0; selected[i] >= 0; i++)
			;
		count = i;
		/* count is now the size of selected */

		list = malloc_or_die(sizeof(gint) * (count + 1));
		memcpy(list, selected, sizeof(gint) * (count + 1));
		qsort(list, count, sizeof(gint), id_cmp);

		selected = list;
	}


	for (i = 0; tasks[i] >= 0; i++) {

		comm = pevent_data_comm_from_pid(pevent, tasks[i]);

		gtk_tree_store_append(treestore, &iter, NULL);

		select = FALSE;

		if (selected) {
			ret = bsearch(&tasks[i], selected, count,
				      sizeof(gint), id_cmp);
			if (ret)
				select = TRUE;
		}

		gtk_tree_store_set(treestore, &iter,
				   TASK_COL_SELECT, select,
				   TASK_COL_PID, tasks[i],
				   TASK_COL_COMM, comm,
				   -1);
	}

	free(tasks);
	free(selected);

	return GTK_TREE_MODEL(treestore);
}

static void task_cursor_changed(gpointer data, GtkTreeView *treeview)
{
	struct task_helper *event_helper = data;
	GtkTreeModel *model;
	GtkTreePath *path;
	GtkTreeIter iter;
	gboolean active;

	if (!event_helper->start) {
		event_helper->start = TRUE;
		return;
	}

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(treeview));
	if (!model)
		return;

	gtk_tree_view_get_cursor(treeview, &path, NULL);
	if (!path)
		return;

	if (!gtk_tree_model_get_iter(model, &iter, path))
		goto free;

	gtk_tree_model_get(model, &iter,
			   TASK_COL_SELECT, &active,
			   -1);

	active = active ? FALSE : TRUE;

	gtk_tree_store_set(GTK_TREE_STORE(model), &iter,
			   TASK_COL_SELECT, active,
			   -1);

 free:
	gtk_tree_path_free(path);
}

static GtkWidget *
create_task_view(struct tracecmd_input *handle,
		 gint *tasks, gint *selected,
		 struct task_helper *event_helper)
{
	GtkTreeViewColumn *col;
	GtkCellRenderer *renderer;
	GtkCellRenderer *togrend;
	GtkWidget *view;
	GtkTreeModel *model;

	view = gtk_tree_view_new();

	renderer  = gtk_cell_renderer_text_new();
	togrend  = gtk_cell_renderer_toggle_new();


	/* --- select column --- */

	col = gtk_tree_view_column_new();

	gtk_tree_view_column_set_title(col, "Plot");

	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);

	gtk_tree_view_column_pack_start(col, togrend, FALSE);
	gtk_tree_view_column_add_attribute(col, togrend, "active", TASK_COL_SELECT);

	/* --- pid column --- */

	col = gtk_tree_view_column_new();

	gtk_tree_view_column_set_title(col, "PID");

	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);

	gtk_tree_view_column_pack_start(col, renderer, FALSE);

	gtk_tree_view_column_add_attribute(col, renderer, "text", TASK_COL_PID);


	/* --- comm column --- */

	col = gtk_tree_view_column_new();

	gtk_tree_view_column_set_title(col, "Task");

	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);

	gtk_tree_view_column_pack_start(col, renderer, FALSE);

	gtk_tree_view_column_add_attribute(col, renderer, "text", TASK_COL_COMM);


	model = create_task_model(handle, tasks, selected);

	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);

	g_object_unref(model);

	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(GTK_TREE_VIEW(view)),
				    GTK_SELECTION_NONE);

	g_signal_connect_swapped (view, "cursor-changed",
				  G_CALLBACK (task_cursor_changed),
				  (gpointer) event_helper);

	return view;
}

/**
 * trace_task_dialog - make dialog to select tasks
 * @handle: the handle to the tracecmd data file
 * @tasks: array of task pids ending with -1
 * @selected: tasks from @tasks that should be selected (can be NULL).
 *      Also an array of pids ending with -1
 * @func: callback function when accept or cancel is selected
 * @data: data to pass to the function @func
 */
void trace_task_dialog(struct tracecmd_input *handle,
		       gint *tasks, gint *selected,
		       trace_task_cb_func func,
		       gpointer data)
{
	struct dialog_helper *helper;
	struct task_helper *event_helper;
	GtkWidget *dialog;
	GtkWidget *scrollwin;
	GtkWidget *view;

	helper = g_malloc(sizeof(*helper));
	g_assert(helper);

	/* --- Make dialog window --- */

	dialog = gtk_dialog_new_with_buttons("Select Tasks",
					     NULL,
					     GTK_DIALOG_MODAL,
					     "Apply",
					     GTK_RESPONSE_ACCEPT,
					     GTK_STOCK_CANCEL,
					     GTK_RESPONSE_REJECT,
					     NULL);

	event_helper = g_new0(typeof(*event_helper), 1);
	g_assert(event_helper);

	helper->dialog = dialog;
	helper->data = event_helper;

	event_helper->func = func;
	event_helper->data = data;
	event_helper->start = FALSE;

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (dialog, "response",
				  G_CALLBACK (task_dialog_response),
				  (gpointer) helper);

	scrollwin = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrollwin),
				       GTK_POLICY_AUTOMATIC,
				       GTK_POLICY_AUTOMATIC);
	view = create_task_view(handle, tasks, selected, event_helper);
	event_helper->view = GTK_TREE_VIEW(view);
	gtk_container_add(GTK_CONTAINER(scrollwin), view);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), scrollwin, TRUE, TRUE, 0);

	gtk_widget_set_size_request(GTK_WIDGET(dialog),
				    DIALOG_WIDTH, DIALOG_HEIGHT);

	gtk_widget_show_all(dialog);
}

enum {
	COL_EVENT,
	COL_ACTIVE,
	COL_NORMAL,
	COL_ACTIVE_START,
	COL_EVENT_ID,
	NUM_EVENT_COLS,
};

struct event_filter_helper {
	trace_filter_event_cb_func	func;
	GtkTreeView			*view;
	gpointer			data;
};

gboolean system_is_enabled(gchar **systems, gint systems_size, const gchar *system)
{
	const gchar **sys = &system;

	if (!systems)
		return FALSE;

	sys = bsearch(sys, systems, systems_size, sizeof(system), str_cmp);

	return sys != NULL;
}

gboolean event_is_enabled(gint *events, gint events_size, gint event)
{
	gint *ret;

	if (!events)
		return FALSE;

	ret = bsearch(&event, events, events_size, sizeof(gint), id_cmp);

	return ret != NULL;
}

static GtkTreeModel *
create_tree_event_model(struct tracecmd_input *handle,
			struct event_filter *filter,
			gboolean all_events, gchar **systems_set,
			gint *event_ids_set)
{
	GtkTreeStore *treestore;
	GtkTreeIter iter_all, iter_sys, iter_events;
	struct pevent *pevent;
	struct event_format **events;
	struct event_format *event;
	char *last_system = NULL;
	gboolean sysactive;
	gboolean active, normal;
	gchar **systems = NULL;
	gint *event_ids = NULL;
	gint systems_size;
	gint event_ids_size;
	gint i;

	pevent = tracecmd_get_pevent(handle);

	treestore = gtk_tree_store_new(NUM_EVENT_COLS, G_TYPE_STRING,
				       G_TYPE_BOOLEAN, G_TYPE_BOOLEAN,
				       G_TYPE_BOOLEAN, G_TYPE_INT);

	gtk_tree_store_append(treestore, &iter_all, NULL);
	gtk_tree_store_set(treestore, &iter_all,
			   COL_EVENT,	"All",
			   COL_ACTIVE, all_events,
			   COL_NORMAL, TRUE,
			   COL_ACTIVE_START, FALSE,
			   -1);

	events = pevent_list_events(pevent, EVENT_SORT_SYSTEM);
	if (!events)
		return GTK_TREE_MODEL(treestore);

	if (systems_set) {
		for (systems_size = 0; systems_set[systems_size]; systems_size++)
			;
		systems = g_new(typeof(*systems), systems_size + 1);
		memcpy(systems, systems_set, sizeof(*systems) * (systems_size + 1));
		qsort(systems, systems_size, sizeof(gchar *), str_cmp);
	}

	if (event_ids_set) {
		for (event_ids_size = 0; event_ids_set[event_ids_size] != -1; event_ids_size++)
			;
		event_ids = g_new(typeof(*event_ids), event_ids_size + 1);
		memcpy(event_ids, event_ids_set, sizeof(*event_ids) * (event_ids_size + 1));
		qsort(event_ids, event_ids_size, sizeof(gint), id_cmp);
	}

	for (i = 0; events[i]; i++) {
		event = events[i];
		if (!last_system || strcmp(last_system, event->system) != 0) {
			gtk_tree_store_append(treestore, &iter_sys, &iter_all);
			sysactive = all_events ||
				system_is_enabled(systems, systems_size, event->system);
			gtk_tree_store_set(treestore, &iter_sys,
					   COL_EVENT, event->system,
					   COL_ACTIVE, sysactive,
					   COL_NORMAL, TRUE,
					   -1);
			last_system = event->system;
		}

		active = all_events || sysactive ||
			event_is_enabled(event_ids, event_ids_size, event->id);

		normal = TRUE;
		if (active && filter) {
			if (pevent_event_filtered(filter, event->id) &&
			    !pevent_filter_event_has_trivial(filter, event->id,
							     FILTER_TRIVIAL_BOTH))
				normal = FALSE;
			/* Make trivial false not selected */
			else if (pevent_filter_event_has_trivial(filter, event->id,
								 FILTER_TRIVIAL_FALSE))
				active = FALSE;
		}
		gtk_tree_store_append(treestore, &iter_events, &iter_sys);
		gtk_tree_store_set(treestore, &iter_events,
				   COL_EVENT, event->name,
				   COL_ACTIVE, active,
				   COL_NORMAL, normal,
				   COL_EVENT_ID, event->id,
				   -1);
	}

	g_free(systems);
	g_free(event_ids);

	return GTK_TREE_MODEL(treestore);
}

static void update_active_events(GtkTreeModel *model, GtkTreeIter *parent,
				 gboolean active)
{
	GtkTreeIter event;

	if (!gtk_tree_model_iter_children(model, &event, parent))
		return;

	for (;;) {
		gtk_tree_store_set(GTK_TREE_STORE(model), &event,
				   COL_ACTIVE, active,
				   -1);

		if (!gtk_tree_model_iter_next(model, &event))
			break;
	}
}

static void update_active_systems(GtkTreeModel *model, GtkTreeIter *parent,
				  gboolean active)
{
	GtkTreeIter sys;

	if (!gtk_tree_model_iter_children(model, &sys, parent))
		return;

	for (;;) {
		gtk_tree_store_set(GTK_TREE_STORE(model), &sys,
				   COL_ACTIVE, active,
				   -1);

		update_active_events(model, &sys, active);

		if (!gtk_tree_model_iter_next(model, &sys))
			break;
	}
}

static void event_cursor_changed(GtkTreeView *treeview, gpointer data)
{
	GtkTreeModel *model;
	GtkTreePath *path;
	GtkTreeIter iter, parent, grandparent;
	gboolean active, start;
	gint depth;

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(treeview));
	if (!model)
		return;

	gtk_tree_view_get_cursor(treeview, &path, NULL);
	if (!path)
		return;

	if (!gtk_tree_model_get_iter(model, &iter, path))
		goto free;

	depth = gtk_tree_path_get_depth(path);

	if (depth == 1) {
		/*
		 * The first time we start up, the cursor will
		 * select the "All Events" row, and call
		 * this routine. But we don't want to do anything.
		 * Check and activate.
		 */
		gtk_tree_model_get(model, &iter,
				   COL_ACTIVE_START, &start,
				   -1);
		if (!start) {
			gtk_tree_store_set(GTK_TREE_STORE(model), &iter,
					   COL_ACTIVE_START, TRUE,
					   -1);
			goto free;
		}
	}

	gtk_tree_model_get(model, &iter,
			   COL_ACTIVE, &active,
			   -1);

	active = active ? FALSE : TRUE;

	gtk_tree_store_set(GTK_TREE_STORE(model), &iter,
			   COL_ACTIVE, active,
			   -1);

	if (depth == 1) {

		/* Set all rows */
		update_active_systems(model, &iter, active);
			
	} else if (depth == 2) {

		/* set this system */
		update_active_events(model, &iter, active);

		if (!active) {
			/* disable the all events toggle */
			gtk_tree_model_iter_parent(model, &parent, &iter);
			gtk_tree_store_set(GTK_TREE_STORE(model), &parent,
					   COL_ACTIVE, FALSE,
					   -1);
		}

	} else {
		if (!active) {
			/* disable system and all events toggles */
			gtk_tree_model_iter_parent(model, &parent, &iter);
			gtk_tree_store_set(GTK_TREE_STORE(model), &parent,
					   COL_ACTIVE, FALSE,
					   -1);
			gtk_tree_model_iter_parent(model, &grandparent, &parent);
			gtk_tree_store_set(GTK_TREE_STORE(model), &grandparent,
					   COL_ACTIVE, FALSE,
					   -1);
		}
	}

 free:
	gtk_tree_path_free(path);
}

static gboolean child_set(GtkTreeModel *model, GtkTreeIter *parent)
{
	GtkTreeIter iter;
	gboolean active;

	if (!gtk_tree_model_iter_children(model, &iter, parent))
		return FALSE;

	for (;;) {

		gtk_tree_model_get(model, &iter,
				   COL_ACTIVE, &active,
				   -1);

		if (active)
			return TRUE;

		if (!gtk_tree_model_iter_next(model, &iter))
			break;
	}

	return FALSE;
}

static void expand_rows(GtkTreeView *tree, GtkTreeModel *model,
			gboolean all_events,
			gchar **systems, gint *events)
{
	GtkTreePath *path;
	GtkTreeIter all;
	GtkTreeIter sys;
	gboolean active;

	/* Expand the "All Events" row */
	path = gtk_tree_path_new_from_string("0");

	gtk_tree_view_expand_row(tree, path, FALSE);

	gtk_tree_path_free(path);

	if (all_events)
		return;

	/* Expand the system rows that are not full or empty */

	if (!gtk_tree_model_get_iter_first(model, &all))
		return;

	if (!gtk_tree_model_iter_children(model, &sys, &all))
		return;

	for (;;) {

		gtk_tree_model_get(model, &sys,
				   COL_ACTIVE, &active,
				   -1);

		if (!active && child_set(model, &sys)) {
			path = gtk_tree_model_get_path(model, &sys);
			gtk_tree_view_expand_row(tree, path, FALSE);
			gtk_tree_path_free(path);
		}

		if (!gtk_tree_model_iter_next(model, &sys))
			break;
	}
}

static GtkWidget *
create_event_list_view(struct tracecmd_input *handle,
		       struct event_filter *filter,
		       gboolean all_events, gchar **systems,
		       gint *events)
{
	GtkTreeViewColumn *col;
	GtkCellRenderer *renderer;
	GtkCellRenderer *togrend;
	GtkWidget *view;
	GtkTreeModel *model;

	view = gtk_tree_view_new();

	/* --- events column --- */

	col = gtk_tree_view_column_new();

	gtk_tree_view_column_set_title(col, "Events");

	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);

	renderer  = gtk_cell_renderer_text_new();

	togrend  = gtk_cell_renderer_toggle_new();

	gtk_tree_view_column_pack_start(col, togrend, FALSE);
	gtk_tree_view_column_pack_start(col, renderer, FALSE);
	gtk_tree_view_column_add_attribute(col, togrend, "active", COL_ACTIVE);
	gtk_tree_view_column_add_attribute(col, togrend, "sensitive", COL_NORMAL);

	gtk_tree_view_column_add_attribute(col, renderer, "text", COL_EVENT);
	gtk_tree_view_column_add_attribute(col, renderer, "sensitive", COL_NORMAL);

	model = create_tree_event_model(handle, filter, all_events, systems, events);

	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);

	g_object_unref(model);

	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(GTK_TREE_VIEW(view)),
				    GTK_SELECTION_NONE);

	expand_rows(GTK_TREE_VIEW(view), model, all_events, systems, events);

	g_signal_connect_swapped (view, "cursor-changed",
				  G_CALLBACK (event_cursor_changed),
				  (gpointer) view);

	return view;
}

static gchar **add_system(gchar **systems, gint size, gchar *system)
{
	if (!systems) {
		systems = g_new0(gchar *, 2);
		size = 0;
	} else {
		systems = g_realloc(systems,
				    sizeof(*systems) * (size + 2));
	}
	systems[size] = g_strdup(system);
	systems[size+1] = NULL;

	return systems;
}

static gint *add_event(gint *events, gint size, gint event)
{
	if (!events) {
		events = g_new0(gint, 2);
		size = 0;
	} else {
		events = g_realloc(events,
				   sizeof(*events) * (size + 2));
	}
	events[size] = event;
	events[size+1] = -1;

	return events;
}

static gint update_events(GtkTreeModel *model,
			  GtkTreeIter *parent,
			  gint **events, gint size)
{
	GtkTreeIter event;
	gboolean active;
	gint id;

	if (!gtk_tree_model_iter_children(model, &event, parent))
		return size;

	for (;;) {

		gtk_tree_model_get(model, &event,
				   COL_ACTIVE, &active,
				   COL_EVENT_ID, &id,
				   -1);

		if (active)
			*events = add_event(*events, size++, id);

		if (!gtk_tree_model_iter_next(model, &event))
			break;
	}

	return size;
}

static gint update_system_events(GtkTreeModel *model,
				 GtkTreeIter *parent,
				 gchar ***systems,
				 gint size,
				 gint **events,
				 gint *events_size)
{
	GtkTreeIter sys;
	gboolean active;
	gchar *system;

	if (!gtk_tree_model_iter_children(model, &sys, parent))
		return size;

	for (;;) {

		gtk_tree_model_get(model, &sys,
				   COL_ACTIVE, &active,
				   COL_EVENT, &system,
				   -1);

		if (active)
			*systems = add_system(*systems, size++, system);
		else
			*events_size = update_events(model, &sys, events, *events_size);

		g_free(system);

		if (!gtk_tree_model_iter_next(model, &sys))
			break;
	}

	return size;
}

static void accept_events(struct event_filter_helper *event_helper)
{
	GtkTreeView *view = event_helper->view;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gboolean active;
	gchar **systems = NULL;
	gint *events = NULL;
	gint events_size = 0;
	gint systems_size = 0;
	gint i;

	model = gtk_tree_view_get_model(view);
	if (!model)
		return;

	if (!gtk_tree_model_get_iter_first(model, &iter))
		return;

	gtk_tree_model_get(model, &iter,
			   COL_ACTIVE, &active,
			   -1);

	if (!active)
		update_system_events(model, &iter,
				     &systems, systems_size,
				     &events, &events_size);

	event_helper->func(TRUE, active, systems, events,
			   event_helper->data);

	if (systems) {
		for (i = 0; systems[i]; i++)
			g_free(systems[i]);

		g_free(systems);
	}
	g_free(events);
}

/* Callback for the clicked signal of the Events filter button */
static void
event_dialog_response (gpointer data, gint response_id)
{
	struct dialog_helper *helper = data;
	struct event_filter_helper *event_helper = helper->data;

	switch (response_id) {
	case GTK_RESPONSE_ACCEPT:
		printf("accept!\n");
		accept_events(event_helper);
		break;
	case GTK_RESPONSE_REJECT:
		printf("reject!\n");
		event_helper->func(FALSE, FALSE, NULL, NULL,
				   event_helper->data);
		break;
	default:
		break;
	};

	gtk_widget_destroy(GTK_WIDGET(helper->dialog));

	g_free(event_helper);
	g_free(helper);
}

static void filter_event_dialog(struct tracecmd_input *handle,
				struct event_filter *filter,
				gboolean all_events,
				gchar **systems, gint *events,
				trace_filter_event_cb_func func,
				gpointer data)
{
	struct dialog_helper *helper;
	struct event_filter_helper *event_helper;
	GtkWidget *dialog;
	GtkWidget *scrollwin;
	GtkWidget *view;

	helper = g_malloc(sizeof(*helper));

	/* --- Make dialog window --- */

	dialog = gtk_dialog_new_with_buttons("Filter Events",
					     NULL,
					     GTK_DIALOG_MODAL,
					     "Apply",
					     GTK_RESPONSE_ACCEPT,
					     GTK_STOCK_CANCEL,
					     GTK_RESPONSE_REJECT,
					     NULL);

	event_helper = g_new0(typeof(*event_helper), 1);
	g_assert(event_helper);

	helper->dialog = dialog;
	helper->data = event_helper;

	event_helper->func = func;
	event_helper->data = data;

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (dialog, "response",
				  G_CALLBACK (event_dialog_response),
				  (gpointer) helper);

	scrollwin = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrollwin),
				       GTK_POLICY_AUTOMATIC,
				       GTK_POLICY_AUTOMATIC);
	view = create_event_list_view(handle, filter, all_events, systems, events);
	event_helper->view = GTK_TREE_VIEW(view);

	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), scrollwin, TRUE, TRUE, 0);
	gtk_container_add(GTK_CONTAINER(scrollwin), view);

	gtk_widget_set_size_request(GTK_WIDGET(dialog),
				    DIALOG_WIDTH, DIALOG_HEIGHT);

	gtk_widget_show_all(dialog);
}

/**
 * trace_filter_event_dialog - make dialog with event listing
 * @handle: the handle to the tracecmd data file
 * @all_events: if TRUE then select all events.
 * @systems: NULL or a string array of systems terminated with NULL
 * @events: NULL or a int array of event ids terminated with -1
 * @func: The function to call when accept or cancel is pressed
 * @data: data to pass to the function @func
 *
 * If @all_events is set, then @systems and @events are ignored.
 */
void trace_filter_event_dialog(struct tracecmd_input *handle,
			       gboolean all_events,
			       gchar **systems, gint *events,
			       trace_filter_event_cb_func func,
			       gpointer data)
{
	filter_event_dialog(handle, NULL, all_events, systems,
			    events, func, data);
}

/**
 * trace_filter_event_filter_dialog - make dialog with event listing
 * @handle: the handle to the tracecmd data file
 * @filter: the event filter to determine what to display.
 * @all_events: if TRUE then select all events.
 * @func: The function to call when accept or cancel is pressed
 * @data: data to pass to the function @func
 *
 * If @all_events is set, then @systems and @events are ignored.
 */
void trace_filter_event_filter_dialog(struct tracecmd_input *handle,
				      struct event_filter *filter,
				      gboolean all_events,
				      trace_filter_event_cb_func func,
				      gpointer data)
{
	gchar **systems;
	gint *event_ids;

	trace_filter_convert_filter_to_names(filter, &systems, &event_ids);

	filter_event_dialog(handle, filter, all_events, systems,
			    event_ids, func, data);
}

struct cpu_filter_helper {
	gboolean			allcpus;
	guint64				*cpu_mask;
	GtkWidget			**buttons;
	int				cpus;
	trace_filter_cpu_cb_func	func;
	gpointer			data;
};

static void destroy_cpu_helper(struct cpu_filter_helper *cpu_helper)
{
	g_free(cpu_helper->cpu_mask);
	g_free(cpu_helper->buttons);
	g_free(cpu_helper);
}

/* Callback for the clicked signal of the CPUS filter button */
static void
cpu_dialog_response (gpointer data, gint response_id)
{
	struct dialog_helper *helper = data;
	struct cpu_filter_helper *cpu_helper = helper->data;
	guint64 *cpu_mask = NULL;

	switch (response_id) {
	case GTK_RESPONSE_ACCEPT:

		if (!cpu_helper->allcpus) {
			cpu_mask = cpu_helper->cpu_mask;
			cpu_helper->cpu_mask = NULL;
		}

		cpu_helper->func(TRUE, cpu_helper->allcpus, cpu_mask, cpu_helper->data);
		break;

	case GTK_RESPONSE_REJECT:
		cpu_helper->func(FALSE, FALSE, NULL, cpu_helper->data);
		break;
	default:
		break;
	};

	g_free(cpu_mask);

	gtk_widget_destroy(GTK_WIDGET(helper->dialog));

	destroy_cpu_helper(helper->data);
	g_free(helper);
}

#define CPU_ALL_CPUS_STR "All CPUs"

void cpu_toggle(gpointer data, GtkWidget *widget)
{
	struct cpu_filter_helper *cpu_helper = data;
	const gchar *label;
	gboolean active;
	gint cpu;

	label = gtk_button_get_label(GTK_BUTTON(widget));
	active = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));

	if (strcmp(label, CPU_ALL_CPUS_STR) == 0) {
		cpu_helper->allcpus = active;
		if (active) {
			/* enable all toggles */
			for (cpu = 0; cpu < cpu_helper->cpus; cpu++)
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cpu_helper->buttons[cpu]),
							     TRUE);
		}
		return;
	}

	/* Get the CPU # from the label. Pass "CPU " */
	cpu = atoi(label + 4);
	if (active) {
		cpu_set(cpu_helper->cpu_mask, cpu);
		return;
	}

	cpu_clear(cpu_helper->cpu_mask, cpu);

	if (!cpu_helper->allcpus)
		return;

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cpu_helper->buttons[cpu_helper->cpus]),
				     FALSE);
}

/**
 * trace_filter_cpu_dialog - make dialog with cpu listing
 * @all_cpus: if TRUE then select all cpus.
 * @cpus_selected: NULL or a CPU mask with the CPUs to be select set.
 * @func: The function to call when accept or cancel is pressed
 * @data: data to pass to the function @func
 *
 * If @all_cpus is set, then @cpus_selected is ignored.
 */
void trace_filter_cpu_dialog(gboolean all_cpus, guint64 *cpus_selected, gint cpus,
			     trace_filter_cpu_cb_func func, gpointer data)
{
	struct dialog_helper *helper;
	struct cpu_filter_helper *cpu_helper;
	GtkWidget *dialog;
	GtkWidget *scrollwin;
	GtkWidget *viewport;
	GtkWidget *hbox;
	GtkWidget *vbox;
	GtkWidget *check;
	GtkRequisition req;
	gchar	counter[100];
	gint width, height;
	gint allset;
	gint cpu;

	helper = g_malloc(sizeof(*helper));
	g_assert(helper != NULL);

	cpu_helper = g_new0(typeof(*cpu_helper), 1);
	g_assert(cpu_helper != NULL);

	helper->data = cpu_helper;

	/* --- Make dialog window --- */

	dialog = gtk_dialog_new_with_buttons("Filter CPUS",
					     NULL,
					     GTK_DIALOG_MODAL,
					     "Apply",
					     GTK_RESPONSE_ACCEPT,
					     GTK_STOCK_CANCEL,
					     GTK_RESPONSE_REJECT,
					     NULL);

	helper->dialog = dialog;

	cpu_helper->cpus = cpus;
	cpu_helper->buttons = g_new0(GtkWidget *, cpus + 1);
	g_assert(cpu_helper->buttons);

	cpu_helper->func = func;
	cpu_helper->data = data;

	g_signal_connect_swapped (dialog, "response",
				  G_CALLBACK (cpu_dialog_response),
				  (gpointer) helper);

	scrollwin = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrollwin),
				       GTK_POLICY_AUTOMATIC,
				       GTK_POLICY_AUTOMATIC);

	viewport = gtk_viewport_new(NULL, NULL);
	gtk_widget_show(viewport);

	gtk_container_add(GTK_CONTAINER(scrollwin), viewport);

	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), scrollwin, TRUE, TRUE, 0);

	/* Add hbox to center buttons. Is there a better way? */
	hbox = gtk_hbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(viewport), hbox);
	gtk_widget_show(hbox);

	vbox = gtk_vbox_new(TRUE, 0);
	gtk_box_pack_start(GTK_BOX(hbox), vbox, TRUE, FALSE, 0);
	gtk_widget_show(vbox);

	check = gtk_check_button_new_with_label(CPU_ALL_CPUS_STR);
	gtk_box_pack_start(GTK_BOX(vbox), check, TRUE, TRUE, 0);

	/* The last button will be the all CPUs button */
	cpu_helper->buttons[cpus] = check;

	allset = cpus_selected ? 0 : 1;
	if (!allset) {
		/* check if the list is all set */
		for (cpu = 0; cpu < cpus; cpu++)
			if (!cpu_isset(cpus_selected, cpu))
				break;
		if (cpu == cpus)
			allset = 1;
	}

	if (allset)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check), TRUE);

	g_signal_connect_swapped (check, "toggled",
				  G_CALLBACK (cpu_toggle),
				  (gpointer) cpu_helper);

	cpu_helper->allcpus = allset;
	cpu_helper->cpu_mask = g_new0(guint64, (cpus >> 6) + 1);
	g_assert(cpu_helper->cpu_mask != NULL);

	gtk_widget_show(check);

	for (cpu = 0; cpu < cpus; cpu++) {
		g_snprintf(counter, 100, "CPU %d", cpu);
		check = gtk_check_button_new_with_label(counter);
		cpu_helper->buttons[cpu] = check;
		gtk_box_pack_start(GTK_BOX(vbox), check, TRUE, FALSE, 0);
		if (cpus_selected && cpu_isset(cpus_selected, cpu)) {
			cpu_set(cpu_helper->cpu_mask, cpu);
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check), TRUE);
		} else
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(check), FALSE);

		g_signal_connect_swapped (check, "toggled",
					  G_CALLBACK (cpu_toggle),
					  (gpointer) cpu_helper);

		gtk_widget_show(check);
	}

	/* Figure out a good size to show */
	gtk_widget_size_request(hbox, &req);

	height = req.height;

	gtk_widget_size_request(scrollwin, &req);

	height += req.height;

	gtk_widget_size_request(dialog, &req);

	width = req.width;
	height += req.height;

	if (width > DIALOG_WIDTH)
		width = DIALOG_WIDTH;
	if (height > DIALOG_HEIGHT)
		height = DIALOG_HEIGHT;

	gtk_widget_set_size_request(GTK_WIDGET(dialog),
				    width, height);

	gtk_widget_show_all(dialog);
}

static void add_system_str(gchar ***systems, char *system, int count)
{
	if (!systems)
		return;

	if (!count)
		*systems = malloc_or_die(sizeof(char *) * 2);
	else
		*systems = realloc(*systems, sizeof(char *) * (count + 2));
	if (!*systems)
		die("Can't allocate systems");

	(*systems)[count] = system;
	(*systems)[count+1] = NULL;
}

static void add_event_int(gint **events, gint event, int count)
{
	if (!events)
		return;

	if (!count)
		*events = malloc_or_die(sizeof(gint) * 2);
	else
		*events = realloc(*events, sizeof(gint) * (count + 2));
	if (!*events)
		die("Can't allocate events");

	(*events)[count] = event;
	(*events)[count+1] = -1;
}

/* -- Helper functions -- */

/**
 * trace_filter_convert_filter_to_names - convert a filter to names.
 * @filter: the filter to convert
 * @systems: array of systems that the filter selects (may be NULL)
 * @event_ids: array of event ids that the filter selects (may be NULL)
 *
 * @systems will be filled when the filter selects all events within
 * its system. (may return NULL)
 *
 * @event_ids will be all events selected (not including those selected
 *  by @systems)
 */
void trace_filter_convert_filter_to_names(struct event_filter *filter,
					  gchar ***systems,
					  gint **event_ids)
{
	struct pevent *pevent = filter->pevent;
	struct event_format **events;
	struct event_format *event;
	char *last_system = NULL;
	int all_selected = 1;
	int start_sys = 0;
	int sys_count = 0;
	int event_count = 0;
	int i, x;

	if (systems)
		*systems = NULL;
	if (event_ids)
		*event_ids = NULL;

	events = pevent_list_events(pevent, EVENT_SORT_SYSTEM);

	for (i = 0; events[i]; i++) {
		event = events[i];

		if (systems && last_system &&
		    strcmp(last_system, events[i]->system) != 0) {
			if (all_selected)
				add_system_str(systems, last_system, sys_count++);
			start_sys = i;
			all_selected = 1;
		}

		if (pevent_filter_event_has_trivial(filter, event->id,
						    FILTER_TRIVIAL_TRUE)) {
			if (!all_selected || !systems)
				add_event_int(event_ids, event->id, event_count++);
		} else {
			if (all_selected && event_ids) {
				for (x = start_sys; x < i; x++) {
					add_event_int(event_ids,
						      events[x]->id, event_count++);
				}
			}
			all_selected = 0;

			/* If this event is filtered, still add it */
			if (pevent_event_filtered(filter, event->id))
				add_event_int(event_ids, event->id, event_count++);
		}
		last_system = event->system;
	}

	if (systems && last_system && all_selected)
		add_system_str(systems, last_system, sys_count++);
}

/**
 * trace_filter_convert_char_to_filter - convert the strings to the filter
 * @filter: the filter to convert
 * @systems: array of systems that will have its events selected in @filter
 * @events: array of event ids that will be selected in @filter
 */
void trace_filter_convert_char_to_filter(struct event_filter *filter,
					 gchar **systems,
					 gint *events)
{
	struct pevent *pevent;
	struct event_filter *copy;
	struct event_format *event;
	int i;

	pevent = filter->pevent;

	/* Make a copy to use later */
	copy = pevent_filter_alloc(pevent);
	pevent_filter_copy(copy, filter);
	pevent_filter_reset(filter);

	if (systems) {
		for (i = 0; systems[i]; i++)
			pevent_filter_add_filter_str(filter,
						     systems[i], NULL);
	}

	if (events) {
		for (i = 0; events[i] >= 0; i++) {
			event = pevent_find_event(filter->pevent, events[i]);
			if (event)
				pevent_filter_add_filter_str(filter,
							     event->name,
							     NULL);
		}
	}

	pevent_update_trivial(filter, copy, FILTER_TRIVIAL_BOTH);

	pevent_filter_free(copy);
}
