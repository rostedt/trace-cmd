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
#include <unistd.h>
#include <gtk/gtk.h>

#include "trace-compat.h"
#include "trace-cmd.h"
#include "trace-local.h"
#include "trace-graph.h"
#include "trace-hash.h"
#include "trace-filter.h"
#include "trace-gui.h"

#include "event-utils.h"

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

#define MAX_WIDTH	10000

#define PLOT_SIZE	10
#define PLOT_BOX_SIZE	PLOT_SIZE
#define PLOT_GIVE	2
#define PLOT_BEGIN	80
#define PLOT_SEP	50
#define PLOT_LINE(plot) (PLOT_SEP * (plot) + PLOT_BEGIN + PLOT_SIZE)
#define PLOT_TOP(plot) (PLOT_LINE(plot) - PLOT_SIZE * 2)
#define PLOT_BOX_TOP(plot) (PLOT_LINE(plot) - PLOT_SIZE)
#define PLOT_BOTTOM(plot) (PLOT_LINE(plot)-1)
#define PLOT_BOX_BOTTOM(plot) (PLOT_LINE(plot))
#define PLOT_SPACE(plots) (PLOT_SEP * (plots) + PLOT_BEGIN)
#define PLOT_LABEL(plot) (PLOT_TOP(plot))
#define PLOT_X		5

static gint largest_plot_label;

static GdkGC *green;
static GdkGC *red;

static void redraw_pixmap_backend(struct graph_info *ginfo);
static void update_label_window(struct graph_info *ginfo);

struct task_list {
	struct task_list	*next;
	gint			pid;
};

static guint get_task_hash_key(gint pid)
{
	return trace_hash(pid) % TASK_HASH_SIZE;
}

static struct task_list *find_task_hash(struct graph_info *ginfo,
					gint key, gint pid)
{
	struct task_list *list;

	for (list = ginfo->tasks[key]; list; list = list->next) {
		if (list->pid == pid)
			return list;
	}

	return NULL;
}

static struct task_list *add_task_hash(struct graph_info *ginfo,
				       int pid)
{
	struct task_list *list;
	guint key = get_task_hash_key(pid);

	list = find_task_hash(ginfo, key, pid);
	if (list)
		return list;

	list = malloc_or_die(sizeof(*list));
	list->pid = pid;
	list->next = ginfo->tasks[key];
	ginfo->tasks[key] = list;

	return list;
}

static void free_task_hash(struct graph_info *ginfo)
{
	struct task_list *list;
	int i;

	for (i = 0; i < TASK_HASH_SIZE; i++) {
		while (ginfo->tasks[i]) {
			list = ginfo->tasks[i];
			ginfo->tasks[i] = list->next;
			free(list);
		}
	}
}

/**
 * trace_graph_task_list - return an allocated list of all found tasks
 * @ginfo: The graph info structure
 *
 * Returns an allocated list of pids found in the graph, ending
 * with a -1. This array must be freed with free().
 */
gint *trace_graph_task_list(struct graph_info *ginfo)
{
	struct task_list *list;
	gint *pids;
	gint count = 0;
	gint i;

	for (i = 0; i < TASK_HASH_SIZE; i++) {
		list = ginfo->tasks[i];
		while (list) {
			if (count)
				pids = realloc(pids, sizeof(*pids) * (count + 2));
			else
				pids = malloc(sizeof(*pids) * 2);
			pids[count++] = list->pid;
			pids[count] = -1;
			list = list->next;
		}
	}

	return pids;
}

static void convert_nano(unsigned long long time, unsigned long *sec,
			 unsigned long *usec)
{
	*sec = time / 1000000000ULL;
	*usec = (time / 1000) % 1000000;
}

static int convert_time_to_x(struct graph_info *ginfo, guint64 time)
{
	if (time < ginfo->view_start_time)
		return 0;
	return (time - ginfo->view_start_time) * ginfo->resolution;
}

static guint64 convert_x_to_time(struct graph_info *ginfo, gint x)
{
	double d = x;

	return (guint64)(d / ginfo->resolution) + ginfo->view_start_time;
}

static void print_time(unsigned long long time)
{
	unsigned long sec, usec;

	if (!DEBUG_LEVEL)
		return;

	convert_nano(time, &sec, &usec);
	printf("%lu.%06lu", sec, usec);
}

static void init_event_cache(struct graph_info *ginfo)
{
	ginfo->ftrace_sched_switch_id = -1;
	ginfo->event_sched_switch_id = -1;
	ginfo->event_wakeup_id = -1;
	ginfo->event_wakeup_new_id = -1;

	ginfo->event_pid_field = NULL;
	ginfo->event_comm_field = NULL;
	ginfo->ftrace_pid_field = NULL;
	ginfo->ftrace_comm_field = NULL;

	ginfo->wakeup_pid_field = NULL;
	ginfo->wakeup_success_field = NULL;
	ginfo->wakeup_new_pid_field = NULL;
	ginfo->wakeup_new_success_field = NULL;

	/*
	 * The first time reading the through the list
	 * test the sched_switch for comms that did not make
	 * it into the pevent command line list.
	 */
	ginfo->read_comms = TRUE;
}

struct filter_task_item *
trace_graph_filter_task_find_pid(struct graph_info *ginfo, gint pid)
{
	return filter_task_find_pid(ginfo->task_filter, pid);
}

struct filter_task_item *
trace_graph_hide_task_find_pid(struct graph_info *ginfo, gint pid)
{
	return filter_task_find_pid(ginfo->hide_tasks, pid);
}

static void graph_filter_task_add_pid(struct graph_info *ginfo, gint pid)
{
	filter_task_add_pid(ginfo->task_filter, pid);

	ginfo->filter_available = 1;
}

static void graph_filter_task_remove_pid(struct graph_info *ginfo, gint pid)
{
	filter_task_remove_pid(ginfo->task_filter, pid);

	if (!filter_task_count(ginfo->task_filter) &&
	    !filter_task_count(ginfo->hide_tasks)) {
		ginfo->filter_available = 0;
		ginfo->filter_enabled = 0;
	}
}

static void graph_hide_task_add_pid(struct graph_info *ginfo, gint pid)
{
	filter_task_add_pid(ginfo->hide_tasks, pid);

	ginfo->filter_available = 1;
}

static void graph_hide_task_remove_pid(struct graph_info *ginfo, gint pid)
{
	filter_task_remove_pid(ginfo->hide_tasks, pid);

	if (!filter_task_count(ginfo->task_filter) &&
	    !filter_task_count(ginfo->hide_tasks)) {
		ginfo->filter_available = 0;
		ginfo->filter_enabled = 0;
	}
}

static void graph_filter_task_clear(struct graph_info *ginfo)
{
	filter_task_clear(ginfo->task_filter);
	filter_task_clear(ginfo->hide_tasks);

	ginfo->filter_available = 0;
	ginfo->filter_enabled = 0;
}

gboolean trace_graph_filter_on_event(struct graph_info *ginfo, struct pevent_record *record)
{
	int ret;

	if (!record)
		return TRUE;

	if (ginfo->all_events)
		return FALSE;

	ret = pevent_filter_match(ginfo->event_filter, record);
	return ret == FILTER_MATCH ? FALSE : TRUE;
}

gboolean trace_graph_filter_on_task(struct graph_info *ginfo, gint pid)
{
	gboolean filter;

	filter = FALSE;

	if (ginfo->filter_enabled &&
	    ((filter_task_count(ginfo->task_filter) &&
	      !trace_graph_filter_task_find_pid(ginfo, pid)) ||
	     (filter_task_count(ginfo->hide_tasks) &&
	      trace_graph_hide_task_find_pid(ginfo, pid))))
		filter = TRUE;

	return filter;
}

static void __update_with_backend(struct graph_info *ginfo,
				gint x, gint y,
				gint width, gint height)
{
	gdk_draw_drawable(ginfo->draw->window,
			  ginfo->draw->style->fg_gc[GTK_WIDGET_STATE(ginfo->draw)],
			  ginfo->curr_pixmap,
			  x, y, x, y,
			  width, height);
}

static void update_label_time(GtkWidget *label, gint64 time)
{
	unsigned long sec, usec;
	struct trace_seq s;
	char *min = "";

	if (time < 0) {
		time *= -1;
		min = "-";
	}

	convert_nano(time, &sec, &usec);

	trace_seq_init(&s);
	trace_seq_printf(&s, "%s%lu.%06lu", min, sec, usec);

	gtk_label_set_text(GTK_LABEL(label), s.buffer);
	trace_seq_destroy(&s);
}

static void update_cursor(struct graph_info *ginfo)
{
	update_label_time(ginfo->cursor_label, ginfo->cursor);
}

static void update_pointer(struct graph_info *ginfo, gint x)
{
	guint64 time;

	time = convert_x_to_time(ginfo, x);
	update_label_time(ginfo->pointer_time, time);
}

static void update_marka(struct graph_info *ginfo, gint x)
{
	guint64 timeA;

	timeA = convert_x_to_time(ginfo, x);
	ginfo->marka_time = timeA;

	update_label_time(ginfo->marka_label, timeA);
}

static void update_markb(struct graph_info *ginfo, guint x)
{
	gint64 timeA, timeB;

	timeA = ginfo->marka_time;
	timeB = convert_x_to_time(ginfo, x);
	ginfo->markb_time = timeB;

	update_label_time(ginfo->markb_label, timeB);
	update_label_time(ginfo->delta_label, timeB - timeA);
}

static void draw_cursor(struct graph_info *ginfo)
{
	gint x;

	if (!ginfo->cursor)
		return;

	update_cursor(ginfo);

	if (ginfo->cursor < ginfo->view_start_time ||
	    ginfo->cursor > ginfo->view_end_time)
		return;

	x = convert_time_to_x(ginfo, ginfo->cursor);

	gdk_draw_line(ginfo->draw->window, ginfo->draw->style->mid_gc[3],
		      x, 0, x, ginfo->draw->allocation.height);
}

static void draw_marka(struct graph_info *ginfo)
{
	gint x;

	if (!ginfo->show_marka)
		return;

	x = convert_time_to_x(ginfo, ginfo->marka_time);
	gdk_draw_line(ginfo->draw->window, green,
		      x, 0, x, ginfo->draw->allocation.height);
}

static void draw_markb(struct graph_info *ginfo)
{
	gint x;

	if (!ginfo->show_markb)
		return;

	x = convert_time_to_x(ginfo, ginfo->markb_time);
	gdk_draw_line(ginfo->draw->window, red,
		      x, 0, x, ginfo->draw->allocation.height);
}

static void update_with_backend(struct graph_info *ginfo,
				gint x, gint y,
				gint width, gint height)
{
	__update_with_backend(ginfo, x, y, width, height);

	draw_cursor(ginfo);
	draw_markb(ginfo);
	draw_marka(ginfo);
}

static gboolean
expose_event(GtkWidget *widget, GdkEventExpose *event, gpointer data)
{
	struct graph_info *ginfo = data;

	update_with_backend(ginfo,
			    event->area.x, event->area.y,
			    event->area.width, event->area.height);

	return FALSE;
}

static void
draw_line(GtkWidget *widget, gdouble x, struct graph_info *ginfo)
{
	gdk_draw_line(widget->window, widget->style->black_gc,
		      x, 0, x, widget->allocation.height);
}

static void clear_line(struct graph_info *ginfo, gint x)
{
	if (x)
		x--;

	update_with_backend(ginfo, x, 0, x+2, ginfo->draw->allocation.height);
}

static void clear_info_box(struct graph_info *ginfo)
{
	update_with_backend(ginfo, ginfo->plot_data_x, ginfo->plot_data_y,
			    ginfo->plot_data_w, ginfo->plot_data_h);
}

static void redraw_graph(struct graph_info *ginfo)
{
	gdouble height;
	gdouble width;

	redraw_pixmap_backend(ginfo);
	width = ginfo->draw->allocation.width;
	height = ginfo->draw->allocation.height;
	update_with_backend(ginfo, 0, 0, width, height);
}

void trace_graph_filter_toggle(struct graph_info *ginfo)
{
	ginfo->filter_enabled ^= 1;

	redraw_graph(ginfo);
}

static void
filter_enable_clicked (gpointer data)
{
	struct graph_info *ginfo = data;

	trace_graph_filter_toggle(ginfo);
}

void trace_graph_filter_add_remove_task(struct graph_info *ginfo,
					gint pid)
{
	gint filter_enabled = ginfo->filter_enabled;
	struct filter_task_item *task;

	task = trace_graph_filter_task_find_pid(ginfo, pid);

	if (task)
		graph_filter_task_remove_pid(ginfo, task->pid);
	else
		graph_filter_task_add_pid(ginfo, pid);

	if (ginfo->callbacks && ginfo->callbacks->filter)
		ginfo->callbacks->filter(ginfo, ginfo->task_filter,
					 ginfo->hide_tasks);

	if (filter_enabled)
		redraw_graph(ginfo);
}

void trace_graph_filter_hide_show_task(struct graph_info *ginfo,
				       gint pid)
{
	gint filter_enabled = ginfo->filter_enabled;
	struct filter_task_item *task;

	task = trace_graph_hide_task_find_pid(ginfo, pid);

	if (task)
		graph_hide_task_remove_pid(ginfo, task->pid);
	else
		graph_hide_task_add_pid(ginfo, pid);

	if (ginfo->callbacks && ginfo->callbacks->filter)
		ginfo->callbacks->filter(ginfo, ginfo->task_filter,
					 ginfo->hide_tasks);

	if (filter_enabled)
		redraw_graph(ginfo);
}

static void
filter_add_task_clicked (gpointer data)
{
	struct graph_info *ginfo = data;

	trace_graph_filter_add_remove_task(ginfo, ginfo->filter_task_selected);
}

static void
filter_hide_task_clicked (gpointer data)
{
	struct graph_info *ginfo = data;

	trace_graph_filter_hide_show_task(ginfo, ginfo->filter_task_selected);
}

void trace_graph_clear_tasks(struct graph_info *ginfo)
{
	gint filter_enabled = ginfo->filter_enabled;

	graph_filter_task_clear(ginfo);

	if (ginfo->callbacks && ginfo->callbacks->filter)
		ginfo->callbacks->filter(ginfo, ginfo->task_filter,
					 ginfo->hide_tasks);

	if (filter_enabled)
		redraw_graph(ginfo);
}

void trace_graph_update_filters(struct graph_info *ginfo,
				struct filter_task *task_filter,
				struct filter_task *hide_tasks)
{
	/* Make sure the filter passed in is not the filter we use */
	if (task_filter != ginfo->task_filter) {
		filter_task_hash_free(ginfo->task_filter);
		ginfo->task_filter = filter_task_hash_copy(task_filter);
	}

	if (hide_tasks != ginfo->hide_tasks) {
		filter_task_hash_free(ginfo->hide_tasks);
		ginfo->hide_tasks = filter_task_hash_copy(hide_tasks);
	}

	if (ginfo->callbacks && ginfo->callbacks->filter)
		ginfo->callbacks->filter(ginfo, ginfo->task_filter,
					 ginfo->hide_tasks);

	if (ginfo->filter_enabled)
		redraw_graph(ginfo);

	if (filter_task_count(ginfo->task_filter) ||
	    filter_task_count(ginfo->hide_tasks))
		ginfo->filter_available = 1;
	else {
		ginfo->filter_enabled = 0;
		ginfo->filter_available = 0;
	}

}

void trace_graph_refresh_filters(struct graph_info *ginfo)
{
	trace_graph_update_filters(ginfo, ginfo->task_filter,
				   ginfo->hide_tasks);
}

static void
filter_clear_tasks_clicked (gpointer data)
{
	struct graph_info *ginfo = data;

	trace_graph_clear_tasks(ginfo);
}

static void
plot_task_clicked (gpointer data)
{
	struct graph_info *ginfo = data;
	struct graph_plot *plot = ginfo->plot_clicked;
	int pos;

	if (plot)
		pos = plot->pos + 1;
	else
		pos = ginfo->plots + 1;

	graph_plot_task(ginfo, ginfo->filter_task_selected, pos);
	ginfo->draw_height = PLOT_SPACE(ginfo->plots);
	gtk_widget_set_size_request(ginfo->draw, ginfo->draw_width, ginfo->draw_height);
	update_label_window(ginfo);
}

static void
remove_plot_clicked (gpointer data)
{
	struct graph_info *ginfo = data;
	struct graph_plot *plot = ginfo->plot_clicked;

	if (!plot)
		return;

	trace_graph_plot_remove(ginfo, plot);
	ginfo->draw_height = PLOT_SPACE(ginfo->plots);
	gtk_widget_set_size_request(ginfo->draw, ginfo->draw_width, ginfo->draw_height);
	update_label_window(ginfo);
}

static struct graph_plot *find_plot_by_y(struct graph_info *ginfo, gint y)
{
	gint i;

	for (i = 0; i < ginfo->plots; i++) {
		if (y >= (PLOT_TOP(i) - PLOT_GIVE) &&
		    y <= (PLOT_BOTTOM(i) + PLOT_GIVE)) {
			return ginfo->plot_array[i];
		}
	}
	return NULL;
}

static gboolean
do_pop_up(GtkWidget *widget, GdkEventButton *event, gpointer data)
{
	struct graph_info *ginfo = data;
	static GtkWidget *menu;
	static GtkWidget *menu_filter_enable;
	static GtkWidget *menu_filter_add_task;
	static GtkWidget *menu_filter_hide_task;
	static GtkWidget *menu_filter_clear_tasks;
	static GtkWidget *menu_plot_task;
	static GtkWidget *menu_remove_plot;
	struct pevent_record *record = NULL;
	struct graph_plot *plot;
	const char *comm;
	guint64 time;
	gchar *text;
	gint pid;
	gint len;
	gint x, y;

	x = event->x;
	y = event->y;

	if (!menu) {
		menu = gtk_menu_new();
		menu_filter_enable = gtk_menu_item_new_with_label("Enable Filter");
		gtk_widget_show(menu_filter_enable);
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), menu_filter_enable);

		g_signal_connect_swapped (G_OBJECT (menu_filter_enable), "activate",
					  G_CALLBACK (filter_enable_clicked),
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

		menu_plot_task = gtk_menu_item_new_with_label("Plot task");
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), menu_plot_task);

		g_signal_connect_swapped (G_OBJECT (menu_plot_task), "activate",
					  G_CALLBACK (plot_task_clicked),
					  data);

		menu_remove_plot = gtk_menu_item_new_with_label("Remove Plot");
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), menu_remove_plot);
		gtk_widget_show(menu_remove_plot);

		g_signal_connect_swapped (G_OBJECT (menu_remove_plot), "activate",
					  G_CALLBACK (remove_plot_clicked),
					  data);

	}

	if (ginfo->filter_enabled)
		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_enable),
					"Disable Filter");
	else
		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_enable),
					"Enable Filter");

	if (ginfo->filter_available)
		gtk_widget_set_sensitive(menu_filter_enable, TRUE);
	else
		gtk_widget_set_sensitive(menu_filter_enable, FALSE);

	if (filter_task_count(ginfo->task_filter) ||
	    filter_task_count(ginfo->hide_tasks))
		gtk_widget_set_sensitive(menu_filter_clear_tasks, TRUE);
	else
		gtk_widget_set_sensitive(menu_filter_clear_tasks, FALSE);

	time =  convert_x_to_time(ginfo, x);

	plot = find_plot_by_y(ginfo, y);
	ginfo->plot_clicked = plot;

	if (plot) {
		record = trace_graph_plot_find_record(ginfo, plot, time);
		gtk_widget_set_sensitive(menu_remove_plot, TRUE);
	} else
		gtk_widget_set_sensitive(menu_remove_plot, FALSE);

	if (record) {

		if (!trace_graph_check_sched_switch(ginfo, record, &pid, &comm)) {
			pid = pevent_data_pid(ginfo->pevent, record);
			comm = pevent_data_comm_from_pid(ginfo->pevent, pid);
		}

		len = strlen(comm) + 50;

		text = g_malloc(len);
		g_assert(text);

		if (trace_graph_filter_task_find_pid(ginfo, pid))
			snprintf(text, len, "Remove %s-%d from filter", comm, pid);
		else
			snprintf(text, len, "Add %s-%d to filter", comm, pid);

		ginfo->filter_task_selected = pid;

		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_add_task),
					text);

		if (trace_graph_hide_task_find_pid(ginfo, pid))
			snprintf(text, len, "Show %s-%d", comm, pid);
		else
			snprintf(text, len, "Hide %s-%d", comm, pid);

		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_hide_task),
					text);

		snprintf(text, len, "Plot %s-%d", comm, pid);
		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_plot_task),
					text);

		g_free(text);

		gtk_widget_set_sensitive(menu_filter_add_task, TRUE);
		gtk_widget_set_sensitive(menu_filter_hide_task, TRUE);
		gtk_widget_show(menu_plot_task);

		free_record(record);
	} else {
		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_add_task),
					"Add task to filter");
		gtk_widget_set_sensitive(menu_filter_add_task, FALSE);

		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_hide_task),
					"Hide task");
		gtk_widget_set_sensitive(menu_filter_hide_task, FALSE);

		gtk_widget_hide(menu_plot_task);
	}

		
	gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL, 3,
		       gtk_get_current_event_time());


	return TRUE;
}

static void draw_info_box(struct graph_info *ginfo, const gchar *buffer,
			  gint x, gint y);

static void stop_zoom_tip(struct graph_info *ginfo)
{
	clear_info_box(ginfo);
}

static void show_zoom_tip(struct graph_info *ginfo, gint x, gint y)
{
	clear_info_box(ginfo);

	draw_info_box(ginfo,
		      "Click and hold left mouse and drag right to zoom in\n"
		      "Click and hold left mouse and drag left to zoom out",
		      x, y);
}

static void button_press(struct graph_info *ginfo, gint x, gint y, guint state)
{
	ginfo->press_x = x;
	ginfo->last_x = 0;

	draw_line(ginfo->draw, x, ginfo);

	ginfo->line_active = TRUE;
	ginfo->line_time = convert_x_to_time(ginfo, x);

	if (state & GDK_SHIFT_MASK) {
		ginfo->show_markb = FALSE;
		clear_line(ginfo, convert_time_to_x(ginfo, ginfo->markb_time));
		/* We only update A if it hasn't been made yet */
		if (!ginfo->marka_time) {
			ginfo->show_marka = FALSE;
			clear_line(ginfo, convert_time_to_x(ginfo, ginfo->marka_time));
			update_marka(ginfo, x);
		}
	} else {
		ginfo->zoom = TRUE;
		show_zoom_tip(ginfo, x, y);
	}

	return;
}

static gboolean
button_press_event(GtkWidget *widget, GdkEventButton *event, gpointer data)
{
	struct graph_info *ginfo = data;

	if (!ginfo->handle)
		return FALSE;

	if (event->button == 3)
		return do_pop_up(widget, event, data);

	if (event->button != 1)
		return TRUE;

	/* check for double click */
	if (event->type == GDK_2BUTTON_PRESS) {
		stop_zoom_tip(ginfo);
		if (ginfo->line_active) {
			ginfo->line_active = FALSE;
			clear_line(ginfo, ginfo->last_x);
			clear_line(ginfo, ginfo->press_x);
		}
		if (ginfo->cursor >= ginfo->view_start_time &&
		    ginfo->cursor <= ginfo->view_end_time) {
			ginfo->last_x = convert_time_to_x(ginfo, ginfo->cursor);
			ginfo->cursor = 0;
			clear_line(ginfo, ginfo->last_x);
		}

		ginfo->cursor = convert_x_to_time(ginfo, event->x);
		draw_cursor(ginfo);
		if (ginfo->callbacks && ginfo->callbacks->select)
			ginfo->callbacks->select(ginfo, ginfo->cursor);
		return TRUE;
	}

	button_press(ginfo, event->x, event->y, event->state);

	return TRUE;
}

static void draw_latency(struct graph_info *ginfo, gint x, gint y);
static void draw_plot_info(struct graph_info *ginfo, struct graph_plot *plot,
			   gint x, gint y);

static void motion_plot(struct graph_info *ginfo, gint x, gint y)
{
	struct graph_plot *plot;

	if (ginfo->zoom)
		stop_zoom_tip(ginfo);

	if (!ginfo->curr_pixmap)
		return;

	if (ginfo->pointer_time)
		update_pointer(ginfo, x);

	if (ginfo->line_active) {
		if (ginfo->last_x)
			clear_line(ginfo, ginfo->last_x);
		ginfo->last_x = x;
		draw_line(ginfo->draw, ginfo->press_x, ginfo);
		draw_line(ginfo->draw, x, ginfo);
		if (!ginfo->zoom)
			draw_latency(ginfo, x, y);
		return;
	}

	plot = find_plot_by_y(ginfo, y);
	if (plot)
		draw_plot_info(ginfo, plot, x, y);
}

static gboolean
info_button_press_event(GtkWidget *widget, GdkEventButton *event, gpointer data)
{
	struct graph_info *ginfo = data;

	if (!ginfo->handle)
		return FALSE;

	if (event->button != 1)
		return FALSE;

	/* check for double click */
	if (event->type == GDK_2BUTTON_PRESS)
		return FALSE;

	button_press(ginfo, gtk_adjustment_get_value(ginfo->hadj), event->y, event->state);

	return FALSE;
}

static gboolean
info_motion_notify_event(GtkWidget *widget, GdkEventMotion *event, gpointer data)
{
	struct graph_info *ginfo = data;
	GdkModifierType state;
	gint x, y;

	if (!ginfo->handle)
		return FALSE;

	if (!ginfo->line_active)
		return FALSE;

	if (!ginfo->curr_pixmap)
		return FALSE;

	clear_info_box(ginfo);

	if (event->is_hint)
		gdk_window_get_pointer(event->window, &x, &y, &state);
	else {
		x = event->x;
		y = event->y;
	}

	/* Position x relative to the location in the drawing area */
	x -= ginfo->scrollwin->allocation.x - ginfo->info_scrollwin->allocation.x;

	if (x < 0)
		return FALSE;

	x += gtk_adjustment_get_value(ginfo->hadj);

	motion_plot(ginfo, x, y);

	return FALSE;
}

static void button_release(struct graph_info *ginfo, gint x);

static gboolean
info_button_release_event(GtkWidget *widget, GdkEventMotion *event, gpointer data)
{
	struct graph_info *ginfo = data;
	gint x;

	if (!ginfo->handle)
		return FALSE;

	x = event->x - ginfo->scrollwin->allocation.x - ginfo->info_scrollwin->allocation.x;

	button_release(ginfo, x);

	return FALSE;
}

#define PLOT_BOARDER 5

int trace_graph_check_sched_wakeup(struct graph_info *ginfo,
				   struct pevent_record *record,
				   gint *pid)
{
	struct event_format *event;
	unsigned long long val;
	gboolean found;
	gint id;

	if (ginfo->event_wakeup_id < 0) {

		found = FALSE;

		event = pevent_find_event_by_name(ginfo->pevent,
						  NULL, "sched_wakeup");
		if (event) {
			found = TRUE;
			ginfo->event_wakeup_id = event->id;
			ginfo->wakeup_pid_field = pevent_find_field(event, "pid");
			ginfo->wakeup_success_field = pevent_find_field(event, "success");
		}


		event = pevent_find_event_by_name(ginfo->pevent,
						  NULL, "sched_wakeup_new");
		if (event) {
			found = TRUE;
			ginfo->event_wakeup_new_id = event->id;
			ginfo->wakeup_new_pid_field = pevent_find_field(event, "pid");
			ginfo->wakeup_new_success_field = pevent_find_field(event, "success");
		}
		if (!found)
			return 0;
	}

	id = pevent_data_type(ginfo->pevent, record);

	if (id == ginfo->event_wakeup_id) {
		/* We only want those that actually woke up the task */
		if (ginfo->wakeup_success_field) {
			pevent_read_number_field(ginfo->wakeup_success_field, record->data, &val);
			if (!val)
				return 0;
		}
		pevent_read_number_field(ginfo->wakeup_pid_field, record->data, &val);
		if (pid)
			*pid = val;
		return 1;
	}

	if (id == ginfo->event_wakeup_new_id) {
		/* We only want those that actually woke up the task */
		if (ginfo->wakeup_new_success_field) {
			pevent_read_number_field(ginfo->wakeup_new_success_field, record->data, &val);
			if (!val)
				return 0;
		}
		pevent_read_number_field(ginfo->wakeup_new_pid_field, record->data, &val);
		if (pid)
			*pid = val;
		return 1;
	}

	return 0;
}

int trace_graph_check_sched_switch(struct graph_info *ginfo,
				   struct pevent_record *record,
				   gint *pid, const char **comm)
{
	unsigned long long val;
	struct event_format *event;
	gint this_pid;
	gint id;
	int ret = 1;

	if (ginfo->read_comms) {
		/* record all pids, for task plots */
		this_pid = pevent_data_pid(ginfo->pevent, record);
		add_task_hash(ginfo, this_pid);
	}

	if (ginfo->event_sched_switch_id < 0) {
		event = pevent_find_event_by_name(ginfo->pevent,
						  NULL, "sched_switch");
		if (!event)
			return 0;

		ginfo->event_sched_switch_id = event->id;
		ginfo->event_prev_state = pevent_find_field(event, "prev_state");
		ginfo->event_pid_field = pevent_find_field(event, "next_pid");
		ginfo->event_comm_field = pevent_find_field(event, "next_comm");

		event = pevent_find_event_by_name(ginfo->pevent,
						  "ftrace", "context_switch");
		if (event) {
			ginfo->ftrace_sched_switch_id = event->id;
			ginfo->ftrace_pid_field = pevent_find_field(event, "next_pid");
			ginfo->ftrace_comm_field = pevent_find_field(event, "next_comm");
		}
	}

	id = pevent_data_type(ginfo->pevent, record);
	if (id == ginfo->event_sched_switch_id) {
		pevent_read_number_field(ginfo->event_pid_field, record->data, &val);
		if (comm)
			*comm = record->data + ginfo->event_comm_field->offset;
		if (pid)
			*pid = val;
		goto out;
	}

	if (id == ginfo->ftrace_sched_switch_id) {
		pevent_read_number_field(ginfo->ftrace_pid_field, record->data, &val);
		if (comm && ginfo->ftrace_comm_field)
			*comm = record->data + ginfo->ftrace_comm_field->offset;
		else
			comm = NULL;
		if (pid)
			*pid = val;
		goto out;
	}

	ret = 0;
 out:
	if (ret && comm && ginfo->read_comms) {
		/*
		 * First time through, register any missing
		 *  comm / pid mappings.
		 */
		if (!pevent_pid_is_registered(ginfo->pevent, *pid))
			pevent_register_comm(ginfo->pevent,
					     *comm, *pid);
	}

	return ret;
}

static void draw_info_box(struct graph_info *ginfo, const gchar *buffer,
			  gint x, gint y)
{
	PangoLayout *layout;
	GtkAdjustment *vadj;
	gint width, height;
	GdkPixmap *pix;
	static GdkGC *pix_bg;
	gint view_width;
	gint view_start;

	if (!pix_bg) {
		GdkColor color;

		pix_bg = gdk_gc_new(ginfo->draw->window);
		color.red = (0xff) *(65535/255);
		color.green = (0xfa) *(65535/255);
		color.blue = (0xcd) *(65535/255);
		gdk_color_alloc(gtk_widget_get_colormap(ginfo->draw), &color);
		gdk_gc_set_foreground(pix_bg, &color);
	}

	layout = gtk_widget_create_pango_layout(ginfo->draw, buffer);
	pango_layout_get_pixel_size(layout, &width, &height);

	width += PLOT_BOARDER * 2;
	height += PLOT_BOARDER * 2;

	view_start = gtk_adjustment_get_value(ginfo->hadj);
	view_width = gtk_adjustment_get_page_size(ginfo->hadj);
	if (x > view_start + width)
		x -= width;

	vadj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(ginfo->scrollwin));
	view_start = gtk_adjustment_get_value(vadj);
	if (y > view_start + height)
		y -= height;

	ginfo->plot_data_x = x;
	ginfo->plot_data_y = y;
	ginfo->plot_data_w = width;
	ginfo->plot_data_h = height;

	pix = gdk_pixmap_new(ginfo->draw->window,
			     width,
			     height,
			     -1);

	gdk_draw_rectangle(pix,
			   pix_bg,
			   TRUE,
			   0, 0,
			   width, height);
	
	gdk_draw_rectangle(pix,
			   ginfo->draw->style->black_gc,
			   FALSE,
			   0, 0,
			   width-1, height-1);

	gdk_draw_layout(pix, ginfo->draw->style->black_gc,
			PLOT_BOARDER, PLOT_BOARDER, layout);
	gdk_draw_drawable(ginfo->draw->window,
			  ginfo->draw->style->fg_gc[GTK_WIDGET_STATE(ginfo->draw)],
			  pix, 0, 0, x, y, width, height);

	g_object_unref(layout);
	g_object_unref(pix);
}

static void draw_plot_info(struct graph_info *ginfo, struct graph_plot *plot,
			   gint x, gint y)
{
	struct pevent *pevent;
	guint64 time;
	unsigned long sec, usec;
	struct trace_seq s;

	time =  convert_x_to_time(ginfo, x);
	convert_nano(time, &sec, &usec);

	pevent = ginfo->pevent;

	trace_seq_init(&s);

	dprintf(3, "start=%llu end=%llu time=%llu\n",
		(u64)ginfo->start_time, (u64)ginfo->end_time, (u64)time);

	if (!trace_graph_plot_display_info(ginfo, plot, &s, time)) {
		/* Just display the current time */
		trace_seq_destroy(&s);
		trace_seq_init(&s);
		trace_seq_printf(&s, "%lu.%06lu", sec, usec);
	}

	trace_seq_putc(&s, 0);

	draw_info_box(ginfo, s.buffer, x, y);
	trace_seq_destroy(&s);
}

static void draw_latency(struct graph_info *ginfo, gint x, gint y)
{
	struct pevent *pevent;
	unsigned long sec, usec;
	struct trace_seq s;
	gboolean neg;
	gint64 time;

	update_markb(ginfo, x);

	time =  convert_x_to_time(ginfo, x);
	time -= ginfo->line_time;

	if (time < 0) {
		neg = TRUE;
		time *= -1;
	} else
		neg = FALSE;

	convert_nano(time, &sec, &usec);

	pevent = ginfo->pevent;

	trace_seq_init(&s);
	trace_seq_printf(&s, "Diff: %s%ld.%06lu secs", neg ? "-":"", sec, usec);

	draw_info_box(ginfo, s.buffer, x, y);
	trace_seq_destroy(&s);
}

static gboolean
motion_notify_event(GtkWidget *widget, GdkEventMotion *event, gpointer data)
{
	struct graph_info *ginfo = data;
	GdkModifierType state;
	gint x, y;

	if (!ginfo->handle)
		return FALSE;

	clear_info_box(ginfo);

	if (event->is_hint)
		gdk_window_get_pointer(event->window, &x, &y, &state);
	else {
		x = event->x;
		y = event->y;
		state = event->state;
	}

	motion_plot(ginfo, x, y);

	return TRUE;
}

static int update_graph(struct graph_info *ginfo, gdouble percent)
{
	gint full_width = ginfo->full_width * percent;
	gdouble resolution = (gdouble)full_width / (gdouble)(ginfo->end_time -
							     ginfo->start_time);

	/* Check if we are too big */
	if (!resolution || full_width <= 0)
		return -1;

	ginfo->full_width = full_width;
	ginfo->resolution = resolution;
	ginfo->start_x = (ginfo->view_start_time - ginfo->start_time) *
		ginfo->resolution;

	dprintf(1, "new resolution = %f\n", resolution);
	return 0;
}

static void update_graph_to_start_x(struct graph_info *ginfo)
{
	gint width = ginfo->draw_width;;

	if (!width) {
		ginfo->view_start_time = ginfo->start_time;
		ginfo->view_end_time = ginfo->end_time;
		return;
	}

	ginfo->view_start_time = (gdouble)ginfo->start_x / ginfo->resolution +
		ginfo->start_time;

	ginfo->view_end_time = (gdouble)width / ginfo->resolution +
		ginfo->view_start_time;

	g_assert (ginfo->view_start_time < ginfo->end_time);
}

static void reset_graph(struct graph_info *ginfo, gdouble view_width)
{
	ginfo->full_width = view_width;
	ginfo->draw_width = 0;
	ginfo->view_start_time = ginfo->start_time;
	ginfo->view_end_time = ginfo->end_time;
	ginfo->start_x = 0;
}

static void zoom_in_window(struct graph_info *ginfo, gint start, gint end)
{
	guint64 start_time;
	gdouble view_width;
	gdouble new_width;
	gdouble select_width;
	gdouble curr_width;
	gdouble mid;
	gdouble percent;
	gint old_width = ginfo->draw_width;

	g_assert(start < end);
	g_assert(ginfo->hadj);

	start_time = ginfo->start_time +
		(ginfo->start_x + start) / ginfo->resolution;

	view_width = gtk_adjustment_get_page_size(ginfo->hadj);
	select_width = end - start;
	percent = view_width / select_width;

	dprintf(1, "view width=%f select width=%f percent=%f\n",
		view_width, select_width, percent);

	if (update_graph(ginfo, percent) < 0)
		return;

	curr_width = ginfo->draw->allocation.width;
	new_width = curr_width * percent;

	ginfo->draw_width = new_width;
	dprintf(1, "zoom in draw_width=%d full_width=%d\n",
	       ginfo->draw_width, ginfo->full_width);

	if (ginfo->draw_width > MAX_WIDTH) {
		gint new_start;
		gint new_end;

		/*
		 * The drawing is now greater than our max. We must
		 * limit the maximum size of the drawing area or
		 * we risk running out of X resources.
		 *
		 * We will now shorten the trace to that of what will
		 * fit in this zoomed area.
		 */
		ginfo->draw_width = MAX_WIDTH;

		mid = start + (end - start) / 2;
		mid *= percent;
		mid += ginfo->start_x;

		/*
		 * mid now points to the center of the viewable area
		 * if the draw area was of new_width.
		 *
		 *       new_start           new_end
		 * +------------------------------------------------+
		 * |        |                 |                     |
		 * |        |                 |                     |
		 * +------------------------------------------------+
		 * ^                ^
		 * |               mid
		 * old view start
		 *
		 */

		new_start = mid - MAX_WIDTH / 2;
		new_end = new_start + MAX_WIDTH;

		if (new_start < 0) {
			mid += new_start;
			new_start = 0;
		} else if (new_end > ginfo->full_width) {
			new_start -= new_end - ginfo->full_width;
			mid += new_end - ginfo->full_width;
			new_end = ginfo->full_width;
			g_assert(new_start >= 0);
		}

		ginfo->start_x = new_start;

		dprintf(1, "new start/end =%d/%d full:%d  start_time:",
		       new_start, new_end, ginfo->full_width);
		print_time(ginfo->view_start_time);
		dprintf(1, "\n");

		/* Adjust start to be the location for the hadj */
		start = (mid - new_start) - view_width / 2;
	} else
		start *= percent;

	update_graph_to_start_x(ginfo);

	ginfo->hadj_value = start;
	ginfo->hadj_value = convert_time_to_x(ginfo, start_time);

	if (ginfo->hadj_value > (ginfo->draw_width - view_width))
		ginfo->hadj_value = ginfo->draw_width - view_width;

	dprintf(1, "new width=%d\n", ginfo->draw_width);

	/* make sure the width is sent */
	if (ginfo->draw_width == old_width)
		redraw_graph(ginfo);
	else
		gtk_widget_set_size_request(ginfo->draw, ginfo->draw_width, ginfo->draw_height);

	dprintf(1, "set val %f\n", ginfo->hadj_value);


	dprintf(1, "*** ended with with ");
	print_time(convert_x_to_time(ginfo, ginfo->hadj_value));
	dprintf(1, "\n");

}

static gboolean
value_changed(GtkWidget *widget, gpointer data)
{
	GtkAdjustment *adj = GTK_ADJUSTMENT(widget);

	dprintf(2, "value = %f\n",
	       gtk_adjustment_get_value(adj));

	return TRUE;

}

static void zoom_out_window(struct graph_info *ginfo, gint start, gint end)
{
	gdouble view_width;
	gdouble divider;
	gdouble curr_width;
	gdouble new_width;
	gdouble mid;
	gdouble start_x;
	unsigned long long time;
	gint old_width = ginfo->draw_width;

	g_assert(start > end);
	g_assert(ginfo->hadj);

	view_width = gtk_adjustment_get_page_size(ginfo->hadj);
	start_x = gtk_adjustment_get_value(ginfo->hadj);
	mid = start_x + view_width / 2;

	time = convert_x_to_time(ginfo, mid);

	divider = start - end;

	curr_width = ginfo->draw->allocation.width;
	new_width = curr_width / divider;

	if (update_graph(ginfo, 1 / divider) < 0)
		return;

	dprintf(1, "width=%d\n", ginfo->draw->allocation.width);

	ginfo->draw_width = new_width;

	dprintf(1, "draw_width=%d full_width=%d\n", ginfo->draw_width, ginfo->full_width);
	if (ginfo->full_width < view_width) {
		reset_graph(ginfo, view_width);
		time = ginfo->view_start_time;

	} else if (ginfo->draw_width < ginfo->full_width) {
		if (ginfo->full_width < MAX_WIDTH) {
			ginfo->draw_width = ginfo->full_width;
			ginfo->view_start_time = ginfo->start_time;
			ginfo->view_end_time = ginfo->end_time;
			ginfo->start_x = 0;
		} else {
			ginfo->draw_width = MAX_WIDTH;
			mid /= divider;
			mid += ginfo->start_x;

			/* mid now is the current mid with full_width */
			ginfo->start_x = mid - MAX_WIDTH / 2;
			if (ginfo->start_x < 0)
				ginfo->start_x = 0;

			update_graph_to_start_x(ginfo);
		}
	}

	dprintf(1, "new width=%d\n", ginfo->draw_width);

	/* make sure the width is sent */
	if (ginfo->draw_width == old_width)
		redraw_graph(ginfo);
	else
		gtk_widget_set_size_request(ginfo->draw, ginfo->draw_width, ginfo->draw_height);

	mid = convert_time_to_x(ginfo, time);
	start_x = mid - view_width / 2;
	if (start_x < 0)
		start_x = 0;

	ginfo->hadj_value = start_x;
}

static void activate_zoom(struct graph_info *ginfo, gint x)
{
	if (!ginfo->zoom)
		return;

	ginfo->zoom = FALSE;

	if (x > ginfo->press_x) {
		/* make a decent zoom */
		if (x - ginfo->press_x < 10)
			return;
		zoom_in_window(ginfo, ginfo->press_x, x);
	} else if (x < ginfo->press_x)
		zoom_out_window(ginfo, ginfo->press_x, x);
}

static void button_release(struct graph_info *ginfo, gint x)
{
	gint old_x;

	if (!ginfo->line_active)
		return;

	if (!ginfo->zoom) {
		ginfo->show_marka = TRUE;
		ginfo->show_markb = TRUE;
		update_markb(ginfo, x);
	} else
		stop_zoom_tip(ginfo);

	clear_line(ginfo, ginfo->last_x);
	clear_line(ginfo, ginfo->press_x);
	ginfo->line_active = FALSE;

	clear_info_box(ginfo);

	/* If button is released at same location, set A (without shift) */
	if (ginfo->zoom &&
	    x >= ginfo->press_x-1 && x <= ginfo->press_x+1) {
		old_x = convert_time_to_x(ginfo, ginfo->marka_time);
		ginfo->show_marka = TRUE;
		update_marka(ginfo, x);
		clear_line(ginfo, old_x);
		if (ginfo->markb_time)
			update_label_time(ginfo->delta_label,
					  ginfo->markb_time - ginfo->marka_time);
	}

	activate_zoom(ginfo, x);
}

static gboolean
button_release_event(GtkWidget *widget, GdkEventMotion *event, gpointer data)
{
	struct graph_info *ginfo = data;

	if (!ginfo->handle)
		return FALSE;

	button_release(ginfo, event->x);

	return TRUE;
}

static gboolean
leave_notify_event(GtkWidget *widget, GdkEventCrossing *event, gpointer data)
{
	struct graph_info *ginfo = data;

	if (!ginfo->handle)
		return FALSE;

	clear_info_box(ginfo);

	return FALSE;
}

static void set_color(GtkWidget *widget, GdkGC *gc, gint c)
{
	GdkColor color;

	color.red = (c & 0xff)*(65535/255);
	color.blue = ((c >> 8) & 0xff)*(65535/255);
	color.green = ((c >> 16) & 0xff)*(65535/255);
	gdk_color_alloc(gtk_widget_get_colormap(widget), &color);
	gdk_gc_set_foreground(gc, &color);
}

#define LABEL_SPACE 3

static gint draw_event_label(struct graph_info *ginfo, gint i,
			    gint p1, gint p2, gint p3,
			    gint width_16, PangoFontDescription *font)
{
	struct graph_plot *plot = ginfo->plot_array[i];
	PangoLayout *layout;
	struct trace_seq s;
	gint text_width;
	gint text_height;
	gint start, end;
	gint x, y;
	gint ret;

	/*
	 * We are testing if we can print the label at p2.
	 * p1 has the start of the area that we can print.
	 * p3 is the location of the next label.
	 * We will not print any label unless we have enough
	 * room to print a minimum of 16 characters.
	 */
	if (p3 - p1 < width_16 ||
	    p3 - p2 < width_16 / 2)
		return p2;

	/* Now get p2's drawing size */
	trace_seq_init(&s);

	/*
	 * Display the event after p2 - 1. We use "-1" because we need to
	 * find the event at this pixel, and due to rounding, p2 time can
	 * be after the time of the event. Since tracecmd finds the next event
	 * after the time, we use this to find our next event.
	 */
	ret = trace_graph_plot_display_last_event(ginfo, plot, &s,
						  convert_x_to_time(ginfo, p2-1));
	if (!ret) {
		trace_seq_destroy(&s);
		return p2;
	}

	layout = gtk_widget_create_pango_layout(ginfo->draw, s.buffer);
	pango_layout_set_font_description(layout, font);
	pango_layout_get_pixel_size(layout, &text_width, &text_height);

	trace_seq_destroy(&s);

	/* Lets see if we can print this info */
	if (p2 < text_width)
		start = 1;
	else
		start = p2 - text_width / 2;
	end = start + text_width;

	if (start < p1 || end > p3) {
		g_object_unref(layout);
		return p2;
	}

	/* Display the info */
	x = start;

	y = (PLOT_TOP(i) - text_height + 5);
	gdk_draw_layout(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
			x, y, layout);

	gdk_draw_line(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
		      p2, PLOT_TOP(i) - 5, p2, PLOT_TOP(i) - 1);

	g_object_unref(layout);

	/*
	 * Set the next p1 to start after the end of what was displayed
	 * plus a little padding.
	 */
	return end + LABEL_SPACE;
}

static gint draw_plot_line(struct graph_info *ginfo, int i,
			   unsigned long long time, GdkGC *gc)
{
	gint x;

	x = convert_time_to_x(ginfo, time);

	gdk_draw_line(ginfo->curr_pixmap, gc,
		      x, PLOT_TOP(i), x, PLOT_BOTTOM(i));

	return x;
}

static void draw_plot_box(struct graph_info *ginfo, int i,
			  unsigned long long start,
			  unsigned long long end,
			  gboolean fill, GdkGC *gc)
{
	gint x1;
	gint x2;

	x1 = convert_time_to_x(ginfo, start);
	x2 = convert_time_to_x(ginfo, end);

	gdk_draw_rectangle(ginfo->curr_pixmap, gc,
			   fill,
			   x1, PLOT_BOX_TOP(i),
			   x2 - x1, PLOT_BOX_SIZE);
}

static void draw_plot(struct graph_info *ginfo, struct graph_plot *plot,
		      struct pevent_record *record)
{
	static PangoFontDescription *font;
	PangoLayout *layout;
	static gint width_16;
	struct plot_info info;
	gint x;

	/* Calculate the size of 16 characters */
	if (!width_16) {
		gchar buf[17];
		gint text_height;

		memset(buf, 'a', 16);
		buf[16] = 0;

		font = pango_font_description_from_string("Sans 8");
		layout = gtk_widget_create_pango_layout(ginfo->draw, buf);
		pango_layout_set_font_description(layout, font);
		pango_layout_get_pixel_size(layout, &width_16, &text_height);
		g_object_unref(layout);
	}

	trace_graph_plot_event(ginfo, plot, record, &info);

	if (info.box) {
		if (info.bcolor != plot->last_color) {
			plot->last_color = info.bcolor;
			set_color(ginfo->draw, plot->gc, plot->last_color);
		}

		draw_plot_box(ginfo, plot->pos, info.bstart, info.bend,
			      info.bfill, plot->gc);
	}

	if (info.line) {
		if (info.lcolor != plot->last_color) {
			plot->last_color = info.lcolor;
			set_color(ginfo->draw, plot->gc, plot->last_color);
		}

		x = draw_plot_line(ginfo, plot->pos, info.ltime, plot->gc);

		/* Figure out if we can show the text for the previous record */

		plot->p3 = x;

		/* Make sure p2 will be non-zero the next iteration */
		if (!plot->p3)
			plot->p3 = 1;

		/* first record, continue */
		if (plot->p2)
			plot->p2 = draw_event_label(ginfo, plot->pos,
						    plot->p1, plot->p2, plot->p3, width_16, font);

		plot->p1 = plot->p2;
		plot->p2 = plot->p3;
	}

	if (!record && plot->p2)
		draw_event_label(ginfo, plot->pos,
				 plot->p1, plot->p2, ginfo->draw_width, width_16, font);
}

static void draw_plots(struct graph_info *ginfo, gint new_width)
{
	struct plot_list *list;
	struct graph_plot *plot;
	struct pevent_record *record;
	struct plot_hash *hash;
	gint pid;
	gint cpu;
	gint i;

	/* Initialize plots */
	for (i = 0; i < ginfo->plots; i++) {
		plot = ginfo->plot_array[i];

		if (!plot->gc)
			plot->gc = gdk_gc_new(ginfo->draw->window);
		plot->p1 = 0;
		plot->p2 = 0;
		plot->p3 = 0;
		plot->last_color = -1;

		gdk_draw_line(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
			      0, PLOT_LINE(i), new_width, PLOT_LINE(i));

		trace_graph_plot_start(ginfo, plot, ginfo->view_start_time);

		set_color(ginfo->draw, plot->gc, plot->last_color);
	}

	tracecmd_set_all_cpus_to_timestamp(ginfo->handle,
					   ginfo->view_start_time);

	trace_set_cursor(GDK_WATCH);

	/* Shortcut if we don't have any task plots */
	if (!ginfo->nr_task_hash && !ginfo->all_recs) {
		for (cpu = 0; cpu < ginfo->cpus; cpu++) {
			hash = trace_graph_plot_find_cpu(ginfo, cpu);
			if (!hash)
				continue;

			while ((record = tracecmd_read_data(ginfo->handle, cpu))) {
				if (record->ts < ginfo->view_start_time) {
					free_record(record);
					continue;
				}
				if (record->ts > ginfo->view_end_time) {
					free_record(record);
					break;
				}
				for (list = hash->plots; list; list = list->next)
					draw_plot(ginfo, list->plot, record);
				free_record(record);
			}
		}
		goto out;
	}

	while ((record = tracecmd_read_next_data(ginfo->handle, &cpu))) {
		if (record->ts < ginfo->view_start_time) {
			free_record(record);
			continue;
		}
		if (record->ts > ginfo->view_end_time) {
			free_record(record);
			break;
		}
		hash = trace_graph_plot_find_cpu(ginfo, cpu);
		if (hash) {
			for (list = hash->plots; list; list = list->next)
				draw_plot(ginfo, list->plot, record);
		}
		pid = pevent_data_pid(ginfo->pevent, record);
		hash = trace_graph_plot_find_task(ginfo, pid);
		if (hash) {
			for (list = hash->plots; list; list = list->next)
				draw_plot(ginfo, list->plot, record);
		}
		for (list = ginfo->all_recs; list; list = list->next)
			draw_plot(ginfo, list->plot, record);
		free_record(record);
	}

out:
	for (i = 0; i < ginfo->plots; i++) {
		plot = ginfo->plot_array[i];
		draw_plot(ginfo, plot, NULL);
		trace_graph_plot_end(ginfo, plot);
		if (plot->gc)
			gdk_gc_unref(plot->gc);
		plot->gc = NULL;
	}
	trace_put_cursor();
}


static void draw_timeline(struct graph_info *ginfo, gint width)
{
	PangoLayout *layout;
	struct trace_seq s;
	unsigned long sec, usec;
	unsigned long long time;
	gint mid;
	gint w, h, height;
	gint view_width;

	/* --- draw timeline text --- */

	layout = gtk_widget_create_pango_layout(ginfo->draw, "Time Line");
	pango_layout_get_pixel_size(layout, &w, &h);

	height = 10 + h;

	mid = width / 2;
	gdk_draw_layout(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
			mid - w / 2, 5, layout);
	g_object_unref(layout);


	/* --- draw time line lines --- */
	gdk_draw_line(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
		      0, height, width, height);

	gdk_draw_line(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
		      0, height, 0, height + 5);

	gdk_draw_line(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
		      width-1, height, width-1, height);

	gdk_draw_line(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
		      width-1, height, width-1, height + 5);

	/* --- draw starting time --- */
	convert_nano(ginfo->view_start_time, &sec, &usec);
	trace_seq_init(&s);
	trace_seq_printf(&s, "%lu.%06lu", sec, usec);

	layout = gtk_widget_create_pango_layout(ginfo->draw, s.buffer);
	pango_layout_get_pixel_size(layout, &w, &h);

	gdk_draw_layout(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
			1, height+10, layout);
	g_object_unref(layout);
	trace_seq_destroy(&s);


	/* --- draw ending time --- */
	convert_nano(ginfo->view_end_time, &sec, &usec);
	trace_seq_init(&s);
	trace_seq_printf(&s, "%lu.%06lu", sec, usec);

	layout = gtk_widget_create_pango_layout(ginfo->draw, s.buffer);
	pango_layout_get_pixel_size(layout, &w, &h);

	gdk_draw_layout(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
			width - (w + 2), height+10, layout);
	g_object_unref(layout);
	trace_seq_destroy(&s);


	/* --- draw time at intervals --- */
	view_width = gtk_adjustment_get_page_size(ginfo->hadj);

	for (mid = view_width / 2; mid < (width - view_width / 2 + 10);
	     mid += view_width / 2) {
		time = convert_x_to_time(ginfo, mid);

		convert_nano(time, &sec, &usec);
		trace_seq_init(&s);
		trace_seq_printf(&s, "%lu.%06lu", sec, usec);

		gdk_draw_line(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
			      mid, height, mid, height + 5);

		layout = gtk_widget_create_pango_layout(ginfo->draw, s.buffer);
		pango_layout_get_pixel_size(layout, &w, &h);

		gdk_draw_layout(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
				mid - (w / 2), height+10, layout);
		g_object_unref(layout);
		trace_seq_destroy(&s);
	}
}

static void draw_info(struct graph_info *ginfo,
		      gint new_width)
{
	if (!ginfo->handle)
		return;

	ginfo->resolution = (gdouble)new_width / (gdouble)(ginfo->view_end_time -
							   ginfo->view_start_time);

	ginfo->full_width = (ginfo->end_time - ginfo->start_time) * ginfo->resolution;

	draw_timeline(ginfo, new_width);

	draw_plots(ginfo, new_width);

	ginfo->read_comms = FALSE;
}

void trace_graph_select_by_time(struct graph_info *ginfo, guint64 time)
{
	GtkAdjustment *vadj;
	gint view_start;
	gint view_width;
	gint width;
	gint mid;
	gint start;
	gint end;
	int ret;
	gint i;
	guint64 old_start_time = ginfo->view_start_time;

	view_width = gtk_adjustment_get_page_size(ginfo->hadj);
	width = ginfo->draw_width ? : ginfo->full_width;

	mid = (time - ginfo->start_time) * ginfo->resolution;
	start = mid - width / 2;
	if (start < 0)
		start = 0;
	end = start + width;

	/*
	 * Readjust the drawing to be centered on the selection.
	 */

	if (end > ginfo->full_width) {
		start -= end - ginfo->full_width;
		g_assert(start >= 0);
		end = ginfo->full_width;
	}

	ginfo->start_x = start;

	update_graph_to_start_x(ginfo);

	/* force redraw if we changed the time*/
	if (old_start_time != ginfo->view_start_time)
		redraw_pixmap_backend(ginfo);

	/* Adjust start to be the location for the hadj */
	mid = convert_time_to_x(ginfo, time);
	start = mid - view_width / 2;
	if (start < 0)
		start = 0;

	if (start > (width - view_width))
		start = width - view_width;
	gtk_adjustment_set_value(ginfo->hadj, start);

	ginfo->last_x = convert_time_to_x(ginfo, ginfo->cursor);
	ginfo->cursor = 0;
	clear_line(ginfo, ginfo->last_x);
	ginfo->cursor = time;

	update_with_backend(ginfo, 0, 0, width, ginfo->draw_height);

	/*
	 * If a record exists at this exact time value, we should
	 * make sure that it is in view.
	 */
	for (i = 0; i < ginfo->plots; i++) {
		ret = trace_graph_plot_match_time(ginfo, ginfo->plot_array[i],
						  time);
		if (ret)
			break;
	}
	if (i == ginfo->plots)
		return;

	/* Make sure PLOT is visible */
	vadj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(ginfo->scrollwin));
	view_start = gtk_adjustment_get_value(vadj);
	view_width = gtk_adjustment_get_page_size(vadj);

	if (PLOT_TOP(i) > view_start &&
	    PLOT_BOTTOM(i) < view_start + view_width)
		return;

	if (PLOT_TOP(i) < view_start)
		gtk_adjustment_set_value(vadj, PLOT_TOP(i) - 5);

	if (PLOT_BOTTOM(i) > view_start + view_width)
		gtk_adjustment_set_value(vadj, (PLOT_BOTTOM(i) - view_width) + 10);
}

void trace_graph_event_filter_callback(gboolean accept,
				       gboolean all_events,
				       gchar **systems,
				       gint *events,
				       gpointer data)
{
	struct graph_info *ginfo = data;

	if (!accept)
		return;

	if (all_events) {
		ginfo->all_events = TRUE;
		/* filter is no longer used */
		pevent_filter_reset(ginfo->event_filter);
		redraw_graph(ginfo);
		return;
	}

	ginfo->all_events = FALSE;

	pevent_filter_clear_trivial(ginfo->event_filter, FILTER_TRIVIAL_BOTH);

	trace_filter_convert_char_to_filter(ginfo->event_filter,
					    systems, events);

	redraw_graph(ginfo);
}

void trace_graph_adv_filter_callback(gboolean accept,
				     const gchar *text,
				     gint *event_ids,
				     gpointer data)
{
	struct graph_info *ginfo = data;
	struct event_filter *event_filter;
	char *error_str;
	int ret;
	int i;

	if (!accept)
		return;

	if (!has_text(text) && !event_ids)
		return;

	event_filter = ginfo->event_filter;

	if (event_ids) {
		for (i = 0; event_ids[i] >= 0; i++)
			pevent_filter_remove_event(event_filter, event_ids[i]);
	}

	if (has_text(text)) {

		ginfo->all_events = FALSE;

		pevent_filter_clear_trivial(event_filter,
					    FILTER_TRIVIAL_BOTH);

		ret = pevent_filter_add_filter_str(event_filter, text, &error_str);
		if (ret < 0) {
			warning("filter failed due to: %s", error_str);
			free(error_str);
			return;
		}
	}

	redraw_graph(ginfo);
}

void trace_graph_copy_filter(struct graph_info *ginfo,
			     gboolean all_events,
			     struct event_filter *event_filter)
{
	if (all_events) {
		ginfo->all_events = TRUE;
		/* filter is no longer used */
		pevent_filter_reset(ginfo->event_filter);
		redraw_graph(ginfo);
		return;
	}

	ginfo->all_events = FALSE;

	pevent_filter_copy(ginfo->event_filter, event_filter);

	redraw_graph(ginfo);
}

static void redraw_pixmap_backend(struct graph_info *ginfo)
{
	GdkPixmap *old_pix;
	static gboolean init;

	old_pix = ginfo->curr_pixmap;

	/* initialize full width if needed */
	if (!ginfo->full_width)
		ginfo->full_width = ginfo->draw->allocation.width;

	ginfo->curr_pixmap = gdk_pixmap_new(ginfo->draw->window,
					    ginfo->draw->allocation.width,
					    ginfo->draw->allocation.height,
					    -1);

	gdk_draw_rectangle(ginfo->curr_pixmap,
			   ginfo->draw->style->white_gc,
			   TRUE,
			   0, 0,
			   ginfo->draw->allocation.width,
			   ginfo->draw->allocation.height);

	draw_info(ginfo, ginfo->draw->allocation.width);

	if (!init) {
		init = TRUE;
		green = gdk_gc_new(ginfo->draw->window);
		red = gdk_gc_new(ginfo->draw->window);
		set_color(ginfo->draw, green, (0xff<<16));
		set_color(ginfo->draw, red, 0xff);
	}

	if (old_pix)
		g_object_unref(old_pix);

	if (ginfo->hadj_value) {
//		gtk_adjustment_set_lower(ginfo->hadj, -100.0);
		gtk_adjustment_set_value(ginfo->hadj, ginfo->hadj_value);
	}
}

static gboolean
configure_event(GtkWidget *widget, GdkEventMotion *event, gpointer data)
{
	struct graph_info *ginfo = data;

	gtk_widget_set_size_request(widget, ginfo->draw_width, ginfo->draw_height);

	redraw_pixmap_backend(ginfo);

	/* debug */
	ginfo->hadj_value = gtk_adjustment_get_value(ginfo->hadj);
	dprintf(2, "get val %f\n", ginfo->hadj_value);
	ginfo->hadj_value = 0.0;

	return TRUE;
}

static gboolean
destroy_event(GtkWidget *widget, gpointer data)
{
	struct graph_info *ginfo = data;

	trace_graph_free_info(ginfo);

	filter_task_hash_free(ginfo->task_filter);
	filter_task_hash_free(ginfo->hide_tasks);

	return TRUE;
}

static void redraw_label_window(struct graph_info *ginfo, int x, int y,
				int w, int h)
{
	gdk_draw_drawable(ginfo->info->window,
			  ginfo->info->style->fg_gc[GTK_WIDGET_STATE(ginfo->info)],
			  ginfo->info_pixmap, x, y, x, y, w, h);
}

static gboolean
info_expose_event(GtkWidget *widget, GdkEventExpose *event, gpointer data)
{
	struct graph_info *ginfo = data;

	redraw_label_window(ginfo, event->area.x, event->area.y,
			    event->area.width, event->area.height);
	return FALSE;
}

static void info_draw_plot_label(struct graph_info *ginfo, gint i)
{
	PangoLayout *layout;
	gint width, height;
	char *label;

	label = ginfo->plot_array[i]->label;

	layout = gtk_widget_create_pango_layout(ginfo->info, label);
	pango_layout_get_pixel_size(layout, &width, &height);
	width += 4;

	if (width > largest_plot_label)
		largest_plot_label = width;
	gdk_draw_rectangle(ginfo->info_pixmap,
			   ginfo->info->style->white_gc,
			   TRUE,
			   PLOT_X, PLOT_LABEL(i)+4,
			   width, height);
	gdk_draw_layout(ginfo->info_pixmap,
			ginfo->info->style->black_gc,
			PLOT_X+ 2, PLOT_LABEL(i) + 4,
			layout);
	g_object_unref(layout);
}

static void info_draw_plot_labels(struct graph_info *ginfo)
{
	gint i;

	if (!ginfo->handle)
		return;

	largest_plot_label = 0;

	for (i = 0; i < ginfo->plots; i++)
		info_draw_plot_label(ginfo, i);
}

static void update_label_window(struct graph_info *ginfo)
{
	if (ginfo->info_pixmap)
		g_object_unref(ginfo->info_pixmap);

	ginfo->info_pixmap = gdk_pixmap_new(ginfo->info->window,
					    ginfo->info->allocation.width,
					    ginfo->info->allocation.height,
					    -1);

	gdk_draw_rectangle(ginfo->info_pixmap,
			   ginfo->info->style->white_gc,
			   TRUE,
			   0, 0,
			   ginfo->info->allocation.width,
			   ginfo->info->allocation.height);

	info_draw_plot_labels(ginfo);

	gtk_widget_set_size_request(ginfo->info, largest_plot_label + 10,
				    ginfo->draw_height);

	redraw_label_window(ginfo, 0, 0, ginfo->info->allocation.width,
			    ginfo->info->allocation.height);
}

static gboolean
info_configure_event(GtkWidget *widget, GdkEventMotion *event, gpointer data)
{
	struct graph_info *ginfo = data;

	update_label_window(ginfo);

	return TRUE;
}

static GtkWidget *
create_graph_info(struct graph_info *ginfo)
{
	GtkWidget *info;

	info = gtk_drawing_area_new();

	gtk_signal_connect(GTK_OBJECT(info), "expose_event",
			   (GtkSignalFunc) info_expose_event, ginfo);
	gtk_signal_connect(GTK_OBJECT(info), "configure_event",
			   (GtkSignalFunc) info_configure_event, ginfo);
	gtk_signal_connect(GTK_OBJECT(info), "button_press_event",
			   (GtkSignalFunc) info_button_press_event, ginfo);
	gtk_signal_connect(GTK_OBJECT(info), "motion_notify_event",
			   (GtkSignalFunc) info_motion_notify_event, ginfo);
	gtk_signal_connect(GTK_OBJECT(info), "button_release_event",
			   (GtkSignalFunc) info_button_release_event, ginfo);

	gtk_widget_set_events(info, GDK_EXPOSURE_MASK
			      | GDK_BUTTON_PRESS_MASK
			      | GDK_BUTTON_RELEASE_MASK
			      | GDK_POINTER_MOTION_MASK
			      | GDK_POINTER_MOTION_HINT_MASK);

	return info;
}

void trace_graph_free_info(struct graph_info *ginfo)
{
	if (ginfo->handle) {
		pevent_filter_free(ginfo->event_filter);
		trace_graph_plot_free(ginfo);
		tracecmd_close(ginfo->handle);
		free_task_hash(ginfo);

		ginfo->cursor = 0;
	}
	ginfo->handle = NULL;
}

static int load_handle(struct graph_info *ginfo,
		       struct tracecmd_input *handle)
{
	struct pevent_record *record;
	unsigned long sec, usec;
	gint cpu;

	if (!handle)
		return -1;

	trace_graph_free_info(ginfo);
	trace_graph_plot_init(ginfo);

	ginfo->handle = handle;
	tracecmd_ref(handle);

	init_event_cache(ginfo);

	ginfo->pevent = tracecmd_get_pevent(handle);
	ginfo->cpus = tracecmd_cpus(handle);
	ginfo->all_events = TRUE;

	ginfo->event_filter = pevent_filter_alloc(ginfo->pevent);

	ginfo->start_time = -1ULL;
	ginfo->end_time = 0;

	graph_plot_init_cpus(ginfo, ginfo->cpus);

	ginfo->draw_height = PLOT_SPACE(ginfo->plots);

	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		record = tracecmd_read_cpu_first(handle, cpu);
		if (!record)
			continue;

		if (record->ts < ginfo->start_time)
			ginfo->start_time = record->ts;

		free_record(record);
		record = tracecmd_read_cpu_last(handle, cpu);
		if (!record)
			continue;

		if (record->ts > ginfo->end_time)
			ginfo->end_time = record->ts;
		free_record(record);
	}

	convert_nano(ginfo->start_time, &sec, &usec);
	dprintf(1, "start=%lu.%06lu ", sec, usec);

	convert_nano(ginfo->end_time, &sec, &usec);
	dprintf(1, "end=%lu.%06lu\n", sec, usec);

	ginfo->view_start_time = ginfo->start_time;
	ginfo->view_end_time = ginfo->end_time;

	if (!ginfo->draw)
		return 0;

	update_cursor(ginfo);
	update_pointer(ginfo, 0);
	update_marka(ginfo, 0);
	update_markb(ginfo, 0);

	return 0;
}

void trace_graph_refresh(struct graph_info *ginfo)
{
	ginfo->draw_height = PLOT_SPACE(ginfo->plots);
	gtk_widget_set_size_request(ginfo->draw, ginfo->draw_width, ginfo->draw_height);
	update_label_window(ginfo);
	redraw_graph(ginfo);
}

int trace_graph_load_handle(struct graph_info *ginfo,
			    struct tracecmd_input *handle)
{

	if (load_handle(ginfo, handle) < 0)
		return -1;

	update_label_window(ginfo);
	redraw_graph(ginfo);

	return 0;
}

static int load_event_filter(struct graph_info *ginfo,
			     struct tracecmd_xml_handle *handle,
			     struct tracecmd_xml_system_node *node)
{
	struct tracecmd_xml_system_node *child;
	struct event_filter *event_filter;
	const char *name;
	const char *value;

	event_filter = ginfo->event_filter;

	child = tracecmd_xml_node_child(node);
	name = tracecmd_xml_node_type(child);
	if (strcmp(name, "FilterType") != 0)
		return -1;

	value = tracecmd_xml_node_value(handle, child);
	/* Do nothing with all events enabled */
	if (strcmp(value, "all events") == 0)
		return 0;

	node = tracecmd_xml_node_next(child);
	if (!node)
		return -1;

	pevent_filter_clear_trivial(event_filter, FILTER_TRIVIAL_BOTH);
	ginfo->all_events = FALSE;

	trace_filter_load_events(event_filter, handle, node);

	return 0;
}

int trace_graph_load_filters(struct graph_info *ginfo,
			     struct tracecmd_xml_handle *handle)
{
	struct tracecmd_xml_system *system;
	struct tracecmd_xml_system_node *syschild;
	const char *name;

	if (filter_task_count(ginfo->task_filter) ||
	    filter_task_count(ginfo->hide_tasks))
		ginfo->filter_available = 1;
	else
		ginfo->filter_available = 0;

	system = tracecmd_xml_find_system(handle, "TraceGraph");
	if (!system)
		return -1;

	syschild = tracecmd_xml_system_node(system);
	if (!syschild)
		goto out_free_sys;

	do {
		name = tracecmd_xml_node_type(syschild);

		if (strcmp(name, "EventFilter") == 0)
			load_event_filter(ginfo, handle, syschild);

		syschild = tracecmd_xml_node_next(syschild);
	} while (syschild);

	if (filter_task_count(ginfo->task_filter) ||
	    filter_task_count(ginfo->hide_tasks))
		ginfo->filter_available = 1;
	else
		ginfo->filter_available = 0;

	tracecmd_xml_free_system(system);

	trace_graph_refresh(ginfo);

	return 0;

 out_free_sys:
	tracecmd_xml_free_system(system);
	if (ginfo->filter_enabled)
		trace_graph_refresh(ginfo);

	return -1;
}

int trace_graph_save_filters(struct graph_info *ginfo,
			     struct tracecmd_xml_handle *handle)
{
	struct event_filter *event_filter;

	tracecmd_xml_start_system(handle, "TraceGraph");

	event_filter = ginfo->event_filter;

	tracecmd_xml_start_sub_system(handle, "EventFilter");

	if (ginfo->all_events || !event_filter)
		tracecmd_xml_write_element(handle, "FilterType", "all events");
	else {
		tracecmd_xml_write_element(handle, "FilterType", "filter");
		trace_filter_save_events(handle, event_filter);
	}

	tracecmd_xml_end_sub_system(handle);

	tracecmd_xml_end_system(handle);

	return 0;
}

static void set_label_a(GtkWidget *widget)
{
	gtk_widget_set_tooltip_text(widget, "Click left mouse on graph\n"
				    "to set Marker A");
}

static void set_label_b(GtkWidget *widget)
{
	gtk_widget_set_tooltip_text(widget, "Shift and click left mouse on graph\n"
				    "to set Marker B");
}

static void set_label_cursor(GtkWidget *widget)
{
	gtk_widget_set_tooltip_text(widget, "Double click Left mouse on graph\n"
				    "to set Cursor");
}

struct graph_info *
trace_graph_create_with_callbacks(struct tracecmd_input *handle,
				  struct graph_callbacks *cbs)
{
	struct graph_info *ginfo;
	GtkWidget *table;
	GtkWidget *hbox;
	GtkWidget *label;
	GtkWidget *eventbox;
	GdkColor color;
	GdkColor colorAB;

	ginfo = g_new0(typeof(*ginfo), 1);
	g_assert(ginfo != NULL);

	if (handle)
		load_handle(ginfo, handle);

	ginfo->handle = handle;

	ginfo->callbacks = cbs;

	ginfo->task_filter = filter_task_hash_alloc();
	ginfo->hide_tasks = filter_task_hash_alloc();

	ginfo->widget = gtk_vbox_new(FALSE, 0);
	gtk_widget_show(ginfo->widget);


	ginfo->status_hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(ginfo->widget), ginfo->status_hbox, FALSE, FALSE, 0);
	gtk_widget_show(ginfo->status_hbox);

	table = gtk_table_new(1, 23, FALSE);
	gtk_box_pack_start(GTK_BOX(ginfo->status_hbox), table, FALSE, FALSE, 0);
	gtk_widget_show(table);

	color.red = (0xff) *(65535/255);
	color.green = (0xff) *(65535/255);
	color.blue = (0xff) *(65535/255);

	/* --- Pointer --- */

	label = gtk_label_new("Pointer:");
	gtk_table_attach(GTK_TABLE(table), label, 0, 1, 0, 1, GTK_EXPAND, GTK_EXPAND, 3, 3);
	gtk_widget_show(label);

	ginfo->pointer_time = gtk_label_new("0.0");
	eventbox = gtk_event_box_new();
	gtk_widget_show(eventbox);
	gtk_widget_modify_bg(eventbox, GTK_STATE_NORMAL, &color);
	gtk_container_add(GTK_CONTAINER(eventbox), ginfo->pointer_time);
	gtk_table_attach(GTK_TABLE(table), eventbox, 1, 3, 0, 1,
			 GTK_EXPAND, GTK_EXPAND, 3, 3);
	gtk_widget_show(ginfo->pointer_time);

	/* --- Cursor --- */

	label = gtk_label_new("Cursor:");
	set_label_cursor(label);
	gtk_table_attach(GTK_TABLE(table), label, 4, 5, 0, 1, GTK_EXPAND, GTK_EXPAND, 3, 3);
	gtk_widget_show(label);

	ginfo->cursor_label = gtk_label_new("0.0");
	eventbox = gtk_event_box_new();
	set_label_cursor(eventbox);
	gtk_widget_show(eventbox);
	gtk_widget_modify_bg(eventbox, GTK_STATE_NORMAL, &color);
	gtk_container_add(GTK_CONTAINER(eventbox), ginfo->cursor_label);
	gtk_table_attach(GTK_TABLE(table), eventbox, 6, 8, 0, 1,
			 GTK_EXPAND, GTK_EXPAND, 3, 3);
	gtk_widget_show(ginfo->cursor_label);


	/* --- Marker A --- */

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_widget_show(hbox);

	label = gtk_label_new("Marker");
	set_label_a(label);
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);


	label = gtk_label_new("A:");

	colorAB.red = 0;
	colorAB.green = (0xff) *(65535/255);
	colorAB.blue = 0;

	eventbox = gtk_event_box_new();
	set_label_a(eventbox);
	gtk_widget_show(eventbox);
	gtk_widget_modify_bg(eventbox, GTK_STATE_NORMAL, &colorAB);
	gtk_container_add(GTK_CONTAINER(eventbox), label);

	gtk_box_pack_start(GTK_BOX(hbox), eventbox, FALSE, FALSE, 0);
	gtk_widget_show(label);

	gtk_table_attach(GTK_TABLE(table), hbox, 9, 10, 0, 1, GTK_EXPAND, GTK_EXPAND, 3, 3);

	ginfo->marka_label = gtk_label_new("0.0");
	eventbox = gtk_event_box_new();
	set_label_a(eventbox);
	gtk_widget_show(eventbox);
	gtk_widget_modify_bg(eventbox, GTK_STATE_NORMAL, &color);
	gtk_container_add(GTK_CONTAINER(eventbox), ginfo->marka_label);
	gtk_table_attach(GTK_TABLE(table), eventbox, 11, 13, 0, 1,
			 GTK_EXPAND, GTK_EXPAND, 3, 3);
	gtk_widget_show(ginfo->marka_label);


	/* --- Marker B --- */

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_widget_show(hbox);

	label = gtk_label_new("Marker");
	set_label_b(label);
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	label = gtk_label_new("B:");

	colorAB.red = (0xff) *(65535/255);
	colorAB.green = 0;
	colorAB.blue = 0;

	eventbox = gtk_event_box_new();
	set_label_b(eventbox);
	gtk_widget_show(eventbox);
	gtk_widget_modify_bg(eventbox, GTK_STATE_NORMAL, &colorAB);
	gtk_container_add(GTK_CONTAINER(eventbox), label);

	gtk_box_pack_start(GTK_BOX(hbox), eventbox, FALSE, FALSE, 0);
	gtk_widget_show(label);

	gtk_table_attach(GTK_TABLE(table), hbox, 14, 15, 0, 1, GTK_EXPAND, GTK_EXPAND, 3, 3);
	gtk_widget_show(label);

	ginfo->markb_label = gtk_label_new("0.0");
	eventbox = gtk_event_box_new();
	set_label_b(eventbox);
	gtk_widget_show(eventbox);
	gtk_widget_modify_bg(eventbox, GTK_STATE_NORMAL, &color);
	gtk_container_add(GTK_CONTAINER(eventbox), ginfo->markb_label);
	gtk_table_attach(GTK_TABLE(table), eventbox, 16, 18, 0, 1,
			 GTK_EXPAND, GTK_EXPAND, 3, 3);
	gtk_widget_show(ginfo->markb_label);


	/* --- Delta --- */

	label = gtk_label_new("A,B Delta:");
	gtk_table_attach(GTK_TABLE(table), label, 19, 20, 0, 1, GTK_EXPAND, GTK_EXPAND, 3, 3);
	gtk_widget_show(label);

	ginfo->delta_label = gtk_label_new("0.0");
	eventbox = gtk_event_box_new();
	gtk_widget_show(eventbox);
	gtk_widget_modify_bg(eventbox, GTK_STATE_NORMAL, &color);
	gtk_container_add(GTK_CONTAINER(eventbox), ginfo->delta_label);
	gtk_table_attach(GTK_TABLE(table), eventbox, 21, 23, 0, 1,
			 GTK_EXPAND, GTK_EXPAND, 3, 3);
	gtk_widget_show(ginfo->delta_label);


	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(ginfo->widget), hbox, TRUE, TRUE, 0);
	gtk_widget_show(hbox);

	ginfo->scrollwin = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(ginfo->scrollwin),
				       GTK_POLICY_AUTOMATIC,
				       GTK_POLICY_AUTOMATIC);
	gtk_widget_show(ginfo->scrollwin);
	ginfo->hadj = gtk_scrolled_window_get_hadjustment(GTK_SCROLLED_WINDOW(ginfo->scrollwin));

	ginfo->info_scrollwin = gtk_scrolled_window_new(NULL,
		gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(ginfo->scrollwin)));

	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(ginfo->info_scrollwin),
				       GTK_POLICY_NEVER,
				       GTK_POLICY_NEVER);
	gtk_widget_show(ginfo->info_scrollwin);
	gtk_box_pack_start(GTK_BOX(hbox), ginfo->info_scrollwin, FALSE, FALSE, 0);

	ginfo->info = create_graph_info(ginfo);
	gtk_widget_show(ginfo->info);

	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(ginfo->info_scrollwin),
					      ginfo->info);

	gtk_box_pack_start(GTK_BOX (hbox), ginfo->scrollwin, TRUE, TRUE, 0);

	gtk_signal_connect(GTK_OBJECT(ginfo->hadj), "value_changed",
			   (GtkSignalFunc) value_changed, ginfo);

	ginfo->draw = gtk_drawing_area_new();

	gtk_signal_connect(GTK_OBJECT(ginfo->draw), "expose_event",
			   (GtkSignalFunc) expose_event, ginfo);
	gtk_signal_connect(GTK_OBJECT(ginfo->draw), "button_press_event",
			   (GtkSignalFunc) button_press_event, ginfo);
	gtk_signal_connect(GTK_OBJECT(ginfo->draw), "configure_event",
			   (GtkSignalFunc) configure_event, ginfo);
	gtk_signal_connect(GTK_OBJECT(ginfo->draw), "motion_notify_event",
			   (GtkSignalFunc) motion_notify_event, ginfo);
	gtk_signal_connect(GTK_OBJECT(ginfo->draw), "button_release_event",
			   (GtkSignalFunc) button_release_event, ginfo);
	gtk_signal_connect(GTK_OBJECT(ginfo->draw), "leave-notify-event",
			   (GtkSignalFunc) leave_notify_event, ginfo);
	gtk_signal_connect(GTK_OBJECT(ginfo->draw), "destroy",
			   (GtkSignalFunc) destroy_event, ginfo);

	gtk_widget_set_events(ginfo->draw, GDK_EXPOSURE_MASK
			      | GDK_LEAVE_NOTIFY_MASK
			      | GDK_BUTTON_PRESS_MASK
			      | GDK_BUTTON_RELEASE_MASK
			      | GDK_POINTER_MOTION_MASK
			      | GDK_POINTER_MOTION_HINT_MASK
			      | GDK_LEAVE_NOTIFY_MASK);

	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(ginfo->scrollwin),
					      ginfo->draw);
	gtk_widget_show(ginfo->draw);

	return ginfo;
}

struct graph_info *
trace_graph_create(struct tracecmd_input *handle)
{
	return trace_graph_create_with_callbacks(handle, NULL);
}
