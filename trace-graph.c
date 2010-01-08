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
#include "trace-local.h"
#include "trace-graph.h"
#include "trace-hash.h"
#include "trace-filter.h"

#define DEBUG_LEVEL	2
#if DEBUG_LEVEL > 0
# define dprintf(l, x...)			\
	do {					\
		if (l <= DEBUG_LEVEL)		\
			printf(x);		\
	} while (0)
#else
# define dprintf(x...)	do { } while (0)
#endif

#define MAX_WIDTH	10000

#define CPU_SIZE	10
#define CPU_BOX_SIZE	CPU_SIZE
#define CPU_GIVE	2
#define CPU_LINE(cpu) (80 * (cpu) + 80 + CPU_SIZE)
#define CPU_TOP(cpu) (CPU_LINE(cpu) - CPU_SIZE * 2)
#define CPU_BOX_TOP(cpu) (CPU_LINE(cpu) - CPU_SIZE)
#define CPU_BOTTOM(cpu) (CPU_LINE(cpu)-1)
#define CPU_BOX_BOTTOM(cpu) (CPU_LINE(cpu))
#define CPU_SPACE(cpus) (80 * (cpus) + 80)
#define CPU_LABEL(cpu) (CPU_TOP(cpu))
#define CPU_X		5

static gint ftrace_sched_switch_id = -1;
static gint event_sched_switch_id = -1;
static gint event_wakeup_id = -1;
static gint event_wakeup_new_id = -1;

static gint largest_cpu_label = 0;

static void redraw_pixmap_backend(struct graph_info *ginfo);

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

gboolean graph_filter_system(struct graph_info *ginfo, const gchar *system)
{
	const gchar **sys = &system;

	if (ginfo->all_events)
		return TRUE;

	if (!ginfo->systems)
		return FALSE;

	sys = bsearch(sys, ginfo->systems, ginfo->systems_size,
		      sizeof(system), str_cmp);

	return sys != NULL;
}

gboolean graph_filter_event(struct graph_info *ginfo, gint event_id)
{
	gint *event = &event_id;

	if (ginfo->all_events)
		return TRUE;

	if (!ginfo->event_ids)
		return FALSE;

	event = bsearch(event, ginfo->event_ids, ginfo->event_ids_size,
			sizeof(event_id), id_cmp);

	return event != NULL;
}

gboolean graph_filter_on_event(struct graph_info *ginfo, struct record *record)
{
	struct event_format *event;
	gint event_id;

	if (!record)
		return TRUE;

	if (ginfo->all_events)
		return FALSE;

	event_id = pevent_data_type(ginfo->pevent, record);
	event = pevent_data_event_from_type(ginfo->pevent, event_id);
	if (!event)
		return TRUE;

	if (graph_filter_system(ginfo, event->system))
		return FALSE;

	if (graph_filter_event(ginfo, event_id))
		return FALSE;

	return TRUE;
}

gboolean graph_filter_on_task(struct graph_info *ginfo, gint pid)
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

static void draw_cursor(struct graph_info *ginfo)
{
	gint x;

	if (ginfo->cursor < ginfo->view_start_time ||
	    ginfo->cursor > ginfo->view_end_time)
		return;

	x = (ginfo->cursor - ginfo->view_start_time)
		* ginfo->resolution;

	gdk_draw_line(ginfo->draw->window, ginfo->draw->style->mid_gc[3],
		      x, 0, x, ginfo->draw->allocation.width);
}

static void update_with_backend(struct graph_info *ginfo,
				gint x, gint y,
				gint width, gint height)
{
	__update_with_backend(ginfo, x, y, width, height);

	if (ginfo->cursor)
		draw_cursor(ginfo);
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
		      x, 0, x, widget->allocation.width);
}

static void clear_last_line(GtkWidget *widget, struct graph_info *ginfo)
{
	gint x;

	x = ginfo->last_x;
	if (x)
		x--;

	update_with_backend(ginfo, x, 0, x+2, widget->allocation.height);
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

static struct record *
find_record_on_cpu(struct graph_info *ginfo, gint cpu, guint64 time)
{
	struct record *record = NULL;
	guint64 offset = 0;

	tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, time);
	do {
		if (record) {
			offset = record->offset;
			free_record(record);
		}
		record = tracecmd_read_data(ginfo->handle, cpu);
	} while (record && record->ts <= (time - 1 / ginfo->resolution));

	if (record) {

		if (record->ts > (time + 1 / ginfo->resolution) && offset) {
			dprintf(3, "old ts = %llu!\n", record->ts);
			free_record(record);
			record = tracecmd_read_at(ginfo->handle, offset, NULL);
		}
	}

	return record;
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

static void
filter_clear_tasks_clicked (gpointer data)
{
	struct graph_info *ginfo = data;

	trace_graph_clear_tasks(ginfo);
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
	struct record *record = NULL;
	const char *comm;
	guint64 time;
	gchar *text;
	gint pid;
	gint len;
	gint x, y;
	gint cpu;

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

	time =  (x / ginfo->resolution) + ginfo->view_start_time;

	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		if (y >= (CPU_TOP(cpu) - CPU_GIVE) &&
		    y <= (CPU_BOTTOM(cpu) + CPU_GIVE)) {
			record = find_record_on_cpu(ginfo, cpu, time);
			break;
		}
	}

	if (record) {
		pid = pevent_data_pid(ginfo->pevent, record);
		comm = pevent_data_comm_from_pid(ginfo->pevent, pid);

		len = strlen(comm) + 50;

		text = g_malloc(len);
		g_assert(text);

		if (trace_graph_filter_task_find_pid(ginfo, pid))
			snprintf(text, len, "Remove %s-%d to filter", comm, pid);
		else
			snprintf(text, len, "Add %s-%d to filter", comm, pid);

		ginfo->filter_task_selected = pid;

		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_add_task),
					text);

		if (trace_graph_hide_task_find_pid(ginfo, pid))
			snprintf(text, len, "Show %s-%d to filter", comm, pid);
		else
			snprintf(text, len, "Hide %s-%d to filter", comm, pid);

		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_hide_task),
					text);

		g_free(text);

		gtk_widget_set_sensitive(menu_filter_add_task, TRUE);
		gtk_widget_set_sensitive(menu_filter_hide_task, TRUE);

		free_record(record);
	} else {
		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_add_task),
					"Add task to filter");
		gtk_widget_set_sensitive(menu_filter_add_task, FALSE);

		gtk_menu_item_set_label(GTK_MENU_ITEM(menu_filter_hide_task),
					"Hide task to filter");
		gtk_widget_set_sensitive(menu_filter_hide_task, FALSE);
	}

		
	gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL, 3,
		       gtk_get_current_event_time());


	return TRUE;
}

static gboolean
button_press_event(GtkWidget *widget, GdkEventButton *event, gpointer data)
{
	struct graph_info *ginfo = data;

	if (event->button == 3)
		return do_pop_up(widget, event, data);

	if (event->button != 1)
		return TRUE;

	/* check for double click */
	if (event->type == GDK_2BUTTON_PRESS) {
		if (ginfo->line_active) {
			ginfo->line_active = FALSE;
			clear_last_line(widget, ginfo);
			ginfo->last_x = ginfo->press_x;
			clear_last_line(widget, ginfo);
		}
		if (ginfo->cursor >= ginfo->view_start_time &&
		    ginfo->cursor <= ginfo->view_end_time) {
			ginfo->last_x = (ginfo->cursor - ginfo->view_start_time)
				* ginfo->resolution;
			ginfo->cursor = 0;
			clear_last_line(widget, ginfo);
		}

		ginfo->cursor = event->x / ginfo->resolution +
			ginfo->view_start_time;
		draw_cursor(ginfo);
		if (ginfo->callbacks && ginfo->callbacks->select)
			ginfo->callbacks->select(ginfo, ginfo->cursor);
		return TRUE;
	}


	ginfo->press_x = event->x;
	ginfo->last_x = 0;

	draw_line(widget, event->x, ginfo);

	ginfo->line_active = TRUE;

	return TRUE;
}

static void print_rec_info(struct record *record, struct pevent *pevent, int cpu)
{
	struct trace_seq s;
	struct event_format *event;
	unsigned long sec, usec;
	gint type;

	if (DEBUG_LEVEL < 3)
		return;

	trace_seq_init(&s);

	convert_nano(record->ts, &sec, &usec);
	trace_seq_printf(&s, "%lu.%06lu", sec, usec);

	type = pevent_data_type(pevent, record);
	event = pevent_data_event_from_type(pevent, type);
	if (!event) {
		printf("No event found for id %d!\n", type);
		return;
	}
	trace_seq_puts(&s, event->name);
	trace_seq_putc(&s, ':');
	pevent_event_info(&s, event, record);
	trace_seq_putc(&s, '\n');
	trace_seq_do_printf(&s);
}

#define CPU_BOARDER 5

static int check_sched_wakeup(struct graph_info *ginfo,
			      struct record *record,
			      gint *pid)
{
	static struct format_field *wakeup_pid_field;
	static struct format_field *wakeup_success_field;
	static struct format_field *wakeup_new_pid_field;
	static struct format_field *wakeup_new_success_field;
	struct event_format *event;
	unsigned long long val;
	gboolean found;
	gint id;

	if (event_wakeup_id < 0) {

		found = FALSE;

		event = pevent_find_event_by_name(ginfo->pevent,
						  "sched", "sched_wakeup");
		if (event) {
			found = TRUE;
			event_wakeup_id = event->id;
			wakeup_pid_field = pevent_find_field(event, "pid");
			wakeup_success_field = pevent_find_field(event, "success");
		}


		event = pevent_find_event_by_name(ginfo->pevent,
						  "sched", "sched_wakeup_new");
		if (event) {
			found = TRUE;
			event_wakeup_new_id = event->id;
			wakeup_new_pid_field = pevent_find_field(event, "pid");
			wakeup_new_success_field = pevent_find_field(event, "success");
		}
		if (!found)
			return 0;
	}

	id = pevent_data_type(ginfo->pevent, record);

	if (id == event_wakeup_id) {
		/* We only want those that actually woke up the task */
		pevent_read_number_field(wakeup_success_field, record->data, &val);
		if (!val)
			return 0;
		pevent_read_number_field(wakeup_pid_field, record->data, &val);
		if (pid)
			*pid = val;
		return 1;
	}

	if (id == event_wakeup_new_id) {
		/* We only want those that actually woke up the task */
		pevent_read_number_field(wakeup_new_success_field, record->data, &val);
		if (!val)
			return 0;
		pevent_read_number_field(wakeup_new_pid_field, record->data, &val);
		if (pid)
			*pid = val;
		return 1;
	}

	return 0;
}

static int check_sched_switch(struct graph_info *ginfo,
			      struct record *record,
			      gint *pid, const char **comm)
{
	static struct format_field *event_pid_field;
	static struct format_field *event_comm_field;
	static struct format_field *ftrace_pid_field;
	static struct format_field *ftrace_comm_field;
	unsigned long long val;
	struct event_format *event;
	gint id;

	if (event_sched_switch_id < 0) {
		event = pevent_find_event_by_name(ginfo->pevent,
						  "sched", "sched_switch");
		if (!event)
			return 0;

		event_sched_switch_id = event->id;
		event_pid_field = pevent_find_field(event, "next_pid");
		event_comm_field = pevent_find_field(event, "next_comm");

		event = pevent_find_event_by_name(ginfo->pevent,
						  "ftrace", "context_switch");
		if (event) {
			ftrace_sched_switch_id = event->id;
			ftrace_pid_field = pevent_find_field(event, "next_pid");
			ftrace_comm_field = pevent_find_field(event, "next_comm");
		}
	}

	id = pevent_data_type(ginfo->pevent, record);
	if (id == event_sched_switch_id) {
		pevent_read_number_field(event_pid_field, record->data, &val);
		if (comm)
			*comm = record->data + event_comm_field->offset;
		if (pid)
			*pid = val;
		return 1;
	}

	if (id == ftrace_sched_switch_id) {
		pevent_read_number_field(ftrace_pid_field, record->data, &val);
		if (comm)
			*comm = record->data + ftrace_comm_field->offset;
		if (pid)
			*pid = val;
		return 1;
	}

	return 0;
}

static void draw_cpu_info(struct graph_info *ginfo, gint cpu, gint x, gint y)
{
	PangoLayout *layout;
	GtkAdjustment *vadj;
	struct record *record = NULL;
	struct pevent *pevent;
	struct event_format *event;
	guint64 time;
	const char *comm;
	gint pid = -1;
	gint type;
	unsigned long sec, usec;
	struct trace_seq s;
	gint width, height;
	GdkPixmap *pix;
	static GdkGC *pix_bg;
	guint64 offset = 0;
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

	time =  (x / ginfo->resolution) + ginfo->view_start_time;
	convert_nano(time, &sec, &usec);

	pevent = ginfo->pevent;

	trace_seq_init(&s);

	dprintf(3, "start=%zu end=%zu time=%lu\n", ginfo->start_time, ginfo->end_time, time);

	record = find_record_on_cpu(ginfo, cpu, time);

	if (record) {

		if (!check_sched_switch(ginfo, record, &pid, &comm)) {
			pid = pevent_data_pid(ginfo->pevent, record);
			comm = pevent_data_comm_from_pid(ginfo->pevent, pid);
		}

		dprintf(3, "record->ts=%llu time=%zu-%zu\n",
			record->ts, time, time-(gint)(1/ginfo->resolution));
		print_rec_info(record, pevent, cpu);

		/*
		 * The function graph trace reads the next record, which may
		 * unmap the record data. We need to reread the record to
		 * make sure it still exists.
		 */
		offset = record->offset;
		free_record(record);
		record = tracecmd_read_at(ginfo->handle, offset, NULL);		

		if (record->ts > time - 2/ginfo->resolution &&
		    record->ts < time + 2/ginfo->resolution) {
			convert_nano(record->ts, &sec, &usec);

			type = pevent_data_type(pevent, record);
			event = pevent_data_event_from_type(pevent, type);
			if (event) {
				trace_seq_puts(&s, event->name);
				trace_seq_putc(&s, '\n');
				pevent_data_lat_fmt(pevent, &s, record);
				trace_seq_putc(&s, '\n');
				pevent_event_info(&s, event, record);
				trace_seq_putc(&s, '\n');
			} else
				trace_seq_printf(&s, "UNKNOW EVENT %d\n", type);
		}

		trace_seq_printf(&s, "%lu.%06lu", sec, usec);
		if (pid)
			trace_seq_printf(&s, " %s-%d", comm, pid);
		else
			trace_seq_puts(&s, " <idle>");

		free_record(record);

	} else
		trace_seq_printf(&s, "%lu.%06lu", sec, usec);

	trace_seq_putc(&s, 0);

	layout = gtk_widget_create_pango_layout(ginfo->draw, s.buffer);
	pango_layout_get_pixel_size(layout, &width, &height);

	width += CPU_BOARDER * 2;
	height += CPU_BOARDER * 2;

	view_start = gtk_adjustment_get_value(ginfo->hadj);
	view_width = gtk_adjustment_get_page_size(ginfo->hadj);
	if (x > view_start + width)
		x -= width;

	vadj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(ginfo->scrollwin));
	view_start = gtk_adjustment_get_value(vadj);
	if (y > view_start + height)
		y -= height;

	ginfo->cpu_data_x = x;
	ginfo->cpu_data_y = y;
	ginfo->cpu_data_w = width;
	ginfo->cpu_data_h = height;

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
			CPU_BOARDER, CPU_BOARDER, layout);
	gdk_draw_drawable(ginfo->draw->window,
			  ginfo->draw->style->fg_gc[GTK_WIDGET_STATE(ginfo->draw)],
			  pix, 0, 0, x, y, width, height);

	g_object_unref(layout);
	g_object_unref(pix);
}

static gboolean
motion_notify_event(GtkWidget *widget, GdkEventMotion *event, gpointer data)
{
	struct graph_info *ginfo = data;
	GdkModifierType state;
	gint x, y;
	gint cpu;

	update_with_backend(ginfo, ginfo->cpu_data_x, ginfo->cpu_data_y,
			    ginfo->cpu_data_w, ginfo->cpu_data_h);
	if (event->is_hint)
		gdk_window_get_pointer(event->window, &x, &y, &state);
	else {
		x = event->x;
		y = event->y;
		state = event->state;
	}

	if (!ginfo->curr_pixmap)
		return TRUE;

	if (ginfo->line_active) {
		if (ginfo->last_x)
			clear_last_line(widget, ginfo);
		ginfo->last_x = x;
		draw_line(widget, ginfo->press_x, ginfo);
		draw_line(widget, x, ginfo);
		return TRUE;
	}

	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		if (y >= (CPU_TOP(cpu) - CPU_GIVE) &&
		    y <= (CPU_BOTTOM(cpu) + CPU_GIVE))
			draw_cpu_info(ginfo, cpu, x, y);
	}

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
	ginfo->hadj_value = (start_time - ginfo->view_start_time) * ginfo->resolution;

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
	print_time(ginfo->hadj_value / ginfo->resolution + ginfo->view_start_time);
	dprintf(1, "\n");

}

static gboolean
value_changed(GtkWidget *widget, gpointer data)
{
//	struct graph_info *ginfo = data;
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

	time = mid / ginfo->resolution + ginfo->view_start_time;

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

	mid = (time - ginfo->view_start_time) * ginfo->resolution;
	start_x = mid - view_width / 2;
	if (start_x < 0)
		start_x = 0;

	ginfo->hadj_value = start_x;
}

static gboolean
button_release_event(GtkWidget *widget, GdkEventMotion *event, gpointer data)
{
	struct graph_info *ginfo = data;

	if (ginfo->line_active) {
		ginfo->line_active = FALSE;
		clear_last_line(widget, ginfo);
		ginfo->last_x = ginfo->press_x;
		clear_last_line(widget, ginfo);

		if (event->x > ginfo->press_x) {
			/* make a decent zoom */
			if (event->x - ginfo->press_x < 10)
				return TRUE;
			zoom_in_window(ginfo, ginfo->press_x, event->x);
		} else if (event->x < ginfo->press_x)
			zoom_out_window(ginfo, ginfo->press_x, event->x);
	}

	return TRUE;
}

static gint hash_pid(gint val)
{
	/* idle always gets black */
	if (!val)
		return 0;

	return trace_hash(val);
}

static void set_color_by_pid(GtkWidget *widget, GdkGC *gc, gint pid)
{
	GdkColor color;
	gint hash = hash_pid(pid);
	static gint last_pid = -1;

	if (!(hash & 0xffffff) && last_pid != pid) {
		last_pid = pid;
		dprintf(2, "pid=%d is black\n", pid);
	}
	color.red = (hash & 0xff)*(65535/255);
	color.blue = ((hash >> 8) & 0xff)*(65535/255);
	color.green = ((hash >> 16) & 0xff)*(65535/255);
	gdk_color_alloc(gtk_widget_get_colormap(widget), &color);
	gdk_gc_set_foreground(gc, &color);
}

static void draw_event_label(struct graph_info *ginfo, gint cpu,
			    gint event_id, gint pid,
			    gint p1, gint p2, gint p3,
			    gint width_16, PangoFontDescription *font)
{
	struct event_format *event;
	PangoLayout *layout;
	struct trace_seq s;
	gint text_width;
	gint text_height;
	gint x, y;


	/* No room to print */
	if ((p2 > width_16 && ((p3 - p2) < width_16 / 2 ||
			       (p2 - p1) < width_16 / 2)) ||
	    (p2 <= width_16 && (p1 || (p3 - p2) < width_16)))
		return;

	/* Check if we can show some data */

	event = pevent_data_event_from_type(ginfo->pevent, event_id);

	trace_seq_init(&s);
	trace_seq_printf(&s, "%s-%d\n%s\n",
			 pevent_data_comm_from_pid(ginfo->pevent, pid),
			 pid, event->name);

	layout = gtk_widget_create_pango_layout(ginfo->draw, s.buffer);
	pango_layout_set_font_description(layout, font);

	pango_layout_get_pixel_size(layout, &text_width, &text_height);

	if ((p2 > text_width && ((p3 - p2) < text_width ||
				 (p2 - p1) < text_width)) ||
	    (p2 < text_width && (p1 || (p3 - p2 < (text_width +
						   text_width / 2))))) {
		g_object_unref(layout);
		return;
	}

	x = p2 - text_width / 2;
	if (x < 0)
		x = 1;

	y = (CPU_TOP(cpu) - text_height + 5);
	gdk_draw_layout(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
			x, y, layout);


	gdk_draw_line(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
		      p2, CPU_TOP(cpu) - 5, p2, CPU_TOP(cpu) - 1);

	g_object_unref(layout);
}

static void draw_cpu(struct graph_info *ginfo, gint cpu,
		     gint new_width, int read_comms)
{
	static PangoFontDescription *font;
	PangoLayout *layout;
	gint height = CPU_LINE(cpu);
	struct record *record;
	static GdkGC *gc;
	static gint width_16;
	guint64 ts;
	gint last_pid = -1;
	gint last_x = 0;
	gint pid;
	gint x;
	gint p1 = 0, p2 = 0, p3 = 0;
	gint last_event_id = 0;
	gint wake_pid;
	gint last_wake_pid;
	gint event_id;
	gboolean filter;
	gboolean is_sched_switch;
	gboolean is_wakeup;
	gboolean last_is_wakeup = FALSE;
	const char *comm;

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

	if (!gc)
		gc = gdk_gc_new(ginfo->draw->window);

	gdk_draw_line(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
		      0, height, new_width, height);

	ts = ginfo->view_start_time;

	tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, ts);

	while ((record = tracecmd_read_data(ginfo->handle, cpu))) {

		if (record->ts < ginfo->view_start_time) {
			free_record(record);
			continue;
		}
		if (record->ts > ginfo->view_end_time)
			break;

		ts = record->ts - ginfo->view_start_time;

		x = (gint)((gdouble)ts * ginfo->resolution);

		is_sched_switch = FALSE;

		if (check_sched_switch(ginfo, record, &pid, &comm)) {
			is_sched_switch = TRUE;
			if (read_comms) {
				/*
				 * First time through, register any missing
				 *  comm / pid mappings.
				 */
				if (!pevent_pid_is_registered(ginfo->pevent, pid))
					pevent_register_comm(ginfo->pevent,
							     strdup(comm), pid);
			}
		} else
			pid = pevent_data_pid(ginfo->pevent, record);

		event_id = pevent_data_type(ginfo->pevent, record);

		if (last_pid != pid) {

			if (last_pid < 0) {
				last_pid = pid;
				set_color_by_pid(ginfo->draw, gc, pid);
			}
				
			filter = graph_filter_on_task(ginfo, last_pid);

			if (!filter && last_pid)

				gdk_draw_rectangle(ginfo->curr_pixmap, gc,
						   TRUE,
						   last_x, CPU_BOX_TOP(cpu),
						   x - last_x, CPU_BOX_SIZE);

			last_x = x;

			set_color_by_pid(ginfo->draw, gc, pid);
		}

		filter = graph_filter_on_task(ginfo, pid);

		/* Also show the task switching out */
		if (filter && is_sched_switch)
			filter = graph_filter_on_task(ginfo, last_pid);

		last_pid = pid;

		/* Lets see if a filtered task is waking up */
		is_wakeup = check_sched_wakeup(ginfo, record, &wake_pid);
		if (filter && is_wakeup)
			filter = graph_filter_on_task(ginfo, wake_pid);

		if (!filter) {
			filter = graph_filter_on_event(ginfo, record);
			if (!filter)
				gdk_draw_line(ginfo->curr_pixmap, gc,
					      x, CPU_TOP(cpu), x, CPU_BOTTOM(cpu));
		}

		if (!filter) {
			/* Figure out if we can show the text for the previous record */

			p3 = x;

			/* Make sure p2 will be non-zero the next iteration */
			if (!p3)
				p3 = 1;

			if (last_is_wakeup)
				pid = last_wake_pid;
			else
				pid = last_pid;

			/* first record, continue */
			if (p2)
				draw_event_label(ginfo, cpu, last_event_id, pid,
						 p1, p2, p3, width_16, font);

			p1 = p2;
			p2 = p3;

			last_event_id = event_id;
			last_is_wakeup = is_wakeup;
			last_wake_pid = wake_pid;
		}

		free_record(record);
	}

	if (p2)
		draw_event_label(ginfo, cpu, last_event_id, last_pid,
				 p1, p2, ginfo->draw_width, width_16, font);

	if (last_pid > 0 &&
	    !graph_filter_on_task(ginfo, last_pid)) {

		x = ginfo->draw_width;

		gdk_draw_rectangle(ginfo->curr_pixmap, gc,
				   TRUE,
				   last_x, CPU_BOX_TOP(cpu),
				   x - last_x, CPU_BOX_SIZE);
	}

	free_record(record);
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


	/* --- draw ending time --- */
	convert_nano(ginfo->view_end_time, &sec, &usec);
	trace_seq_init(&s);
	trace_seq_printf(&s, "%lu.%06lu", sec, usec);

	layout = gtk_widget_create_pango_layout(ginfo->draw, s.buffer);
	pango_layout_get_pixel_size(layout, &w, &h);

	gdk_draw_layout(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
			width - (w + 2), height+10, layout);
	g_object_unref(layout);


	/* --- draw time at intervals --- */
	view_width = gtk_adjustment_get_page_size(ginfo->hadj);

	for (mid = view_width / 2; mid < (width - view_width / 2 + 10);
	     mid += view_width / 2) {
		time = mid / ginfo->resolution + ginfo->view_start_time;

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
	}
}

static void draw_info(struct graph_info *ginfo,
		      gint new_width)
{
	static int read_comms = 1;
	gint cpu;

	ginfo->resolution = (gdouble)new_width / (gdouble)(ginfo->view_end_time -
							   ginfo->view_start_time);

	ginfo->full_width = (ginfo->end_time - ginfo->start_time) * ginfo->resolution;

	draw_timeline(ginfo, new_width);

	
	for (cpu = 0; cpu < ginfo->cpus; cpu++)
		draw_cpu(ginfo, cpu, new_width, read_comms);

	read_comms = 0;
}

void trace_graph_select_by_time(struct graph_info *ginfo, guint64 time)
{
	gint view_width;
	gint width;
	gint mid;
	gint start;
	gint end;
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
	mid = (time - ginfo->view_start_time) * ginfo->resolution;
	start = mid - view_width / 2;
	if (start < 0)
		start = 0;

	if (start > (width - view_width))
		start = width - view_width;
	gtk_adjustment_set_value(ginfo->hadj, start);

	ginfo->last_x = (ginfo->cursor - ginfo->view_start_time)
		* ginfo->resolution;
	ginfo->cursor = 0;
	clear_last_line(ginfo->draw, ginfo);
	ginfo->cursor = time;

	update_with_backend(ginfo, 0, 0, width, ginfo->draw_height);
}

static void graph_free_systems(struct graph_info *ginfo)
{
	gint i;

	if (!ginfo->systems)
		return;

	for (i = 0; ginfo->systems[i]; i++)
		g_free(ginfo->systems[i]);

	g_free(ginfo->systems);
	ginfo->systems = NULL;
	ginfo->systems_size = 0;
}

static void graph_free_events(struct graph_info *ginfo)
{
	g_free(ginfo->event_ids);
	ginfo->event_ids = NULL;
	ginfo->event_ids_size = 0;
}

void trace_graph_event_filter_callback(gboolean accept,
				       gboolean all_events,
				       gchar **systems,
				       gint *events,
				       gpointer data)
{
	struct graph_info *ginfo = data;
	gint i;

	if (!accept)
		return;

	graph_free_systems(ginfo);
	graph_free_events(ginfo);

	if (all_events) {
		ginfo->all_events = TRUE;
		redraw_graph(ginfo);
		return;
	}

	ginfo->all_events = FALSE;

	if (systems) {
		for (ginfo->systems_size = 0;
		     systems[ginfo->systems_size];
		     ginfo->systems_size++)
			;

		ginfo->systems = g_new(typeof(*systems), ginfo->systems_size + 1);
		for (i = 0; i < ginfo->systems_size; i++)
			ginfo->systems[i] = g_strdup(systems[i]);
		ginfo->systems[i] = NULL;

		qsort(ginfo->systems, ginfo->systems_size, sizeof(gchar *), str_cmp);
	}

	if (events) {
		for (ginfo->event_ids_size = 0;
		     events[ginfo->event_ids_size] >= 0;
		     ginfo->event_ids_size++)
			;

		ginfo->event_ids = g_new(typeof(*events), ginfo->event_ids_size + 1);
		for (i = 0; i < ginfo->event_ids_size; i++)
			ginfo->event_ids[i] = events[i];
		ginfo->event_ids[i] = -1;

		qsort(ginfo->event_ids, ginfo->event_ids_size, sizeof(gint), id_cmp);
	}

	redraw_graph(ginfo);
}

static void redraw_pixmap_backend(struct graph_info *ginfo)
{
	GdkPixmap *old_pix;

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

	if (old_pix) {
#if 0
		gdk_draw_drawable(ginfo->curr_pixmap,
				  ginfo->draw->style->fg_gc[GTK_WIDGET_STATE(ginfo->draw)],
				  old_pix,
				  0, 0, 0, 0,
				  old_w, old_h);
#endif

		g_object_unref(old_pix);
	}

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

	graph_free_systems(ginfo);
	graph_free_events(ginfo);

	filter_task_hash_free(ginfo->task_filter);
	filter_task_hash_free(ginfo->hide_tasks);

	if (ginfo->test)
		dprintf(1, "test = %s\n", ginfo->test);

	return TRUE;
}

static gboolean
info_expose_event(GtkWidget *widget, GdkEventExpose *event, gpointer data)
{
	struct graph_info *ginfo = data;

	gdk_draw_drawable(ginfo->info->window,
			  ginfo->info->style->fg_gc[GTK_WIDGET_STATE(ginfo->info)],
			  ginfo->info_pixmap,
			  event->area.x, event->area.y,
			  event->area.x, event->area.y,
			  event->area.width, event->area.height);

	return FALSE;
}

static void info_draw_cpu_label(struct graph_info *ginfo, gint cpu)
{
	PangoLayout *layout;
	gchar buf[BUFSIZ];
	gint width, height;

	snprintf(buf, BUFSIZ, "CPU %d", cpu);

	layout = gtk_widget_create_pango_layout(ginfo->info, buf);
	pango_layout_get_pixel_size(layout, &width, &height);
	width += 4;

	if (width > largest_cpu_label)
		largest_cpu_label = width;
	gdk_draw_rectangle(ginfo->info_pixmap,
			   ginfo->info->style->white_gc,
			   TRUE,
			   CPU_X, CPU_LABEL(cpu)+4,
			   width, height);
	gdk_draw_layout(ginfo->info_pixmap,
			ginfo->info->style->black_gc,
			CPU_X+ 2, CPU_LABEL(cpu) + 4,
			layout);
	g_object_unref(layout);
}

static void info_draw_cpu_labels(struct graph_info *ginfo)
{
	gint cpu;
#if 0
	clear_old_cpu_labels(ginfo);
	ginfo->cpu_x = gtk_adjustment_get_value(ginfo->hadj) + 5;
#endif

	for (cpu = 0; cpu < ginfo->cpus; cpu++)
		info_draw_cpu_label(ginfo, cpu);
}

static gboolean
info_configure_event(GtkWidget *widget, GdkEventMotion *event, gpointer data)
{
	struct graph_info *ginfo = data;

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

	info_draw_cpu_labels(ginfo);

	gtk_widget_set_size_request(ginfo->info, largest_cpu_label + 10,
				    ginfo->draw_height);
	
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

	gtk_widget_set_events(info, GDK_EXPOSURE_MASK);

	return info;
}

struct graph_info *
trace_graph_create_with_callbacks(struct tracecmd_input *handle,
				  struct graph_callbacks *cbs)
{
	struct graph_info *ginfo;
	unsigned long sec, usec;
	gint cpu;

	ginfo = g_new0(typeof(*ginfo), 1);
	g_assert(ginfo != NULL);
	ginfo->test = "hello!";

	ginfo->handle = handle;
	ginfo->pevent = tracecmd_get_pevent(handle);
	ginfo->cpus = tracecmd_cpus(handle);

	ginfo->all_events = TRUE;

	ginfo->callbacks = cbs;

	ginfo->start_time = -1ULL;
	ginfo->end_time = 0;

	ginfo->task_filter = filter_task_hash_alloc();
	ginfo->hide_tasks = filter_task_hash_alloc();

	ginfo->widget = gtk_hbox_new(FALSE, 0);
	gtk_widget_show(ginfo->widget);

	ginfo->scrollwin = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(ginfo->scrollwin),
				       GTK_POLICY_AUTOMATIC,
				       GTK_POLICY_AUTOMATIC);
	gtk_widget_show(ginfo->scrollwin);


	ginfo->info_scrollwin = gtk_scrolled_window_new(NULL,
		gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(ginfo->scrollwin)));

	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(ginfo->info_scrollwin),
				       GTK_POLICY_NEVER,
				       GTK_POLICY_NEVER);
	gtk_widget_show(ginfo->info_scrollwin);
	gtk_box_pack_start(GTK_BOX(ginfo->widget), ginfo->info_scrollwin, FALSE, FALSE, 0);

	ginfo->info = create_graph_info(ginfo);
	gtk_widget_show(ginfo->info);

	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(ginfo->info_scrollwin),
					      ginfo->info);

	gtk_box_pack_start(GTK_BOX (ginfo->widget), ginfo->scrollwin, TRUE, TRUE, 0);

	ginfo->draw_height = CPU_SPACE(ginfo->cpus);
	ginfo->hadj = gtk_scrolled_window_get_hadjustment(GTK_SCROLLED_WINDOW(ginfo->scrollwin));

	gtk_signal_connect(GTK_OBJECT(ginfo->hadj), "value_changed",
			   (GtkSignalFunc) value_changed, ginfo);

	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		struct record *record;

		record = tracecmd_read_cpu_first(handle, cpu);
		if (!record)
			continue;

		if (record->ts < ginfo->start_time)
			ginfo->start_time = record->ts;

		free_record(record);
		record = tracecmd_read_cpu_last(handle, cpu);

		if (record->ts > ginfo->end_time)
			ginfo->end_time = record->ts;
		free_record(record);
	}

	convert_nano(ginfo->start_time, &sec, &usec);
	dprintf(1,"start=%lu.%06lu ", sec, usec);

	convert_nano(ginfo->end_time, &sec, &usec);
	dprintf(1, "end=%lu.%06lu\n", sec, usec);

	ginfo->view_start_time = ginfo->start_time;
	ginfo->view_end_time = ginfo->end_time;

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
	gtk_signal_connect(GTK_OBJECT(ginfo->draw), "destroy",
			   (GtkSignalFunc) destroy_event, ginfo);

	gtk_widget_set_events(ginfo->draw, GDK_EXPOSURE_MASK
			      | GDK_LEAVE_NOTIFY_MASK
			      | GDK_BUTTON_PRESS_MASK
			      | GDK_BUTTON_RELEASE_MASK
			      | GDK_POINTER_MOTION_MASK
			      | GDK_POINTER_MOTION_HINT_MASK);


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
