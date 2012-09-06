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
#ifndef _TRACE_GRAPH_H
#define _TRACE_GRAPH_H

#include <gtk/gtk.h>
#include "trace-cmd.h"
#include "trace-hash.h"
#include "trace-xml.h"

struct graph_info;

typedef void (graph_select_cb)(struct graph_info *ginfo, guint64 time);
typedef void (graph_filter_cb)(struct graph_info *ginfo,
			       struct filter_task *task_filter,
			       struct filter_task *hide_tasks);

/* Used for quereing what plots are defined */
enum graph_plot_type {
	PLOT_TYPE_OTHER,
	PLOT_TYPE_CPU,
	PLOT_TYPE_TASK,
};

struct graph_plot;

struct plot_info {
	gboolean		line;
	int			lcolor;
	unsigned long long	ltime;
	gboolean		box;
	int			bcolor;
	unsigned long long	bstart;
	unsigned long long	bend;
	gboolean		bfill;
};

/*
 * match_time:
 *   Return true if a selected time should expose plot.
 *   Should only return true if an event has the exact time that
 *   is passed in.
 *
 * start:
 *   Initialize for plotting. This is called with the start time
 *   to start plotting.
 *
 * plot_event:
 *   This is called by the plotter.
 *   color returns the color that should be printed.
 *   line returns 1 or 0 if a line should be drawn.
 *   ltime returns the time that the line should be drawn at
 *    (ignored if line is 0)
 *   box returns 1 or 0 if a box should be drawn
 *    bstart is the time the box starts at
 *    bend is the time the box ends at
 *     (bstart and bend are ignored if box is 0)
 *    bfill whether or not to fill the box (default TRUE)
 *   time is the time of the current event
 *
 * end:
 *   called at the end of the plotting in case the plotter needs to
 *   release any resourses.
 * display_last_event:
 *   If enough space between the event before and the event after
 *   a event, the plot may ask to display that event.
 *   The time will be given to find the event, the time may be before
 *   the given event.
 *
 * find_record:
 *   return a tracecmd record for a given time.
 *
 * display_info:
 *   display information about a given time. A resolution is
 *   passed in to show how much time is in 1 pixel.
 *
 * destroy:
 *   destructor routine. Cleans up all resourses that the plot allocated.
 */
struct plot_callbacks {
	int (*match_time)(struct graph_info *, struct graph_plot *,
			  unsigned long long time);
	void (*start)(struct graph_info *, struct graph_plot *,
		      unsigned long long time);
	int (*plot_event)(struct graph_info *ginfo,
			  struct graph_plot *plot,
			  struct pevent_record *record,
			  struct plot_info *info);
	void (*end)(struct graph_info *, struct graph_plot *);
	int (*display_last_event)(struct graph_info *ginfo, struct graph_plot *plot,
				  struct trace_seq *s, unsigned long long time);
	struct pevent_record *(*find_record)(struct graph_info *, struct graph_plot *,
				      unsigned long long time);
	int (*display_info)(struct graph_info *, struct graph_plot *,
			    struct trace_seq *s,
			    unsigned long long time);
	void (*destroy)(struct graph_info *, struct graph_plot *);
};

struct graph_plot {
	enum graph_plot_type		type;
	int				pos;
	char				*label;
	const struct plot_callbacks	*cb;
	void				*private;

	/* Used for drawing */
	gint				 last_color;
	gint				p1, p2, p3;
	GdkGC				*gc;
};

struct graph_callbacks {
	graph_select_cb		*select;
	graph_filter_cb		*filter;
};

struct plot_list {
	struct plot_list	*next;
	struct graph_plot	*plot;
};

struct plot_hash {
	struct plot_hash	*next;
	struct plot_list	*plots;
	gint			val;
};

#define PLOT_HASH_SIZE 1024
#define TASK_HASH_SIZE 1024
struct task_list;

struct graph_info {
	struct tracecmd_input	*handle;
	struct pevent		*pevent;
	gint			cpus;

	gint			plots;
	struct graph_plot	**plot_array;	/* all plots */
	struct graph_plot	*plot_clicked;	/* plot that was clicked on */

	gint			nr_task_hash;
	struct plot_hash	*task_hash[PLOT_HASH_SIZE];
	struct plot_hash	*cpu_hash[PLOT_HASH_SIZE];
	struct plot_list	*all_recs;

	struct task_list	 *tasks[TASK_HASH_SIZE];

	GtkWidget		*widget;	/* Box to hold graph */
	GtkWidget		*status_hbox;	/* hbox holding status info */
	GtkWidget		*pointer_time;	/* time that pointer is at */
	GtkWidget		*cursor_label;	/* label showing cursor time */
	GtkWidget		*marka_label;	/* label showing Marker A time */
	GtkWidget		*markb_label;	/* label showing Marker B time */
	GtkWidget		*delta_label;	/* label showing delta of B - A */
	GtkWidget		*scrollwin;	/* graph scroll window */
	GtkWidget		*info_scrollwin; /* graph scroll window (for info widget) */
	GtkWidget		*info;		/* info window */
	GtkWidget		*draw;
	GdkPixmap		*curr_pixmap;	/* pixmap backstore */
	GdkPixmap		*info_pixmap;	/* pixmap backstore */
	GtkAdjustment		*hadj;		/* scrollwindow horizontal adjust */
	guint64			start_time;	/* True start time of trace */
	guint64			end_time;	/* True end time of trace */
	guint64			view_start_time; /* visible start time */
	guint64			view_end_time;	/* visible end time */
	gint			start_x;	/* virutal start of visible area */

	guint64			cursor;		/* time of cursor (double clicked) */

	gdouble			resolution;	/* pixels / time */

	gint			press_x;	/* x where button is pressed */
	gint			last_x;		/* last x seen while moving mouse */
	gboolean		line_active;	/* set when button is pressed */
	guint64			line_time;	/* time line of where line_active is set */
	guint64			marka_time;	/* time that marker A is at */
	guint64			markb_time;	/* time that marker B is at */
	gboolean		show_marka;	/* draw marker A line */
	gboolean		show_markb;	/* draw marker B line */
	gboolean		zoom;		/* set when shift button is pressed */

	gdouble			hadj_value;	/* value to set hadj width */
	gdouble			hadj_page_size;	/* visible size to set hadj */

	gint			draw_width;	/* width of pixmap */
	gint			draw_height;	/* height of pixmap */
	gint			full_width;	/* width of full trace in pixels */
						/* This includes non visible part of trace */

	struct graph_callbacks	*callbacks;	/* call back hooks for changes to graph */

	gboolean		filter_enabled;
	gboolean		filter_available;

	gboolean		all_events;	/* all events enabled */
	struct event_filter	*event_filter;	/* filtered events */

	/* cache of event fields */
	gint			ftrace_sched_switch_id;
	gint			event_sched_switch_id;
	gint			event_wakeup_id;
	gint			event_wakeup_new_id;
	struct format_field	*event_prev_state;
	struct format_field	*event_pid_field;
	struct format_field	*event_comm_field;
	struct format_field	*ftrace_pid_field;
	struct format_field	*ftrace_comm_field;
	struct format_field	*wakeup_pid_field;
	struct format_field	*wakeup_success_field;
	struct format_field	*wakeup_new_pid_field;
	struct format_field	*wakeup_new_success_field;

	gboolean		read_comms;	/* Read all comms on first load */

	struct filter_task	*task_filter;
	gint			filter_task_selected;

	struct filter_task	*hide_tasks;

	/* Box info for plot data info window */
	gint			plot_data_x;
	gint			plot_data_y;
	gint			plot_data_w;
	gint			plot_data_h;
};


struct graph_info *
trace_graph_create(struct tracecmd_input *handle);
struct graph_info *
trace_graph_create_with_callbacks(struct tracecmd_input *handle,
				  struct graph_callbacks *cbs);
void trace_graph_select_by_time(struct graph_info *ginfo, guint64 time);

void trace_graph_event_filter_callback(gboolean accept,
				       gboolean all_events,
				       gchar **systems,
				       gint *events,
				       gpointer data);

void trace_graph_adv_filter_callback(gboolean accept,
				     const gchar *text,
				     gint *event_ids,
				     gpointer data);

static inline GtkWidget *trace_graph_get_draw(struct graph_info *ginfo)
{
	return ginfo->draw;
}

static inline struct graph_callbacks *trace_graph_get_callbacks(struct graph_info *ginfo)
{
	return ginfo->callbacks;
}

static inline GtkWidget *trace_graph_get_window(struct graph_info *ginfo)
{
	return ginfo->widget;
}

void trace_graph_refresh(struct graph_info *ginfo);

struct filter_task_item *
trace_graph_filter_task_find_pid(struct graph_info *ginfo, gint pid);
struct filter_task_item *
trace_graph_hide_task_find_pid(struct graph_info *ginfo, gint pid);
void trace_graph_filter_toggle(struct graph_info *ginfo);
void trace_graph_filter_add_remove_task(struct graph_info *info,
					gint pid);
void trace_graph_filter_hide_show_task(struct graph_info *ginfo,
				       gint pid);
void trace_graph_clear_tasks(struct graph_info *ginfo);
void trace_graph_free_info(struct graph_info *ginfo);
int trace_graph_load_handle(struct graph_info *ginfo,
			    struct tracecmd_input *handle);

int trace_graph_check_sched_switch(struct graph_info *ginfo,
				   struct pevent_record *record,
				   gint *pid, const char **comm);
int trace_graph_check_sched_wakeup(struct graph_info *ginfo,
				   struct pevent_record *record,
				   gint *pid);
gboolean trace_graph_filter_on_task(struct graph_info *ginfo, gint pid);
gboolean trace_graph_filter_on_event(struct graph_info *ginfo, struct pevent_record *record);

void trace_graph_copy_filter(struct graph_info *ginfo,
			     gboolean all_events,
			     struct event_filter *event_filter);
gint *trace_graph_task_list(struct graph_info *ginfo);

int trace_graph_load_filters(struct graph_info *ginfo,
			     struct tracecmd_xml_handle *handle);
int trace_graph_save_filters(struct graph_info *ginfo,
			     struct tracecmd_xml_handle *handle);
void trace_graph_update_filters(struct graph_info *ginfo,
				struct filter_task *task_filter,
				struct filter_task *hide_tasks);
void trace_graph_refresh_filters(struct graph_info *ginfo);

/* plots */
void trace_graph_plot_free(struct graph_info *ginfo);
void trace_graph_plot_init(struct graph_info *ginfo);
struct graph_plot *trace_graph_plot_append(struct graph_info *ginfo,
					   const char *label,
					   enum graph_plot_type type,
					   const struct plot_callbacks *cb,
					   void *data);
struct graph_plot *trace_graph_plot_insert(struct graph_info *ginfo,
					   int pos,
					   const char *label,
					   enum graph_plot_type type,
					   const struct plot_callbacks *cb,
					   void *data);
void trace_graph_plot_remove(struct graph_info *ginfo, struct graph_plot *plot);
struct plot_hash *trace_graph_plot_find_task(struct graph_info *ginfo, gint task);
void trace_graph_plot_add_task(struct graph_info *ginfo, struct graph_plot *plot,
			       gint task);
void trace_graph_plot_remove_task(struct graph_info *ginfo,
				  struct graph_plot *plot,
				  gint task);
struct plot_hash *trace_graph_plot_find_cpu(struct graph_info *ginfo, gint cpu);
void trace_graph_plot_add_cpu(struct graph_info *ginfo, struct graph_plot *plot,
			      gint cpu);
void trace_graph_plot_remove_cpu(struct graph_info *ginfo, struct graph_plot *plot,
				 gint cpu);
void trace_graph_plot_add_all_recs(struct graph_info *ginfo,
				   struct graph_plot *plot);
void trace_graph_plot_remove_all_recs(struct graph_info *ginfo,
				      struct graph_plot *plot);

/* plot callbacks */
int trace_graph_plot_match_time(struct graph_info *ginfo,
				struct graph_plot *plot,
				unsigned long long time);

int trace_graph_plot_display_last_event(struct graph_info *ginfo,
					struct graph_plot *plot,
					struct trace_seq *s,
					unsigned long long time);

void trace_graph_plot_start(struct graph_info *ginfo,
			    struct graph_plot *plot,
			    unsigned long long time);

int trace_graph_plot_event(struct graph_info *ginfo,
			   struct graph_plot *plot,
			   struct pevent_record *record,
			   struct plot_info *info);

void trace_graph_plot_end(struct graph_info *ginfo,
			  struct graph_plot *plot);

struct pevent_record *
trace_graph_plot_find_record(struct graph_info *ginfo,
			     struct graph_plot *plot,
			     unsigned long long time);

int trace_graph_plot_display_info(struct graph_info *ginfo,
				  struct graph_plot *plot,
				  struct trace_seq *s,
				  unsigned long long time);

/* cpu plot */
void graph_plot_init_cpus(struct graph_info *ginfo, int cpus);
void graph_plot_cpus_plotted(struct graph_info *ginfo,
			     gboolean *all_cpus, guint64 **cpu_mask);
void graph_plot_cpus_update_callback(gboolean accept,
				     gboolean all_cpus,
				     guint64 *selected_cpu_mask,
				     gpointer data);

/* task plot */
void graph_plot_task(struct graph_info *ginfo, int pid, int pos);
void graph_plot_task_update_callback(gboolean accept,
				     gint *selected,
				     gint *non_select,
				     gpointer data);
void graph_plot_task_plotted(struct graph_info *ginfo,
			     gint **plotted);

#endif /* _TRACE_GRAPH_H */
