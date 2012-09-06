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
#ifndef _trace_view_store_h_included_
#define _trace_view_store_h_included_

#include <gtk/gtk.h>
#include "trace-cmd.h"
#include "trace-hash.h"

/* Some boilerplate GObject defines. 'klass' is used
 *   instead of 'class', because 'class' is a C++ keyword */

#define TRACE_VIEW_STORE_TYPE	(trace_view_store_get_type ())
#define TRACE_VIEW_STORE(obj)	(G_TYPE_CHECK_INSTANCE_CAST ((obj), TRACE_VIEW_STORE_TYPE, TraceViewStore))
#define TRACE_VIEW_STORE_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  TRACE_VIEW_STORE_TYPE, TraceViewStoreClass))
#define TRACE_VIEW_IS_LIST(obj)	(G_TYPE_CHECK_INSTANCE_TYPE ((obj), TRACE_VIEW_STORE_TYPE))
#define TRACE_VIEW_IS_LIST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  TRACE_VIEW_STORE_TYPE))
#define TRACE_VIEW_STORE_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  TRACE_VIEW_STORE_TYPE, TraceViewStoreClass))

/* The data columns that we export via the tree model interface */

enum
{
	TRACE_VIEW_STORE_COL_INDEX,
	TRACE_VIEW_STORE_COL_CPU,
	TRACE_VIEW_STORE_COL_TS,
	TRACE_VIEW_STORE_COL_COMM,
	TRACE_VIEW_STORE_COL_PID,
	TRACE_VIEW_STORE_COL_LAT,
	TRACE_VIEW_STORE_COL_EVENT,
	TRACE_VIEW_STORE_COL_INFO,
	TRACE_VIEW_STORE_N_COLUMNS,
} ;


typedef struct trace_view_record	TraceViewRecord;
typedef struct trace_view_store	TraceViewStore;
typedef struct trace_view_store_class	TraceViewStoreClass;



/* TraceViewRecord: this structure represents a row */

struct trace_view_record
{
	/* What we need from the record */
	guint64		timestamp;
	guint64		offset;
	gint		cpu;

	/* admin stuff used by the trace view store model */
	gint		visible;
	guint		pos;	/* pos within the array */
};



/* TraceViewStore: this structure contains everything we need for our
 *             model implementation. You can add extra fields to
 *             this structure, e.g. hashtables to quickly lookup
 *             rows or whatever else you might need, but it is
 *             crucial that 'parent' is the first member of the
 *             structure.                                          */

struct trace_view_store
{
	GObject			parent;	/* this MUST be the first member */

	guint			start_row; /* row to start at */
	guint			num_rows; /* number of rows that we have showing   */
	guint			visible_rows; /* number of rows defined */
	guint			actual_rows; /* size of rows array */
	TraceViewRecord		**rows;	/* a dynamically allocated array of pointers to
					 *   the TraceViewRecord structure for each row    */

	guint			visible_column_mask;
	gint			n_columns;		/* number of columns visible */

	GType			column_types[TRACE_VIEW_STORE_N_COLUMNS];

	/* Tracecmd specific info */
	struct tracecmd_input *handle;
	struct event_format	*sched_switch_event;
	struct format_field	*sched_switch_next_field;
	struct event_format	*sched_wakeup_event;
	struct format_field	*sched_wakeup_pid_field;
	struct event_format	*sched_wakeup_new_event;
	struct format_field	*sched_wakeup_new_pid_field;
	int			cpus;

	TraceViewRecord		**cpu_list;
	gint			*cpu_items;

	gint			page;
	gint			pages;
	gint			rows_per_page;
	GtkWidget		*spin;

	/* filters */
	gint			all_events; /* set 1 when all events are enabled */
						/* else */
	struct event_filter	*event_filter; /* Filtered events */
	struct filter_task	*task_filter;	/* hash of tasks to filter on */
	struct filter_task	*hide_tasks;	/* hash of tasks to not display */

	gint			all_cpus;   /* set 1 when all cpus are enabled */
						/* else */
	guint64			*cpu_mask;  /* cpus that are enabled */

	gint		stamp;	/* Random integer to check whether an iter belongs to our model */
};

gboolean trace_view_store_cpu_isset(TraceViewStore *store, gint cpu);

void trace_view_store_set_all_cpus(TraceViewStore *store);
void trace_view_store_set_cpu(TraceViewStore *store, gint cpu);
void trace_view_store_clear_cpu(TraceViewStore *store, gint cpu);

void trace_view_store_set_spin_button(TraceViewStore *store, GtkWidget *spin);

void trace_view_store_set_page(TraceViewStore *store, gint page);

gint trace_view_store_get_timestamp_page(TraceViewStore *store, guint64 ts);

gint trace_view_store_get_timestamp_visible_row(TraceViewStore *store, guint64 ts);

void trace_view_store_filter_tasks(TraceViewStore *store, struct filter_task *filter);

void trace_view_store_hide_tasks(TraceViewStore *store, struct filter_task *filter);

void trace_view_store_assign_filters(TraceViewStore *store,
				     struct filter_task *task_filter,
				     struct filter_task *hide_tasks);

TraceViewRecord *trace_view_store_get_row(TraceViewStore *store, gint row);

TraceViewRecord *trace_view_store_get_visible_row(TraceViewStore *store, gint row);

TraceViewRecord *trace_view_store_get_actual_row(TraceViewStore *store, gint row);

gint trace_view_store_get_num_actual_rows(TraceViewStore *store);

gboolean trace_view_store_event_enabled(TraceViewStore *store, gint event_id);

void trace_view_store_set_all_events_enabled(TraceViewStore *store);

void trace_view_store_clear_all_events_enabled(TraceViewStore *store);

void trace_view_store_update_filter(TraceViewStore *store);

/* TraceViewStore methods */
GtkTreeModelFlags trace_view_store_get_flags	(GtkTreeModel	*tree_model);

gint trace_view_store_get_n_columns	(GtkTreeModel	*tree_model);

GType trace_view_store_get_column_type (GtkTreeModel	*tree_model,
							  gint	index);

void trace_view_store_get_value	(GtkTreeModel	*tree_model,
							 GtkTreeIter	*iter,
							 gint	column,
							 GValue	*value);

/* TraceViewStoreClass: more boilerplate GObject stuff */

struct trace_view_store_class
{
	GObjectClass		parent_class;
};


GType		trace_view_store_get_type (void);

TraceViewStore	*trace_view_store_new (struct tracecmd_input *handle);

#define TRACE_VIEW_DEFAULT_MAX_ROWS 1000000

#if 0
void		trace_view_store_append_record (TraceViewStore   *trace_view_store,
						const gchar  *name,
						guint         year_born);
#endif


/* helper functions */

static inline gint trace_view_store_get_cpus(TraceViewStore *store)
{
	g_return_val_if_fail (TRACE_VIEW_IS_LIST (store), -1);
	return store->cpus;
}

static inline guint64 *trace_view_store_get_cpu_mask(TraceViewStore *store)
{
	g_return_val_if_fail (TRACE_VIEW_IS_LIST (store), NULL);
	return store->cpu_mask;
}

static inline gint trace_view_store_get_all_cpus(TraceViewStore *store)
{
	g_return_val_if_fail (TRACE_VIEW_IS_LIST (store), -1);
	return store->all_cpus;
}

static inline gint trace_view_store_get_page(TraceViewStore *store)
{
	g_return_val_if_fail (TRACE_VIEW_IS_LIST (store), -1);
	return store->page;
}

static inline gint trace_view_store_get_pages(TraceViewStore *store)
{
	g_return_val_if_fail (TRACE_VIEW_IS_LIST (store), -1);
	return store->pages;
}

static inline gint trace_view_store_visible_rows(TraceViewStore *store)
{
	g_return_val_if_fail (TRACE_VIEW_IS_LIST (store), 0);
	return store->visible_rows;
}

static inline GtkWidget *trace_view_store_get_spin(TraceViewStore *store)
{
	g_return_val_if_fail (TRACE_VIEW_IS_LIST (store), NULL);
	return store->spin;
}

static inline gboolean trace_view_store_get_all_events_enabled(TraceViewStore *store)
{
	g_return_val_if_fail (TRACE_VIEW_IS_LIST (store), FALSE);
	return store->all_events;
}

static inline struct event_filter *
trace_view_store_get_event_filter(TraceViewStore *store)
{
	g_return_val_if_fail (TRACE_VIEW_IS_LIST (store), FALSE);
	return store->event_filter;
}

#endif /* _trace_view_store_h_included_ */
