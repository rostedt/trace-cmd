/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * Implemented a fixed row size to speed up list.
 *  Copyright (C) 2010 Darren Hart <dvhltc@us.ibm.com>
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
#include "trace-view-store.h"
#include <stdlib.h>
#include <string.h>

#include "cpu.h"
#include "trace-filter.h"

/* boring declarations of local functions */

static void		trace_view_store_init		(TraceViewStore	*pkg_tree);

static void		trace_view_store_class_init	(TraceViewStoreClass *klass);

static void		trace_view_store_tree_model_init (GtkTreeModelIface *iface);

static void		trace_view_store_finalize	(GObject	*object);

static gboolean		trace_view_store_get_iter	(GtkTreeModel	*tree_model,
							 GtkTreeIter	*iter,
							 GtkTreePath	*path);

static GtkTreePath	*trace_view_store_get_path	(GtkTreeModel	*tree_model,
							 GtkTreeIter	*iter);

static gboolean		trace_view_store_iter_next	(GtkTreeModel	*tree_model,
							 GtkTreeIter	*iter);

static gboolean		trace_view_store_iter_children	(GtkTreeModel	*tree_model,
							 GtkTreeIter	*iter,
							 GtkTreeIter	*parent);

static gboolean		trace_view_store_iter_has_child	(GtkTreeModel	*tree_model,
							 GtkTreeIter	*iter);

static gint		trace_view_store_iter_n_children (GtkTreeModel	*tree_model,
							  GtkTreeIter	*iter);

static gboolean		trace_view_store_iter_nth_child	(GtkTreeModel	*tree_model,
							 GtkTreeIter	*iter,
							 GtkTreeIter	*parent,
							 gint	n);

static gboolean		trace_view_store_iter_parent	(GtkTreeModel	*tree_model,
							 GtkTreeIter	*iter,
							 GtkTreeIter	*child);


static GObjectClass *parent_class = NULL;	/* GObject stuff - nothing to worry about */


/*****************************************************************************
 *
 *	trace_view_store_get_type: here we register our new type and its interfaces
 *	with the type system. If you want to implement
 *	additional interfaces like GtkTreeSortable, you
 *	will need to do it here.
 *
 *****************************************************************************/

GType
trace_view_store_get_type (void)
{
	static GType trace_view_store_type = 0;

	/* Some boilerplate type registration stuff */
	if (trace_view_store_type == 0)
	{
		static const GTypeInfo trace_view_store_info =
			{
				sizeof (TraceViewStoreClass),
				NULL,	/* base_init */
				NULL,	/* base_finalize */
				(GClassInitFunc) trace_view_store_class_init,
				NULL,	/* class finalize */
				NULL,	/* class_data */
				sizeof (TraceViewStore),
				0,	/* n_preallocs */
				(GInstanceInitFunc) trace_view_store_init
			};
		static const GInterfaceInfo tree_model_info =
			{
				(GInterfaceInitFunc) trace_view_store_tree_model_init,
				NULL,
				NULL
			};

		/* First register the new derived type with the GObject type system */
		trace_view_store_type = g_type_register_static (G_TYPE_OBJECT, "TraceViewStore",
								&trace_view_store_info, (GTypeFlags)0);

		/* Now register our GtkTreeModel interface with the type system */
		g_type_add_interface_static (trace_view_store_type, GTK_TYPE_TREE_MODEL, &tree_model_info);
	}

	return trace_view_store_type;
}


/*****************************************************************************
 *
 *	trace_view_store_class_init: more boilerplate GObject/GType stuff.
 *	Init callback for the type system,
 *	called once when our new class is created.
 *
 *****************************************************************************/

static void
trace_view_store_class_init (TraceViewStoreClass *klass)
{
	GObjectClass *object_class;

	parent_class = (GObjectClass*) g_type_class_peek_parent (klass);
	object_class = (GObjectClass*) klass;

	object_class->finalize = trace_view_store_finalize;
}

/*****************************************************************************
 *
 *	trace_view_store_tree_model_init: init callback for the interface registration
 *	in trace_view_store_get_type. Here we override
 *	the GtkTreeModel interface functions that
 *	we implement.
 *
 *****************************************************************************/

static void
trace_view_store_tree_model_init (GtkTreeModelIface *iface)
{
	iface->get_flags	= trace_view_store_get_flags;
	iface->get_n_columns	= trace_view_store_get_n_columns;
	iface->get_column_type	= trace_view_store_get_column_type;
	iface->get_iter		= trace_view_store_get_iter;
	iface->get_path		= trace_view_store_get_path;
	iface->get_value	= trace_view_store_get_value;
	iface->iter_next	= trace_view_store_iter_next;
	iface->iter_children	= trace_view_store_iter_children;
	iface->iter_has_child	= trace_view_store_iter_has_child;
	iface->iter_n_children	= trace_view_store_iter_n_children;
	iface->iter_nth_child	= trace_view_store_iter_nth_child;
	iface->iter_parent	= trace_view_store_iter_parent;
}


/*****************************************************************************
 *
 *	trace_view_store_init: this is called everytime a new trace view store object
 *	instance is created (we do that in trace_view_store_new).
 *	Initialise the list structure's fields here.
 *
 *****************************************************************************/

static void
trace_view_store_init (TraceViewStore *trace_view_store)
{
	trace_view_store->n_columns	= TRACE_VIEW_STORE_N_COLUMNS;

	trace_view_store->column_types[0] = G_TYPE_UINT;	/* INDEX */
	trace_view_store->column_types[1] = G_TYPE_UINT;	/* CPU	*/
	trace_view_store->column_types[2] = G_TYPE_STRING;	/* TS	*/
	trace_view_store->column_types[3] = G_TYPE_STRING;	/* COMM */
	trace_view_store->column_types[4] = G_TYPE_UINT;	/* PID */
	trace_view_store->column_types[5] = G_TYPE_STRING;	/* LAT */
	trace_view_store->column_types[6] = G_TYPE_STRING;	/* EVENT */
	trace_view_store->column_types[7] = G_TYPE_STRING;	/* INFO */

	g_assert (TRACE_VIEW_STORE_N_COLUMNS == 8);

	trace_view_store->num_rows = 0;
	trace_view_store->rows	= NULL;

	trace_view_store->spin = NULL;
	trace_view_store->page = 1;
	trace_view_store->pages = 1;
	trace_view_store->rows_per_page = TRACE_VIEW_DEFAULT_MAX_ROWS;
	trace_view_store->num_rows = 0;
	trace_view_store->start_row = 0;
	trace_view_store->visible_rows = 0;
	trace_view_store->actual_rows = 0;

	/* Set all columns visible */
	trace_view_store->visible_column_mask = (1 << TRACE_VIEW_STORE_N_COLUMNS) - 1;

	trace_view_store->stamp = g_random_int();	/* Random int to check whether an iter belongs to our model */

}


/*****************************************************************************
 *
 *	trace_view_store_finalize: this is called just before a trace view store is
 *	destroyed. Free dynamically allocated memory here.
 *
 *****************************************************************************/

static void
trace_view_store_finalize (GObject *object)
{
	TraceViewStore *store = TRACE_VIEW_STORE(object);
	gint cpu;

	/* free all records and free all memory used by the list */

	for (cpu = 0; cpu < store->cpus; cpu++)
		g_free(store->cpu_list[cpu]);

	g_free(store->cpu_list);
	g_free(store->cpu_mask);
	g_free(store->rows);
	g_free(store->cpu_items);

	filter_task_hash_free(store->task_filter);

	if (store->spin) {
		g_object_unref(store->spin);
		store->spin = NULL;
	}

	pevent_filter_free(store->event_filter);
	tracecmd_close(store->handle);

	/* must chain up - finalize parent */
	(* parent_class->finalize) (object);
}


/*****************************************************************************
 *
 *	trace_view_store_get_flags: tells the rest of the world whether our tree model
 *	has any special characteristics. In our case,
 *	we have a list model (instead of a tree), and each
 *	tree iter is valid as long as the row in question
 *	exists, as it only contains a pointer to our struct.
 *
 *****************************************************************************/

GtkTreeModelFlags
trace_view_store_get_flags (GtkTreeModel *tree_model)
{
	g_return_val_if_fail (TRACE_VIEW_IS_LIST(tree_model), (GtkTreeModelFlags)0);

	return (GTK_TREE_MODEL_LIST_ONLY | GTK_TREE_MODEL_ITERS_PERSIST);
}


/*****************************************************************************
 *
 *	trace_view_store_get_n_columns: tells the rest of the world how many data
 *	columns we export via the tree model interface
 *
 *****************************************************************************/

gint
trace_view_store_get_n_columns (GtkTreeModel *tree_model)
{
	g_return_val_if_fail (TRACE_VIEW_IS_LIST(tree_model), 0);

	return TRACE_VIEW_STORE(tree_model)->n_columns;
}

/*****************************************************************************
 *
 *	get_visible_column: Return the index of the visible columns
 *
 *****************************************************************************/

static gint get_visible_column(TraceViewStore *trace_view, gint column)
{
	guint i;

	/* If all columns are visible just use what was passed in */
	if (trace_view->visible_column_mask == ((1 << TRACE_VIEW_STORE_N_COLUMNS) - 1))
		return column;

	column++; /* make 0 drop out */

	for (i = 0; column && i < TRACE_VIEW_STORE_N_COLUMNS; i++) {
		if (!(trace_view->visible_column_mask & (1 << i)))
			continue;

		column--;
	}
	g_assert(column == 0);

	/* We upped column, so me must dec the return */
	return i - 1;
}

/*****************************************************************************
 *
 *	trace_view_store_get_column_type: tells the rest of the world which type of
 *	data an exported model column contains
 *
 *****************************************************************************/

GType
trace_view_store_get_column_type (GtkTreeModel *tree_model,
				  gint	index)
{
	g_return_val_if_fail (TRACE_VIEW_IS_LIST(tree_model), G_TYPE_INVALID);
	g_return_val_if_fail (index < TRACE_VIEW_STORE(tree_model)->n_columns && index >= 0, G_TYPE_INVALID);

	index = get_visible_column(TRACE_VIEW_STORE(tree_model), index);
	return TRACE_VIEW_STORE(tree_model)->column_types[index];
}


/*****************************************************************************
 *
 *	trace_view_store_get_iter: converts a tree path (physical position) into a
 *	tree iter structure (the content of the iter
 *	fields will only be used internally by our model).
 *	We simply store a pointer to our TraceViewRecord
 *	structure that represents that row in the tree iter.
 *
 *****************************************************************************/

static gboolean
trace_view_store_get_iter (GtkTreeModel *tree_model,
			   GtkTreeIter	*iter,
			   GtkTreePath	*path)
{
	TraceViewStore	*trace_view_store;
	TraceViewRecord	*record;
	gint	*indices, n, depth;

	g_assert(TRACE_VIEW_IS_LIST(tree_model));
	g_assert(path!=NULL);

	trace_view_store = TRACE_VIEW_STORE(tree_model);

	indices = gtk_tree_path_get_indices(path);
	depth	= gtk_tree_path_get_depth(path);

	/* we do not allow children */
	g_assert(depth == 1); /* depth 1 = top level; a list only has top level nodes and no children */

	n = indices[0]; /* the n-th top level row */

	record = trace_view_store_get_visible_row(trace_view_store, n);
	if (!record)
		return FALSE;

	/* We simply store a pointer to our custom record in the iter */
	iter->stamp	= trace_view_store->stamp;
	iter->user_data	= record;
	iter->user_data2 = NULL;	/* unused */
	iter->user_data3 = NULL;	/* unused */

	return TRUE;
}


/*****************************************************************************
 *
 *	trace_view_store_get_path: converts a tree iter into a tree path (ie. the
 *	physical position of that row in the list).
 *
 *****************************************************************************/

static GtkTreePath *
trace_view_store_get_path (GtkTreeModel *tree_model,
			   GtkTreeIter	*iter)
{
	GtkTreePath	*path;
	TraceViewRecord *record;
	TraceViewStore	*store;

	g_return_val_if_fail (TRACE_VIEW_IS_LIST(tree_model), NULL);
	g_return_val_if_fail (iter != NULL,	NULL);
	g_return_val_if_fail (iter->user_data != NULL,	NULL);

	store = TRACE_VIEW_STORE(tree_model);

	record = (TraceViewRecord*) iter->user_data;

	path = gtk_tree_path_new();
	gtk_tree_path_append_index(path, record->pos - store->start_row);

	return path;
}


/*****************************************************************************
 *
 *	trace_view_store_get_value: Returns a row's exported data columns
 *	(_get_value is what gtk_tree_model_get uses)
 *
 *****************************************************************************/

void
trace_view_store_get_value (GtkTreeModel *tree_model,
			    GtkTreeIter	*iter,
			    gint	column,
			    GValue	*value)
{
	TraceViewRecord	*record;
	TraceViewStore	*trace_view_store;
	struct trace_seq s;
	struct pevent *pevent;
	struct event_format *event;
	struct pevent_record *data;
	const gchar *comm;
	gchar *str;
	guint64 secs, usecs;
	gint val;
	int cpu;

	g_return_if_fail (TRACE_VIEW_IS_LIST (tree_model));
	g_return_if_fail (iter != NULL);
	g_return_if_fail (column < TRACE_VIEW_STORE(tree_model)->n_columns);

	g_value_init (value, TRACE_VIEW_STORE(tree_model)->column_types[column]);

	trace_view_store = TRACE_VIEW_STORE(tree_model);

	pevent = tracecmd_get_pevent(trace_view_store->handle);

	record = (TraceViewRecord*)iter->user_data;

	g_return_if_fail ( record != NULL );

	column = get_visible_column(TRACE_VIEW_STORE(tree_model), column);

	switch(column)
	{
	case TRACE_VIEW_STORE_COL_INDEX:
		g_value_set_uint(value, record->pos);
		break;

	case TRACE_VIEW_STORE_COL_CPU:
		g_value_set_uint(value, record->cpu);
		break;

	case TRACE_VIEW_STORE_COL_TS:
		usecs = record->timestamp;
		usecs /= 1000;
		secs = usecs / 1000000ULL;
		usecs -= secs * 1000000ULL;
		str = g_strdup_printf("%llu.%06llu",
				      (long long)secs, (long long)usecs);
		g_value_set_string(value, str);
		g_free(str);
		break;
		
	case TRACE_VIEW_STORE_COL_COMM:
	case TRACE_VIEW_STORE_COL_PID:
	case TRACE_VIEW_STORE_COL_LAT:
	case TRACE_VIEW_STORE_COL_EVENT:
	case TRACE_VIEW_STORE_COL_INFO:

		data = tracecmd_read_at(trace_view_store->handle, record->offset, &cpu);
		g_assert(data != NULL);
		if (cpu != record->cpu) {
			free_record(data);
			return;
		}

		switch (column) {
		case TRACE_VIEW_STORE_COL_COMM:
		case TRACE_VIEW_STORE_COL_PID:
			val = pevent_data_pid(pevent, data);
			if (column == TRACE_VIEW_STORE_COL_PID)
				g_value_set_uint(value, val);
			else {
				comm = pevent_data_comm_from_pid(pevent, val);
				g_value_set_string(value, comm);
			}
			break;

		case TRACE_VIEW_STORE_COL_LAT:
			trace_seq_init(&s);
			pevent_data_lat_fmt(pevent, &s, data);
			g_value_set_string(value, s.buffer);
			trace_seq_destroy(&s);
			break;

		case TRACE_VIEW_STORE_COL_EVENT:
		case TRACE_VIEW_STORE_COL_INFO:
			val = pevent_data_type(pevent, data);
			event = pevent_data_event_from_type(pevent, val);
			if (!event) {
				if (column == TRACE_VIEW_STORE_COL_EVENT)
					g_value_set_string(value, "[UNKNOWN EVENT]");
				break;
			}

			if (column == TRACE_VIEW_STORE_COL_EVENT) {
				g_value_set_string(value, event->name);
				break;
			}

			trace_seq_init(&s);
			pevent_event_info(&s, event, data);
			g_value_set_string(value, s.buffer);
			trace_seq_destroy(&s);
			break;
		}
		free_record(data);
	}
}

void trace_view_store_clear_all_events_enabled(TraceViewStore *store)
{
	g_return_if_fail (TRACE_VIEW_IS_LIST (store));

	pevent_filter_clear_trivial(store->event_filter, FILTER_TRIVIAL_BOTH);
	store->all_events = 0;
}

void trace_view_store_set_all_events_enabled(TraceViewStore *store)
{
	g_return_if_fail (TRACE_VIEW_IS_LIST (store));

	if (store->all_events)
		return;

	/*
	 * All enabled means that we don't need to look at 
	 * the system events, so free those arrays.
	 */
	pevent_filter_reset(store->event_filter);

	store->all_events = 1;
}


/*****************************************************************************
 *
 *	trace_view_store_iter_next: Takes an iter structure and sets it to point
 *	to the next row.
 *
 *****************************************************************************/

static gboolean
trace_view_store_iter_next (GtkTreeModel	*tree_model,
			    GtkTreeIter	*iter)
{
	TraceViewRecord	*record, *nextrecord;
	TraceViewStore	*trace_view_store;
	gint pos;

	g_return_val_if_fail (TRACE_VIEW_IS_LIST (tree_model), FALSE);

	if (iter == NULL || iter->user_data == NULL)
		return FALSE;

	trace_view_store = TRACE_VIEW_STORE(tree_model);

	record = (TraceViewRecord *) iter->user_data;

	pos = record->pos - trace_view_store->start_row;

	/* Is this the last record in the list? */
	if ((pos + 1) >= trace_view_store->num_rows)
		return FALSE;

	nextrecord = trace_view_store->rows[(record->pos + 1)];

	g_assert ( nextrecord != NULL );
	g_assert ( nextrecord->pos == (record->pos + 1) );

	iter->stamp	= trace_view_store->stamp;
	iter->user_data = nextrecord;

	return TRUE;
}


/*****************************************************************************
 *
 *	trace_view_store_iter_children: Returns TRUE or FALSE depending on whether
 *	the row specified by 'parent' has any children.
 *	If it has children, then 'iter' is set to
 *	point to the first child. Special case: if
 *	'parent' is NULL, then the first top-level
 *	row should be returned if it exists.
 *
 *****************************************************************************/

static gboolean
trace_view_store_iter_children (GtkTreeModel *tree_model,
				GtkTreeIter	*iter,
				GtkTreeIter	*parent)
{
	TraceViewStore	*trace_view_store;

	g_return_val_if_fail (parent == NULL || parent->user_data != NULL, FALSE);

	/* this is a list, nodes have no children */
	if (parent)
		return FALSE;

	/* parent == NULL is a special case; we need to return the first top-level row */

	g_return_val_if_fail (TRACE_VIEW_IS_LIST (tree_model), FALSE);

	trace_view_store = TRACE_VIEW_STORE(tree_model);

	/* No rows => no first row */
	if (trace_view_store->num_rows == 0)
		return FALSE;

	/* Set iter to first item in list */
	iter->stamp	= trace_view_store->stamp;
	iter->user_data = trace_view_store->rows[0];

	return TRUE;
}


/*****************************************************************************
 *
 *	trace_view_store_iter_has_child: Returns TRUE or FALSE depending on whether
 *	the row specified by 'iter' has any children.
 *	We only have a list and thus no children.
 *
 *****************************************************************************/

static gboolean
trace_view_store_iter_has_child (GtkTreeModel *tree_model,
				 GtkTreeIter	*iter)
{
	return FALSE;
}


/*****************************************************************************
 *
 *	trace_view_store_iter_n_children: Returns the number of children the row
 *	specified by 'iter' has. This is usually 0,
 *	as we only have a list and thus do not have
 *	any children to any rows. A special case is
 *	when 'iter' is NULL, in which case we need
 *	to return the number of top-level nodes,
 *	ie. the number of rows in our list.
 *
 *****************************************************************************/

static gint
trace_view_store_iter_n_children (GtkTreeModel *tree_model,
				  GtkTreeIter	*iter)
{
	TraceViewStore	*trace_view_store;

	g_return_val_if_fail (TRACE_VIEW_IS_LIST (tree_model), -1);
	g_return_val_if_fail (iter == NULL || iter->user_data != NULL, FALSE);

	trace_view_store = TRACE_VIEW_STORE(tree_model);

	/* special case: if iter == NULL, return number of top-level rows */
	if (!iter)
		return trace_view_store->num_rows;

	return 0; /* otherwise, this is easy again for a list */
}


/*****************************************************************************
 *
 *	trace_view_store_iter_nth_child: If the row specified by 'parent' has any
 *	children, set 'iter' to the n-th child and
 *	return TRUE if it exists, otherwise FALSE.
 *	A special case is when 'parent' is NULL, in
 *	which case we need to set 'iter' to the n-th
 *	row if it exists.
 *
 *****************************************************************************/

static gboolean
trace_view_store_iter_nth_child (GtkTreeModel *tree_model,
				 GtkTreeIter	*iter,
				 GtkTreeIter	*parent,
				 gint	n)
{
	TraceViewRecord	*record;
	TraceViewStore	*trace_view_store;

	g_return_val_if_fail (TRACE_VIEW_IS_LIST (tree_model), FALSE);

	trace_view_store = TRACE_VIEW_STORE(tree_model);

	/* a list has only top-level rows */
	if(parent)
		return FALSE;

	/* special case: if parent == NULL, set iter to n-th top-level row */

	if( n >= trace_view_store->num_rows )
		return FALSE;

	record = trace_view_store->rows[trace_view_store->start_row + n];

	g_assert( record != NULL );
	g_assert( record->pos - trace_view_store->start_row == n );

	iter->stamp = trace_view_store->stamp;
	iter->user_data = record;

	return TRUE;
}


/*****************************************************************************
 *
 *	trace_view_store_iter_parent: Point 'iter' to the parent node of 'child'. As
 *	we have a list and thus no children and no
 *	parents of children, we can just return FALSE.
 *
 *****************************************************************************/

static gboolean
trace_view_store_iter_parent (GtkTreeModel *tree_model,
			      GtkTreeIter	*iter,
			      GtkTreeIter	*child)
{
	return FALSE;
}

static int mask_cpu_isset(TraceViewStore *store, gint cpu)
{
	return cpu_isset(store->cpu_mask, cpu);
}

static void mask_cpu_set(TraceViewStore *store, gint cpu)
{
	cpu_set(store->cpu_mask, cpu);
}

static void mask_cpu_clear(TraceViewStore *store, gint cpu)
{
	cpu_clear(store->cpu_mask, cpu);
}

static void mask_set_cpus(TraceViewStore *store, gint cpus)
{
	set_cpus(store->cpu_mask, cpus);
}

static void update_page(TraceViewStore *store)
{
	if (!store->spin)
		return;

	gtk_spin_button_set_range(GTK_SPIN_BUTTON(store->spin),
				  1, store->pages);
}

/*****************************************************************************
 *
 *	merge_sort_rows_ts: Merge sort the data by time stamp.
 *	
 *
 *****************************************************************************/

static void merge_sort_rows_ts(TraceViewStore *store)
{
	guint64 ts;
	gint next;
	guint *indexes;
	guint count = 0;
	gint cpu;
	guint i;


	indexes = g_new0(guint, store->cpus);

	/* Now sort these by timestamp */
	do {
		next = -1;
		ts = 0;
		for (cpu = 0; cpu < store->cpus; cpu++) {
			if (!store->all_cpus && !mask_cpu_isset(store, cpu))
				continue;

 try_again:
			if (indexes[cpu] == store->cpu_items[cpu])
				continue;

			i = indexes[cpu];

			if (!store->cpu_list[cpu][i].visible) {
				indexes[cpu]++;
				goto try_again;
			}

			if (!ts || store->cpu_list[cpu][i].timestamp < ts) {
				ts = store->cpu_list[cpu][i].timestamp;
				next = cpu;
			}
		}
		if (next >= 0) {
			i = indexes[next]++;
			store->rows[count] = &store->cpu_list[next][i];
			store->cpu_list[next][i].pos = count++;
		}
	} while (next >= 0);

	store->visible_rows = count;
	store->start_row = 0;
	store->pages = (count / store->rows_per_page) + 1;

	if (store->page > 1) {
		if (count < store->page * store->rows_per_page)
			store->page = store->pages;

		/* still greater? */
		if (store->page > 1) {
			store->start_row =
				(store->page - 1) * store->rows_per_page;
			g_assert(store->start_row < count);
		}
	}

	store->num_rows = count > (store->start_row + store->rows_per_page) ?
		store->rows_per_page :
		count - store->start_row;

	update_page(store);

	g_free(indexes);
}

/*****************************************************************************
 *
 *	trace_view_store_new:	This is what you use in your own code to create a
 *	new trace view store tree model for you to use.
 *
 *****************************************************************************/

TraceViewStore *
trace_view_store_new (struct tracecmd_input *handle)
{
	TraceViewStore *newstore;
	struct pevent_record *data;
	gint cpu, count, total=0;
	struct temp {
		guint64		offset;
		guint64		ts;
		struct temp	*next;
	} *list, **next, *rec;

	newstore = (TraceViewStore*) g_object_new (TRACE_VIEW_STORE_TYPE, NULL);

	g_assert( newstore != NULL );

	newstore->handle = handle;
	newstore->cpus = tracecmd_cpus(handle);
	tracecmd_ref(handle);
	newstore->event_filter = pevent_filter_alloc(tracecmd_get_pevent(handle));

	newstore->cpu_list = g_new(TraceViewRecord *, newstore->cpus);
	g_assert(newstore->cpu_list != NULL);

	newstore->cpu_items = g_new(gint, newstore->cpus);
	g_assert(newstore->cpu_items != NULL);

	newstore->all_cpus = 1;
	newstore->all_events = 1;

	newstore->cpu_mask = g_new0(guint64, (newstore->cpus >> 6) + 1);
	g_assert(newstore->cpu_mask != NULL);

	mask_set_cpus(newstore, newstore->cpus);

	for (cpu = 0; cpu < newstore->cpus; cpu++) {

		count = 0;
		list = NULL;
		next = &list;

		data = tracecmd_read_cpu_first(handle, cpu);
		while (data) {
			*next = rec = g_malloc(sizeof(*rec));
			g_assert(rec != NULL);
			rec->offset = data->offset;
			rec->ts = data->ts;
			rec->next = NULL;
			next = &rec->next;
			free_record(data);
			count++;
			data = tracecmd_read_data(handle, cpu);
		}

		if (count) {
			TraceViewRecord *trec;
			struct temp *t;
			gint i;

			rec = list;

			trec = g_new(TraceViewRecord, count);
			g_assert(trec != NULL);

			for (i = 0; i < count; i++) {
				g_assert(rec != NULL);
				trec[i].cpu = cpu;
				trec[i].timestamp = rec->ts;
				trec[i].offset = rec->offset;
				trec[i].visible = 1;
				trec[i].pos = i;
				t = rec;
				rec = rec->next;
				g_free(t);
			}
			g_assert(rec == NULL);

			newstore->cpu_list[cpu] = trec;
		} else
			newstore->cpu_list[cpu] = NULL;

		newstore->cpu_items[cpu] = count;

		total += count;
	}

	newstore->actual_rows = total;
	newstore->rows = g_malloc(sizeof(*newstore->rows) * total + 1);

	merge_sort_rows_ts(newstore);

	return newstore;
}

void trace_view_store_set_spin_button(TraceViewStore *store, GtkWidget *spin)
{
	g_return_if_fail (TRACE_VIEW_IS_LIST (store));
	g_return_if_fail (GTK_IS_SPIN_BUTTON (spin));

	if (store->spin)
		g_object_unref(store->spin);

	store->spin = spin;

	g_object_ref(spin);
	gtk_spin_button_set_increments(GTK_SPIN_BUTTON(store->spin),
				       1.0, 5.0);
	update_page(store);
}

/* --- helper functions --- */

gboolean trace_view_store_cpu_isset(TraceViewStore *store, gint cpu)
{
	g_return_val_if_fail (TRACE_VIEW_IS_LIST (store), FALSE);
	g_return_val_if_fail (cpu >= 0 || cpu < store->cpus, FALSE);

	if (mask_cpu_isset(store, cpu))
		return TRUE;
	return FALSE;
}

void trace_view_store_set_all_cpus(TraceViewStore *store)
{
	g_return_if_fail (TRACE_VIEW_IS_LIST (store));

	if (store->all_cpus)
		return;

	mask_set_cpus(store, store->cpus);
	store->all_cpus = 1;

	merge_sort_rows_ts(store);
}

void trace_view_store_set_cpu(TraceViewStore *store, gint cpu)
{
	g_return_if_fail (TRACE_VIEW_IS_LIST (store));
	g_return_if_fail (cpu >= 0 || cpu < store->cpus);

	if (store->all_cpus || mask_cpu_isset(store, cpu))
		return;

	mask_cpu_set(store, cpu);

	merge_sort_rows_ts(store);
}

void trace_view_store_clear_cpu(TraceViewStore *store, gint cpu)
{
	g_return_if_fail (TRACE_VIEW_IS_LIST (store));
	g_return_if_fail (cpu >= 0 || cpu < store->cpus);

	if (!mask_cpu_isset(store, cpu))
		return;

	store->all_cpus = 0;
	mask_cpu_clear(store, cpu);

	merge_sort_rows_ts(store);
}

void trace_view_store_set_page(TraceViewStore *store, gint page)
{
	g_return_if_fail (TRACE_VIEW_IS_LIST (store));
	g_return_if_fail (page >= 0 || page < store->pages);

	store->page = page;
	store->start_row = (page - 1) * store->rows_per_page;
	g_assert(store->start_row < store->visible_rows);
	store->num_rows = store->start_row + store->rows_per_page <
		store->visible_rows ? store->rows_per_page :
		store->visible_rows - store->start_row;
}

static int rows_ts_cmp(const void *a, const void *b)
{
	/* a is just a key, but b is a pointer to a record pointer */
	const TraceViewRecord *ta = a;
	const TraceViewRecord *tb = *(TraceViewRecord **)b;
	const TraceViewRecord *tb1 = *((TraceViewRecord **)b+1);

	/* match inbetween too */
	if ((ta->timestamp == tb->timestamp) ||

	    (ta->timestamp > tb->timestamp &&
	     ta->timestamp < tb1->timestamp))
		return 0;

	if (ta->timestamp < tb->timestamp)
		return -1;

	return 1;
}

static TraceViewRecord *
search_for_record_by_timestamp(TraceViewStore *store, guint64 ts)
{
	TraceViewRecord key;
	TraceViewRecord *rec, **prec;

	if (!store->visible_rows)
		return NULL;

	if (ts < store->rows[0]->timestamp)
		return NULL;

	if (ts >= store->rows[store->visible_rows-1]->timestamp)
		return store->rows[store->visible_rows-1];

	key.timestamp = ts;
	prec = bsearch(&key, store->rows, store->visible_rows - 1,
		       sizeof(store->rows[0]), rows_ts_cmp);

	g_assert(prec != NULL);

	rec = *prec;

	return rec;
}

gint trace_view_store_get_timestamp_visible_row(TraceViewStore *store, guint64 ts)
{
	TraceViewRecord *rec;

	g_return_val_if_fail (TRACE_VIEW_IS_LIST (store), 0);

	rec = search_for_record_by_timestamp(store, ts);
	if (!rec)
		return 0;

	return rec->pos - (store->page - 1) * store->rows_per_page;
}

gint trace_view_store_get_timestamp_page(TraceViewStore *store, guint64 ts)
{
	TraceViewRecord *rec;

	g_return_val_if_fail (TRACE_VIEW_IS_LIST (store), 0);

	rec = search_for_record_by_timestamp(store, ts);
	if (!rec)
		return 1;

	return rec->pos / store->rows_per_page + 1;
}

static TraceViewRecord *get_row(TraceViewStore *store, gint row)
{
	TraceViewRecord *record;
	gint index = row - store->start_row;

	g_return_val_if_fail(index >= 0 && index < store->visible_rows, NULL);

	record = store->rows[row];
	g_assert(record != NULL);
	g_assert(record->pos == row);
	return record;
}


TraceViewRecord *
trace_view_store_get_row(TraceViewStore *store, gint row)
{
	g_return_val_if_fail(TRACE_VIEW_IS_LIST(store), NULL);

	return get_row(store, row);
}


TraceViewRecord *
trace_view_store_get_visible_row(TraceViewStore *store, gint row)
{
	g_return_val_if_fail(TRACE_VIEW_IS_LIST(store), NULL);

	/* If we don't have any visible rows, return NULL */
	if (!store->visible_rows)
		return NULL;

	row += store->start_row;

	return get_row(store, row);
}

TraceViewRecord *
trace_view_store_get_actual_row(TraceViewStore *store, gint row)
{
	g_return_val_if_fail (TRACE_VIEW_IS_LIST (store), NULL);
	g_return_val_if_fail (row >= 0, NULL);
	g_return_val_if_fail (row < store->actual_rows, NULL);

	if (!store->rows)
		return NULL;

	return store->rows[row];
}

gint trace_view_store_get_num_actual_rows(TraceViewStore *store)
{
	g_return_val_if_fail (TRACE_VIEW_IS_LIST (store), -1);
	return store->actual_rows;
}

gint get_next_pid(TraceViewStore *store, struct pevent *pevent, struct pevent_record *record)
{
	unsigned long long val;
	int ret;

	ret = pevent_read_number_field(store->sched_switch_next_field, record->data, &val);

	return val;
}

gint get_wakeup_pid(TraceViewStore *store, struct pevent *pevent, struct pevent_record *record)
{
	unsigned long long val;
	int ret;

	ret = pevent_read_number_field(store->sched_wakeup_pid_field, record->data, &val);

	return val;
}

gint get_wakeup_new_pid(TraceViewStore *store, struct pevent *pevent, struct pevent_record *record)
{
	unsigned long long val;
	int ret;

	ret = pevent_read_number_field(store->sched_wakeup_new_pid_field, record->data, &val);

	return val;
}

static gboolean view_task(TraceViewStore *store, gint pid)
{
	return (!store->task_filter ||
		!filter_task_count(store->task_filter) ||
		filter_task_find_pid(store->task_filter, pid)) &&
		(!store->hide_tasks ||
		 !filter_task_count(store->hide_tasks) ||
		 !filter_task_find_pid(store->hide_tasks, pid));
}

static gboolean show_task(TraceViewStore *store, struct pevent *pevent,
			  struct pevent_record *record, gint pid)
{
	gint event_id;

	if (view_task(store, pid))
		return TRUE;

	event_id = pevent_data_type(pevent, record);

	if (store->sched_switch_next_field &&
	    event_id == store->sched_switch_event->id) {
		/* show sched switch to task */
		pid = get_next_pid(store, pevent, record);
		if (view_task(store, pid))
			return TRUE;
	}

	if (store->sched_wakeup_pid_field &&
	    event_id == store->sched_wakeup_event->id) {
		/* show sched switch to task */
		pid = get_wakeup_pid(store, pevent, record);
		if (view_task(store, pid))
			return TRUE;
	}

	if (store->sched_wakeup_new_pid_field &&
	    event_id == store->sched_wakeup_new_event->id) {
		/* show sched switch to task */
		pid = get_wakeup_new_pid(store, pevent, record);
		if (view_task(store, pid))
			return TRUE;
	}

	return FALSE;
}

static void update_filter_tasks(TraceViewStore *store)
{
	struct tracecmd_input *handle;
	struct pevent *pevent;
	struct pevent_record *record;
	gint pid;
	gint cpu;
	gint i;

	handle = store->handle;
	pevent = tracecmd_get_pevent(store->handle);

	if (!store->sched_switch_event) {
		store->sched_switch_event =
			pevent_find_event_by_name(pevent, "sched", "sched_switch");
		if (store->sched_switch_event)
			store->sched_switch_next_field =
				pevent_find_any_field(store->sched_switch_event,
						      "next_pid");
		store->sched_wakeup_event =
			pevent_find_event_by_name(pevent, "sched", "sched_wakeup");
		if (store->sched_wakeup_event)
			store->sched_wakeup_pid_field =
				pevent_find_any_field(store->sched_wakeup_event,
						      "pid");

		store->sched_wakeup_new_event =
			pevent_find_event_by_name(pevent, "sched", "sched_wakeup");
		if (store->sched_wakeup_new_event)
			store->sched_wakeup_new_pid_field =
				pevent_find_any_field(store->sched_wakeup_new_event,
						      "pid");
	}

	for (cpu = 0; cpu < store->cpus; cpu++) {
		record = tracecmd_read_cpu_first(handle, cpu);

		for (i = 0; i < store->cpu_items[cpu]; i++) {

			g_assert(record->offset == store->cpu_list[cpu][i].offset);

			/* The record may be filtered by the events */
			if (!store->all_events) {
				int ret;
				ret = pevent_filter_match(store->event_filter,
							  record);
				if (ret != FILTER_MATCH) {
					store->cpu_list[cpu][i].visible = 0;
					goto skip;
				}
			}

			pid = pevent_data_pid(pevent, record);
			if (show_task(store, pevent, record, pid))
				store->cpu_list[cpu][i].visible = 1;
			else
				store->cpu_list[cpu][i].visible = 0;

 skip:
			free_record(record);
			record = tracecmd_read_data(handle, cpu);
		}
		g_assert(record == NULL);
	}

	merge_sort_rows_ts(store);
}

void trace_view_store_filter_tasks(TraceViewStore *store, struct filter_task *filter)
{
	g_return_if_fail (TRACE_VIEW_IS_LIST (store));

	/* We may pass in the store->task_filter. Don't free it if we do */
	if (store->task_filter && store->task_filter != filter)
		filter_task_hash_free(store->task_filter);

	if (store->task_filter != filter)
		store->task_filter = filter_task_hash_copy(filter);

	update_filter_tasks(store);
}

void trace_view_store_hide_tasks(TraceViewStore *store, struct filter_task *filter)
{
	g_return_if_fail (TRACE_VIEW_IS_LIST (store));

	/* We may pass in the store->task_filter. Don't free it if we do */
	if (store->hide_tasks && store->hide_tasks != filter)
		filter_task_hash_free(store->hide_tasks);

	if (store->hide_tasks != filter)
		store->hide_tasks = filter_task_hash_copy(filter);

	update_filter_tasks(store);
}

void trace_view_store_update_filter(TraceViewStore *store)
{
	g_return_if_fail (TRACE_VIEW_IS_LIST (store));

	update_filter_tasks(store);
}

void trace_view_store_assign_filters(TraceViewStore *store,
				     struct filter_task *task_filter,
				     struct filter_task *hide_tasks)
{
	g_return_if_fail (TRACE_VIEW_IS_LIST (store));

	/* We may pass in the store->task_filter. Don't free it if we do */
	if (store->task_filter && store->task_filter != task_filter)
		filter_task_hash_free(store->task_filter);

	if (store->hide_tasks && store->hide_tasks != hide_tasks)
		filter_task_hash_free(store->hide_tasks);

	if (store->hide_tasks != hide_tasks)
		store->hide_tasks = filter_task_hash_copy(hide_tasks);

	if (store->task_filter != task_filter)
		store->task_filter = filter_task_hash_copy(task_filter);
}

/*****************************************************************************
 *
 *	trace_view_store_append_record:	Empty lists are boring. This function can
 *	be used in your own code to add rows to the
 *	list. Note how we emit the "row-inserted"
 *	signal after we have appended the row
 *	internally, so the tree view and other
 *	interested objects know about the new row.
 *
 *****************************************************************************/

#if 0
void
trace_view_store_append_record (TraceViewStore	*trace_view_store,
				const gchar	*name,
				guint	year_born)
{
	GtkTreeIter	iter;
	GtkTreePath	*path;
	TraceViewRecord *newrecord;
	gulong	newsize;
	guint	pos;

	g_return_if_fail (TRACE_VIEW_IS_LIST(trace_view_store));
	g_return_if_fail (name != NULL);

	pos = trace_view_store->num_rows;

	trace_view_store->num_rows++;

	newsize = trace_view_store->num_rows * sizeof(TraceViewRecord*);

	trace_view_store->rows = g_realloc(trace_view_store->rows, newsize);

	newrecord = g_new0(TraceViewRecord, 1);

	newrecord->name = g_strdup(name);
	newrecord->name_collate_key = g_utf8_collate_key(name,-1); /* for fast sorting, used later */
	newrecord->year_born = year_born;

	trace_view_store->rows[pos] = newrecord;
	newrecord->pos = pos;

	/* inform the tree view and other interested objects
	 *	(e.g. tree row references) that we have inserted
	 *	a new row, and where it was inserted */

	path = gtk_tree_path_new();
	gtk_tree_path_append_index(path, newrecord->pos);

	trace_view_store_get_iter(GTK_TREE_MODEL(trace_view_store), &iter, path);

	gtk_tree_model_row_inserted(GTK_TREE_MODEL(trace_view_store), path, &iter);

	gtk_tree_path_free(path);
}
#endif
