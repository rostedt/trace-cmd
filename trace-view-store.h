#ifndef _trace_view_store_h_included_
#define _trace_view_store_h_included_

#include <gtk/gtk.h>
#include "trace-cmd.h"

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
	TRACE_VIEW_STORE_COL_CPU,
	TRACE_VIEW_STORE_COL_TS,
	TRACE_VIEW_STORE_COL_COMM,
	TRACE_VIEW_STORE_COL_PID,
	TRACE_VIEW_STORE_COL_LAT,
	TRACE_VIEW_STORE_COL_EVENT,
	TRACE_VIEW_STORE_COL_INFO,
	TRACE_VIEW_STORE_N_COLUMNS,
} ;


typedef struct _TraceViewRecord	TraceViewRecord;
typedef struct _TraceViewStore	TraceViewStore;
typedef struct _TraceViewStoreClass	TraceViewStoreClass;



/* TraceViewRecord: this structure represents a row */

struct _TraceViewRecord
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

struct _TraceViewStore
{
	GObject			parent;	/* this MUST be the first member */

	guint			num_rows; /* number of rows that we have   */
	TraceViewRecord		**rows;	/* a dynamically allocated array of pointers to
					 *   the TraceViewRecord structure for each row    */

	guint			visible_column_mask;
	gint			n_columns;		/* number of columns visible */

	GType			column_types[TRACE_VIEW_STORE_N_COLUMNS];

	/* Tracecmd specific info */
	struct tracecmd_input *handle;
	int			cpus;

	TraceViewRecord		**cpu_list;
	gint			*cpu_items;

	/* filters */
	gint			all_events; /* set 1 when all events are enabled */
						/* else */
	gchar			**systems;  /* sorted list of systems that are enabled */
	gint			**event_types; /* sorted list of events that are enabled */

	gint			all_cpus;   /* set 1 when all cpus are enabled */
						/* else */
	guint64			*cpu_mask;  /* cpus that are enabled */

	gint		stamp;	/* Random integer to check whether an iter belongs to our model */
};

/* helper functions */

static inline gint trace_view_store_get_cpus(TraceViewStore *store)
{
	return store->cpus;
}

static inline guint64 *trace_view_store_get_cpu_mask(TraceViewStore *store)
{
	return store->cpu_mask;
}

static inline gint trace_view_store_get_all_cpus(TraceViewStore *store)
{
	return store->all_cpus;
}

gboolean trace_view_store_cpu_isset(TraceViewStore *store, gint cpu);

void trace_view_store_set_all_cpus(TraceViewStore *store);
void trace_view_store_set_cpu(TraceViewStore *store, gint cpu);
void trace_view_store_clear_cpu(TraceViewStore *store, gint cpu);


/* TraceViewStoreClass: more boilerplate GObject stuff */

struct _TraceViewStoreClass
{
	GObjectClass		parent_class;
};


GType		trace_view_store_get_type (void);

TraceViewStore	*trace_view_store_new (struct tracecmd_input *handle);

#if 0
void		trace_view_store_append_record (TraceViewStore   *trace_view_store,
						const gchar  *name,
						guint         year_born);
#endif

#endif /* _trace_view_store_h_included_ */
