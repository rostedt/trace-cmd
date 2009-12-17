#ifndef _TRACE_GRAPH_H
#define _TRACE_GRAPH_H

#include "trace-cmd.h"

struct graph_info {
	struct tracecmd_input	*handle;
	struct pevent		*pevent;
	gint			cpus;
	GtkWidget		*draw;
	GdkPixmap		*curr_pixmap;	/* pixmap backstore */
	GtkAdjustment		*vadj;		/* scrollwindow vert adjust */
	guint64			start_time;	/* True start time of trace */
	guint64			end_time;	/* True end time of trace */
	guint64			view_start_time; /* visible start time */
	guint64			view_end_time;	/* visible end time */
	gint			start_x;	/* virutal start of visible area */

	gdouble			resolution;	/* pixels / time */

	gint			press_x;	/* x where button is pressed */
	gint			last_x;		/* last x seen while moving mouse */
	gboolean		line_active;	/* set when button is pressed */

	gdouble			vadj_value;	/* value to set vadj width */
	gdouble			vadj_page_size;	/* visible size to set vadj */

	gint			draw_width;	/* width of pixmap */
	gint			draw_height;	/* height of pixmap */
	gint			full_width;	/* width of full trace in pixels */
						/* This includes non visible part of trace */

	/* Box info for CPU data info window */
	gint			cpu_data_x;
	gint			cpu_data_y;
	gint			cpu_data_w;
	gint			cpu_data_h;

	/* not needed in future */

	gchar			*test;
};

#endif /* _TRACE_GRAPH_H */
