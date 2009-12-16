#ifndef _TRACE_GRAPH_H
#define _TRACE_GRAPH_H

#include "trace-cmd.h"

struct graph_info {
	struct tracecmd_input	*handle;
	struct pevent		*pevent;
	gint			cpus;
	GtkWidget		*draw;
	GdkPixmap		*main_pixmap;
	GdkPixmap		*curr_pixmap;
	GtkAdjustment		*vadj;
	guint64			start_time;
	guint64			end_time;
	guint64			view_start_time;
	guint64			view_end_time;

	gdouble			resolution;

	gint			start_x;
	gint			last_x;
	gboolean		line_active;
	gdouble			vadj_value;

	gint			draw_width;
	gint			draw_height;

	gint			cpu_data_x;
	gint			cpu_data_y;
	gint			cpu_data_w;
	gint			cpu_data_h;

	/* not needed in future */

	gint			last_y;
	gint			mov_w;
	gint			mov_h;

	gint			max_width;
	gint			max_height;

	gboolean		save;
	gboolean		draw_line;
	gchar			*test;
};

#endif /* _TRACE_GRAPH_H */
