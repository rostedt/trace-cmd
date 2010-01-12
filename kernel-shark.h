#ifndef _KERNEL_SHARK_H
#define _KERNEL_SHARK_H

#include "trace-graph.h"
#include "trace-view.h"

struct shark_info {
	GtkWidget			*window;
	struct graph_info		*ginfo;
	struct tracecmd_input  		*handle;
	GtkWidget			*treeview;
	GtkWidget			*spin;
	struct graph_callbacks		graph_cbs;
	gint				selected_task;
	gboolean			list_filter_enabled;
};

#define offset_of(type, field)		(long)(&((type *)0)->field)
#define container_of(p, type, field)	(type *)((long)p - offset_of(type, field))

#endif /* _KERNEL_SHARK_H */
