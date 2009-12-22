#ifndef _KERNEL_SHARK_H
#define _KERNEL_SHARK_H

#include "trace-graph.h"
#include "trace-view.h"

struct shark_info {
	struct graph_info	*ginfo;
	GtkWidget		*treeview;
	struct graph_callbacks	graph_cbs;
};

#endif /* _KERNEL_SHARK_H */
