#ifndef _KERNEL_SHARK_H
#define _KERNEL_SHARK_H

#include "trace-graph.h"
#include "trace-view.h"

struct shark_info {
	struct graph_info	*ginfo;
	GtkWidget		*treeview;
	struct graph_callbacks	graph_cbs;
};

#define offset_of(type, field)		(long)(&((type *)0)->field)
#define container_of(p, type, field)	(type *)((long)p - offset_of(type, field))

#endif /* _KERNEL_SHARK_H */
