#include "trace-graph.h"

static struct plot_callbacks cpu_plot_cb;

void graph_plot_init_cpus(struct graph_info *ginfo, int cpus)
{
	char label[100];
	int cpu;

	for (cpu = 0; cpu < cpus; cpu++) {
		snprintf(label, 100, "CPU %d", cpu);
		trace_graph_plot_append(ginfo, label, &cpu_plot_cb);
	}
}
