#include "trace-graph.h"

static int cpu_plot_match_time(struct graph_info *ginfo, struct graph_plot *plot,
			       unsigned long long time)
{
	struct record *record;
	long cpu;
	int ret = 0;

	cpu = (long)plot->private;

	tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, time);
	record = tracecmd_read_data(ginfo->handle, cpu);
	while (record && record->ts < time) {
		free_record(record);
		record = tracecmd_read_data(ginfo->handle, cpu);
	}
	if (record && record->ts == time)
		ret = 1;
	free_record(record);

	return ret;
}

static const struct plot_callbacks cpu_plot_cb = {
	.match_time		 = cpu_plot_match_time
};

void graph_plot_init_cpus(struct graph_info *ginfo, int cpus)
{
	char label[100];
	long cpu;

	for (cpu = 0; cpu < cpus; cpu++) {
		snprintf(label, 100, "CPU %ld", cpu);
		trace_graph_plot_append(ginfo, label, &cpu_plot_cb, (void *)cpu);
	}
}
