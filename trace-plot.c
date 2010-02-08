#include <string.h>
#include "trace-graph.h"

void trace_graph_plot_free(struct graph_info *ginfo)
{
	struct graph_plot *plot;

	while (ginfo->plot_list) {
		plot = ginfo->plot_list;
		ginfo->plot_list = plot->next;
		free(plot);
	}

	if (ginfo->plot_array) {
		free(ginfo->plot_array);
		ginfo->plot_array = NULL;
	};

	ginfo->plots = 0;
}

void trace_graph_plot_init(struct graph_info *ginfo)
{
	ginfo->plots = 0;
	ginfo->plot_array = NULL;
	ginfo->plot_list = NULL;
}

void trace_graph_plot_append(struct graph_info *ginfo,
			     const char *label, const struct plot_callbacks *cb,
			     void *data)
{
	struct graph_plot *plot;
	char *name;

	name = strdup(label);
	if (!name)
		die("Unable to allocate label");

	plot = malloc_or_die(sizeof(*plot));
	memset(plot, 0, sizeof(*plot));

	plot->label = name;
	plot->cb = cb;
	plot->private = data;

	plot->next = ginfo->plot_list;
	ginfo->plot_list = plot;

	if (!ginfo->plots) {
		ginfo->plot_array = malloc_or_die(sizeof(ginfo->plot_array[0]));
		ginfo->plot_array[0] = plot;
	} else {
		ginfo->plot_array = realloc(ginfo->plot_array,
					    sizeof(ginfo->plot_array[0]) *
					    (ginfo->plots + 1));

		if (!ginfo->plot_array)
			die("unable to resize plot array");

		ginfo->plot_array[ginfo->plots] = plot;
	}

	ginfo->plots++;
}

int trace_graph_plot_match_time(struct graph_info *ginfo,
				struct graph_plot *plot,
				unsigned long long time)
{
	if (!plot->cb->match_time)
		return 0;

	return plot->cb->match_time(ginfo, plot, time);
}

void trace_graph_plot_start(struct graph_info *ginfo,
			    struct graph_plot *plot,
			    unsigned long long time)
{
	if (!plot->cb->start)
		return;

	return plot->cb->start(ginfo, plot, time);
}

int trace_graph_plot_event(struct graph_info *ginfo,
			   struct graph_plot *plot,
			   gboolean *line, int *lcolor,
			   unsigned long long *ltime,
			   gboolean *box, int *bcolor,
			   unsigned long long *bstart,
			   unsigned long long *bend)
{
	*line = FALSE;
	*box = FALSE;

	if (!plot->cb->plot_event)
		return 0;

	return plot->cb->plot_event(ginfo, plot, line, lcolor, ltime,
				    box, bcolor, bstart, bend);
}

void trace_graph_plot_end(struct graph_info *ginfo,
			  struct graph_plot *plot)
{
	if (!plot->cb->end)
		return;

	return plot->cb->end(ginfo, plot);
}

int trace_graph_plot_display_last_event(struct graph_info *ginfo,
					struct graph_plot *plot,
					struct trace_seq *s,
					unsigned long long time)
{
	if (!plot->cb->display_last_event)
		return 0;

	return plot->cb->display_last_event(ginfo, plot, s, time);
}
