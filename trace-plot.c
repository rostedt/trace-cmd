#include <string.h>
#include "trace-graph.h"

void trace_graph_plot_free(struct graph_info *ginfo)
{
	int i;

	for (i = 0; i < ginfo->plots; i++)
		free(ginfo->plot_array[i]);

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
}

static struct graph_plot *
allocate_plot(struct graph_info *ginfo,
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

	return plot;
}

void trace_graph_plot_append(struct graph_info *ginfo,
			     const char *label, const struct plot_callbacks *cb,
			     void *data)
{
	struct graph_plot *plot;

	plot = allocate_plot(ginfo, label, cb, data);

	plot->pos = ginfo->plots;

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

void trace_graph_plot_insert(struct graph_info *ginfo,
			     int pos,
			     const char *label, const struct plot_callbacks *cb,
			     void *data)
{
	struct graph_plot *plot;
	int i;

	if (pos >= ginfo->plots)
		return trace_graph_plot_append(ginfo, label, cb, data);

	if (pos < 0)
		pos = 0;

	plot = allocate_plot(ginfo, label, cb, data);
	plot->pos = pos;
	ginfo->plot_array = realloc(ginfo->plot_array,
				    sizeof(ginfo->plot_array[0]) *
				    (ginfo->plots + 1));

	if (!ginfo->plot_array)
		die("unable to resize plot array");

	memmove(&ginfo->plot_array[pos+1], &ginfo->plot_array[pos],
		sizeof(ginfo->plot_array[0]) * (ginfo->plots - pos));

	ginfo->plot_array[pos] = plot;

	ginfo->plots++;

	/* Update the new positions */
	for (i = pos + 1; i < ginfo->plots; i++)
		ginfo->plot_array[i]->pos = i;
}

void trace_graph_plot_remove(struct graph_info *ginfo, struct graph_plot *plot)
{
	int pos = plot->pos;
	int i;

	if (pos < 0 || pos >= ginfo->plots || !ginfo->plots)
		return;

	free(ginfo->plot_array[pos]);

	ginfo->plots--;

	if (ginfo->plots) {
		memmove(&ginfo->plot_array[pos], &ginfo->plot_array[pos+1],
			sizeof(ginfo->plot_array[0]) * (ginfo->plots - pos));
		/* Update the new positions */
		for (i = pos; i < ginfo->plots; i++)
			ginfo->plot_array[i]->pos = i;
	} else {
		free(ginfo->plot_array);
		ginfo->plot_array = NULL;
	}
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

struct record *
trace_graph_plot_find_record(struct graph_info *ginfo,
			     struct graph_plot *plot,
			     unsigned long long time)
{
	if (!plot->cb->find_record)
		return 0;

	return plot->cb->find_record(ginfo, plot, time);
}

int trace_graph_plot_display_info(struct graph_info *ginfo,
				  struct graph_plot *plot,
				  struct trace_seq *s,
				  unsigned long long time)
{
	if (!plot->cb->display_info)
		return 0;

	return plot->cb->display_info(ginfo, plot, s, time);
}

