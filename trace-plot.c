/*
 * Copyright (C) 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <string.h>
#include "trace-graph.h"

void trace_graph_plot_free(struct graph_info *ginfo)
{
	struct graph_plot **array;
	int plots;
	int i;

	/* copy the plot_array since the removing plots will modify it */
	array = malloc_or_die(sizeof(*array) * ginfo->plots);
	memcpy(array, ginfo->plot_array, sizeof(*array) * ginfo->plots);
	plots = ginfo->plots;


	for (i = 0; i < plots; i++)
		trace_graph_plot_remove(ginfo, array[i]);
	free(array);

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

struct graph_plot *
trace_graph_plot_append(struct graph_info *ginfo,
			const char *label, enum graph_plot_type type,
			const struct plot_callbacks *cb, void *data)
{
	struct graph_plot *plot;

	plot = allocate_plot(ginfo, label, cb, data);

	plot->type = type;
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

	return plot;
}

struct graph_plot *
trace_graph_plot_insert(struct graph_info *ginfo,
			int pos, const char *label, enum graph_plot_type type,
			const struct plot_callbacks *cb, void *data)
{
	struct graph_plot *plot;
	int i;

	if (pos >= ginfo->plots)
		return trace_graph_plot_append(ginfo, label, type, cb, data);

	if (pos < 0)
		pos = 0;

	plot = allocate_plot(ginfo, label, cb, data);
	plot->pos = pos;
	plot->type = type;
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

	return plot;
}

void trace_graph_plot_remove(struct graph_info *ginfo, struct graph_plot *plot)
{
	int pos = plot->pos;
	int i;

	if (plot->cb->destroy)
		plot->cb->destroy(ginfo, plot);

	free(plot->label);
	free(plot);

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

static struct plot_hash *find_hash(struct plot_hash **array, gint val)
{
	struct plot_hash *hash;
	gint key;

	key = trace_hash(val) % PLOT_HASH_SIZE;

	for (hash = array[key]; hash; hash = hash->next) {
		if (hash->val == val)
			return hash;
	}

	return NULL;
}

static void add_hash(struct plot_hash **array, struct graph_plot *plot, gint val)
{
	struct plot_hash *hash;
	struct plot_list *list;
	gint key;

	list = malloc_or_die(sizeof(*list));
	hash = find_hash(array, val);
	if (!hash) {
		hash = g_new0(typeof(*hash), 1);
		g_assert(hash);
		key = trace_hash(val) % PLOT_HASH_SIZE;
		hash->next = array[key];
		hash->val = val;
		array[key] = hash;
	}

	list->next = hash->plots;
	list->plot = plot;

	hash->plots = list;
}

static void remove_hash(struct plot_hash **array, struct graph_plot *plot, gint val)
{
	struct plot_hash *hash, **phash;
	struct plot_list **pplot;
	struct plot_list *list;
	gint key;

	hash = find_hash(array, val);
	pplot = &hash->plots;

	while ((list = *pplot)) {
		if (list->plot == plot) {
			*pplot = list->next;
			free(list);
			break;
		}
		pplot = &list->next;
	}

	if (hash->plots)
		return;

	/* remove this hash item */
	key = trace_hash(val) % PLOT_HASH_SIZE;
	phash = &array[key];
	while (*phash) {
		if (*phash == hash) {
			*phash = hash->next;
			break;
		}
		phash = &(*phash)->next;
	}

	g_free(hash);
}

struct plot_hash *
trace_graph_plot_find_task(struct graph_info *ginfo, gint task)
{
	return find_hash(ginfo->task_hash, task);
}

void trace_graph_plot_add_task(struct graph_info *ginfo,
			       struct graph_plot *plot,
			       gint task)
{
	add_hash(ginfo->task_hash, plot, task);
	ginfo->nr_task_hash++;
}

void trace_graph_plot_remove_task(struct graph_info *ginfo,
				  struct graph_plot *plot,
				  gint task)
{
	remove_hash(ginfo->task_hash, plot, task);
	ginfo->nr_task_hash--;
}

struct plot_hash *
trace_graph_plot_find_cpu(struct graph_info *ginfo, gint cpu)
{
	return find_hash(ginfo->cpu_hash, cpu);
}

void trace_graph_plot_add_cpu(struct graph_info *ginfo,
			      struct graph_plot *plot,
			      gint cpu)
{
	add_hash(ginfo->cpu_hash, plot, cpu);
}

void trace_graph_plot_remove_cpu(struct graph_info *ginfo,
				 struct graph_plot *plot,
				 gint cpu)
{
	remove_hash(ginfo->cpu_hash, plot, cpu);
}

void trace_graph_plot_add_all_recs(struct graph_info *ginfo,
				   struct graph_plot *plot)
{
	struct plot_list *list;

	list = malloc_or_die(sizeof(*list));
	list->next = ginfo->all_recs;
	list->plot = plot;

	ginfo->all_recs = list;
}

void trace_graph_plot_remove_all_recs(struct graph_info *ginfo,
				      struct graph_plot *plot)
{
	struct plot_list **pplot;
	struct plot_list *list;

	pplot = &ginfo->all_recs;

	while ((list = *pplot)) {
		if (list->plot == plot) {
			*pplot = list->next;
			free(list);
			break;
		}
		pplot = &list->next;
	}
}

/* Plot callback helpers */

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
			   struct pevent_record *record,
			   struct plot_info *info)
{
	info->line = FALSE;
	info->box = FALSE;
	info->bfill = TRUE;

	if (!plot->cb->plot_event)
		return 0;

	return plot->cb->plot_event(ginfo, plot, record, info);
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

struct pevent_record *
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

