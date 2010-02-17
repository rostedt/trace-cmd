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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#ifndef _TRACE_FILTER_H
#define _TRACE_FILTER_H

#include <gtk/gtk.h>

struct event_filter_list {
	struct event_filter_list	*next;
	struct event			*event;
};

/**
 * trace_filter_event_cb_func - callback type for event dialog
 * @accept: TRUE if the accept button was pressed, otherwise FALSE
 * @all_events: TRUE if "All Events" was checked
 * @systems: NULL or a string array of systems terminated with NULL
 * @events: NULL or a int array of event ids terminated with -1
 * @data: The data given passed in to the event dialog function
 *
 * If @accept is FALSE then @all_events, @systems, and @events
 * should be ignored. @data is still valid.
 *
 * If @all_events is TRUE then @systems and @events should be ignored.
 */
typedef void (*trace_filter_event_cb_func)(gboolean accept,
					   gboolean all_events,
					   char **systems,
					   gint *events,
					   gpointer data);

void trace_filter_event_dialog(struct tracecmd_input *handle,
			       gboolean all_events,
			       gchar **systems,
			       gint *events,
			       trace_filter_event_cb_func func,
			       gpointer data);

void trace_filter_convert_filter_to_names(struct event_filter *filter,
					  gchar ***systems,
					  gint **events);

void trace_filter_convert_char_to_filter(struct event_filter *filter,
					 gchar **systems,
					 gint *events);
/**
 * trace_filter_cpu_cb_func - callback type for CPU dialog
 * @accept: TRUE if the accept button was pressed, otherwise FALSE
 * @all_cpus: TRUE if "All CPUS" was checked
 * @selected_cpus: NULL or a cpu_mask with the cpus that were checked set.
 * @data: The data given passed in to the CPU dialog function
 *
 * If @accept is FALSE then @all_cpus and @selected_cpus should be ignored.
 * @data is still valid.
 *
 * If @all_cpus is TRUE then @selected_cpus should be ignored.
 */
typedef void (*trace_filter_cpu_cb_func)(gboolean accept,
					 gboolean all_cpus,
					 guint64 *selected_cpus,
					 gpointer data);

void trace_filter_cpu_dialog(gboolean all_cpus, guint64 *cpu_mask_selected, gint cpus,
			     trace_filter_cpu_cb_func func, gpointer data);

/* put here because there's no other place */

int str_cmp(const void *a, const void *b);
int id_cmp(const void *a, const void *b);

#endif /* _TRACE_FILTER_H */
