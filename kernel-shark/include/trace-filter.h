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
#ifndef _TRACE_FILTER_H
#define _TRACE_FILTER_H

#include <gtk/gtk.h>

#include "trace-xml.h"

struct event_filter_list {
	struct event_filter_list	*next;
	struct event			*event;
};

/**
 * trace_adv_filter_cb_func - callback type for advanced filter dialog
 * @accept: TRUE if the accept button was pressed, otherwise FALSE
 * @text: The text that was entered
 * @delete_event_filters: The list of event ids for filters to remove
 * @data: The data given passed in to the event dialog function
 *
 * If @accept is FALSE then @text and @delete_event_filters
 * should be ignored. @data is still valid.
 *
 * @text may be NULL or empty, and @delete_event_ids may also be NULL.
 * @delete_event_ids if not NULL, then ends with -1
 */
typedef void (*trace_adv_filter_cb_func)(gboolean accept,
					 const gchar *text,
					 gint *delete_event_filters,
					 gpointer data);

/**
 * trace_task_cb_func - callback type for task dialog
 * @accept: TRUE if the accept button was pressed, otherwise FALSE
 * @selected: list of pids of tasks selected
 * @non_select: list of pids of tasks not selected
 * @data: The data given passed in to the event dialog function
 *
 * If @accept is FALSE then @selected and @non_select
 * should be ignored. @data is still valid.
 *
 * Both @selected and @non_select may be NULL, if either is not
 * NULL they will be sorted and end with -1.
 */
typedef void (*trace_task_cb_func)(gboolean accept,
				   gint *selected,
				   gint *non_selected,
				   gpointer data);

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

void trace_adv_filter_dialog(struct tracecmd_input *handle,
			     struct event_filter *event_filter,
			     trace_adv_filter_cb_func func,
			     gpointer data);

void trace_task_dialog(struct tracecmd_input *handle,
		       gint *tasks, gint *selected,
		       trace_task_cb_func func,
		       gpointer data);

void trace_filter_event_dialog(struct tracecmd_input *handle,
			       gboolean all_events,
			       gchar **systems,
			       gint *events,
			       trace_filter_event_cb_func func,
			       gpointer data);

void trace_filter_pevent_dialog(struct pevent *pevent,
				gboolean all_events,
				gchar **systems, gint *events,
				trace_filter_event_cb_func func,
				gpointer data);

void trace_filter_event_filter_dialog(struct tracecmd_input *handle,
			       struct event_filter *filter,
			       gboolean all_events,
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

void trace_array_add(gint **array, gint *count, gint val);

/* save and load filters */
int trace_filter_save_events(struct tracecmd_xml_handle *handle,
			     struct event_filter *filter);
int trace_filter_save_tasks(struct tracecmd_xml_handle *handle,
			    struct filter_task *filter);
int trace_filter_load_events(struct event_filter *event_filter,
			     struct tracecmd_xml_handle *handle,
			     struct tracecmd_xml_system_node *node);
int trace_filter_load_task_filter(struct filter_task *filter,
				  struct tracecmd_xml_handle *handle,
				  struct tracecmd_xml_system_node *node);
int trace_filter_load_filters(struct tracecmd_xml_handle *handle,
			      const char *system_name,
			      struct filter_task *task_filter,
			      struct filter_task *hide_tasks);
int trace_filter_save_filters(struct tracecmd_xml_handle *handle,
			      const char *system_name,
			      struct filter_task *task_filter,
			      struct filter_task *hide_tasks);

GtkWidget *trace_create_event_list_view(struct pevent *pevent,
					struct event_filter *filter,
					gboolean all_events, gchar **systems,
					gint *events);
gint trace_extract_event_list_view(GtkWidget *event_view,
				   gboolean *all_events,
				   gchar ***systems,
				   gint **events);
int trace_update_event_view(GtkWidget *event_view,
			    struct pevent *pevent,
			    struct event_filter *filter,
			    gboolean all_events,
			    gchar **systems, gint *events);

/* put here because there's no other place */

int str_cmp(const void *a, const void *b);
int id_cmp(const void *a, const void *b);

#endif /* _TRACE_FILTER_H */
