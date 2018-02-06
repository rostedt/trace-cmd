/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
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
	GtkWidget			*load_filter_menu;
	GtkWidget			*task_sync_menu;
	GtkWidget			*events_sync_menu;
	GtkWidget			*list_task_menu;
	GtkWidget			*graph_task_menu;
	GtkWidget			*list_hide_task_menu;
	GtkWidget			*graph_hide_task_menu;
	GtkWidget			*list_events_menu;
	GtkWidget			*graph_events_menu;
	GtkWidget			*list_adv_events_menu;
	GtkWidget			*graph_adv_events_menu;
	gchar				*current_filter;
	struct graph_callbacks		graph_cbs;
	gint				selected_task;
	gboolean			list_filter_enabled;
	gboolean			list_filter_available;
	gboolean			graph_follows;
	gboolean			sync_task_filters;
	gboolean			sync_event_filters;
	struct filter_task		*list_task_filter;
	struct filter_task		*list_hide_tasks;

	/* Save capture state. */
	gboolean			cap_all_events;
	gchar				**cap_systems;
	int				*cap_events;
	gchar				*cap_plugin;
	gchar				*cap_command;
	gchar				*cap_file;
	gchar				*cap_settings_name;
	int				cap_max_buf_size;
	gchar				*cap_buffer_output;
};

#define offset_of(type, field)		(long)(&((type *)0)->field)
#define container_of(p, type, field)	(type *)((long)p - offset_of(type, field))

int kernelshark_load_file(struct shark_info *info, const char *file);
void kernel_shark_clear_capture(struct shark_info *info);

#endif /* _KERNEL_SHARK_H */
