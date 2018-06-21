/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
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
	struct tracecmd_filter_id	*list_task_filter;
	struct tracecmd_filter_id	*list_hide_tasks;

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
