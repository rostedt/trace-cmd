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
#ifndef _TRACE_GUI
#define _TRACE_GUI

#include <gtk/gtk.h>

enum trace_dialog_type {
	TRACE_GUI_INFO,
	TRACE_GUI_WARNING,
	TRACE_GUI_ERROR,
	TRACE_GUI_ASK,
};

GtkWidget *trace_status_bar_new(void);

enum trace_dialog_filter {
	TRACE_DIALOG_FILTER_NONE,
	TRACE_DIALOG_FILTER_DATA,
	TRACE_DIALOG_FILTER_FILTER,
	TRACE_DIALOG_FILTER_SETTING,
};

void trace_dialog_register_window(GtkWidget *window);
void trace_dialog_register_alt_warning(void (*alt)(const char *fmt, va_list ap));

void trace_show_help(GtkWidget *window, const gchar *link, GError **error);

GtkResponseType trace_dialog(GtkWindow *parent, enum trace_dialog_type type,
			     gchar *message, ...);

gchar *trace_get_file_dialog_filter(const gchar *title, const char *open,
			     enum trace_dialog_filter, gboolean warn);
gchar *trace_get_file_dialog(const gchar *title, const char *open,
			     gboolean warn);

void trace_set_cursor(GdkCursorType type);
void trace_put_cursor(void);
void trace_freeze_all(void);
void trace_unfreeze_all(void);

GtkWidget *
trace_create_combo_box(GtkWidget *hbox, const gchar *text,
		       GtkTreeModel *(*combo_model_create)(gpointer data),
		       gpointer data);

#endif /* _TRACE_GUI */
