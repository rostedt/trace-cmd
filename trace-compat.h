/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#ifndef _TRACE_COMPAT_H
#define _TRACE_COMPAT_H

#include <gtk/gtk.h>
#include <stdarg.h>

#define CALC_GTK_VERSION(maj, min, ext) ((maj << 16) + (min << 8) + ext)

#if GTK_VERSION < CALC_GTK_VERSION(2,18,0)

void gtk_cell_renderer_get_padding(GtkCellRenderer *cell,
				   gint *xpad, gint *ypad);

#endif /* version < 2.18.0 */

#if GTK_VERSION < CALC_GTK_VERSION(2,16,0)

const gchar *gtk_menu_item_get_label(GtkMenuItem *menu_item);
void gtk_menu_item_set_label(GtkMenuItem *menu_item, const gchar *label);

#endif /* version < 2.16.0 */

#if GTK_VERSION < CALC_GTK_VERSION(2,14,0)

gdouble gtk_adjustment_get_page_size(GtkAdjustment *adj);
gdouble gtk_adjustment_get_upper(GtkAdjustment *adj);
gdouble gtk_adjustment_get_lower(GtkAdjustment *adj);
gboolean gtk_show_uri(GdkScreen *screen, const gchar *uri,
		      guint32 timestamp, GError **error);

void g_string_vprintf(GString *string, const gchar *format, va_list args);

#endif /* version < 2.14.0 */

#if GTK_VERSION < CALC_GTK_VERSION(2,12,0)

GtkWidget *gtk_tree_view_column_get_tree_view(GtkTreeViewColumn *col);
void gtk_widget_set_tooltip_text(GtkWidget *widget, const gchar *text);

#endif /* version < 2.12.0 */

#endif /* _TRACE_COMPAT_H */
