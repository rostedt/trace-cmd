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
#include "trace-compat.h"
#include "trace-gui.h"
#include "trace-cmd.h"

#include <gdk/gdk.h>

#if GTK_VERSION < CALC_GTK_VERSION(2,18,0)

#warning Using compat functions for older GTK library. This should work fine
#warning but when you get a chance, please upgrade your GTK to at least 2.18

void gtk_cell_renderer_get_padding(GtkCellRenderer *cell,
				   gint *xpad, gint *ypad)
{
	if (xpad)
		*xpad = cell->xpad;
	if (ypad)
		*ypad = cell->ypad;
}

#endif /* version < 2.18.0 */

#if GTK_VERSION < CALC_GTK_VERSION(2,16,0)

const gchar *gtk_menu_item_get_label(GtkMenuItem *menu_item)
{
	g_return_val_if_fail(GTK_IS_MENU_ITEM(menu_item), NULL);

	if (GTK_IS_LABEL(GTK_BIN(menu_item)->child))
		return gtk_label_get_label(GTK_LABEL(GTK_BIN(menu_item)->child));
	return NULL;
}

void gtk_menu_item_set_label(GtkMenuItem *menu_item, const gchar *label)
{
	g_return_if_fail(GTK_IS_MENU_ITEM(menu_item));

	if (GTK_IS_LABEL(GTK_BIN(menu_item)->child)) {
		gtk_label_set_label(GTK_LABEL(GTK_BIN(menu_item)->child),
				    label ? label : "");
	}
}

#endif /* version < 2.18.0 */

#if GTK_VERSION < CALC_GTK_VERSION(2,14,0)

gdouble gtk_adjustment_get_page_size(GtkAdjustment *adj)
{
	return adj->page_size;
}

gdouble gtk_adjustment_get_upper(GtkAdjustment *adj)
{
	return adj->upper;
}

gdouble gtk_adjustment_get_lower(GtkAdjustment *adj)
{
	return adj->lower;
}

gboolean gtk_show_uri(GdkScreen *screen, const gchar *uri,
		      guint32 timestamp, GError **error)
{
	return FALSE;
}

void g_string_vprintf(GString *string, const gchar *format, va_list args)
{
	char buf[1024];
	gint len;

	len = vsnprintf(buf, 1024, format, args);
	if (len >= 1024)
		die("compat g_string_vprintf can not process length of %d\n", len);

	g_string_printf(string, "%s", buf);
}

#endif /* version < 2.14.0 */

#if GTK_VERSION < CALC_GTK_VERSION(2,12,0)

GtkWidget *gtk_tree_view_column_get_tree_view(GtkTreeViewColumn *col)
{
	return col->tree_view;
}

void gtk_widget_set_tooltip_text(GtkWidget *widget, const gchar *text)
{
	static GtkTooltips *tooltips;

	/* Only works for widgets with windows, sorry */
	if (GTK_WIDGET_NO_WINDOW(widget))
		return;

	if (!tooltips) {
		tooltips = gtk_tooltips_new();
		gtk_tooltips_enable(tooltips);
	}

	gtk_tooltips_set_tip(GTK_TOOLTIPS(tooltips), widget, text, text);
}

#endif /* version < 2.12.0 */
