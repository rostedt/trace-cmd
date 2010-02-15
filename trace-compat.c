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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  The parts for function graph printing was taken and modified from the
 *  Linux Kernel that were written by Frederic Weisbecker.
 */
#include "trace-compat.h"

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

#endif /* version < 2.14.0 */

#if GTK_VERSION < CALC_GTK_VERSION(2,12,0)

GtkWidget *gtk_tree_view_column_get_tree_view(GtkTreeViewColumn *col)
{
	return col->tree_view;
}

#endif /* version < 2.12.0 */
