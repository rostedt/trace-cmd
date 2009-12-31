#include "trace-compat.h"

#if GTK_VERSION < CALC_GTK_VERSION(2,18,0)

#warning Using compat functions for older GTK library
#warning Please upgrade your GTK to at least 2.18

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
