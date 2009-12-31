#include "trace-compat.h"

#if GTK_VERSION < CALC_GTK_VERSION(2,18,0)

void gtk_cell_renderer_get_padding(GtkCellRenderer *cell,
				   gint *xpad, gint *ypad)
{
	if (xpad)
		*xpad = cell->xpad;
	if (ypad)
		*ypad = cell->ypad;
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
