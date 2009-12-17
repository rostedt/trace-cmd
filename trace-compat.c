#include "trace-compat.h"

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

#endif
