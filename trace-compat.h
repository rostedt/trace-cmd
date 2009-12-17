#ifndef _TRACE_COMPAT_H
#define _TRACE_COMPAT_H

#include <gtk/gtk.h>

#define CALC_GTK_VERSION(maj, min, ext) ((maj << 16) + (min << 8) + ext)

#if GTK_VERSION < CALC_GTK_VERSION(2,14,0)

gdouble gtk_adjustment_get_page_size(GtkAdjustment *adj);
gdouble gtk_adjustment_get_upper(GtkAdjustment *adj);
gdouble gtk_adjustment_get_lower(GtkAdjustment *adj);

#endif

#endif /* _TRACE_COMPAT_H */
