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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#include "trace-compat.h"
#include "trace-gui.h"

#define DIALOG_WIDTH	400
#define DIALOG_HEIGHT	600

void trace_show_help(GtkWidget *window, const gchar *link, GError **error)
{
#if GTK_VERSION < CALC_GTK_VERSION(2,14,0)
	trace_dialog(GTK_WINDOW(window), TRACE_GUI_WARNING,
		     "This version of GTK+ does not implement gtk_show_uri.\n"
		     "Please upgrade your GTK and recompile");
#else
	gtk_show_uri(gtk_widget_get_screen(GTK_WIDGET(window)),
		     link,
		     GDK_CURRENT_TIME,
		     error);
#endif
}

void trace_dialog(GtkWindow *parent, enum trace_dialog_type type,
		  gchar *message, ...)
{
	GtkWidget *dialog;
	GtkMessageType mtype;
	gchar *str;
	va_list ap;

	switch (type) {
	case TRACE_GUI_INFO:
		mtype = GTK_MESSAGE_INFO;
		break;
	case TRACE_GUI_WARNING:
		mtype = GTK_MESSAGE_WARNING;
		break;
	case TRACE_GUI_ERROR:
		mtype = GTK_MESSAGE_ERROR;
		break;
	}

	va_start(ap, message);
	str = g_strdup_vprintf(message, ap);
	va_end(ap);

	dialog = gtk_message_dialog_new(parent,
					GTK_DIALOG_DESTROY_WITH_PARENT,
					mtype,
					GTK_BUTTONS_CLOSE,
					"%s", str);
	g_free(str);
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
}

gchar *trace_get_file_dialog(const gchar *title)
{
	GtkWidget *dialog;
	gchar *filename = NULL;

	dialog = gtk_file_chooser_dialog_new(title,
					     NULL,
					     GTK_FILE_CHOOSER_ACTION_OPEN,
					     GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					     GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
					     NULL);
	if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT)
		filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));

	gtk_widget_destroy(dialog);

	return filename;
}
