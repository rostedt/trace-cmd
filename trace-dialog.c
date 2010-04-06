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
#include <errno.h>
#include <ctype.h>

#include "trace-compat.h"
#include "trace-cmd.h"
#include "trace-gui.h"

#define DIALOG_WIDTH	500
#define DIALOG_HEIGHT	550

static GtkWidget *statusbar;
static GtkWidget *statuspix;
static GString *statusstr;

static GtkWidget *parent_window;

void pr_stat(char *fmt, ...)
{
	GString *str;
	va_list ap;

	if (!statusstr) {
		statusstr = g_string_new("");
		if (!statusstr)
			die("Allocating status string");
	}

	str = g_string_new("");

	va_start(ap, fmt);
	g_string_vprintf(str, fmt, ap);
	va_end(ap);

	g_string_append_printf(statusstr, "%s\n", str->str);

	if (statusbar) {
		gtk_statusbar_push(GTK_STATUSBAR(statusbar), 1, str->str);
		gtk_widget_show(statuspix);
	}

	g_string_free(str, TRUE);
}

/**
 * trace_dialog_register_window - register window for warning dialogs
 * @window: parent window to use for other dialogs
 *
 * The warning messages do not have a way to pass the window to
 * the function, since these functions are also used by the command
 * line interface. This allows an application to give the warning
 * messages a window to use.
 */
void trace_dialog_register_window(GtkWidget *window)
{
	parent_window = window;
}

void warning(char *fmt, ...)
{
	GString *str;
	va_list ap;

	if (!parent_window) {
		va_start(ap, fmt);
		__vwarning(fmt, ap);
		va_end(ap);
		return;
	}

	str = g_string_new("");

	va_start(ap, fmt);
	g_string_vprintf(str, fmt, ap);
	va_end(ap);

	g_string_append(str, "\n");

	if (errno)
		g_string_prepend(str, strerror(errno));

	errno = 0;

	trace_dialog(GTK_WINDOW(parent_window), TRACE_GUI_WARNING,
		     str->str);

	g_string_free(str, TRUE);
}

static void
status_display_clicked (gpointer data)
{
	GtkWidget *dialog;
	GtkWidget *scrollwin;
	GtkWidget *viewport;
	GtkWidget *textview;
	GtkTextBuffer *buffer;

	dialog = gtk_dialog_new_with_buttons("Status",
					     NULL,
					     GTK_DIALOG_MODAL,
					     "OK",
					     GTK_RESPONSE_ACCEPT,
					     NULL);

	scrollwin = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrollwin),
				       GTK_POLICY_AUTOMATIC,
				       GTK_POLICY_AUTOMATIC);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), scrollwin, TRUE, TRUE, 0);
	gtk_widget_show(scrollwin);

	viewport = gtk_viewport_new(NULL, NULL);
	gtk_widget_show(viewport);

	gtk_container_add(GTK_CONTAINER(scrollwin), viewport);

	textview = gtk_text_view_new();
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));
	gtk_text_buffer_set_text(buffer, statusstr->str, -1);

	gtk_container_add(GTK_CONTAINER(viewport), textview);
	gtk_widget_show(textview);

	gtk_widget_set_size_request(GTK_WIDGET(dialog),
				    DIALOG_WIDTH, DIALOG_HEIGHT);

	gtk_dialog_run(GTK_DIALOG(dialog));

	gtk_widget_destroy(dialog);
}

static gboolean
do_status_popup(GtkWidget *widget, GdkEventButton *event, gpointer data)
{
	static GtkWidget *menu;
	static GtkWidget *menu_status_display;

	if (!menu) {
		menu = gtk_menu_new();
		menu_status_display = gtk_menu_item_new_with_label("Display Status");
		gtk_widget_show(menu_status_display);
		gtk_menu_shell_append(GTK_MENU_SHELL (menu), menu_status_display);

		g_signal_connect_swapped (G_OBJECT (menu_status_display), "activate",
					  G_CALLBACK (status_display_clicked),
					  data);
	}

	gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL, 3,
		       gtk_get_current_event_time());

	return TRUE;
}

static gboolean
button_press_status(GtkWidget *widget, GdkEventButton *event, gpointer data)
{
	if (event->button == 1)
		return do_status_popup(widget, event, data);

	return FALSE;
}

GtkWidget *trace_status_bar_new(void)
{
	GtkWidget *eventbox;

	statusbar = gtk_statusbar_new();

	statuspix = gtk_image_new_from_stock(GTK_STOCK_INFO,
					     GTK_ICON_SIZE_SMALL_TOOLBAR);

	eventbox = gtk_event_box_new();
	gtk_container_add(GTK_CONTAINER(eventbox), statuspix);
	gtk_widget_show(eventbox);

	gtk_box_pack_end(GTK_BOX(statusbar), eventbox, FALSE, FALSE, 0);

	if (statusstr)
		gtk_widget_show(statuspix);

	gtk_signal_connect(GTK_OBJECT(eventbox), "button_press_event",
			   (GtkSignalFunc) button_press_status, NULL);

	return statusbar;
}

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
