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
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

#include "trace-compat.h"
#include "trace-cmd.h"
#include "trace-gui.h"

#define DIALOG_WIDTH	500
#define DIALOG_HEIGHT	550

static GtkWidget *statusbar;
static GtkWidget *statuspix;
static GString *statusstr;

static GtkWidget *parent_window;

static void (*alt_warning)(const char *fmt, va_list ap);

void vpr_stat(const char *fmt, va_list ap)
{
	GString *str;

	if (!statusstr) {
		statusstr = g_string_new("");
		if (!statusstr)
			die("Allocating status string");
	}

	str = g_string_new("");

	g_string_vprintf(str, fmt, ap);

	g_string_append_printf(statusstr, "%s\n", str->str);

	if (statusbar) {
		gtk_statusbar_push(GTK_STATUSBAR(statusbar), 1, str->str);
		gtk_widget_show(statuspix);
	}

	g_string_free(str, TRUE);
}

void pr_stat(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vpr_stat(fmt, ap);
	va_end(ap);
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

static struct cursor_stack {
	struct cursor_stack	*next;
	GdkCursor		*cursor;
} *cursor_stack;

static void push_cursor(GdkCursor *cursor)
{
	struct cursor_stack *item;

	item = malloc_or_die(sizeof(item));
	item->next = cursor_stack;
	cursor_stack = item;
	item->cursor = cursor;
}

static GdkCursor *pop_cursor(void)
{
	struct cursor_stack *item;
	GdkCursor *cursor;

	item = cursor_stack;
	if (!item)
		return NULL;

	cursor_stack = item->next;
	cursor = item->cursor;
	free(item);
	return cursor;
}

void trace_set_cursor(GdkCursorType type)
{
	GdkWindow *window;
	GdkCursor *cursor;

	if (!parent_window)
		return;

	window = GTK_WIDGET(parent_window)->window;

	/* save the previous cursor */
	cursor = gdk_window_get_cursor(window);
	push_cursor(cursor);

	cursor = gdk_cursor_new(type);
	if (!cursor)
		die("Can't create cursor");
	gdk_window_set_cursor(window, cursor);
}

void trace_put_cursor(void)
{
	GdkWindow *window;
	GdkCursor *cursor;

	if (!parent_window)
		return;

	window = GTK_WIDGET(parent_window)->window;
	cursor = gdk_window_get_cursor(window);
	if (cursor)
		gdk_cursor_unref(cursor);

	cursor = pop_cursor();
	gdk_window_set_cursor(window, cursor);
}

void trace_freeze_all(void)
{
	if (parent_window)
		gtk_widget_set_sensitive(GTK_WIDGET(parent_window), FALSE);
}

void trace_unfreeze_all(void)
{
	if (parent_window)
		gtk_widget_set_sensitive(GTK_WIDGET(parent_window), TRUE);
}

/**
 * trace_dialog_register_alt_warning - register an alternate function for warning()
 * @alt: the function to be called instead of warning.
 *
 * Add an alternate warning function to be called instead of a popup.
 * To go back to the popup, simply call this again with NULL.
 */
void trace_dialog_register_alt_warning(void (*alt)(const char *fmt, va_list ap))
{
	alt_warning = alt;
}

void warning(const char *fmt, ...)
{
	GString *str;
	va_list ap;
	int err;

	if (alt_warning) {
		va_start(ap, fmt);
		alt_warning(fmt, ap);
		va_end(ap);
		return;
	}

	if (!parent_window) {
		va_start(ap, fmt);
		__vwarning(fmt, ap);
		va_end(ap);
		return;
	}

	err = errno;
	errno = 0;

	str = g_string_new("");

	va_start(ap, fmt);
	g_string_vprintf(str, fmt, ap);
	va_end(ap);

	g_string_append(str, "\n");

	if (errno) {
		g_string_prepend(str, "\n");
		g_string_prepend(str, strerror(errno));
	}

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

GtkResponseType trace_dialog(GtkWindow *parent, enum trace_dialog_type type,
			     gchar *message, ...)
{
	GtkWidget *dialog;
	GtkMessageType mtype;
	GtkButtonsType btype = GTK_BUTTONS_CLOSE;
	gchar *str;
	va_list ap;
	int result;

	if (!parent)
		parent = GTK_WINDOW(parent_window);

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
	case TRACE_GUI_ASK:
		mtype = GTK_MESSAGE_WARNING;
		btype = GTK_BUTTONS_YES_NO;
		break;
	}

	va_start(ap, message);
	str = g_strdup_vprintf(message, ap);
	va_end(ap);

	dialog = gtk_message_dialog_new(parent,
					GTK_DIALOG_DESTROY_WITH_PARENT,
					mtype,
					btype,
					"%s", str);
	g_free(str);

	result = gtk_dialog_run(GTK_DIALOG(dialog));

	gtk_widget_destroy(dialog);

	return result;
}

/**
 * trace_get_file_dialog - pop up a file dialog to get a file
 * @title: the title of the dialog
 * @open: the text for the "open" button (NULL for default)
 * @ftype: What extension the dialog should default filter on.
 * @warn: if the file exists, warn and let them choose again.
 *
 * Returns: the filename if it should be used. NULL otherwise.
 *  The filename needs to be freed with g_free().
 */
gchar *trace_get_file_dialog_filter(const gchar *title, const char *open,
			     enum trace_dialog_filter ftype, gboolean warn)
{
	struct stat st;
	GtkWidget *dialog;
	GtkResponseType ret;
	GtkFileFilter *filter;
	GtkFileFilter *setfilter;
	gchar *filename = NULL;
	gchar *ext = NULL;

	if (!open)
		open = GTK_STOCK_OPEN;

	dialog = gtk_file_chooser_dialog_new(title,
					     NULL,
					     GTK_FILE_CHOOSER_ACTION_OPEN,
					     GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					     open, GTK_RESPONSE_ACCEPT,
					     NULL);

	setfilter = filter = gtk_file_filter_new();
	gtk_file_filter_set_name(filter, "All Files");
	gtk_file_filter_add_pattern(filter, "*");
	gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), filter);

	filter = gtk_file_filter_new();
	gtk_file_filter_set_name(filter, "trace-cmd .dat files");
	gtk_file_filter_add_pattern(filter, "*.dat");
	gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), filter);

	if (ftype == TRACE_DIALOG_FILTER_DATA) {
		setfilter = filter;
		ext = ".dat";
	}

	filter = gtk_file_filter_new();
	gtk_file_filter_set_name(filter, "KernelShark filter files");
	gtk_file_filter_add_pattern(filter, "*.ksf");
	gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), filter);

	if (ftype == TRACE_DIALOG_FILTER_FILTER) {
		setfilter = filter;
		ext = ".ksf";
	}

	filter = gtk_file_filter_new();
	gtk_file_filter_set_name(filter, "KernelShark setting files");
	gtk_file_filter_add_pattern(filter, "*.kss");
	gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), filter);

	if (ftype == TRACE_DIALOG_FILTER_SETTING) {
		setfilter = filter;
		ext = ".kss";
	}

	gtk_file_chooser_set_filter(GTK_FILE_CHOOSER(dialog), setfilter);

 again:
	ret = gtk_dialog_run(GTK_DIALOG(dialog));

	if (ret == GTK_RESPONSE_ACCEPT) {
		filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
		if (filename && warn) {
			if (ext) {
				int len = strlen(filename);
				gchar *tmp;

				/* Add extension if not already there */
				if (strcmp(filename + (len - 4), ext) != 0) {
					tmp = filename;
					filename = g_strdup_printf("%s%s",
								   tmp, ext);
					g_free(tmp);
				}
			}
			if (stat(filename, &st) >= 0) {
				ret = trace_dialog(GTK_WINDOW(dialog), TRACE_GUI_ASK,
						   "The file '%s' already exists.\n"
						   "Are you sure you want to replace it",
						   filename);
				if (ret == GTK_RESPONSE_NO) {
					g_free(filename);
					filename = NULL;
					goto again;
				}
			}
		}
	}

	gtk_widget_destroy(dialog);

	return filename;
}

gchar *trace_get_file_dialog(const gchar *title, const char *open,
			     gboolean warn)
{
	return trace_get_file_dialog_filter(title, open, TRACE_DIALOG_FILTER_NONE, warn);
}

/**
 * trace_create_combo_box - helper function to create a label and combo box
 * @hbox: The hbox to add the label and combo box to
 * @text: The text of the label
 * @combo_model_create: The function used to create the combo model
 * @data: data to pass to the combo_model_create.
 *
 * If no @hbox is given, the @text is ignored, and only the combo box
 * is created.
 *
 * Returns the combo box in the hbox.
 */
GtkWidget *
trace_create_combo_box(GtkWidget *hbox, const gchar *text,
		       GtkTreeModel *(*combo_model_create)(gpointer data),
		       gpointer data)
{
	GtkCellRenderer *renderer;
	GtkTreeModel *model;
	GtkWidget *label;
	GtkWidget *combo;

	if (hbox) {
		label = gtk_label_new(text);
		gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
		gtk_widget_show(label);
	}

	/* --- Set up the selection combo box --- */

	model = combo_model_create(data);

	renderer = gtk_cell_renderer_text_new();

	combo = gtk_combo_box_new_with_model(model);
	if (hbox)
		gtk_box_pack_start(GTK_BOX(hbox), combo, FALSE, FALSE, 0);
	gtk_widget_show(combo);

	/* Free model with combobox */
	g_object_unref(model);

	gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(combo),
				   renderer,
				   TRUE);
	gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(combo),
				       renderer,
				       "text", 0,
				       NULL);

	gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);

	return combo;
}
