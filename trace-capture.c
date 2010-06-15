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
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <gtk/gtk.h>
#include <errno.h>
#include <getopt.h>

#include "trace-cmd.h"
#include "trace-gui.h"
#include "kernel-shark.h"

#define default_output_file "trace.dat"

struct trace_capture {
	struct pevent		*pevent;
	GtkWidget		*main_dialog;
	GtkWidget		*command_entry;
	GtkWidget		*file_entry;
	GtkWidget		*output_text;
	GtkTextBuffer		*output_buffer;
	GtkWidget		*output_dialog;
	GtkWidget		*plugin_combo;
	GtkWidget		*stop_dialog;
	pthread_t		thread;
	gboolean		all_events;
	gboolean		kill_thread;
	gboolean		capture_done;
	gchar			**systems;
	int			*events;
	gchar			*plugin;
	int			command_input_fd;
	int			command_output_fd;
	int			command_pid;
};

static int is_just_ws(const char *str)
{
	int i;

	for (i = 0; str[i]; i++)
		if (!isspace(str[i]))
			break;
	return !str[i];
}

static void clear_capture_events(struct trace_capture *cap)
{
	int i;

	cap->all_events = FALSE;

	if (cap->systems) {
		for (i = 0; cap->systems[i]; i++)
			free(cap->systems[i]);

		free(cap->systems);
		cap->systems = NULL;
	}

	free(cap->events);
	cap->events = NULL;
}

void end_capture(struct trace_capture *cap)
{
	int pid;

	cap->capture_done = TRUE;

	pid = cap->command_pid;
	cap->command_pid = 0;
	if (pid) {
		kill(pid, SIGINT);
		gdk_threads_leave();
		waitpid(pid, NULL, 0);
		gdk_threads_enter();
	}

	if (cap->kill_thread) {
		gdk_threads_leave();
		pthread_join(cap->thread, NULL);
		gdk_threads_enter();
	}

	if (cap->command_input_fd)
		close(cap->command_input_fd);

	if (cap->command_output_fd)
		close(cap->command_output_fd);
}

static char *get_tracing_dir(void)
{
	static char *tracing_dir;

	if (tracing_dir)
		return tracing_dir;

	tracing_dir = tracecmd_find_tracing_dir();
	return tracing_dir;
}

static void free_list(char **list)
{
	int i;

	for (i = 0; list[i]; i++)
		free(list[i]);

	free(list);
}

static int is_latency(char *plugin)
{
	return strcmp(plugin, "wakeup") == 0 ||
		strcmp(plugin, "wakeup_rt") == 0 ||
		strcmp(plugin, "irqsoff") == 0 ||
		strcmp(plugin, "preemptoff") == 0 ||
		strcmp(plugin, "preemptirqsoff") == 0;
}

static void close_command_display(struct trace_capture *cap)
{
	gtk_widget_destroy(cap->output_dialog);
	cap->output_dialog = NULL;
	cap->stop_dialog = NULL;
}

static void display_command_close(GtkWidget *widget, gint id, gpointer data)
{
	struct trace_capture *cap = data;

	close_command_display(cap);
}

static void display_command_destroy(GtkWidget *widget, gpointer data)
{
	struct trace_capture *cap = data;

	close_command_display(cap);
}

static void display_command(struct trace_capture *cap)
{
	GtkWidget *dialog;
	GtkWidget *scrollwin;
	GtkWidget *viewport;
	GtkWidget *textview;
	GtkTextBuffer *buffer;
	const gchar *command;
	GString *str;

	command = gtk_entry_get_text(GTK_ENTRY(cap->command_entry));

	if (!command || !strlen(command) || is_just_ws(command))
		command = "trace-cmd";

	str = g_string_new("");

	g_string_printf(str, "(%s)", command);

	dialog = gtk_dialog_new_with_buttons(str->str,
					     NULL,
					     GTK_DIALOG_MODAL,
					     "Close",
					     GTK_RESPONSE_ACCEPT,
					     NULL);

	g_string_free(str, TRUE);

	g_signal_connect(dialog, "response",
			 G_CALLBACK(display_command_close),
			 (gpointer)cap);

	gtk_signal_connect (GTK_OBJECT(dialog), "delete_event",
			    (GtkSignalFunc) display_command_destroy,
			    (gpointer)cap);

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

	gtk_container_add(GTK_CONTAINER(viewport), textview);
	gtk_widget_show(textview);

	cap->output_text = textview;
	cap->output_buffer = buffer;

	gtk_widget_set_size_request(GTK_WIDGET(dialog),
				    500, 600);

	gtk_widget_show(dialog);

	cap->output_dialog = dialog;

}

static int calculate_trace_cmd_words(struct trace_capture *cap)
{
	int words = 4;		/* trace-cmd record -o file */
	int i;

	if (cap->all_events)
		words += 2;
	else {
		if (cap->systems) {
			for (i = 0; cap->systems[i]; i++)
				words += 2;
		}

		if (cap->events)
			for (i = 0; cap->events[i] >= 0; i++)
				words += 2;
	}

	if (cap->plugin)
		words += 2;

	return words;
}

static int add_trace_cmd_words(struct trace_capture *cap, char **args)
{
	struct event_format *event;
	char **systems = cap->systems;
	const gchar *output;
	int *events = cap->events;
	int words = 0;
	int len;
	int i;

	output = gtk_entry_get_text(GTK_ENTRY(cap->file_entry));

	args[words++] = strdup("trace-cmd");
	args[words++] = strdup("record");
	args[words++] = strdup("-o");
	args[words++] = strdup(output);

	if (cap->plugin) {
		args[words++] = strdup("-p");
		args[words++] = strdup(cap->plugin);
	}

	if (cap->all_events) {
		args[words++] = strdup("-e");
		args[words++] = strdup("all");
	} else {
		if (systems) {
			for (i = 0; systems[i]; i++) {
				args[words++] = strdup("-e");
				args[words++] = strdup(systems[i]);
			}
		}

		if (events) {
			for (i = 0; events[i] >= 0; i++) {
				event = pevent_find_event(cap->pevent, events[i]);
				if (!event)
					continue;
				args[words++] = strdup("-e");
				len = strlen(event->name) + strlen(event->system) + 2;
				args[words] = malloc_or_die(len);
				snprintf(args[words++], len, "%s:%s",
					 event->system, event->name);
			}
		}
	}

	return words;
}

static gchar *get_combo_text(GtkComboBox *combo)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	gchar *text;

	model = gtk_combo_box_get_model(combo);
	if (!model)
		return NULL;

	if (!gtk_combo_box_get_active_iter(combo, &iter))
		return NULL;

	gtk_tree_model_get(model, &iter,
			   0, &text,
			   -1);

	return text;
}

static void execute_command(struct trace_capture *cap)
{
	const gchar *ccommand;
	gchar *command;
	gchar **args;
	gboolean space;
	int words;
	int tc_words;
	int i;

	cap->plugin = get_combo_text(GTK_COMBO_BOX(cap->plugin_combo));
	if (strcmp(cap->plugin, "NONE") == 0) {
		g_free(cap->plugin);
		cap->plugin = NULL;
	}

	ccommand = gtk_entry_get_text(GTK_ENTRY(cap->command_entry));
	if (!ccommand || !strlen(ccommand) || is_just_ws(ccommand)) {
		words = 0;
		command = NULL;
	} else {

		command = strdup(ccommand);

		space = TRUE;
		words = 0;
		for (i = 0; command[i]; i++) {
			if (isspace(command[i]))
				space = TRUE;
			else {
				if (space)
					words++;
				space = FALSE;
			}
		}
	}

	tc_words = calculate_trace_cmd_words(cap);

	args = malloc_or_die(sizeof(*args) * (tc_words + words + 1));

	add_trace_cmd_words(cap, args);

	words = tc_words;
	space = TRUE;
	for (i = 0; command && command[i]; i++) {
		if (isspace(command[i])) {
			space = TRUE;
			command[i] = 0;
		} else {
			if (space) {
				args[words] = &command[i];
				words++;
			}
			space = FALSE;
		}
	}
	args[words] = NULL;

	write(1, "# ", 2);
	for (i = 0; args[i]; i++) {
		write(1, args[i], strlen(args[i]));
		write(1, " ", 1);
	}
	write(1, "\n", 1);

	execvp(args[0], args);
	perror("execvp");

	for (i = 0; args[i]; i++)
		free(args[i]);
	free(args);
	g_free(cap->plugin);
}

static gint
delete_stop_dialog(GtkWidget *widget, GdkEvent *event, gpointer data)
{
	struct trace_capture *cap = data;
	GtkWidget *dialog = cap->stop_dialog;

	cap->stop_dialog = NULL;
	if (!dialog)
		return TRUE;

	end_capture(cap);
	gtk_widget_destroy(dialog);

	return TRUE;
}

void end_stop_dialog(struct trace_capture *cap)
{
	GdkEvent dummy_event;
	gboolean dummy_retval;
	guint sigid;

	if (!cap->stop_dialog)
		return;

	sigid = g_signal_lookup("delete-event", G_OBJECT_TYPE(cap->stop_dialog));
	g_signal_emit(cap->stop_dialog, sigid, 0,
		      cap->stop_dialog, &dummy_event , cap, &dummy_retval);
}

static void *monitor_pipes(void *data)
{
	struct trace_capture *cap = data;
	GtkTextIter iter;
	gchar buf[BUFSIZ+1];
	struct timeval tv;
	fd_set fds;
	gboolean eof;
	int ret;
	int r;

	do {
		FD_ZERO(&fds);
		FD_SET(cap->command_input_fd, &fds);
		tv.tv_sec = 6;
		tv.tv_usec = 0;
		ret = select(cap->command_input_fd+1, &fds, NULL, NULL, &tv);
		if (ret < 0)
			break;

		eof = TRUE;
		while ((r = read(cap->command_input_fd, buf, BUFSIZ)) > 0) {
			eof = FALSE;
			buf[r] = 0;
			gdk_threads_enter();
			gtk_text_buffer_get_end_iter(cap->output_buffer,
						     &iter);
			gtk_text_buffer_insert(cap->output_buffer, &iter, buf, -1);
			gdk_threads_leave();
		}
	} while (!cap->capture_done && !eof);

	if (eof) {
		gdk_threads_enter();
		end_stop_dialog(cap);
		gdk_threads_leave();
	}

	pthread_exit(NULL);
}

static void run_command(struct trace_capture *cap)
{
	int brass[2];
	int copper[2];
	int pid;

	if (pipe(brass) < 0) {
		warning("Could not create pipe");
		return;
	}

	if (pipe(copper) < 0) {
		warning("Could not create pipe");
		goto fail_pipe;
	}

	if ((pid = fork()) < 0) {
		warning("Could not fork process");
		goto fail_fork;
	}

	cap->command_pid = pid;

	if (!pid) {
		close(brass[0]);
		close(copper[1]);
		close(0);
		close(1);
		close(2);

		dup(copper[0]);
		dup(brass[1]);
		dup(brass[1]);

		execute_command(cap);

		close(1);
		exit(0);
	}
	close(brass[1]);
	close(copper[0]);

	/* these should never be 0 */
	if (!brass[1] || !copper[0])
		warning("Pipes have zero as file descriptor");

	cap->command_input_fd = brass[0];
	cap->command_output_fd = copper[1];

	/* Do not create a thread under the gdk lock */
	gdk_threads_leave();
	if (pthread_create(&cap->thread, NULL, monitor_pipes, cap) < 0)
		warning("Failed to create thread");
	else
		cap->kill_thread = 1;
	gdk_threads_enter();

	return;

 fail_fork:
	close(copper[0]);
	close(copper[1]);
 fail_pipe:
	close(brass[0]);
	close(brass[1]);
}

static int trim_plugins(char **plugins)
{
	int len = 0;
	int i;

	if (!plugins)
		return 0;

	for (i = 0; plugins[i]; i++) {
		if (is_latency(plugins[i]))
			continue;
		plugins[len++] = plugins[i];
	}
	plugins[len] = NULL;

	return len;
}

static void event_filter_callback(gboolean accept,
				  gboolean all_events,
				  gchar **systems,
				  gint *events,
				  gpointer data)
{
	struct trace_capture *cap = data;
	int nr_sys, nr_events;
	int i;

	if (!accept)
		return;

	clear_capture_events(cap);

	if (all_events) {
		cap->all_events = TRUE;
		return;
	}

	if (systems) {
		for (nr_sys = 0; systems[nr_sys]; nr_sys++)
			;
		cap->systems = malloc_or_die(sizeof(*cap->systems) * (nr_sys + 1));
		for (i = 0; i < nr_sys; i++)
			cap->systems[i] = strdup(systems[i]);
		cap->systems[i] = NULL;
	}

	if (events) {
		for (nr_events = 0; events[nr_events] >= 0; nr_events++)
			;
		cap->events = malloc_or_die(sizeof(*cap->events) * (nr_events + 1));
		for (i = 0; i < nr_events; i++)
			cap->events[i] = events[i];
		cap->events[i] = -1;
	}
}

static void event_button_clicked(GtkWidget *widget, gpointer data)
{
	struct trace_capture *cap = data;
	struct pevent *pevent = cap->pevent;

	trace_filter_pevent_dialog(pevent, cap->all_events,
				   cap->systems, cap->events,
				   event_filter_callback, cap);
}

static void
file_clicked (GtkWidget *widget, gpointer data)
{
	struct trace_capture *cap = data;
	gchar *filename;

	filename = trace_get_file_dialog("Trace File", "Save", FALSE);
	if (!filename)
		return;

	gtk_entry_set_text(GTK_ENTRY(cap->file_entry), filename);
}

static void execute_button_clicked(GtkWidget *widget, gpointer data)
{
	struct trace_capture *cap = data;
	struct stat st;
	GtkResponseType ret;
	GtkWidget *dialog;
	GtkWidget *label;
	const char *filename;

	filename = gtk_entry_get_text(GTK_ENTRY(cap->file_entry));

	if (stat(filename, &st) >= 0) {
		ret = trace_dialog(GTK_WINDOW(cap->main_dialog), TRACE_GUI_ASK,
				   "The file '%s' already exists.\n"
				   "Are you sure you want to replace it",
				   filename);
		if (ret == GTK_RESPONSE_NO)
			return;
	}

	display_command(cap);

	run_command(cap);

	dialog = gtk_dialog_new_with_buttons("Stop Execution",
					     NULL,
					     GTK_DIALOG_MODAL,
					     "Stop",
					     GTK_RESPONSE_ACCEPT,
					     NULL);

	cap->stop_dialog = dialog;

	label = gtk_label_new("Hit Stop to end execution");
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), label, TRUE, TRUE, 0);
	gtk_widget_show(label);

	gtk_signal_connect(GTK_OBJECT (dialog), "delete_event",
			   (GtkSignalFunc)delete_stop_dialog,
			   (gpointer)cap);

	gtk_dialog_run(GTK_DIALOG(dialog));

	end_stop_dialog(cap);
}

static GtkTreeModel *create_plugin_combo_model(gpointer data)
{
	char **plugins = data;
	GtkListStore *list;
	GtkTreeIter iter;
	int i;

	list = gtk_list_store_new(1, G_TYPE_STRING);

	gtk_list_store_append(list, &iter);
	gtk_list_store_set(list, &iter,
			   0, "NONE",
			   -1);

	for (i = 0; plugins && plugins[i]; i++) {
		gtk_list_store_append(list, &iter);
		gtk_list_store_set(list, &iter,
				   0, plugins[i],
				   -1);
	}

	return GTK_TREE_MODEL(list);
}

static void tracing_dialog(struct shark_info *info, const char *tracing)
{
	struct pevent *pevent;
	GtkWidget *dialog;
	GtkWidget *button;
	GtkWidget *hbox;
	GtkWidget *combo;
	GtkWidget *label;
	GtkWidget *entry;
	char **plugins;
	int nr_plugins;
	struct trace_capture cap;

	memset(&cap, 0, sizeof(cap));

	plugins = tracecmd_local_plugins(tracing);

	/* Skip latency plugins */
	nr_plugins = trim_plugins(plugins);
	if (!nr_plugins && plugins) {
		free_list(plugins);
		plugins = NULL;
	}

	/* Send parse warnings to status display */
	trace_dialog_register_alt_warning(vpr_stat);

	pevent = tracecmd_local_events(tracing);
	trace_dialog_register_alt_warning(NULL);

	cap.pevent = pevent;

	if (!pevent && !nr_plugins) {
		warning("No events or plugins found");
		return;
	}

	dialog = gtk_dialog_new_with_buttons("Capture",
					     NULL,
					     GTK_DIALOG_MODAL,
					     "Done",
					     GTK_RESPONSE_ACCEPT,
					     NULL);

	cap.main_dialog = dialog;

	if (pevent) {
		button = gtk_button_new_with_label("Select Events");
		gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox),
				   button, TRUE, TRUE, 0);
		gtk_widget_show(button);

		g_signal_connect (button, "clicked",
				  G_CALLBACK (event_button_clicked),
				  (gpointer)&cap);
	}

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), hbox, TRUE, TRUE, 0);
	gtk_widget_show(hbox);

	combo = trace_create_combo_box(hbox, "Plugin: ", create_plugin_combo_model, plugins);
	cap.plugin_combo = combo;

	label = gtk_label_new("Command:");
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), label, TRUE, TRUE, 0);
	gtk_widget_show(label);

	entry = gtk_entry_new();
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), entry, TRUE, TRUE, 0);
	gtk_widget_show(entry);

	cap.command_entry = entry;

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), hbox, TRUE, TRUE, 0);
	gtk_widget_show(hbox);

	button = gtk_button_new_with_label("Save file: ");
	gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
	gtk_widget_show(button);

	g_signal_connect (button, "clicked",
			  G_CALLBACK (file_clicked),
			  (gpointer)&cap);

	entry = gtk_entry_new();
	gtk_box_pack_start(GTK_BOX(hbox), entry, TRUE, TRUE, 0);
	gtk_widget_show(entry);

	gtk_entry_set_text(GTK_ENTRY(entry), default_output_file);
	cap.file_entry = entry;

	button = gtk_button_new_with_label("Execute");
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), button, TRUE, TRUE, 0);
	gtk_widget_show(button);

	g_signal_connect (button, "clicked",
			  G_CALLBACK (execute_button_clicked),
			  (gpointer)&cap);

	gtk_widget_show(dialog);
	gtk_dialog_run(GTK_DIALOG(dialog));

	gtk_widget_destroy(dialog);

	end_capture(&cap);

	if (cap.output_dialog)
		gtk_widget_destroy(cap.output_dialog);

	if (pevent)
		pevent_free(pevent);

	if (plugins)
		free_list(plugins);

	clear_capture_events(&cap);
}

void tracecmd_capture_clicked(gpointer data)
{
	struct shark_info *info = data;
	char *tracing;

	tracing = get_tracing_dir();

	if (!tracing) {
		warning("Can not find or mount tracing directory!\n"
			"Either tracing is not configured for this kernel\n"
			"or you do not have the proper permissions to mount the directory");
		return;
	}

	tracing_dialog(info, tracing);
}
