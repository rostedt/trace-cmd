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
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <dirent.h>
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
#include "version.h"

#define default_output_file "trace.dat"

#define PLUGIN_NONE "NONE"

#define DIALOG_WIDTH	820
#define DIALOG_HEIGHT	600

#define CAP_STOP	"Stop"

#define DEFAULT_MAX_BUF_SIZE 1000000

struct trace_capture {
	struct pevent		*pevent;
	struct shark_info	*info;
	GtkWidget		*main_dialog;
	GtkWidget		*command_entry;
	GtkWidget		*file_entry;
	GtkWidget		*output_text;
	GtkTextBuffer		*output_buffer;
	GtkWidget		*event_view;
	GtkWidget		*plugin_combo;
	GtkWidget		*settings_combo;
	GtkWidget		*run_button;
	GtkWidget		*max_num_entry;
	pthread_t		thread;
	gboolean		kill_thread;
	gboolean		capture_done;
	gboolean		load_file;
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

static gboolean settings_saved;

static GString *get_home_settings_new(void)
{
	char *path = getenv("HOME");
	GString *str;

	str = g_string_new(path);
	g_string_append(str, "/.trace-cmd/settings/");
	return str;
}

static int create_home_settings(void)
{
	char *path = getenv("HOME");
	GString *str;
	struct stat st;
	int ret;

	str = g_string_new(path);
	g_string_append(str, "/.trace-cmd");
	ret = stat(str->str, &st);
	if (ret < 0) {
		ret = mkdir(str->str, 0755);
		if (ret < 0) {
			warning("Can not create %s", str->str);
			goto out;
		}
	}

	g_string_append(str, "/settings");
	ret = stat(str->str, &st);
	if (ret < 0) {
		ret = mkdir(str->str, 0755);
		if (ret < 0) {
			warning("Can not create %s", str->str);
			goto out;
		}
	}

	ret = 0;
 out:
	g_string_free(str, TRUE);
	return ret;
}

static GtkTreeModel *create_settings_model(gpointer data)
{
	struct dirent *dent;
	GtkListStore *list;
	GtkTreeIter iter;
	struct stat st;
	GString *str;
	DIR *dir;
	int ret;

	list = gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_STRING);

	gtk_list_store_append(list, &iter);
	gtk_list_store_set(list, &iter,
			   0, "Current",
			   1, "",
			   -1);

	/* Search for user settings first */
	str = get_home_settings_new();
	ret = stat(str->str, &st);
	if (ret < 0 || !S_ISDIR(st.st_mode))
		goto read_system;

	dir = opendir(str->str);
	if (!dir)
		goto read_system;

	while ((dent = readdir(dir))) {
		const char *name = dent->d_name;
		GString *file;
		gchar *item;


		if (strcmp(name, ".") == 0 ||
		    strcmp(name, "..") == 0)
			continue;

		if (strcmp(name + strlen(name) - 4, ".kss") != 0)
			continue;

		file = g_string_new(str->str);
		g_string_append_printf(file, "/%s", name);

		/* Save the file name but remove the .kss extention */
		item = g_strdup(name);
		item[strlen(name) - 4] = 0;

		gtk_list_store_append(list, &iter);
		gtk_list_store_set(list, &iter,
				   0, item,
				   1, file->str,
				   -1);
		g_free(item);
		g_string_free(file, TRUE);
	}

read_system:
	g_string_free(str, TRUE);

	return GTK_TREE_MODEL(list);
}

static void refresh_settings(struct trace_capture *cap)
{
	GtkTreeModel *model;

	model = create_settings_model(NULL);
	gtk_combo_box_set_model(GTK_COMBO_BOX(cap->settings_combo), model);
	g_object_unref(model);
}

static void ks_clear_capture_events(struct shark_info *info)
{
	info->cap_all_events = FALSE;

	tracecmd_free_list(info->cap_systems);
	info->cap_systems = NULL;

	free(info->cap_events);
	info->cap_events = NULL;
}

static void clear_capture_events(struct trace_capture *cap)
{
	ks_clear_capture_events(cap->info);
}

void kernel_shark_clear_capture(struct shark_info *info)
{
	ks_clear_capture_events(info);

	g_free(info->cap_plugin);
	info->cap_plugin = NULL;

	g_free(info->cap_settings_name);
	info->cap_settings_name = NULL;

	free(info->cap_file);
	info->cap_file = NULL;

	g_free(info->cap_buffer_output);
	info->cap_buffer_output = NULL;
}

static gboolean end_capture(struct trace_capture *cap)
{
	const char *filename;
	const char *val;
	int pid;

	val = gtk_button_get_label(GTK_BUTTON(cap->run_button));
	if (strcmp(val, CAP_STOP) != 0)
		return FALSE;

	gtk_button_set_label(GTK_BUTTON(cap->run_button), "Run");

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
		cap->kill_thread = FALSE;
	}

	if (cap->command_input_fd) {
		close(cap->command_input_fd);
		cap->command_input_fd = 0;
	}

	if (cap->command_output_fd) {
		close(cap->command_output_fd);
		cap->command_output_fd = 0;
	}

	if (cap->load_file) {
		filename = gtk_entry_get_text(GTK_ENTRY(cap->file_entry));
		kernelshark_load_file(cap->info, filename);
		cap->load_file = FALSE;
	}

	return TRUE;
}

static char *get_tracing_dir(void)
{
	static char *tracing_dir;

	if (tracing_dir)
		return tracing_dir;

	tracing_dir = tracecmd_find_tracing_dir();
	return tracing_dir;
}

static int is_latency(char *plugin)
{
	return strcmp(plugin, "wakeup") == 0 ||
		strcmp(plugin, "wakeup_rt") == 0 ||
		strcmp(plugin, "irqsoff") == 0 ||
		strcmp(plugin, "preemptoff") == 0 ||
		strcmp(plugin, "preemptirqsoff") == 0;
}

static int calculate_trace_cmd_words(struct trace_capture *cap)
{
	int words = 4;		/* trace-cmd record -o file */
	int i;

	if (cap->info->cap_all_events)
		words += 2;
	else {
		if (cap->info->cap_systems) {
			for (i = 0; cap->info->cap_systems[i]; i++)
				words += 2;
		}

		if (cap->info->cap_events)
			for (i = 0; cap->info->cap_events[i] >= 0; i++)
				words += 2;
	}

	if (cap->info->cap_plugin)
		words += 2;

	return words;
}

static char *find_tracecmd(void)
{
	struct stat st;
	char *path = getenv("PATH");
	char *saveptr;
	char *str;
	char *loc;
	char *tracecmd = NULL;
	int len;
	int ret;

	if (!path)
		return NULL;

	path = strdup(path);

	for (str = path; ; str = NULL) {
		loc = strtok_r(str, ":", &saveptr);
		if (!loc)
			break;
		len = strlen(loc) + 11;
		tracecmd = malloc_or_die(len);
		snprintf(tracecmd, len, "%s/trace-cmd", loc);
		ret = stat(tracecmd, &st);

		if (ret >= 0 && S_ISREG(st.st_mode)) {
			/* Do we have execute permissions */
			if (st.st_uid == geteuid() &&
			    st.st_mode & S_IXUSR)
				break;
			if (st.st_gid == getegid() &&
			    st.st_mode & S_IXGRP)
				break;
			if (st.st_mode & S_IXOTH)
				break;
		}

		free(tracecmd);
		tracecmd = NULL;
	}
	free(path);

	return tracecmd;
}

static int add_trace_cmd_words(struct trace_capture *cap, char **args)
{
	struct event_format *event;
	char **systems = cap->info->cap_systems;
	const gchar *output;
	int *events = cap->info->cap_events;
	int words = 0;
	int len;
	int i;

	output = gtk_entry_get_text(GTK_ENTRY(cap->file_entry));

	args[words++] = find_tracecmd();
	if (!args[0])
		return -1;

	args[words++] = strdup("record");
	args[words++] = strdup("-o");
	args[words++] = strdup(output);

	if (cap->info->cap_plugin) {
		args[words++] = strdup("-p");
		args[words++] = strdup(cap->info->cap_plugin);
	}

	if (cap->info->cap_all_events) {
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

static void update_plugin(struct trace_capture *cap)
{
	cap->info->cap_plugin = get_combo_text(GTK_COMBO_BOX(cap->plugin_combo));
	if (strcmp(cap->info->cap_plugin, PLUGIN_NONE) == 0) {
		g_free(cap->info->cap_plugin);
		cap->info->cap_plugin = NULL;
	}

}

/*
 * The plugin and settings combo's are set by the first item
 * in the model. The can share the same code to set the model.
 *
 * Return TRUE if set, FALSE if name was not found.
 */
static int set_combo(GtkComboBox *combo, const char *name)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	gchar *text;
	gboolean ret;

	model = gtk_combo_box_get_model(combo);
	if (!model)
		return FALSE;

	if (!gtk_tree_model_get_iter_first(model, &iter))
		return FALSE;

	do {
		gtk_tree_model_get(model, &iter,
				   0, &text,
				   -1);
		if (strcmp(text, name) == 0) {
			g_free(text);
			break;
		}

		g_free(text);

		ret = gtk_tree_model_iter_next(model, &iter);
	} while (ret);

	if (ret) {
		/* Found */
		gtk_combo_box_set_active_iter(GTK_COMBO_BOX(combo),
					      &iter);
		return TRUE;
	}

	/* set to first item (default) */
	gtk_tree_model_get_iter_first(model, &iter);
	gtk_combo_box_set_active_iter(GTK_COMBO_BOX(combo),
				      &iter);

	return FALSE;
}

static void set_plugin(struct trace_capture *cap)
{
	GtkComboBox *combo = GTK_COMBO_BOX(cap->plugin_combo);
	const gchar *plugin = cap->info->cap_plugin;

	if (!plugin)
		plugin = PLUGIN_NONE;

	if (set_combo(combo, plugin))
		return;

	/* Not found? */
	g_free(cap->info->cap_plugin);
	cap->info->cap_plugin = NULL;
}

static void set_settings(struct trace_capture *cap)
{
	GtkComboBox *combo = GTK_COMBO_BOX(cap->settings_combo);
	const gchar *name = cap->info->cap_settings_name;

	if (!name)
		name = "";

	if (set_combo(combo, name))
		return;

	/* Not found? */
	g_free(cap->info->cap_settings_name);
	cap->info->cap_settings_name = NULL;
}

static void update_events(struct trace_capture *cap)
{
	struct shark_info *info = cap->info;

	if (!cap->event_view)
		return;

	clear_capture_events(cap);

	trace_extract_event_list_view(cap->event_view,
				      &info->cap_all_events,
				      &info->cap_systems,
				      &info->cap_events);
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

	update_plugin(cap);
	update_events(cap);

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
	g_free(cap->info->cap_plugin);
}

static void *monitor_pipes(void *data)
{
	struct trace_capture *cap = data;
	GtkTextIter start_iter;
	GtkTextIter cut_iter;
	GtkTextIter iter;
	gchar buf[BUFSIZ+1];
	struct timeval tv;
	const char *val;
	fd_set fds;
	gboolean eof;
	int max_size;
	int total;
	int del;
	int ret;
	int r;

	gdk_threads_enter();
	/* get the max size */
	val = gtk_entry_get_text(GTK_ENTRY(cap->max_num_entry));
	max_size = atoi(val);

	/* Clear the buffer */
	gtk_text_buffer_get_start_iter(cap->output_buffer, &start_iter);
	gtk_text_buffer_get_end_iter(cap->output_buffer, &cut_iter);
	gtk_text_buffer_delete(cap->output_buffer, &start_iter, &cut_iter);
	total = 0;
	gdk_threads_leave();

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
			total += r;
			if (total > max_size)
				del = total - max_size;
			else
				del = 0;
			gdk_threads_enter();
			if (del) {
				gtk_text_buffer_get_start_iter(cap->output_buffer, &start_iter);
				gtk_text_buffer_get_start_iter(cap->output_buffer, &cut_iter);
				gtk_text_iter_forward_chars(&cut_iter, del);
				gtk_text_buffer_delete(cap->output_buffer, &start_iter, &cut_iter);
				total -= del;
			}
			gtk_text_buffer_get_end_iter(cap->output_buffer,
						     &iter);
			gtk_text_buffer_insert(cap->output_buffer, &iter, buf, -1);
			gdk_threads_leave();
		}
	} while (!cap->capture_done && !eof);

	if (eof) {
		gdk_threads_enter();
		end_capture(cap);
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
	else {
		cap->kill_thread = TRUE;
		cap->load_file = TRUE;
	}
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

static void
file_clicked (GtkWidget *widget, gpointer data)
{
	struct trace_capture *cap = data;
	gchar *filename;

	filename = trace_get_file_dialog_filter("Trace File", "Save",
					 TRACE_DIALOG_FILTER_DATA, FALSE);
	if (!filename)
		return;

	gtk_entry_set_text(GTK_ENTRY(cap->file_entry), filename);
}

static void execute_button_clicked(struct trace_capture *cap)
{
	struct stat st;
	GtkResponseType ret;
	const char *filename;
	char *tracecmd;

	if (end_capture(cap))
		return;

	tracecmd = find_tracecmd();
	if (!tracecmd) {
		warning("trace-cmd not found in path");
		return;
	}
	free(tracecmd);

	filename = gtk_entry_get_text(GTK_ENTRY(cap->file_entry));

	if (stat(filename, &st) >= 0) {
		ret = trace_dialog(GTK_WINDOW(cap->main_dialog), TRACE_GUI_ASK,
				   "The file '%s' already exists.\n"
				   "Are you sure you want to replace it",
				   filename);
		if (ret == GTK_RESPONSE_NO)
			return;
	}

	gtk_button_set_label(GTK_BUTTON(cap->run_button), CAP_STOP);
	run_command(cap);
}

static int load_events(struct trace_capture *cap,
			   struct tracecmd_xml_handle *handle,
			   struct tracecmd_xml_system_node *node)
{
	struct shark_info *info = cap->info;
	struct tracecmd_xml_system_node *event_node;
	struct event_format *event;
	struct pevent *pevent = cap->pevent;
	const char *name;
	int *events = NULL;
	int event_len = 0;
	const char *system;
	const char *event_name;

	for (node = tracecmd_xml_node_child(node); node;
	     node = tracecmd_xml_node_next(node)) {
		name = tracecmd_xml_node_type(node);

		if (strcmp(name, "Event") != 0)
			continue;

		event_node = tracecmd_xml_node_child(node);
		if (!event_node)
			continue;

		name = tracecmd_xml_node_type(event_node);
		if (strcmp(name, "System") != 0)
			continue;
		system = tracecmd_xml_node_value(handle, event_node);

		event_node = tracecmd_xml_node_next(event_node);
		if (!event_node)
			continue;

		name = tracecmd_xml_node_type(event_node);
		if (strcmp(name, "Name") != 0)
			continue;
		event_name = tracecmd_xml_node_value(handle, event_node);

		event = pevent_find_event_by_name(pevent, system, event_name);

		if (!event)
			continue;

		events = tracecmd_add_id(events, event->id, event_len++);
	}

	info->cap_events = events;
	return 0;
}

static int load_cap_events(struct trace_capture *cap,
			   struct tracecmd_xml_handle *handle,
			   struct tracecmd_xml_system_node *node)
{
	struct shark_info *info = cap->info;
	const char *name;
	char **systems = NULL;
	int sys_len = 0;

	ks_clear_capture_events(info);

	for (node = tracecmd_xml_node_child(node); node;
	     node = tracecmd_xml_node_next(node)) {

		name = tracecmd_xml_node_type(node);

		if (strcmp(name, "CaptureType") == 0) {
			name = tracecmd_xml_node_value(handle, node);
			if (strcmp(name, "all events") == 0) {
				info->cap_all_events = TRUE;
				break;
			}
			continue;

		} else if (strcmp(name, "System") == 0) {
			name = tracecmd_xml_node_value(handle, node);
			systems = tracecmd_add_list(systems, name, sys_len++);

		} else if (strcmp(name, "Events") == 0)
			load_events(cap, handle, node);
	}

	info->cap_systems = systems;

	return 0;
}

static void load_settings(struct trace_capture *cap, gchar *filename)
{
	struct shark_info *info = cap->info;
	struct tracecmd_xml_system_node *syschild;
	struct tracecmd_xml_handle *handle;
	struct tracecmd_xml_system *system;
	const char *plugin;
	const char *name;

	handle = tracecmd_xml_open(filename);
	if (!handle) {
		warning("Could not open %s", filename);
		return;
	}

	system = tracecmd_xml_find_system(handle, "CaptureSettings");
	if (!system)
		goto out;

	syschild = tracecmd_xml_system_node(system);
	if (!syschild)
		goto out_free_sys;

	g_free(info->cap_plugin);
	info->cap_plugin = NULL;

	do {
		name = tracecmd_xml_node_type(syschild);
		if (strcmp(name, "Events") == 0) {
			load_cap_events(cap, handle, syschild);
			trace_update_event_view(cap->event_view,
						cap->pevent,
						NULL,
						info->cap_all_events,
						info->cap_systems,
						info->cap_events);
		}

		else if (strcmp(name, "Plugin") == 0) {
			plugin = tracecmd_xml_node_value(handle, syschild);
			info->cap_plugin = g_strdup(plugin);

		} else if (strcmp(name, "Command") == 0) {
			name = tracecmd_xml_node_value(handle, syschild);
			gtk_entry_set_text(GTK_ENTRY(cap->command_entry), name);

		} else if (strcmp(name, "File") == 0) {
			name = tracecmd_xml_node_value(handle, syschild);
			gtk_entry_set_text(GTK_ENTRY(cap->file_entry), name);
		}

		syschild = tracecmd_xml_node_next(syschild);
	} while (syschild);

	set_plugin(cap);

 out_free_sys:
	tracecmd_xml_free_system(system);

 out:
	tracecmd_xml_close(handle);
}

static void settings_changed(GtkComboBox *combo,
			     gpointer data)
{
	struct trace_capture *cap = data;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gchar *text;

	model = gtk_combo_box_get_model(combo);
	if (!model)
		return;

	if (!gtk_combo_box_get_active_iter(combo, &iter))
		return;

	gtk_tree_model_get(model, &iter,
			   1, &text,
			   -1);

	if (text && strlen(text))
		load_settings(cap, text);

	g_free(text);
}

static void import_settings_clicked(GtkWidget *widget, gpointer data)
{
	struct trace_capture *cap = data;
	gchar *filename;

	filename = trace_get_file_dialog_filter("Import Settings", NULL,
					 TRACE_DIALOG_FILTER_SETTING, FALSE);
	if (!filename)
		return;

	load_settings(cap, filename);

	g_free(filename);
}

static void save_events(struct trace_capture *cap,
			struct tracecmd_xml_handle *handle)
{
	struct pevent *pevent = cap->pevent;
	struct event_format *event;
	char **systems = cap->info->cap_systems;
	int *events = cap->info->cap_events;
	int i;

	tracecmd_xml_write_element(handle, "CaptureType", "Events");

	for (i = 0; systems && systems[i]; i++)
		tracecmd_xml_write_element(handle, "System", systems[i]);

	if (!events || events[0] < 0)
		return;

	tracecmd_xml_start_sub_system(handle, "Events");
	for (i = 0; events[i] > 0; i++) {
		event = pevent_find_event(pevent, events[i]);
		if (event) {
			tracecmd_xml_start_sub_system(handle, "Event");
			tracecmd_xml_write_element(handle, "System", event->system);
			tracecmd_xml_write_element(handle, "Name", event->name);
			tracecmd_xml_end_sub_system(handle);
		}
	}

	tracecmd_xml_end_sub_system(handle);
}

static void save_settings(struct trace_capture *cap, const char *filename)
{
	struct shark_info *info = cap->info;
	struct tracecmd_xml_handle *handle;
	const char *file;
	const char *command;

	handle = tracecmd_xml_create(filename, VERSION_STRING);
	if (!handle) {
		warning("Could not create %s", filename);
		return;
	}

	update_events(cap);

	tracecmd_xml_start_system(handle, "CaptureSettings");

	tracecmd_xml_start_sub_system(handle, "Events");

	if (info->cap_all_events)
		tracecmd_xml_write_element(handle, "CaptureType", "all events");
	else if ((info->cap_systems && info->cap_systems[0]) ||
		 (info->cap_events && info->cap_events[0] >= 0)) {
		save_events(cap, handle);
	}

	tracecmd_xml_end_sub_system(handle);

	update_plugin(cap);
	if (info->cap_plugin)
		tracecmd_xml_write_element(handle, "Plugin", info->cap_plugin);

	command = gtk_entry_get_text(GTK_ENTRY(cap->command_entry));
	if (command && strlen(command) && !is_just_ws(command))
		tracecmd_xml_write_element(handle, "Command", command);

	file = gtk_entry_get_text(GTK_ENTRY(cap->file_entry));
	if (file && strlen(file) && !is_just_ws(file))
		tracecmd_xml_write_element(handle, "File", file);

	tracecmd_xml_end_system(handle);

	tracecmd_xml_close(handle);
}

static void save_settings_clicked(GtkWidget *widget, gpointer data)
{
	struct trace_capture *cap = data;
	struct stat st;
	GtkWidget *dialog;
	GtkWidget *hbox;
	GtkWidget *label;
	GtkWidget *entry;
	GString *file;
	const char *name;
	gint result;
	int ret;

	dialog = gtk_dialog_new_with_buttons("Save Settings",
					     NULL,
					     GTK_DIALOG_MODAL,
					     GTK_STOCK_OK,
					     GTK_RESPONSE_ACCEPT,
					     GTK_STOCK_CANCEL,
					     GTK_RESPONSE_REJECT,
					     NULL);

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), hbox, FALSE, FALSE, 0);
	gtk_widget_show(hbox);

	label = gtk_label_new("Settings Name: ");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	entry = gtk_entry_new();
	gtk_box_pack_start(GTK_BOX(hbox), entry, FALSE, FALSE, 0);
	gtk_widget_show(entry);

 again:
	result = gtk_dialog_run(GTK_DIALOG(dialog));
	switch (result) {
	case GTK_RESPONSE_ACCEPT:
		name = gtk_entry_get_text(GTK_ENTRY(entry));
		if (!name || is_just_ws(name)) {
			warning("Must enter a name");
			goto again;
		}
		/* Make sure home settings exists */
		if (create_home_settings() < 0)
			break;
		file = get_home_settings_new();
		g_string_append_printf(file, "/%s.kss", name);
		ret = stat(file->str, &st);
		if (ret >= 0) {
			ret = trace_dialog(GTK_WINDOW(dialog), TRACE_GUI_ASK,
					   "The setting '%s' already exists.\n"
					   "Are you sure you want to replace it",
					   name);
			if (ret == GTK_RESPONSE_NO) {
				g_string_free(file, TRUE);
				goto again;
			}
		}
		save_settings(cap, file->str);

		refresh_settings(cap);
		g_free(cap->info->cap_settings_name);
		cap->info->cap_settings_name = g_strdup(name);
		set_settings(cap);

		g_string_free(file, TRUE);
		break;

	case GTK_RESPONSE_REJECT:
		break;
	default:
		break;
	};

	gtk_widget_destroy(dialog);
}

static void export_settings_clicked(GtkWidget *widget, gpointer data)
{
	struct trace_capture *cap = data;
	gchar *filename;

	filename = trace_get_file_dialog_filter("Save Settings", "Save",
					 TRACE_DIALOG_FILTER_SETTING, TRUE);
	if (!filename)
		return;

	save_settings(cap, filename);

	g_free(filename);
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
			   0, PLUGIN_NONE,
			   -1);

	for (i = 0; plugins && plugins[i]; i++) {
		gtk_list_store_append(list, &iter);
		gtk_list_store_set(list, &iter,
				   0, plugins[i],
				   -1);
	}

	return GTK_TREE_MODEL(list);
}

static void insert_text(GtkEditable *buffer,
			gchar *new_text,
			gint new_text_length,
			gint *position,
			gpointer data)
{
	int i;
	guint sigid;

	/* Only allow 0-9 to be written to the entry */
	for (i = 0; i < new_text_length; i++) {
		if (new_text[i] < '0' || new_text[i] > '9') {
			sigid = g_signal_lookup("insert-text",
						G_OBJECT_TYPE(buffer));
			g_signal_stop_emission(buffer, sigid, 0);
			return;
		}
	}
}

/*
 * Trace Capture Dialog Window
 *
 *    +--------------------------------------------------------------------+
 *    |  Dialog Window                                                     |
 *    |  +-------------------------------+-------------------------------+ |
 *    |  | Paned Window                  | +---------------------------+ | |
 *    |  | +---------------------------+ | | Scroll window             | | |
 *    |  | | Hbox                      | | | +-----------------------+ | | |
 *    |  | |  Label   Plugin Combo     | | | | Event Tree            | | | |
 *    |  | +---------------------------+ | | |                       | | | |
 *    |  |                               | | |                       | | | |
 *    |  |                               | | +-----------------------+ | | |
 *    |  |                               | +---------------------------+ | |
 *    |  +-------------------------------+-------------------------------+ |
 *    +--------------------------------------------------------------------+
 */
static void tracing_dialog(struct shark_info *info, const char *tracing)
{
	struct pevent *pevent;
	GtkWidget *dialog;
	GtkWidget *button;
	GtkWidget *combo;
	GtkWidget *label;
	GtkWidget *entry;
	GtkWidget *frame;
	GtkWidget *vbox;
	GtkWidget *scrollwin;
	GtkWidget *table;
	GtkWidget *table2;
	GtkWidget *event_tree;
	GtkWidget *viewport;
	GtkWidget *textview;
	GtkWidget *hbox;
	GtkTextBuffer *buffer;
	GtkTextIter start_iter;
	GtkTextIter end_iter;
	char **plugins;
	int nr_plugins;
	struct trace_capture cap;
	const gchar *file;
	const char *command;
	const char *val;
	GString *str;
	gint result;

	memset(&cap, 0, sizeof(cap));

	cap.info = info;
	plugins = tracecmd_local_plugins(tracing);

	/* Skip latency plugins */
	nr_plugins = trim_plugins(plugins);
	if (!nr_plugins && plugins) {
		tracecmd_free_list(plugins);
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

	dialog = gtk_dialog_new();
	gtk_window_set_title(GTK_WINDOW(dialog), "Capture");

	button = gtk_button_new_with_label("Run");
	gtk_dialog_add_action_widget(GTK_DIALOG(dialog), button,
				       GTK_RESPONSE_ACCEPT);
	gtk_widget_show(button);

	cap.run_button = button;

	gtk_dialog_add_button(GTK_DIALOG(dialog), GTK_STOCK_CLOSE,
			      GTK_RESPONSE_REJECT);

	cap.main_dialog = dialog;

	/* --- Top Level Hpaned --- */
	table = gtk_table_new(4, 2, FALSE);

	/* It is possible that no pevents exist. */
	if (pevent) {

		scrollwin = gtk_scrolled_window_new(NULL, NULL);
		gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrollwin),
					       GTK_POLICY_AUTOMATIC,
					       GTK_POLICY_AUTOMATIC);

		gtk_table_attach(GTK_TABLE(table), scrollwin, 0, 1, 1, 2,
				 GTK_FILL, GTK_FILL|GTK_EXPAND, 0, 0);
		gtk_widget_show(scrollwin);

		event_tree = trace_create_event_list_view(pevent, NULL,
							  cap.info->cap_all_events,
							  cap.info->cap_systems,
							  cap.info->cap_events);

		gtk_container_add(GTK_CONTAINER(scrollwin), event_tree);
		gtk_widget_show(event_tree);

		cap.event_view = event_tree;

	} else {
		/* No events */
		label = gtk_label_new("No events enabled on system");
		gtk_table_attach(GTK_TABLE(table), label, 0, 1, 1, 2,
				 GTK_FILL, GTK_EXPAND|GTK_FILL,
				 0, 10);
		gtk_widget_show(label);
		cap.event_view = NULL;
	}

	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), table, TRUE, TRUE, 0);
	gtk_widget_show(table);

	/*------------------ Frame Settings --------------------------- */

	frame = gtk_frame_new("Settings");
	gtk_table_attach(GTK_TABLE(table), frame, 0, 1, 0, 1,
			 GTK_FILL, 0, 0, 10);
	gtk_widget_show(frame);

	table2 = gtk_table_new(2, 3, FALSE);
	gtk_container_add(GTK_CONTAINER(frame), table2);
	gtk_widget_show(table2);

	gtk_table_set_col_spacings(GTK_TABLE(table2), 5);

	button = gtk_button_new_with_label("Save Settings");
	gtk_table_attach_defaults(GTK_TABLE(table2), button, 0, 1, 0, 1);
	gtk_widget_show(button);

	g_signal_connect (button, "clicked",
			  G_CALLBACK (save_settings_clicked),
			  (gpointer)&cap);

	button = gtk_button_new_with_label("Import Settings");
	gtk_table_attach_defaults(GTK_TABLE(table2), button, 1, 2, 0, 1);
	gtk_widget_show(button);

	g_signal_connect (button, "clicked",
			  G_CALLBACK (import_settings_clicked),
			  (gpointer)&cap);


	button = gtk_button_new_with_label("Export Settings");
	gtk_table_attach_defaults(GTK_TABLE(table2), button, 2, 3, 0, 1);
	gtk_widget_show(button);

	g_signal_connect (button, "clicked",
			  G_CALLBACK (export_settings_clicked),
			  (gpointer)&cap);

	if (cap.info->cap_settings_name)
		set_settings(&cap);

	label = gtk_label_new("Available Settings: ");
	gtk_table_attach_defaults(GTK_TABLE(table2), label, 0, 1, 1, 2);
	gtk_widget_show(label);

	combo = trace_create_combo_box(NULL, NULL,
				       create_settings_model, NULL);
	gtk_table_attach_defaults(GTK_TABLE(table2), combo, 1, 3, 1, 2);

	cap.settings_combo = combo;

	g_signal_connect (combo, "changed",
			  G_CALLBACK (settings_changed),
			  (gpointer)&cap);



	/*------------------ Frame Settings --------------------------- */

	frame = gtk_frame_new("Execute");
	gtk_table_attach(GTK_TABLE(table), frame, 0, 1, 3, 4,
			 GTK_FILL, 0, 0, 10);
	gtk_widget_show(frame);

	table2 = gtk_table_new(3, 3, FALSE);
	gtk_container_add(GTK_CONTAINER(frame), table2);
	gtk_widget_show(table2);

	label = gtk_label_new("Plugin: ");
	gtk_table_attach_defaults(GTK_TABLE(table2), label, 0, 1, 0, 1);
	gtk_widget_show(label);

	combo = trace_create_combo_box(NULL, NULL, create_plugin_combo_model, plugins);
	cap.plugin_combo = combo;

	gtk_table_attach_defaults(GTK_TABLE(table2), combo, 1, 3, 0, 1);

	if (cap.info->cap_plugin)
		set_plugin(&cap);


	label = gtk_label_new("Command:");
	gtk_table_attach_defaults(GTK_TABLE(table2), label, 0, 1, 1, 2);
	gtk_widget_show(label);

	entry = gtk_entry_new();
	gtk_table_attach_defaults(GTK_TABLE(table2), entry, 1, 3, 1, 2);
	gtk_widget_show(entry);

	cap.command_entry = entry;

	if (cap.info->cap_command)
		gtk_entry_set_text(GTK_ENTRY(entry), cap.info->cap_command);

	label = gtk_label_new("Output file: ");
	gtk_table_attach_defaults(GTK_TABLE(table2), label, 0, 1, 2, 3);
	gtk_widget_show(label);

	entry = gtk_entry_new();
	gtk_table_attach_defaults(GTK_TABLE(table2), entry, 1, 2, 2, 3);
	gtk_widget_show(entry);

	if (cap.info->cap_file)
		file = cap.info->cap_file;
	else
		file = default_output_file;

	gtk_entry_set_text(GTK_ENTRY(entry), file);
	cap.file_entry = entry;

	button = gtk_button_new_with_label("Browse");
	gtk_table_attach_defaults(GTK_TABLE(table2), button, 2, 3, 2, 3);
	gtk_widget_show(button);

	g_signal_connect (button, "clicked",
			  G_CALLBACK (file_clicked),
			  (gpointer)&cap);


	/*------------------ Command Output ------------------ */

	vbox = gtk_vbox_new(FALSE, 0);
	gtk_table_attach_defaults(GTK_TABLE(table), vbox, 1, 2, 0, 4);
	gtk_widget_show(vbox);
	gtk_widget_set_size_request(GTK_WIDGET(vbox), 500, 0);


	label = gtk_label_new("Output Display:");
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	scrollwin = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrollwin),
				       GTK_POLICY_AUTOMATIC,
				       GTK_POLICY_AUTOMATIC);
	gtk_box_pack_start(GTK_BOX(vbox), scrollwin, TRUE, TRUE, 0);
	gtk_widget_show(scrollwin);

	viewport = gtk_viewport_new(NULL, NULL);
	gtk_widget_show(viewport);

	gtk_container_add(GTK_CONTAINER(scrollwin), viewport);

	textview = gtk_text_view_new();
	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));

	gtk_container_add(GTK_CONTAINER(viewport), textview);
	gtk_widget_show(textview);

	cap.output_text = textview;
	cap.output_buffer = buffer;

	/* set the buffer from its previous setting */
	if (info->cap_buffer_output)
		gtk_text_buffer_set_text(buffer, info->cap_buffer_output,
					 strlen(info->cap_buffer_output));

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
	gtk_widget_show(hbox);

	label = gtk_label_new("Max # of characters in output display: ");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
	gtk_widget_show(label);

	entry = gtk_entry_new();
	gtk_box_pack_start(GTK_BOX(hbox), entry, FALSE, FALSE, 0);
	gtk_widget_show(entry);

	cap.max_num_entry = entry;

	if (!info->cap_max_buf_size)
		info->cap_max_buf_size = DEFAULT_MAX_BUF_SIZE;

	str = g_string_new("");
	g_string_append_printf(str, "%d", info->cap_max_buf_size);
	gtk_entry_set_text(GTK_ENTRY(entry), str->str);
	g_string_free(str, TRUE);

	g_signal_connect (entry, "insert-text",
			  G_CALLBACK (insert_text),
			  (gpointer)&cap);


	gtk_widget_set_size_request(GTK_WIDGET(dialog),
				    DIALOG_WIDTH, DIALOG_HEIGHT);

	gtk_widget_show(dialog);

 cont:
	result = gtk_dialog_run(GTK_DIALOG(dialog));

	if (result == GTK_RESPONSE_ACCEPT) {
		execute_button_clicked(&cap);
		goto cont;
	}

	/* Make sure no capture is running */
	end_capture(&cap);

	/* Get the max buffer size */
	val = gtk_entry_get_text(GTK_ENTRY(entry));
	info->cap_max_buf_size = atoi(val);

	gtk_text_buffer_get_start_iter(cap.output_buffer, &start_iter);
	gtk_text_buffer_get_end_iter(cap.output_buffer, &end_iter);

	g_free(info->cap_buffer_output);
	info->cap_buffer_output = gtk_text_buffer_get_text(cap.output_buffer,
							   &start_iter,
							   &end_iter,
							   FALSE);

	/* save the plugin and file to reuse if we come back */
	update_plugin(&cap);

	free(info->cap_file);
	cap.info->cap_file = strdup(gtk_entry_get_text(GTK_ENTRY(cap.file_entry)));

	free(info->cap_command);
	command = gtk_entry_get_text(GTK_ENTRY(cap.command_entry));
	if (command && strlen(command) && !is_just_ws(command))
		cap.info->cap_command = strdup(command);
	else
		cap.info->cap_command = NULL;

	update_events(&cap);

	gtk_widget_destroy(dialog);

	if (pevent)
		pevent_free(pevent);

	if (plugins)
		tracecmd_free_list(plugins);
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
