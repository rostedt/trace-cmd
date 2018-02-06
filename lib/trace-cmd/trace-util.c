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
 * License along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "trace-cmd.h"
#include "event-utils.h"

#define LOCAL_PLUGIN_DIR ".trace-cmd/plugins"
#define TRACEFS_PATH "/sys/kernel/tracing"
#define DEBUGFS_PATH "/sys/kernel/debug"

int tracecmd_disable_sys_plugins;
int tracecmd_disable_plugins;

static struct registered_plugin_options {
	struct registered_plugin_options	*next;
	struct pevent_plugin_option			*options;
} *registered_options;

static struct trace_plugin_options {
	struct trace_plugin_options	*next;
	char				*plugin;
	char				*option;
	char				*value;
} *trace_plugin_options;

#define _STR(x) #x
#define STR(x) _STR(x)

struct plugin_list {
	struct plugin_list	*next;
	char			*name;
	void			*handle;
};

/**
 * trace_util_list_plugin_options - get list of plugin options
 *
 * Returns an array of char strings that list the currently registered
 * plugin options in the format of <plugin>:<option>. This list can be
 * used by toggling the option.
 *
 * Returns NULL if there's no options registered.
 *
 * Must be freed with trace_util_free_plugin_options_list().
 */
char **trace_util_list_plugin_options(void)
{
	struct registered_plugin_options *reg;
	struct pevent_plugin_option *op;
	char **list = NULL;
	char *name;
	int count = 0;

	for (reg = registered_options; reg; reg = reg->next) {
		for (op = reg->options; op->name; op++) {
			char *alias = op->plugin_alias ? op->plugin_alias : op->file;
			int ret;

			ret = asprintf(&name, "%s:%s", alias, op->name);
			if (ret < 0) {
				warning("Failed to allocate plugin option %s:%s",
					alias, op->name);
				break;
			}

			list = realloc(list, count + 2);
			if (!list) {
				warning("Failed to allocate plugin list for %s", name);
				free(name);
				break;
			}
			list[count++] = name;
			list[count] = NULL;
		}
	}
	if (!count)
		return NULL;
	return list;
}

void trace_util_free_plugin_options_list(char **list)
{
	tracecmd_free_list(list);
}

static int process_option(const char *plugin, const char *option, const char *val);
static int update_option(const char *file, struct pevent_plugin_option *option);

/**
 * trace_util_add_options - Add a set of options by a plugin
 * @name: The name of the plugin adding the options
 * @options: The set of options being loaded
 *
 * Sets the options with the values that have been added by user.
 */
int trace_util_add_options(const char *name, struct pevent_plugin_option *options)
{
	struct registered_plugin_options *reg;
	int ret;

	reg = malloc(sizeof(*reg));
	if (!reg)
		return -ENOMEM;
	reg->next = registered_options;
	reg->options = options;
	registered_options = reg;

	while (options->name) {
		ret = update_option("ftrace", options);
		if (ret < 0)
			return ret;
		options++;
	}
	return 0;
}

/**
 * trace_util_remove_options - remove plugin options that were registered
 * @options: Options to removed that were registered with trace_util_add_options
 */
void trace_util_remove_options(struct pevent_plugin_option *options)
{
	struct registered_plugin_options **last;
	struct registered_plugin_options *reg;

	for (last = &registered_options; *last; last = &(*last)->next) {
		if ((*last)->options == options) {
			reg = *last;
			*last = reg->next;
			free(reg);
			return;
		}
	}
			
}

/**
 * trace_util_print_plugins - print out the list of plugins loaded
 * @s: the trace_seq descripter to write to
 * @prefix: The prefix string to add before listing the option name
 * @suffix: The suffix string ot append after the option name
 * @list: The list of plugins (usually returned by tracecmd_load_plugins()
 *
 * Writes to the trace_seq @s the list of plugins (files) that is
 * returned by tracecmd_load_plugins(). Use @prefix and @suffix for formating:
 * @prefix = "  ", @suffix = "\n".
 */
void trace_util_print_plugins(struct trace_seq *s,
			      const char *prefix, const char *suffix,
			      const struct plugin_list *list)
{
	while (list) {
		trace_seq_printf(s, "%s%s%s", prefix, list->name, suffix);
		list = list->next;
	}
}

static void parse_option_name(char **option, char **plugin)
{
	char *p;

	*plugin = NULL;

	if ((p = strstr(*option, ":"))) {
		*plugin = *option;
		*p = '\0';
		*option = strdup(p + 1);
		if (!*option)
			return;
	}
}

static struct pevent_plugin_option *
find_registered_option(const char *plugin, const char *option)
{
	struct registered_plugin_options *reg;
	struct pevent_plugin_option *op;
	const char *op_plugin;

	for (reg = registered_options; reg; reg = reg->next) {
		for (op = reg->options; op->name; op++) {
			if (op->plugin_alias)
				op_plugin = op->plugin_alias;
			else
				op_plugin = op->file;

			if (plugin && strcmp(plugin, op_plugin) != 0)
				continue;
			if (strcmp(option, op->name) != 0)
				continue;

			return op;
		}
	}

	return NULL;
}

static struct pevent_plugin_option *
find_registered_option_parse(const char *name)
{
	struct pevent_plugin_option *option;
	char *option_str;
	char *plugin;

	option_str = strdup(name);
	if (!option_str)
		return NULL;

	parse_option_name(&option_str, &plugin);
	option = find_registered_option(plugin, option_str);
	free(option_str);
	free(plugin);

	return option;
}

/**
 * trace_util_plugin_option_value - return a plugin option value
 * @name: The name of the plugin option to find (format: <plugin>:<option>)
 *
 * Returns the value char string of the option. If the option is only
 * boolean, then it returns "1" if set, and "0" if not.
 *
 * Returns NULL if the option is not found.
 */
const char *trace_util_plugin_option_value(const char *name)
{
	struct pevent_plugin_option *option;

	option = find_registered_option_parse(name);
	if (!option)
		return NULL;

	if (option->value)
		return option->value;

	return option->set ? "1" : "0";
}

/**
 * trace_util_add_option - add an option/val pair to set plugin options
 * @name: The name of the option (format: <plugin>:<option> or just <option>)
 * @val: (optiona) the value for the option
 *
 * Modify a plugin option. If @val is given than the value of the option
 * is set (note, some options just take a boolean, so @val must be either
 * "1" or "0" or "true" or "false").
 */
int trace_util_add_option(const char *name, const char *val)
{
	struct trace_plugin_options *op;
	char *option_str;
	char *plugin;
	
	option_str = strdup(name);
	if (!option_str)
		return -ENOMEM;

	parse_option_name(&option_str, &plugin);

	/* If the option exists, update the val */
	for (op = trace_plugin_options; op; op = op->next) {
		/* Both must be NULL or not NULL */
		if ((!plugin || !op->plugin) && plugin != op->plugin)
			continue;
		if (plugin && strcmp(plugin, op->plugin) != 0)
			continue;
		if (strcmp(op->option, option_str) != 0)
			continue;

		/* update option */
		free(op->value);
		if (val) {
			op->value = strdup(val);
			if (!op->value)
				goto out_free;
		} else
			op->value = NULL;

		/* plugin and option_str don't get freed at the end */
		free(plugin);
		free(option_str);

		plugin = op->plugin;
		option_str = op->option;
		break;
	}

	/* If not found, create */
	if (!op) {
		op = malloc(sizeof(*op));
		if (!op)
			return -ENOMEM;
		memset(op, 0, sizeof(*op));
		op->next = trace_plugin_options;
		trace_plugin_options = op;

		op->plugin = plugin;
		op->option = option_str;

		if (val) {
			op->value = strdup(val);
			if (!op->value)
				goto out_free;
		}
	}

	return process_option(plugin, option_str, val);
 out_free:
	free(option_str);
	return -ENOMEM;
}

static void print_op_data(struct trace_seq *s, const char *name,
			  const char *op)
{
	if (op)
		trace_seq_printf(s, "%8s:\t%s\n", name, op);
}

/**
 * trace_util_print_plugin_options - print out the registered plugin options
 * @s: The trace_seq descriptor to write the plugin options into
 * 
 * Writes a list of options into trace_seq @s.
 */
void trace_util_print_plugin_options(struct trace_seq *s)
{
	struct registered_plugin_options *reg;
	struct pevent_plugin_option *op;

	for (reg = registered_options; reg; reg = reg->next) {
		if (reg != registered_options)
			trace_seq_printf(s, "============\n");
		for (op = reg->options; op->name; op++) {
			if (op != reg->options)
				trace_seq_printf(s, "------------\n");
			print_op_data(s, "file", op->file);
			print_op_data(s, "plugin", op->plugin_alias);
			print_op_data(s, "option", op->name);
			print_op_data(s, "desc", op->description);
			print_op_data(s, "value", op->value);
			trace_seq_printf(s, "%8s:\t%d\n", "set", op->set);
		}
	}
}

void tracecmd_parse_cmdlines(struct pevent *pevent,
			     char *file, int size __maybe_unused)
{
	char *comm;
	char *line;
	char *next = NULL;
	int pid;

	line = strtok_r(file, "\n", &next);
	while (line) {
		sscanf(line, "%d %ms", &pid, &comm);
		pevent_register_comm(pevent, comm, pid);
		free(comm);
		line = strtok_r(NULL, "\n", &next);
	}
}

static void extract_trace_clock(struct pevent *pevent, char *line)
{
	char *data;
	char *clock;
	char *next = NULL;

	data = strtok_r(line, "[]", &next);
	sscanf(data, "%ms", &clock);
	pevent_register_trace_clock(pevent, clock);
	free(clock);
}

void tracecmd_parse_trace_clock(struct pevent *pevent,
				char *file, int size __maybe_unused)
{
	char *line;
	char *next = NULL;

	line = strtok_r(file, " ", &next);
	while (line) {
		/* current trace_clock is shown as "[local]". */
		if (*line == '[')
			return extract_trace_clock(pevent, line);
		line = strtok_r(NULL, " ", &next);
	}
}

void tracecmd_parse_proc_kallsyms(struct pevent *pevent,
			 char *file, unsigned int size __maybe_unused)
{
	unsigned long long addr;
	char *func;
	char *line;
	char *next = NULL;
	char *addr_str;
	char *mod;
	char ch;

	line = strtok_r(file, "\n", &next);
	while (line) {
		mod = NULL;
		errno = 0;
		sscanf(line, "%ms %c %ms\t[%ms",
			     &addr_str, &ch, &func, &mod);
		if (errno) {
			free(addr_str);
			free(func);
			free(mod);
			perror("sscanf");
			return;
		}
		addr = strtoull(addr_str, NULL, 16);
		free(addr_str);

		/* truncate the extra ']' */
		if (mod)
			mod[strlen(mod) - 1] = 0;

		/*
		 * Hacks for
		 *  - arm arch that adds a lot of bogus '$a' functions
		 *  - x86-64 that reports per-cpu variable offsets as absolute
		 */
		if (func[0] != '$' && ch != 'A' && ch != 'a')
			pevent_register_function(pevent, func, addr, mod);
		free(func);
		free(mod);

		line = strtok_r(NULL, "\n", &next);
	}
}

void tracecmd_parse_ftrace_printk(struct pevent *pevent,
			 char *file, unsigned int size __maybe_unused)
{
	unsigned long long addr;
	char *printk;
	char *line;
	char *next = NULL;
	char *addr_str;
	char *fmt;

	line = strtok_r(file, "\n", &next);
	while (line) {
		addr_str = strtok_r(line, ":", &fmt);
		if (!addr_str) {
			warning("printk format with empty entry");
			break;
		}
		addr = strtoull(addr_str, NULL, 16);
		/* fmt still has a space, skip it */
		printk = strdup(fmt+1);
		line = strtok_r(NULL, "\n", &next);
		pevent_register_print_string(pevent, printk, addr);
		free(printk);
	}
}

static void lower_case(char *str)
{
	if (!str)
		return;
	for (; *str; str++)
		*str = tolower(*str);
}

static int update_option_value(struct pevent_plugin_option *op, const char *val)
{
	char *op_val;
	int ret = 1;

	if (!val) {
		/* toggle, only if option is boolean */
		if (op->value)
			/* Warn? */
			return 0;
		op->set ^= 1;
		return 1;
	}

	/*
	 * If the option has a value then it takes a string
	 * otherwise the option is a boolean.
	 */
	if (op->value) {
		op->value = val;
		return 1;
	}

	/* Option is boolean, must be either "1", "0", "true" or "false" */

	op_val = strdup(val);
	if (!op_val)
		return -ENOMEM;
	lower_case(op_val);

	if (strcmp(val, "1") == 0 || strcmp(val, "true") == 0)
		op->set = 1;
	else if (strcmp(val, "0") == 0 || strcmp(val, "false") == 0)
		op->set = 0;
	else
		/* Warn on else? */
		ret = 0;
	free(op_val);

	return ret;
}

static int process_option(const char *plugin, const char *option, const char *val)
{
	struct pevent_plugin_option *op;

	op = find_registered_option(plugin, option);
	if (!op)
		return 0;

	return update_option_value(op, val);
}

static int update_option(const char *file, struct pevent_plugin_option *option)
{
	struct trace_plugin_options *op;
	char *plugin;

	if (option->plugin_alias) {
		plugin = strdup(option->plugin_alias);
		if (!plugin)
			return -ENOMEM;
	} else {
		char *p;
		plugin = strdup(file);
		if (!plugin)
			return -ENOMEM;
		p = strstr(plugin, ".");
		if (p)
			*p = '\0';
	}

	/* first look for named options */
	for (op = trace_plugin_options; op; op = op->next) {
		if (!op->plugin)
			continue;
		if (strcmp(op->plugin, plugin) != 0)
			continue;
		if (strcmp(op->option, option->name) != 0)
			continue;

		option->value = op->value;
		option->set ^= 1;
		goto out;
	}

	/* first look for unnamed options */
	for (op = trace_plugin_options; op; op = op->next) {
		if (op->plugin)
			continue;
		if (strcmp(op->option, option->name) != 0)
			continue;

		option->value = op->value;
		option->set ^= 1;
		break;
	}

 out:
	free(plugin);
	return 0;
}

static int load_plugin(struct pevent *pevent, const char *path,
		       const char *file, void *data)
{
	struct plugin_list **plugin_list = data;
	pevent_plugin_load_func func;
	struct plugin_list *list;
	struct pevent_plugin_option *options;
	const char *alias;
	char *plugin;
	void *handle;
	int ret;

	ret = asprintf(&plugin, "%s/%s", path, file);
	if (ret < 0)
		return -ENOMEM;

	handle = dlopen(plugin, RTLD_NOW | RTLD_GLOBAL);
	if (!handle) {
		warning("cound not load plugin '%s'\n%s\n",
			plugin, dlerror());
		goto out_free;
	}

	alias = dlsym(handle, PEVENT_PLUGIN_ALIAS_NAME);
	if (!alias)
		alias = file;

	options = dlsym(handle, PEVENT_PLUGIN_OPTIONS_NAME);
	if (options) {
		while (options->name) {
			ret = update_option(alias, options);
			if (ret < 0)
				goto out_free;
			options++;
		}
	}

	func = dlsym(handle, PEVENT_PLUGIN_LOADER_NAME);
	if (!func) {
		warning("cound not find func '%s' in plugin '%s'\n%s\n",
			PEVENT_PLUGIN_LOADER_NAME, plugin, dlerror());
		goto out_free;
	}

	list = malloc(sizeof(*list));
	if (!list)
		goto out_free;
	list->next = *plugin_list;
	list->handle = handle;
	list->name = plugin;
	*plugin_list = list;

	pr_stat("registering plugin: %s", plugin);
	func(pevent);
	return 0;

 out_free:
	free(plugin);
	return -1;
}

static int mount_debugfs(void)
{
	struct stat st;
	int ret;

	/* make sure debugfs exists */
	ret = stat(DEBUGFS_PATH, &st);
	if (ret < 0)
		return -1;

	ret = mount("nodev", DEBUGFS_PATH,
		    "debugfs", 0, NULL);

	return ret;
}

static int mount_tracefs(void)
{
	struct stat st;
	int ret;

	/* make sure debugfs exists */
	ret = stat(TRACEFS_PATH, &st);
	if (ret < 0)
		return -1;

	ret = mount("nodev", TRACEFS_PATH,
		    "tracefs", 0, NULL);

	return ret;
}

char *tracecmd_find_tracing_dir(void)
{
	char *debug_str = NULL;
	char fspath[PATH_MAX+1];
	char *tracing_dir;
	char type[100];
	int use_debug = 0;
	FILE *fp;

	if ((fp = fopen("/proc/mounts","r")) == NULL) {
		warning("Can't open /proc/mounts for read");
		return NULL;
	}

	while (fscanf(fp, "%*s %"
		      STR(PATH_MAX)
		      "s %99s %*s %*d %*d\n",
		      fspath, type) == 2) {
		if (strcmp(type, "tracefs") == 0)
			break;
		if (!debug_str && strcmp(type, "debugfs") == 0) {
			debug_str = strdup(fspath);
			if (!debug_str) {
				fclose(fp);
				return NULL;
			}
		}
	}
	fclose(fp);

	if (strcmp(type, "tracefs") != 0) {
		if (mount_tracefs() < 0) {
			if (debug_str) {
				strncpy(fspath, debug_str, PATH_MAX);
				fspath[PATH_MAX] = 0;
			} else {
				if (mount_debugfs() < 0) {
					warning("debugfs not mounted, please mount");
					free(debug_str);
					return NULL;
				}
				strcpy(fspath, DEBUGFS_PATH);
			}
			use_debug = 1;
		} else
			strcpy(fspath, TRACEFS_PATH);
	}
	free(debug_str);

	if (use_debug) {
		int ret;

		ret = asprintf(&tracing_dir, "%s/tracing", fspath);
		if (ret < 0)
			return NULL;
	} else {
		tracing_dir = strdup(fspath);
		if (!tracing_dir)
			return NULL;
	}

	return tracing_dir;
}

const char *tracecmd_get_tracing_dir(void)
{
	static const char *tracing_dir;

	if (tracing_dir)
		return tracing_dir;

	tracing_dir = tracecmd_find_tracing_dir();
	return tracing_dir;
}

/* FIXME: append_file() is duplicated and could be consolidated */
static char *append_file(const char *dir, const char *name)
{
	char *file;
	int ret;

	ret = asprintf(&file, "%s/%s", dir, name);

	return ret < 0 ? NULL : file;
}

/**
 * tracecmd_add_list - add an new string to a string list.
 * @list: list to add the string to (may be NULL)
 * @name: the string to add
 * @len: current length of list of strings.
 *
 * The typical usage is:
 *
 *    systems = tracecmd_add_list(systems, name, len++);
 *
 * Returns the new allocated list with an allocated name added.
 * The list will end with NULL.
 */
char **tracecmd_add_list(char **list, const char *name, int len)
{
	if (!list)
		list = malloc(sizeof(*list) * 2);
	else
		list = realloc(list, sizeof(*list) * (len + 2));
	if (!list)
		return NULL;

	list[len] = strdup(name);
	if (!list[len])
		return NULL;

	list[len + 1] = NULL;

	return list;
}

/**
 * tracecmd_free_list - free a list created with tracecmd_add_list.
 * @list: The list to free.
 *
 * Frees the list as well as the names within the list.
 */
void tracecmd_free_list(char **list)
{
	int i;

	if (!list)
		return;

	for (i = 0; list[i]; i++)
		free(list[i]);

	free(list);
}

/**
 * tracecmd_add_id - add an int to the event id list
 * @list: list to add the id to
 * @id: id to add
 * @len: current length of list of ids.
 *
 * The typical usage is:
 *
 *    events = tracecmd_add_id(events, id, len++);
 *
 * Returns the new allocated list with the id included.
 * the list will contain a '-1' at the end.
 *
 * The returned list should be freed with free().
 */
int *tracecmd_add_id(int *list, int id, int len)
{
	if (!list)
		list = malloc(sizeof(*list) * 2);
	else
		list = realloc(list, sizeof(*list) * (len + 2));
	if (!list)
		return NULL;

	list[len++] = id;
	list[len] = -1;

	return list;
}

/**
 * tracecmd_event_systems - return list of systems for tracing
 * @tracing_dir: directory holding the "events" directory
 *
 * Returns an allocated list of system names. Both the names and
 * the list must be freed with free().
 * The list returned ends with a "NULL" pointer.
 */
char **tracecmd_event_systems(const char *tracing_dir)
{
	struct dirent *dent;
	char **systems = NULL;
	char *events_dir;
	struct stat st;
	DIR *dir;
	int len = 0;
	int ret;

	if (!tracing_dir)
		return NULL;

	events_dir = append_file(tracing_dir, "events");
	if (!events_dir)
		return NULL;

	/*
	 * Search all the directories in the events directory,
 	 * and collect the ones that have the "enable" file.
	 */
	ret = stat(events_dir, &st);
	if (ret < 0 || !S_ISDIR(st.st_mode))
		goto out_free;

	dir = opendir(events_dir);
	if (!dir)
		goto out_free;

	while ((dent = readdir(dir))) {
		const char *name = dent->d_name;
		char *enable;
		char *sys;

		if (strcmp(name, ".") == 0 ||
		    strcmp(name, "..") == 0)
			continue;

		sys = append_file(events_dir, name);
		ret = stat(sys, &st);
		if (ret < 0 || !S_ISDIR(st.st_mode)) {
			free(sys);
			continue;
		}

		enable = append_file(sys, "enable");

		ret = stat(enable, &st);
		if (ret >= 0)
			systems = tracecmd_add_list(systems, name, len++);

		free(enable);
		free(sys);
	}

	closedir(dir);

 out_free:
	free(events_dir);
	return systems;
}

/**
 * tracecmd_system_events - return list of events for system
 * @tracing_dir: directory holding the "events" directory
 * @system: the system to return the events for
 *
 * Returns an allocated list of event names. Both the names and
 * the list must be freed with free().
 * The list returned ends with a "NULL" pointer.
 */
char **tracecmd_system_events(const char *tracing_dir, const char *system)
{
	struct dirent *dent;
	char **events = NULL;
	char *events_dir;
	char *system_dir;
	struct stat st;
	DIR *dir;
	int len = 0;
	int ret;

	if (!tracing_dir || !system)
		return NULL;

	events_dir = append_file(tracing_dir, "events");
	if (!events_dir)
		return NULL;

	/*
	 * Search all the directories in the systems directory,
	 * and collect the ones that have the "enable" file.
	 */
	ret = stat(events_dir, &st);
	if (ret < 0 || !S_ISDIR(st.st_mode))
		goto out_free;

	system_dir = append_file(events_dir, system);
	if (!system_dir)
		goto out_free;

	ret = stat(system_dir, &st);
	if (ret < 0 || !S_ISDIR(st.st_mode))
		goto out_free_sys;

	dir = opendir(system_dir);
	if (!dir)
		goto out_free_sys;

	while ((dent = readdir(dir))) {
		const char *name = dent->d_name;
		char *enable;
		char *event;

		if (strcmp(name, ".") == 0 ||
		    strcmp(name, "..") == 0)
			continue;

		event = append_file(system_dir, name);
		ret = stat(event, &st);
		if (ret < 0 || !S_ISDIR(st.st_mode)) {
			free(event);
			continue;
		}

		enable = append_file(event, "enable");

		ret = stat(enable, &st);
		if (ret >= 0)
			events = tracecmd_add_list(events, name, len++);

		free(enable);
		free(event);
	}

	closedir(dir);

 out_free_sys:
	free(system_dir);

 out_free:
	free(events_dir);

	return events;
}

static int read_file(const char *file, char **buffer)
{
	char *buf;
	int len = 0;
	int fd;
	int r;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return -1;

	buf = malloc(BUFSIZ + 1);
	if (!buf) {
		len = -1;
		goto out;
	}

	while ((r = read(fd, buf + len, BUFSIZ)) > 0) {
		len += r;
		buf = realloc(buf, len + BUFSIZ + 1);
		if (!buf) {
			len = -1;
			goto out;
		}
	}

	*buffer = buf;
	buf[len] = 0;
 out:
	close(fd);

	return len;
}

static int load_events(struct pevent *pevent, const char *system,
			const char *sys_dir)
{
	struct dirent *dent;
	struct stat st;
	DIR *dir;
	int len = 0;
	int ret = 0, failure = 0;

	ret = stat(sys_dir, &st);
	if (ret < 0 || !S_ISDIR(st.st_mode))
		return EINVAL;

	dir = opendir(sys_dir);
	if (!dir)
		return errno;

	while ((dent = readdir(dir))) {
		const char *name = dent->d_name;
		char *event;
		char *format;
		char *buf;

		if (strcmp(name, ".") == 0 ||
		    strcmp(name, "..") == 0)
			continue;

		event = append_file(sys_dir, name);
		ret = stat(event, &st);
		if (ret < 0 || !S_ISDIR(st.st_mode))
			goto free_event;

		format = append_file(event, "format");
		ret = stat(format, &st);
		if (ret < 0)
			goto free_format;

		len = read_file(format, &buf);
		if (len < 0)
			goto free_format;

		ret = pevent_parse_event(pevent, buf, len, system);
		free(buf);
 free_format:
		free(format);
 free_event:
		free(event);
		if (ret)
			failure = ret;
	}

	closedir(dir);
	return failure;
}

static int read_header(struct pevent *pevent, const char *events_dir)
{
	struct stat st;
	char *header;
	char *buf;
	int len;
	int ret = -1;

	header = append_file(events_dir, "header_page");

	ret = stat(header, &st);
	if (ret < 0)
		goto out;

	len = read_file(header, &buf);
	if (len < 0)
		goto out;

	pevent_parse_header_page(pevent, buf, len, sizeof(long));

	free(buf);

	ret = 0;
 out:
	free(header);
	return ret;
}

/**
 * tracecmd_local_events - create a pevent from the events on system
 * @tracing_dir: The directory that contains the events.
 *
 * Returns a pevent structure that contains the pevents local to
 * the system.
 */
struct pevent *tracecmd_local_events(const char *tracing_dir)
{
	struct pevent *pevent = NULL;

	pevent = pevent_alloc();
	if (!pevent)
		return NULL;

	if (tracecmd_fill_local_events(tracing_dir, pevent)) {
		pevent_free(pevent);
		pevent = NULL;
	}

	return pevent;
}

/**
 * tracecmd_fill_local_events - Fill a pevent with the events on system
 * @tracing_dir: The directory that contains the events.
 * @pevent: Allocated pevent which will be filled
 *
 * Returns whether the operation succeeded
 */
int tracecmd_fill_local_events(const char *tracing_dir, struct pevent *pevent)
{
	struct dirent *dent;
	char *events_dir;
	struct stat st;
	DIR *dir;
	int ret, failure = 0;

	if (!tracing_dir)
		return -1;

	events_dir = append_file(tracing_dir, "events");
	if (!events_dir)
		return -1;

	ret = stat(events_dir, &st);
	if (ret < 0 || !S_ISDIR(st.st_mode)) {
		ret = -1;
		goto out_free;
	}

	dir = opendir(events_dir);
	if (!dir) {
		ret = -1;
		goto out_free;
	}

	ret = read_header(pevent, events_dir);
	if (ret < 0) {
		ret = -1;
		goto out_free;
	}

	while ((dent = readdir(dir))) {
		const char *name = dent->d_name;
		char *sys;

		if (strcmp(name, ".") == 0 ||
		    strcmp(name, "..") == 0)
			continue;

		sys = append_file(events_dir, name);
		ret = stat(sys, &st);
		if (ret < 0 || !S_ISDIR(st.st_mode)) {
			free(sys);
			continue;
		}

		ret = load_events(pevent, name, sys);

		free(sys);

		if (ret)
			failure = 1;
	}

	closedir(dir);
	/* always succeed because parsing failures are not critical */
	ret = 0;

 out_free:
	free(events_dir);

	pevent->parsing_failures = failure;

	return ret;
}

/**
 * tracecmd_local_plugins - returns an array of available tracer plugins
 * @tracing_dir: The directory that contains the tracing directory
 *
 * Returns an allocate list of plugins. The array ends with NULL.
 * Both the plugin names and array must be freed with free().
 */
char **tracecmd_local_plugins(const char *tracing_dir)
{
	char *available_tracers;
	struct stat st;
	char **plugins = NULL;
	char *buf;
	char *str, *saveptr;
	char *plugin;
	int slen;
	int len;
	int ret;

	if (!tracing_dir)
		return NULL;

	available_tracers = append_file(tracing_dir, "available_tracers");
	if (!available_tracers)
		return NULL;

	ret = stat(available_tracers, &st);
	if (ret < 0)
		goto out_free;

	len = read_file(available_tracers, &buf);
	if (len < 0)
		goto out_free;

	len = 0;
	for (str = buf; ; str = NULL) {
		plugin = strtok_r(str, " ", &saveptr);
		if (!plugin)
			break;
		if (!(slen = strlen(plugin)))
			continue;

		/* chop off any newlines */
		if (plugin[slen - 1] == '\n')
			plugin[slen - 1] = '\0';

		/* Skip the non tracers */
		if (strcmp(plugin, "nop") == 0 ||
		    strcmp(plugin, "none") == 0)
			continue;

		plugins = tracecmd_add_list(plugins, plugin, len++);
	}
	free(buf);

 out_free:
	free(available_tracers);

	return plugins;
}

static void
trace_util_load_plugins_dir(struct pevent *pevent, const char *suffix,
			    const char *path,
			    int (*load_plugin)(struct pevent *pevent,
					       const char *path,
					       const char *name,
						void *data),
			    void *data)
{
	struct dirent *dent;
	struct stat st;
	DIR *dir;
	int ret;

	ret = stat(path, &st);
	if (ret < 0)
		return;

	if (!S_ISDIR(st.st_mode))
		return;

	dir = opendir(path);
	if (!dir)
		return;

	while ((dent = readdir(dir))) {
		const char *name = dent->d_name;

		if (strcmp(name, ".") == 0 ||
		    strcmp(name, "..") == 0)
			continue;

		/* Only load plugins that end in suffix */
		if (strcmp(name + (strlen(name) - strlen(suffix)), suffix) != 0)
			continue;

		load_plugin(pevent, path, name, data);
	}

	closedir(dir);

	return;
}

struct add_plugin_data {
	int ret;
	int index;
	char **files;
};

static int add_plugin_file(struct pevent *pevent, const char *path,
			   const char *name, void *data)
{
	struct add_plugin_data *pdata = data;
	char **ptr;
	int size;
	int i;

	if (pdata->ret)
		return 0;

	size = pdata->index + 2;
	ptr = realloc(pdata->files, sizeof(char *) * size);
	if (!ptr)
		goto out_free;

	ptr[pdata->index] = strdup(name);
	if (!ptr[pdata->index])
		goto out_free;

	pdata->files = ptr;
	pdata->index++;
	pdata->files[pdata->index] = NULL;
	return 0;

 out_free:
	for (i = 0; i < pdata->index; i++)
		free(pdata->files[i]);
	free(pdata->files);
	pdata->files = NULL;
	pdata->ret = errno;
	return -ENOMEM;
}

int trace_util_load_plugins(struct pevent *pevent, const char *suffix,
			    int (*load_plugin)(struct pevent *pevent,
					       const char *path,
					       const char *name,
					       void *data),
			    void *data)
{
	char *home;
	char *path;
	char *envdir;
	int ret;

	if (tracecmd_disable_plugins)
		return -EBUSY;

/* If a system plugin directory was defined, check that first */
#ifdef PLUGIN_DIR
	if (!tracecmd_disable_sys_plugins)
		trace_util_load_plugins_dir(pevent, suffix, PLUGIN_DIR,
					    load_plugin, data);
#endif

	/* Next let the environment-set plugin directory override the system defaults */
	envdir = getenv("TRACE_CMD_PLUGIN_DIR");
	if (envdir)
		trace_util_load_plugins_dir(pevent, suffix, envdir, load_plugin, data);

	/* Now let the home directory override the environment or system defaults */
	home = getenv("HOME");

	if (!home)
		return -EINVAL;

	ret = asprintf(&path, "%s/%s", home, LOCAL_PLUGIN_DIR);
	if (ret < 0)
		return -ENOMEM;

	trace_util_load_plugins_dir(pevent, suffix, path, load_plugin, data);

	free(path);
	return 0;
}

/**
 * trace_util_find_plugin_files - find list of possible plugin files
 * @suffix: The suffix of the plugin files to find
 *
 * Searches the plugin directory for files that end in @suffix, and
 * will return an allocated array of file names, or NULL if none is
 * found.
 *
 * Must check against TRACECMD_ISERR(ret) as if an error happens
 * the errno will be returned with the TRACECMD_ERR_MSK to denote
 * such an error occurred.
 *
 * Use trace_util_free_plugin_files() to free the result.
 */
char **trace_util_find_plugin_files(const char *suffix)
{
	struct add_plugin_data pdata;

	memset(&pdata, 0, sizeof(pdata));

	trace_util_load_plugins(NULL, suffix, add_plugin_file, &pdata);

	if (pdata.ret)
		return TRACECMD_ERROR(pdata.ret);

	return pdata.files;
}

/**
 * trace_util_free_plugin_files - free the result of trace_util_find_plugin_files()
 * @files: The result from trace_util_find_plugin_files()
 *
 * Frees the contents that were allocated by trace_util_find_plugin_files().
 */
void trace_util_free_plugin_files(char **files)
{
	int i;

	if (!files || TRACECMD_ISERR(files))
		return;

	for (i = 0; files[i]; i++) {
		free(files[i]);
	}
	free(files);
}

struct plugin_option_read {
	struct pevent_plugin_option	*options;
};

static int append_option(struct plugin_option_read *options,
			 struct pevent_plugin_option *option,
			 const char *alias, void *handle)
{
	struct pevent_plugin_option *op;

	while (option->name) {
		op = malloc(sizeof(*op));
		if (!op)
			return -ENOMEM;
		*op = *option;
		op->next = options->options;
		options->options = op;
		op->file = strdup(alias);
		op->handle = handle;
		option++;
	}
	return 0;
}

static int read_options(struct pevent *pevent, const char *path,
			 const char *file, void *data)
{
	struct plugin_option_read *options = data;
	struct pevent_plugin_option *option;
	const char *alias;
	int unload = 0;
	char *plugin;
	void *handle;
	int ret;

	ret = asprintf(&plugin, "%s/%s", path, file);
	if (ret < 0)
		return -ENOMEM;

	handle = dlopen(plugin, RTLD_NOW | RTLD_GLOBAL);
	if (!handle) {
		warning("cound not load plugin '%s'\n%s\n",
			plugin, dlerror());
		goto out_free;
	}

	alias = dlsym(handle, PEVENT_PLUGIN_ALIAS_NAME);
	if (!alias)
		alias = file;

	option = dlsym(handle, PEVENT_PLUGIN_OPTIONS_NAME);
	if (!option) {
		unload = 1;
		goto out_unload;
	}

	append_option(options, option, alias, handle);

 out_unload:
	if (unload)
		dlclose(handle);
 out_free:
	free(plugin);
	return 0;
}

struct pevent_plugin_option *trace_util_read_plugin_options(void)
{
	struct plugin_option_read option = {
		.options = NULL,
	};

	append_option(&option, trace_ftrace_options, "ftrace", NULL);

	trace_util_load_plugins(NULL, ".so", read_options, &option);

	return option.options;
}

void trace_util_free_options(struct pevent_plugin_option *options)
{
	struct pevent_plugin_option *op;
	void *last_handle = NULL;

	while (options) {
		op = options;
		options = op->next;
		if (op->handle && op->handle != last_handle) {
			last_handle = op->handle;
			dlclose(op->handle);
		}
		free(op->file);
		free(op);
	}
}

struct plugin_list *tracecmd_load_plugins(struct pevent *pevent)
{
	struct plugin_list *list = NULL;

	trace_util_load_plugins(pevent, ".so", load_plugin, &list);

	return list;
}

void
tracecmd_unload_plugins(struct plugin_list *plugin_list, struct pevent *pevent)
{
	pevent_plugin_unload_func func;
	struct plugin_list *list;

	while (plugin_list) {
		list = plugin_list;
		plugin_list = list->next;
		func = dlsym(list->handle, PEVENT_PLUGIN_UNLOADER_NAME);
		if (func)
			func(pevent);
		dlclose(list->handle);
		free(list->name);
		free(list);
	}
}

char *tracecmd_get_tracing_file(const char *name)
{
	static const char *tracing;
	char *file;
	int ret;

	if (!tracing) {
		tracing = tracecmd_find_tracing_dir();
		if (!tracing)
			return NULL;
	}

	ret = asprintf(&file, "%s/%s", tracing, name);
	if (ret < 0)
		return NULL;

	return file;
}

void tracecmd_put_tracing_file(char *name)
{
	free(name);
}

void __noreturn __vdie(const char *fmt, va_list ap)
{
	int ret = errno;

	if (errno)
		perror("trace-cmd");
	else
		ret = -1;

	fprintf(stderr, "  ");
	vfprintf(stderr, fmt, ap);

	fprintf(stderr, "\n");
	exit(ret);
}

void __noreturn __die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__vdie(fmt, ap);
	va_end(ap);
}

void __weak __noreturn die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__vdie(fmt, ap);
	va_end(ap);
}

void __weak *malloc_or_die(unsigned int size)
{
	void *data;

	data = malloc(size);
	if (!data)
		die("malloc");
	return data;
}
