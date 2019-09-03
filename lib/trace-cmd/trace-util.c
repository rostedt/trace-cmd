// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
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
#include <libgen.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "trace-cmd.h"
#include "event-utils.h"

#define LOCAL_PLUGIN_DIR ".trace-cmd/plugins"
#define TRACEFS_PATH "/sys/kernel/tracing"
#define DEBUGFS_PATH "/sys/kernel/debug"
#define PROC_STACK_FILE "/proc/sys/kernel/stack_tracer_enabled"

int tracecmd_disable_sys_plugins;
int tracecmd_disable_plugins;
static bool debug;

static FILE *logfp;

#define _STR(x) #x
#define STR(x) _STR(x)

/**
 * tracecmd_set_debug - Set debug mode of the tracecmd library
 * @set_debug: The new "debug" mode. If true, the tracecmd library is
 * in "debug" mode
 */
void tracecmd_set_debug(bool set_debug)
{
	debug = set_debug;
}

/**
 * tracecmd_get_debug - Get debug mode of tracecmd library
 * Returns true, if the tracecmd library is in debug mode.
 *
 */
bool tracecmd_get_debug(void)
{
	return debug;
}

void tracecmd_parse_cmdlines(struct tep_handle *pevent,
			     char *file, int size __maybe_unused)
{
	char *comm;
	char *line;
	char *next = NULL;
	int pid;

	line = strtok_r(file, "\n", &next);
	while (line) {
		sscanf(line, "%d %ms", &pid, &comm);
		tep_register_comm(pevent, comm, pid);
		free(comm);
		line = strtok_r(NULL, "\n", &next);
	}
}

static void extract_trace_clock(struct tep_handle *pevent, char *line)
{
	char *data;
	char *clock;
	char *next = NULL;

	data = strtok_r(line, "[]", &next);
	sscanf(data, "%ms", &clock);
	tep_register_trace_clock(pevent, clock);
	free(clock);
}

void tracecmd_parse_trace_clock(struct tep_handle *pevent,
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

void tracecmd_parse_proc_kallsyms(struct tep_handle *pevent,
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
			tep_register_function(pevent, func, addr, mod);
		free(func);
		free(mod);

		line = strtok_r(NULL, "\n", &next);
	}
}

void tracecmd_parse_ftrace_printk(struct tep_handle *pevent,
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
		tep_register_print_string(pevent, printk, addr);
		free(printk);
	}
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

static int load_events(struct tep_handle *pevent, const char *system,
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

		ret = tep_parse_event(pevent, buf, len, system);
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

static int read_header(struct tep_handle *pevent, const char *events_dir)
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

	tep_parse_header_page(pevent, buf, len, sizeof(long));

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
struct tep_handle *tracecmd_local_events(const char *tracing_dir)
{
	struct tep_handle *pevent = NULL;

	pevent = tep_alloc();
	if (!pevent)
		return NULL;

	if (tracecmd_fill_local_events(tracing_dir, pevent, NULL)) {
		tep_free(pevent);
		pevent = NULL;
	}

	return pevent;
}

/**
 * tracecmd_fill_local_events - Fill a pevent with the events on system
 * @tracing_dir: The directory that contains the events.
 * @pevent: Allocated pevent which will be filled
 * @parsing_failures: return number of failures while parsing the event files
 *
 * Returns whether the operation succeeded
 */
int tracecmd_fill_local_events(const char *tracing_dir,
			       struct tep_handle *pevent, int *parsing_failures)
{
	struct dirent *dent;
	char *events_dir;
	struct stat st;
	DIR *dir;
	int ret;

	if (!tracing_dir)
		return -1;
	if (parsing_failures)
		*parsing_failures = 0;

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

		if (ret && parsing_failures)
			(*parsing_failures)++;
	}

	closedir(dir);
	/* always succeed because parsing failures are not critical */
	ret = 0;

 out_free:
	free(events_dir);

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

struct add_plugin_data {
	int ret;
	int index;
	char **files;
};

static void add_plugin_file(struct tep_handle *pevent, const char *path,
			   const char *name, void *data)
{
	struct add_plugin_data *pdata = data;
	char **ptr;
	int size;
	int i;

	if (pdata->ret)
		return;

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
	return;

 out_free:
	for (i = 0; i < pdata->index; i++)
		free(pdata->files[i]);
	free(pdata->files);
	pdata->files = NULL;
	pdata->ret = errno;
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

	tep_load_plugins_hook(NULL, suffix, add_plugin_file, &pdata);

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

#define LOG_BUF_SIZE 1024
static void __plog(const char *prefix, const char *fmt, va_list ap, FILE *fp)
{
	static int newline = 1;
	char buf[LOG_BUF_SIZE];
	int r;

	r = vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);

	if (r > LOG_BUF_SIZE)
		r = LOG_BUF_SIZE;

	if (logfp) {
		if (newline)
			fprintf(logfp, "[%d]%s%.*s", getpid(), prefix, r, buf);
		else
			fprintf(logfp, "[%d]%s%.*s", getpid(), prefix, r, buf);
		newline = buf[r - 1] == '\n';
		fflush(logfp);
		return;
	}

	fprintf(fp, "%.*s", r, buf);
}

void tracecmd_plog(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__plog("", fmt, ap, stdout);
	va_end(ap);
	/* Make sure it gets to the screen, in case we crash afterward */
	fflush(stdout);
}

void tracecmd_plog_error(const char *fmt, ...)
{
	va_list ap;
	char *str = "";

	va_start(ap, fmt);
	__plog("Error: ", fmt, ap, stderr);
	va_end(ap);
	if (errno)
		str = strerror(errno);
	if (logfp)
		fprintf(logfp, "\n%s\n", str);
	else
		fprintf(stderr, "\n%s\n", str);
}

/**
 * tracecmd_set_logfile - Set file for logging
 * @logfile: Name of the log file
 *
 * Returns 0 on successful completion or -1 in case of error
 */
int tracecmd_set_logfile(char *logfile)
{
	if (logfp)
		fclose(logfp);
	logfp = fopen(logfile, "w");
	if (!logfp)
		return -1;
	return 0;
}

/**
 * tracecmd_stack_tracer_status - Check stack trace status
 * @status: Returned stack trace status:
 *             0 - not configured, disabled
 *             non 0 - enabled
 *
 * Returns -1 in case of an error, 0 if file does not exist
 * (stack tracer not configured in kernel) or 1 on successful completion.
 */
int tracecmd_stack_tracer_status(int *status)
{
	struct stat stat_buf;
	char buf[64];
	long num;
	int fd;
	int n;

	if (stat(PROC_STACK_FILE, &stat_buf) < 0) {
		/* stack tracer not configured on running kernel */
		*status = 0; /* not configured means disabled */
		return 0;
	}

	fd = open(PROC_STACK_FILE, O_RDONLY);

	if (fd < 0)
		return -1;

	n = read(fd, buf, sizeof(buf));
	close(fd);

	if (n <= 0)
		return -1;

	if (n >= sizeof(buf))
		return -1;

	buf[n] = 0;

	errno = 0;
	num = strtol(buf, NULL, 10);

	/* Check for various possible errors */
	if (num > INT_MAX || num < INT_MIN || (!num && errno))
		return -1;

	*status = num;
	return 1; /* full success */
}
