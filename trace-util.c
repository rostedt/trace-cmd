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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "trace-cmd.h"

#define LOCAL_PLUGIN_DIR ".trace-cmd/plugins"
#define DEBUGFS_PATH "/sys/kernel/debug"

int tracecmd_disable_sys_plugins;
int tracecmd_disable_plugins;

#define __weak __attribute__((weak))

#define _STR(x) #x
#define STR(x) _STR(x)

#ifndef MAX_PATH
# define MAX_PATH 1024
#endif

struct plugin_list {
	struct plugin_list	*next;
	char			*name;
	void			*handle;
};

void __weak die(char *fmt, ...)
{
	va_list ap;
	int ret = errno;

	if (errno)
		perror("trace-cmd");
	else
		ret = -1;

	va_start(ap, fmt);
	fprintf(stderr, "  ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");
	exit(ret);
}

void __weak warning(char *fmt, ...)
{
	va_list ap;

	if (errno)
		perror("trace-cmd");
	errno = 0;

	va_start(ap, fmt);
	fprintf(stderr, "  ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");
}

void __weak pr_stat(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	printf("\n");
}

void __weak *malloc_or_die(unsigned int size)
{
	void *data;

	data = malloc(size);
	if (!data)
		die("malloc");
	return data;
}

int __weak bigendian(void)
{
	unsigned char str[] = { 0x1, 0x2, 0x3, 0x4 };
	unsigned int *ptr;

	ptr = (unsigned int *)str;
	return *ptr == 0x01020304;
}

void parse_cmdlines(struct pevent *pevent,
		    char *file, int size __unused)
{
	char *comm;
	char *line;
	char *next = NULL;
	int pid;

	line = strtok_r(file, "\n", &next);
	while (line) {
		sscanf(line, "%d %as", &pid,
		       (float *)(void *)&comm); /* workaround gcc warning */
		pevent_register_comm(pevent, comm, pid);
		free(comm);
		line = strtok_r(NULL, "\n", &next);
	}
}

void parse_proc_kallsyms(struct pevent *pevent,
			 char *file, unsigned int size __unused)
{
	unsigned long long addr;
	char *func;
	char *line;
	char *next = NULL;
	char *addr_str;
	char *mod;
	char ch;
	int ret;

	line = strtok_r(file, "\n", &next);
	while (line) {
		mod = NULL;
		ret = sscanf(line, "%as %c %as\t[%as",
			     (float *)(void *)&addr_str, /* workaround gcc warning */
			     &ch,
			     (float *)(void *)&func,
			     (float *)(void *)&mod);
		addr = strtoull(addr_str, NULL, 16);
		free(addr_str);

		/* truncate the extra ']' */
		if (mod)
			mod[strlen(mod) - 1] = 0;

		pevent_register_function(pevent, func, addr, mod);
		free(func);
		free(mod);

		line = strtok_r(NULL, "\n", &next);
	}
}

void parse_ftrace_printk(struct pevent *pevent,
			 char *file, unsigned int size __unused)
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
	}
}

static void load_plugin(struct pevent *pevent, const char *path,
			const char *file, void *data)
{
	struct plugin_list **plugin_list = data;
	pevent_plugin_load_func func;
	struct plugin_list *list;
	char *plugin;
	void *handle;

	plugin = malloc_or_die(strlen(path) + strlen(file) + 2);

	strcpy(plugin, path);
	strcat(plugin, "/");
	strcat(plugin, file);

	handle = dlopen(plugin, RTLD_NOW | RTLD_GLOBAL);
	if (!handle) {
		warning("cound not load plugin '%s'\n%s\n",
			plugin, dlerror());
		goto out_free;
	}

	func = dlsym(handle, PEVENT_PLUGIN_LOADER_NAME);
	if (!func) {
		warning("cound not find func '%s' in plugin '%s'\n%s\n",
			PEVENT_PLUGIN_LOADER_NAME, plugin, dlerror());
		goto out_free;
	}

	list = malloc_or_die(sizeof(*list));
	list->next = *plugin_list;
	list->handle = handle;
	list->name = plugin;
	*plugin_list = list;

	pr_stat("registering plugin: %s", plugin);
	func(pevent);
	return;

 out_free:
	free(plugin);
}

static int mount_debugfs(void)
{
	struct stat st;
	int ret;

	/* make sure debugfs exists */
	ret = stat(DEBUGFS_PATH, &st);
	if (ret < 0)
		die("debugfs is not configured on this kernel");

	ret = mount("nodev", DEBUGFS_PATH,
		    "debugfs", 0, NULL);

	return ret;
}

char *tracecmd_find_tracing_dir(void)
{
	char debugfs[MAX_PATH+1];
	char *tracing_dir;
	char type[100];
	FILE *fp;
	
	if ((fp = fopen("/proc/mounts","r")) == NULL) {
		warning("Can't open /proc/mounts for read");
		return NULL;
	}

	while (fscanf(fp, "%*s %"
		      STR(MAX_PATH)
		      "s %99s %*s %*d %*d\n",
		      debugfs, type) == 2) {
		if (strcmp(type, "debugfs") == 0)
			break;
	}
	fclose(fp);

	if (strcmp(type, "debugfs") != 0) {
		/* If debugfs is not mounted, try to mount it */
		if (mount_debugfs() < 0) {
			warning("debugfs not mounted, please mount");
			return NULL;
		}
		strcpy(debugfs, DEBUGFS_PATH);
	}

	tracing_dir = malloc_or_die(strlen(debugfs) + 9);
	if (!tracing_dir)
		return NULL;

	sprintf(tracing_dir, "%s/tracing", debugfs);

	return tracing_dir;
}

static void
trace_util_load_plugins_dir(struct pevent *pevent, const char *suffix,
			    const char *path,
			    void (*load_plugin)(struct pevent *pevent,
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

void trace_util_load_plugins(struct pevent *pevent, const char *suffix,
			     void (*load_plugin)(struct pevent *pevent,
						 const char *path,
						 const char *name,
						 void *data),
			     void *data)
{
	char *home;
	char *path;

	if (tracecmd_disable_plugins)
		return;

/* If a system plugin directory was defined, check that first */
#ifdef PLUGIN_DIR
	if (!tracecmd_disable_sys_plugins)
		trace_util_load_plugins_dir(pevent, suffix, MAKE_STR(PLUGIN_DIR),
					    load_plugin, data);
#endif

	/* Now let the home directory override the system defaults */
	home = getenv("HOME");

	if (!home)
		return;

	path = malloc_or_die(strlen(home) + strlen(LOCAL_PLUGIN_DIR) + 2);

	strcpy(path, home);
	strcat(path, "/");
	strcat(path, LOCAL_PLUGIN_DIR);

	trace_util_load_plugins_dir(pevent, suffix, path, load_plugin, data);

	free(path);
}

struct plugin_list *tracecmd_load_plugins(struct pevent *pevent)
{
	struct plugin_list *list = NULL;

	trace_util_load_plugins(pevent, ".so", load_plugin, &list);

	return list;
}

void tracecmd_unload_plugins(struct plugin_list *plugin_list)
{
	pevent_plugin_unload_func func;
	struct plugin_list *list;

	while (plugin_list) {
		list = plugin_list;
		plugin_list = list->next;
		func = dlsym(list->handle, PEVENT_PLUGIN_UNLOADER_NAME);
		if (func)
			func();
		dlclose(list->handle);
		free(list->name);
		free(list);
	}
}
