#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "trace-cmd.h"

#define PLUGIN_DIR ".trace-cmd/plugins"

#define __weak __attribute__((weak))

#define _STR(x) #x
#define STR(x) _STR(x)

#ifndef MAX_PATH
# define MAX_PATH 1024
#endif

struct plugin_list {
	struct plugin_list	*next;
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

void parse_ftrace_printk(char *file, unsigned int size __unused)
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
		addr = strtoull(addr_str, NULL, 16);
		/* fmt still has a space, skip it */
		printk = strdup(fmt+1);
		line = strtok_r(NULL, "\n", &next);
	}
}

static struct plugin_list *
load_plugin(struct pevent *pevent, struct plugin_list *plugin_list,
	    const char *path, const char *file)
{
	pevent_plugin_load_func func;
	struct plugin_list *list;
	char *plugin;
	void *handle;
	int ret = -1;

	plugin = malloc_or_die(strlen(path) + strlen(file) + 2);

	strcpy(plugin, path);
	strcat(plugin, "/");
	strcat(plugin, file);

	handle = dlopen(plugin, RTLD_NOW);
	if (!handle) {
		warning("cound not load plugin '%s'\n%s\n",
			plugin, dlerror());
		goto out;
	}

	list = malloc_or_die(sizeof(*list));
	list->next = plugin_list;
	list->handle = handle;
	plugin_list = list;

	func = dlsym(handle, PEVENT_PLUGIN_LOADER_NAME);
	if (!func) {
		warning("cound not find func '%s' in plugin '%s'\n%s\n",
			PEVENT_PLUGIN_LOADER_NAME, plugin, dlerror());
		goto out;
	}

	printf("registering plugin: %s\n", plugin);
	ret = func(pevent);

 out:
	free(plugin);

	return plugin_list;
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
		warning("debugfs not mounted, please mount");
		return NULL;
	}

	tracing_dir = malloc_or_die(strlen(debugfs) + 9);
	if (!tracing_dir)
		return NULL;

	sprintf(tracing_dir, "%s/tracing", debugfs);

	return tracing_dir;
}

struct plugin_list *tracecmd_load_plugins(struct pevent *pevent)
{
	struct plugin_list *list = NULL;
	struct dirent *dent;
	struct stat st;
	DIR *dir;
	char *home;
	char *path;
	int ret;

	home = getenv("HOME");

	if (!home)
		return NULL;

	path = malloc_or_die(strlen(home) + strlen(PLUGIN_DIR) + 2);

	strcpy(path, home);
	strcat(path, "/");
	strcat(path, PLUGIN_DIR);

	ret = stat(path, &st);
	if (ret < 0)
		goto fail;

	if (!S_ISDIR(st.st_mode))
		goto fail;

	dir = opendir(path);
	if (!dir)
		goto fail;

	while ((dent = readdir(dir))) {
		const char *name = dent->d_name;

		if (strcmp(name, ".") == 0 ||
		    strcmp(name, "..") == 0)
			continue;

		list = load_plugin(pevent, list, path, name);
	}

	closedir(dir);
 fail:
	free(path);

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
		free(list);
	}
}
