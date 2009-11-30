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

void parse_cmdlines(char *file, int size __unused)
{
	char *comm;
	char *line;
	char *next = NULL;
	int pid;

	line = strtok_r(file, "\n", &next);
	while (line) {
		sscanf(line, "%d %as", &pid,
		       (float *)(void *)&comm); /* workaround gcc warning */
		pevent_register_comm(comm, pid);
		line = strtok_r(NULL, "\n", &next);
	}
}

void parse_proc_kallsyms(char *file, unsigned int size __unused)
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

		pevent_register_function(func, addr, mod);

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

static int load_plugin(const char *path, const char *file)
{
	char *plugin;
	void *handle;
	pevent_plugin_load_func func;
	int ret;

	plugin = malloc_or_die(strlen(path) + strlen(file) + 2);

	strcpy(plugin, path);
	strcat(plugin, "/");
	strcat(plugin, file);

	handle = dlopen(plugin, RTLD_NOW);
	if (!handle) {
		warning("cound not load plugin '%s'\n%s\n",
			plugin, dlerror());
		return -1;
	}

	func = dlsym(handle, PEVENT_PLUGIN_LOADER_NAME);
	if (!func) {
		warning("cound not find func '%s' in plugin '%s'\n%s\n",
			PEVENT_PLUGIN_LOADER_NAME, plugin, dlerror());
		return -1;
	}

	printf("registering plugin: %s\n", plugin);
	ret = func();

	/* dlclose ?? */
	return ret;
}

int trace_load_plugins(void)
{
	struct dirent *dent;
	struct stat st;
	DIR *dir;
	char *home;
	char *path;
	int ret;


	home = getenv("HOME");

	if (!home)
		return -1;

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

		load_plugin(path, name);
	}

 fail:
	free(path);
	return -1;
}
