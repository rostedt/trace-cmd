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
#define _LARGEFILE64_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <glob.h>

#include "trace-cmd-local.h"
#include "list.h"
#include "trace-msg.h"
#include "version.h"

/* We can't depend on the host size for size_t, all must be 64 bit */
typedef unsigned long long	tsize_t;
typedef long long		stsize_t;

static struct tracecmd_event_list all_event_list = {
	.next = NULL,
	.glob = "all"
};

struct tracecmd_option {
	unsigned short	id;
	int		size;
	void		*data;
	tsize_t		offset;
	struct list_head list;
};

enum {
	OUTPUT_FL_SEND_META	= (1 << 0),
};

struct tracecmd_output {
	int		fd;
	int		page_size;
	int		cpus;
	struct pevent	*pevent;
	char		*tracing_dir;
	int		options_written;
	int		nr_options;
	struct list_head options;
	struct tracecmd_msg_handle *msg_handle;
};

struct list_event {
	struct list_event		*next;
	char				*name;
	char				*file;
};

struct list_event_system {
	struct list_event_system	*next;
	struct list_event		*events;
	char				*name;
};

static stsize_t
do_write_check(struct tracecmd_output *handle, const void *data, tsize_t size)
{
	if (handle->msg_handle)
		return tracecmd_msg_metadata_send(handle->msg_handle, data, size);

	return __do_write_check(handle->fd, data, size);
}

static short convert_endian_2(struct tracecmd_output *handle, short val)
{
	if (!handle->pevent)
		return val;

	return __data2host2(handle->pevent, val);
}

static int convert_endian_4(struct tracecmd_output *handle, int val)
{
	if (!handle->pevent)
		return val;

	return __data2host4(handle->pevent, val);
}

static unsigned long long convert_endian_8(struct tracecmd_output *handle,
					   unsigned long long val)
{
	if (!handle->pevent)
		return val;

	return __data2host8(handle->pevent, val);
}

void tracecmd_output_free(struct tracecmd_output *handle)
{
	struct tracecmd_option *option;

	if (!handle)
		return;

	if (handle->tracing_dir)
		free(handle->tracing_dir);

	if (handle->pevent)
		pevent_unref(handle->pevent);

	while (!list_empty(&handle->options)) {
		option = container_of(handle->options.next,
				      struct tracecmd_option, list);
		list_del(&option->list);
		free(option->data);
		free(option);
	}

	free(handle);
}

void tracecmd_output_close(struct tracecmd_output *handle)
{
	if (!handle)
		return;

	if (handle->fd >= 0) {
		close(handle->fd);
		handle->fd = -1;
	}

	tracecmd_output_free(handle);
}
static unsigned long get_size_fd(int fd)
{
	unsigned long long size = 0;
	char buf[BUFSIZ];
	int r;

	do {
		r = read(fd, buf, BUFSIZ);
		if (r > 0)
			size += r;
	} while (r > 0);

	lseek(fd, 0, SEEK_SET);

	return size;
}

static unsigned long get_size(const char *file)
{
	unsigned long long size = 0;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		warning("Can't read '%s'", file);
		return 0; /* Caller will fail with zero */
	}
	size = get_size_fd(fd);
	close(fd);

	return size;
}

static tsize_t copy_file_fd(struct tracecmd_output *handle, int fd)
{
	tsize_t size = 0;
	char buf[BUFSIZ];
	stsize_t r;

	do {
		r = read(fd, buf, BUFSIZ);
		if (r > 0) {
			size += r;
			if (do_write_check(handle, buf, r))
				return 0;
		}
	} while (r > 0);

	return size;
}

static tsize_t copy_file(struct tracecmd_output *handle,
				    const char *file)
{
	tsize_t size = 0;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		warning("Can't read '%s'", file);
		return 0;
	}
	size = copy_file_fd(handle, fd);
	close(fd);

	return size;
}

/*
 * Finds the path to the debugfs/tracing
 * Allocates the string and stores it.
 */
static const char *find_tracing_dir(struct tracecmd_output *handle)
{
	if (!handle->tracing_dir)
		handle->tracing_dir = tracecmd_find_tracing_dir();

	return handle->tracing_dir;
}

static char *get_tracing_file(struct tracecmd_output *handle, const char *name)
{
	const char *tracing;
	char *file;
	int ret;

	tracing = find_tracing_dir(handle);
	if (!tracing)
		return NULL;

	ret = asprintf(&file, "%s/%s", tracing, name);
	if (ret < 0)
		return NULL;

	return file;
}

static void put_tracing_file(char *file)
{
	free(file);
}

int tracecmd_ftrace_enable(int set)
{
	struct stat buf;
	char *path = "/proc/sys/kernel/ftrace_enabled";
	int fd;
	char *val = set ? "1" : "0";
	int ret = 0;

	/* if ftace_enable does not exist, simply ignore it */
	fd = stat(path, &buf);
	if (fd < 0)
		return ENODEV;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		warning("Can't %s ftrace", set ? "enable" : "disable");
		return EIO;
	}

	if (write(fd, val, 1) < 0)
		ret = -1;
	close(fd);

	return ret;
}

static int read_header_files(struct tracecmd_output *handle)
{
	tsize_t size, check_size, endian8;
	struct stat st;
	char *path;
	int fd;
	int ret;

	path = get_tracing_file(handle, "events/header_page");
	if (!path)
		return -1;

	ret = stat(path, &st);
	if (ret < 0) {
		/* old style did not show this info, just add zero */
		put_tracing_file(path);
		if (do_write_check(handle, "header_page", 12))
			return -1;
		size = 0;
		if (do_write_check(handle, &size, 8))
			return -1;
		if (do_write_check(handle, "header_event", 13))
			return -1;
		if (do_write_check(handle, &size, 8))
			return -1;
		return 0;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		warning("can't read '%s'", path);
		return -1;
	}

	/* unfortunately, you can not stat debugfs files for size */
	size = get_size_fd(fd);

	if (do_write_check(handle, "header_page", 12))
		goto out_close;
	endian8 = convert_endian_8(handle, size);
	if (do_write_check(handle, &endian8, 8))
		goto out_close;
	check_size = copy_file_fd(handle, fd);
	close(fd);
	if (size != check_size) {
		warning("wrong size for '%s' size=%lld read=%lld",
			path, size, check_size);
		errno = EINVAL;
		return -1;
	}
	put_tracing_file(path);

	path = get_tracing_file(handle, "events/header_event");
	if (!path)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		warning("can't read '%s'", path);
		return -1;
	}

	size = get_size_fd(fd);

	if (do_write_check(handle, "header_event", 13))
		goto out_close;
	endian8 = convert_endian_8(handle, size);
	if (do_write_check(handle, &endian8, 8))
		goto out_close;
	check_size = copy_file_fd(handle, fd);
	close(fd);
	if (size != check_size) {
		warning("wrong size for '%s'", path);
		return -1;
	}
	put_tracing_file(path);
	return 0;

 out_close:
	close(fd);
	return -1;
}

static int copy_event_system(struct tracecmd_output *handle,
			     struct list_event_system *slist)
{
	struct list_event *elist;
	unsigned long long size, check_size, endian8;
	struct stat st;
	char *format;
	int endian4;
	int count = 0;
	int ret;

	for (elist = slist->events; elist; elist = elist->next)
		count++;

	endian4 = convert_endian_4(handle, count);
	if (do_write_check(handle, &endian4, 4))
		return -1;

	for (elist = slist->events; elist; elist = elist->next) {
		format = elist->file;
		ret = stat(format, &st);

		if (ret >= 0) {
			/* unfortunately, you can not stat debugfs files for size */
			size = get_size(format);
			endian8 = convert_endian_8(handle, size);
			if (do_write_check(handle, &endian8, 8))
				return -1;
			check_size = copy_file(handle, format);
			if (size != check_size) {
				warning("error in size of file '%s'", format);
				return -1;
			}
		}
	}

	return 0;
}

static void add_list_event_system(struct list_event_system **systems,
				  const char *system,
				  const char *event,
				  const char *path)
{
	struct list_event_system *slist;
	struct list_event *elist;

	for (slist = *systems; slist; slist = slist->next)
		if (strcmp(slist->name, system) == 0)
			break;

	if (!slist) {
		slist = malloc(sizeof(*slist));
		if (!slist)
			goto err_mem;
		slist->name = strdup(system);
		if (!slist->name) {
			free(slist);
			goto err_mem;
		}
		slist->next = *systems;
		slist->events = NULL;
		*systems = slist;
	}

	for (elist = slist->events; elist; elist = elist->next)
		if (strcmp(elist->name, event) == 0)
			break;

	if (!elist) {
		elist = malloc(sizeof(*elist));
		if (!elist)
			goto err_mem;
		elist->name = strdup(event);
		elist->file = strdup(path);
		if (!elist->name || !elist->file) {
			free(elist->name);
			free(elist->file);
			free(elist);
			goto err_mem;
		}
		elist->next = slist->events;
		slist->events = elist;
	}
	return;
 err_mem:
	warning("Insufficient memory");
}

static void free_list_events(struct list_event_system *list)
{
	struct list_event_system *slist;
	struct list_event *elist;

	while (list) {
		slist = list;
		list = list->next;
		while (slist->events) {
			elist = slist->events;
			slist->events = elist->next;
			free(elist->name);
			free(elist->file);
			free(elist);
		}
		free(slist->name);
		free(slist);
	}
}

static void glob_events(struct tracecmd_output *handle,
			struct list_event_system **systems,
			const char *str)
{
	glob_t globbuf;
	char *events_path;
	char *system;
	char *event;
	char *path;
	char *file;
	char *ptr;
	int do_ftrace = 0;
	int events_len;
	int ret;
	int i;

	if (strncmp(str, "ftrace/", 7) == 0)
		do_ftrace = 1;

	events_path = get_tracing_file(handle, "events");
	events_len = strlen(events_path);

	path = malloc(events_len + strlen(str) +
		      strlen("/format") + 2);
	if (!path)
		return;
	path[0] = '\0';
	strcat(path, events_path);
	strcat(path, "/");
	strcat(path, str);
	strcat(path, "/format");
	put_tracing_file(events_path);

	globbuf.gl_offs = 0;
	ret = glob(path, 0, NULL, &globbuf);
	free(path);
	if (ret < 0)
		return;

	for (i = 0; i < globbuf.gl_pathc; i++) {
		file = globbuf.gl_pathv[i];
		system = strdup(file + events_len + 1);
		system = strtok_r(system, "/", &ptr);
		if (!ptr) {
			/* ?? should we warn? */
			free(system);
			continue;
		}

		if (!do_ftrace && strcmp(system, "ftrace") == 0) {
			free(system);
			continue;
		}

		event = strtok_r(NULL, "/", &ptr);
		if (!ptr) {
			/* ?? should we warn? */
			free(system);
			continue;
		}

		add_list_event_system(systems, system, event, file);
		free(system);
	}
	globfree(&globbuf);
}

static void
create_event_list_item(struct tracecmd_output *handle,
		       struct list_event_system **systems,
		       struct tracecmd_event_list *list)
{
	char *ptr;
	char *str;

	str = strdup(list->glob);
	if (!str)
		goto err_mem;

	/* system and event names are separated by a ':' */
	ptr = strchr(str, ':');
	if (ptr)
		*ptr = '/';
	else
		/* system and event may also be separated by a '/' */
		ptr = strchr(str, '/');

	if (ptr) {
		glob_events(handle, systems, str);
		free(str);
		return;
	}

	ptr = str;
	str = malloc(strlen(ptr) + 3);
	if (!str)
		goto err_mem;
	str[0] = '\0';
	strcat(str, ptr);
	strcat(str, "/*");
	glob_events(handle, systems, str);

	str[0] = '\0';
	strcat(str, "*/");
	strcat(str, ptr);
	glob_events(handle, systems, str);

	free(ptr);
	free(str);
	return;
 err_mem:
	warning("Insufficient memory");
}

static int read_ftrace_files(struct tracecmd_output *handle)
{
	struct list_event_system *systems = NULL;
	struct tracecmd_event_list list = { .glob = "ftrace/*" };
	int ret;

	create_event_list_item(handle, &systems, &list);

	ret = copy_event_system(handle, systems);

	free_list_events(systems);

	return ret;
}

static struct list_event_system *
create_event_list(struct tracecmd_output *handle,
		  struct tracecmd_event_list *event_list)
{
	struct list_event_system *systems = NULL;
	struct tracecmd_event_list *list;

	for (list = event_list; list; list = list->next)
		create_event_list_item(handle, &systems, list);

	return systems;
}

static int read_event_files(struct tracecmd_output *handle,
			    struct tracecmd_event_list *event_list)
{
	struct list_event_system *systems;
	struct list_event_system *slist;
	struct tracecmd_event_list *list;
	struct tracecmd_event_list all_events = { .glob = "*/*" };
	int count = 0;
	int endian4;
	int ret;

	/*
	 * If any of the list is the special keyword "all" then
	 * just do all files.
	 */
	for (list = event_list; list; list = list->next) {
		if (strcmp(list->glob, "all") == 0)
			break;
	}
	/* all events are listed, use a global glob */
	if (list)
		event_list = &all_events;

	systems = create_event_list(handle, event_list);

	for (slist = systems; slist; slist = slist->next)
		count++;

	ret = -1;
	endian4 = convert_endian_4(handle, count);
	if (do_write_check(handle, &endian4, 4))
		goto out_free;

	ret = 0;
	for (slist = systems; !ret && slist; slist = slist->next) {
		if (do_write_check(handle, slist->name,
				   strlen(slist->name) + 1)) {
			ret = -1;
			continue;
		}
		ret = copy_event_system(handle, slist);
	}

 out_free:
	free_list_events(systems);

	return ret;
}

static int read_proc_kallsyms(struct tracecmd_output *handle,
			      const char *kallsyms)
{
	unsigned int size, check_size, endian4;
	const char *path = "/proc/kallsyms";
	struct stat st;
	int ret;

	if (kallsyms)
		path = kallsyms;

	ret = stat(path, &st);
	if (ret < 0) {
		/* not found */
		size = 0;
		endian4 = convert_endian_4(handle, size);
		if (do_write_check(handle, &endian4, 4))
			return -1;
		return 0;
	}
	size = get_size(path);
	endian4 = convert_endian_4(handle, size);
	if (do_write_check(handle, &endian4, 4))
		return -1;
	check_size = copy_file(handle, path);
	if (size != check_size) {
		errno = EINVAL;
		warning("error in size of file '%s'", path);
		return -1;
	}

	return 0;
}

static int read_ftrace_printk(struct tracecmd_output *handle)
{
	unsigned int size, check_size, endian4;
	struct stat st;
	char *path;
	int ret;

	path = get_tracing_file(handle, "printk_formats");
	if (!path)
		return -1;

	ret = stat(path, &st);
	if (ret < 0) {
		/* not found */
		size = 0;
		endian4 = convert_endian_4(handle, size);
		if (do_write_check(handle, &endian4, 4))
			goto fail;
		goto out;
	}
	size = get_size(path);
	endian4 = convert_endian_4(handle, size);
	if (do_write_check(handle, &endian4, 4))
		goto fail;
	check_size = copy_file(handle, path);
	if (size != check_size) {
		errno = EINVAL;
		warning("error in size of file '%s'", path);
		goto fail;
	}

 out:
	put_tracing_file(path);
	return 0;
 fail:
	put_tracing_file(path);
	return -1;
}

static int save_tracing_file_data(struct tracecmd_output *handle,
						const char *filename)
{
	unsigned long long endian8;
	char *file = NULL;
	struct stat st;
	off64_t check_size;
	off64_t size;
	int ret = -1;

	file = get_tracing_file(handle, filename);
	if (!file)
		return -1;

	ret = stat(file, &st);
	if (ret >= 0) {
		size = get_size(file);
		endian8 = convert_endian_8(handle, size);
		if (do_write_check(handle, &endian8, 8))
			goto out_free;
		check_size = copy_file(handle, file);
		if (size != check_size) {
			errno = EINVAL;
			warning("error in size of file '%s'", file);
			goto out_free;
		}
	} else {
		size = 0;
		endian8 = convert_endian_8(handle, size);
		if (do_write_check(handle, &endian8, 8))
			goto out_free;
	}
	ret = 0;

out_free:
	put_tracing_file(file);
	return ret;
}

static struct tracecmd_output *
create_file_fd(int fd, struct tracecmd_input *ihandle,
	       const char *tracing_dir,
	       const char *kallsyms,
	       struct tracecmd_event_list *list,
	       struct tracecmd_msg_handle *msg_handle)
{
	struct tracecmd_output *handle;
	struct pevent *pevent;
	char buf[BUFSIZ];
	int endian4;

	handle = malloc(sizeof(*handle));
	if (!handle)
		return NULL;
	memset(handle, 0, sizeof(*handle));

	handle->fd = fd;
	if (tracing_dir) {
		handle->tracing_dir = strdup(tracing_dir);
		if (!handle->tracing_dir)
			goto out_free;
	}

	handle->msg_handle = msg_handle;

	list_head_init(&handle->options);

	buf[0] = 23;
	buf[1] = 8;
	buf[2] = 68;
	memcpy(buf + 3, "tracing", 7);

	if (do_write_check(handle, buf, 10))
		goto out_free;

	if (do_write_check(handle, FILE_VERSION_STRING, strlen(FILE_VERSION_STRING) + 1))
		goto out_free;

	/* get endian and page size */
	if (ihandle) {
		pevent = tracecmd_get_pevent(ihandle);
		/* Use the pevent of the ihandle for later writes */
		handle->pevent = tracecmd_get_pevent(ihandle);
		pevent_ref(pevent);
		if (pevent->file_bigendian)
			buf[0] = 1;
		else
			buf[0] = 0;
		handle->page_size = tracecmd_page_size(ihandle);
	} else {
		if (tracecmd_host_bigendian())
			buf[0] = 1;
		else
			buf[0] = 0;
		handle->page_size = getpagesize();
	}

	if (do_write_check(handle, buf, 1))
		goto out_free;

	/* save size of long (this may not be what the kernel is) */
	buf[0] = sizeof(long);
	if (do_write_check(handle, buf, 1))
		goto out_free;

	endian4 = convert_endian_4(handle, handle->page_size);
	if (do_write_check(handle, &endian4, 4))
		goto out_free;

	if (ihandle)
		return handle;

	if (read_header_files(handle))
		goto out_free;
	if (read_ftrace_files(handle))
		goto out_free;
	if (read_event_files(handle, list))
		goto out_free;
	if (read_proc_kallsyms(handle, kallsyms))
		goto out_free;
	if (read_ftrace_printk(handle))
		goto out_free;

	/*
	 * Save the command lines;
	 */
	if (save_tracing_file_data(handle, "saved_cmdlines") < 0)
		goto out_free;

	return handle;

 out_free:
	tracecmd_output_close(handle);
	return NULL;
}

static struct tracecmd_output *create_file(const char *output_file,
					   struct tracecmd_input *ihandle,
					   const char *tracing_dir,
					   const char *kallsyms,
					   struct tracecmd_event_list *list)
{
	struct tracecmd_output *handle;
	int fd;

	fd = open(output_file, O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
	if (fd < 0)
		return NULL;

	handle = create_file_fd(fd, ihandle, tracing_dir, kallsyms, list, NULL);
	if (!handle) {
		close(fd);
		unlink(output_file);
	}

	return handle;
}

/**
 * tracecmd_add_option - add options to the file
 * @handle: the output file handle name
 * @id: the id of the option
 * @size: the size of the option data
 * @data: the data to write to the file.
 *
 * Returns handle to update option if needed.
 *  Just the content can be updated, with smaller or equal to
 *  content than the specified size.
 */
struct tracecmd_option *
tracecmd_add_option(struct tracecmd_output *handle,
		    unsigned short id, int size, const void *data)
{
	struct tracecmd_option *option;

	/*
	 * We can only add options before they were written.
	 * This may change in the future.
	 */
	if (handle->options_written)
		return NULL;

	handle->nr_options++;

	option = malloc(sizeof(*option));
	if (!option) {
		warning("Could not allocate space for option");
		return NULL;
	}

	option->id = id;
	option->size = size;
	option->data = malloc(size);
	if (!option->data) {
		warning("Insufficient memory");
		free(option);
		return NULL;
	}

	/* Some IDs (like TRACECMD_OPTION_TRACECLOCK) pass 0 / NULL data */
	if (size)
		memcpy(option->data, data, size);

	list_add_tail(&option->list, &handle->options);

	return option;
}

static int add_options(struct tracecmd_output *handle)
{
	struct tracecmd_option *options;
	unsigned short option;
	unsigned short endian2;
	unsigned int endian4;

	/* If already written, ignore */
	if (handle->options_written)
		return 0;

	if (do_write_check(handle, "options  ", 10))
		return -1;

	list_for_each_entry(options, &handle->options, list) {
		endian2 = convert_endian_2(handle, options->id);
		if (do_write_check(handle, &endian2, 2))
			return -1;

		endian4 = convert_endian_4(handle, options->size);
		if (do_write_check(handle, &endian4, 4))
			return -1;

		/* Save the data location in case it needs to be updated */
		options->offset = lseek64(handle->fd, 0, SEEK_CUR);

		if (do_write_check(handle, options->data,
				   options->size))
			return -1;
	}

	option = TRACECMD_OPTION_DONE;

	if (do_write_check(handle, &option, 2))
		return -1;

	handle->options_written = 1;

	return 0;
}

int tracecmd_update_option(struct tracecmd_output *handle,
			   struct tracecmd_option *option, int size,
			   const void *data)
{
	tsize_t offset;
	stsize_t ret;

	if (size > option->size) {
		warning("Can't update option with more data than allocated");
		return -1;
	}

	if (!handle->options_written) {
		/* Hasn't been written yet. Just update current pointer */
		option->size = size;
		memcpy(option->data, data, size);
		return 0;
	}

	/* Save current offset */
	offset = lseek64(handle->fd, 0, SEEK_CUR);

	ret = lseek64(handle->fd, option->offset, SEEK_SET);
	if (ret == (off64_t)-1) {
		warning("could not seek to %lld\n", option->offset);
		return -1;
	}

	if (do_write_check(handle, data, size))
		return -1;

	ret = lseek64(handle->fd, offset, SEEK_SET);
	if (ret == (off64_t)-1) {
		warning("could not seek to %lld\n", offset);
		return -1;
	}

	return 0;
}

struct tracecmd_option *
tracecmd_add_buffer_option(struct tracecmd_output *handle, const char *name,
			   int cpus)
{
	struct tracecmd_option *option;
	char *buf;
	int size = 8 + strlen(name) + 1;

	buf = malloc(size);
	if (!buf) {
		warning("Failed to malloc buffer");
		return NULL;
	}
	*(tsize_t *)buf = 0;
	strcpy(buf + 8, name);

	option = tracecmd_add_option(handle, TRACECMD_OPTION_BUFFER, size, buf);
	free(buf);

	/*
	 * In case a buffer instance has different number of CPUs as the
	 * local machine.
	 */
	if (cpus)
		tracecmd_add_option(handle, TRACECMD_OPTION_CPUCOUNT,
				    sizeof(int), &cpus);

	return option;
}

struct tracecmd_output *tracecmd_create_file_latency(const char *output_file, int cpus)
{
	struct tracecmd_output *handle;
	char *path;

	handle = create_file(output_file, NULL, NULL, NULL, &all_event_list);
	if (!handle)
		return NULL;

	cpus = convert_endian_4(handle, cpus);
	if (do_write_check(handle, &cpus, 4))
		goto out_free;

	if (add_options(handle) < 0)
		goto out_free;

	if (do_write_check(handle, "latency  ", 10))
		goto out_free;

	path = get_tracing_file(handle, "trace");
	if (!path)
		goto out_free;

	copy_file(handle, path);

	put_tracing_file(path);

	return handle;

out_free:
	tracecmd_output_close(handle);
	return NULL;
}

static int __tracecmd_append_cpu_data(struct tracecmd_output *handle,
				      int cpus, char * const *cpu_data_files)
{
	off64_t *offsets = NULL;
	unsigned long long *sizes = NULL;
	off64_t offset;
	unsigned long long endian8;
	off64_t check_size;
	char *file;
	struct stat st;
	int ret;
	int i;

	if (do_write_check(handle, "flyrecord", 10))
		goto out_free;

	offsets = malloc(sizeof(*offsets) * cpus);
	if (!offsets)
		goto out_free;
	sizes = malloc(sizeof(*sizes) * cpus);
	if (!sizes)
		goto out_free;

	offset = lseek64(handle->fd, 0, SEEK_CUR);

	/* hold any extra data for data */
	offset += cpus * (16);

	/*
	 * Unfortunately, the trace_clock data was placed after the
	 * cpu data, and wasn't accounted for with the offsets.
	 * We need to save room for the trace_clock file. This means
	 * we need to find the size of it before we define the final
	 * offsets.
	 */
	file = get_tracing_file(handle, "trace_clock");
	if (!file)
		goto out_free;

	/* Save room for storing the size */
	offset += 8;

	ret = stat(file, &st);
	if (ret >= 0)
		offset += get_size(file);

	put_tracing_file(file);

	/* Page align offset */
	offset = (offset + (handle->page_size - 1)) & ~(handle->page_size - 1);

	for (i = 0; i < cpus; i++) {
		file = cpu_data_files[i];
		ret = stat(file, &st);
		if (ret < 0) {
			warning("can not stat '%s'", file);
			goto out_free;
		}
		offsets[i] = offset;
		sizes[i] = st.st_size;
		offset += st.st_size;
		offset = (offset + (handle->page_size - 1)) & ~(handle->page_size - 1);

		endian8 = convert_endian_8(handle, offsets[i]);
		if (do_write_check(handle, &endian8, 8))
			goto out_free;
		endian8 = convert_endian_8(handle, sizes[i]);
		if (do_write_check(handle, &endian8, 8))
			goto out_free;
	}

	if (save_tracing_file_data(handle, "trace_clock") < 0)
		goto out_free;

	for (i = 0; i < cpus; i++) {
		if (!quiet)
			fprintf(stderr, "CPU%d data recorded at offset=0x%llx\n",
				i, (unsigned long long) offsets[i]);
		offset = lseek64(handle->fd, offsets[i], SEEK_SET);
		if (offset == (off64_t)-1) {
			warning("could not seek to %lld\n", offsets[i]);
			goto out_free;
		}
		check_size = copy_file(handle, cpu_data_files[i]);
		if (check_size != sizes[i]) {
			errno = EINVAL;
			warning("did not match size of %lld to %lld",
			    check_size, sizes[i]);
			goto out_free;
		}
		if (!quiet)
			fprintf(stderr, "    %llu bytes in size\n",
				(unsigned long long)check_size);
	}

	free(offsets);
	free(sizes);

	return 0;

 out_free:
	free(offsets);
	free(sizes);
	return -1;
}

int tracecmd_append_cpu_data(struct tracecmd_output *handle,
			     int cpus, char * const *cpu_data_files)
{
	int endian4;

	endian4 = convert_endian_4(handle, cpus);
	if (do_write_check(handle, &endian4, 4))
		return -1;

	if (add_options(handle) < 0)
		return -1;

	return __tracecmd_append_cpu_data(handle, cpus, cpu_data_files);
}

int tracecmd_append_buffer_cpu_data(struct tracecmd_output *handle,
				    struct tracecmd_option *option,
				    int cpus, char * const *cpu_data_files)
{
	tsize_t offset;
	stsize_t ret;

	offset = lseek64(handle->fd, 0, SEEK_CUR);

	/* Go to the option data, where will write the offest */
	ret = lseek64(handle->fd, option->offset, SEEK_SET);
	if (ret == (off64_t)-1) {
		warning("could not seek to %lld\n", option->offset);
		return -1;
	}

	if (do_write_check(handle, &offset, 8))
		return -1;

	/* Go back to end of file */
	ret = lseek64(handle->fd, offset, SEEK_SET);
	if (ret == (off64_t)-1) {
		warning("could not seek to %lld\n", offset);
		return -1;
	}

	return __tracecmd_append_cpu_data(handle, cpus, cpu_data_files);
}

int tracecmd_attach_cpu_data_fd(int fd, int cpus, char * const *cpu_data_files)
{
	struct tracecmd_input *ihandle;
	struct tracecmd_output *handle;
	struct pevent *pevent;
	int ret = -1;

	/* Move the file descriptor to the beginning */
	if (lseek(fd, 0, SEEK_SET) == (off_t)-1)
		return -1;

	/* get a input handle from this */
	ihandle = tracecmd_alloc_fd(fd);
	if (!ihandle)
		return -1;

	/* move the file descriptor to the end */
	if (lseek(fd, 0, SEEK_END) == (off_t)-1)
		goto out_free;

	/* create a partial output handle */

	handle = malloc(sizeof(*handle));
	if (!handle)
		goto out_free;
	memset(handle, 0, sizeof(*handle));

	handle->fd = fd;

	/* get endian and page size */
	pevent = tracecmd_get_pevent(ihandle);
	/* Use the pevent of the ihandle for later writes */
	handle->pevent = tracecmd_get_pevent(ihandle);
	pevent_ref(pevent);
	handle->page_size = tracecmd_page_size(ihandle);
	list_head_init(&handle->options);

	if (tracecmd_append_cpu_data(handle, cpus, cpu_data_files) >= 0)
		ret = 0;

	tracecmd_output_close(handle);
 out_free:
	tracecmd_close(ihandle);
	return ret;
}

int tracecmd_attach_cpu_data(char *file, int cpus, char * const *cpu_data_files)
{
	int fd;

	fd = open(file, O_RDWR);
	if (fd < 0)
		return -1;

	return tracecmd_attach_cpu_data_fd(fd, cpus, cpu_data_files);
}

struct tracecmd_output *
tracecmd_create_file_glob(const char *output_file,
			  int cpus, char * const *cpu_data_files,
			  struct tracecmd_event_list *list)
{
	struct tracecmd_output *handle;

	handle = create_file(output_file, NULL, NULL, NULL, list);
	if (!handle)
		return NULL;

	if (tracecmd_append_cpu_data(handle, cpus, cpu_data_files) < 0) {
		tracecmd_output_close(handle);
		return NULL;
	}

	return handle;
}

struct tracecmd_output *tracecmd_create_file(const char *output_file,
					     int cpus, char * const *cpu_data_files)
{
	return tracecmd_create_file_glob(output_file, cpus,
					 cpu_data_files, &all_event_list);
}

struct tracecmd_output *tracecmd_create_init_fd(int fd)
{
	return create_file_fd(fd, NULL, NULL, NULL, &all_event_list, NULL);
}

struct tracecmd_output *
tracecmd_create_init_fd_msg(struct tracecmd_msg_handle *msg_handle,
			    struct tracecmd_event_list *list)
{
	return create_file_fd(msg_handle->fd, NULL, NULL, NULL, list, msg_handle);
}

struct tracecmd_output *
tracecmd_create_init_fd_glob(int fd, struct tracecmd_event_list *list)
{
	return create_file_fd(fd, NULL, NULL, NULL, list, NULL);
}

struct tracecmd_output *
tracecmd_create_init_file_glob(const char *output_file,
			       struct tracecmd_event_list *list)
{
	return create_file(output_file, NULL, NULL, NULL, list);
}

struct tracecmd_output *tracecmd_create_init_file(const char *output_file)
{
	return create_file(output_file, NULL, NULL, NULL, &all_event_list);
}

struct tracecmd_output *tracecmd_create_init_file_override(const char *output_file,
							   const char *tracing_dir,
							   const char *kallsyms)
{
	return create_file(output_file, NULL, tracing_dir, kallsyms, &all_event_list);
}

/**
 * tracecmd_copy - copy the headers of one trace.dat file for another
 * @ihandle: input handle of the trace.dat file to copy
 * @file: the trace.dat file to create
 *
 * Reads the header information and creates a new trace data file
 * with the same characteristics (events and all) and returns
 * tracecmd_output handle to this new file.
 */
struct tracecmd_output *tracecmd_copy(struct tracecmd_input *ihandle,
				      const char *file)
{
	struct tracecmd_output *handle;

	handle = create_file(file, ihandle, NULL, NULL, &all_event_list);
	if (!handle)
		return NULL;

	if (tracecmd_copy_headers(ihandle, handle->fd) < 0)
		goto out_free;

	/* The file is all ready to have cpu data attached */
	return handle;

out_free:
	tracecmd_output_close(handle);
	return NULL;
}
