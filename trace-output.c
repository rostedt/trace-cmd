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
#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
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

#include "trace-cmd-local.h"
#include "version.h"

struct tracecmd_output {
	int		fd;
	int		page_size;
	int		cpus;
	struct pevent	*pevent;
	char		*tracing_dir;
};

static int
do_write_check(struct tracecmd_output *handle, void *data, int size)
{
	return __do_write_check(handle->fd, data, size);
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

void tracecmd_output_close(struct tracecmd_output *handle)
{
	if (!handle)
		return;

	if (handle->fd >= 0) {
		close(handle->fd);
		handle->fd = -1;
	}

	if (handle->tracing_dir)
		free(handle->tracing_dir);

	if (handle->pevent)
		pevent_unref(handle->pevent);

	free(handle);
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
	if (fd < 0)
		die("Can't read '%s'", file);
	size = get_size_fd(fd);
	close(fd);

	return size;
}

static unsigned long long copy_file_fd(struct tracecmd_output *handle, int fd)
{
	unsigned long long size = 0;
	char buf[BUFSIZ];
	int r;

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

static unsigned long long copy_file(struct tracecmd_output *handle,
				    const char *file)
{
	unsigned long long size = 0;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		die("Can't read '%s'", file);
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

	tracing = find_tracing_dir(handle);
	if (!tracing)
		return NULL;

	file = malloc_or_die(strlen(tracing) + strlen(name) + 2);
	if (!file)
		return NULL;

	sprintf(file, "%s/%s", tracing, name);
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
	if (fd < 0)
		die ("Can't %s ftrace", set ? "enable" : "disable");

	if (write(fd, val, 1) < 0)
		ret = -1;
	close(fd);

	return ret;
}

static int read_header_files(struct tracecmd_output *handle)
{
	unsigned long long size, check_size, endian8;
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
	if (fd < 0)
		die("can't read '%s'", path);

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

static int copy_event_system(struct tracecmd_output *handle, const char *sys)
{
	unsigned long long size, check_size, endian8;
	struct dirent *dent;
	struct stat st;
	char *format;
	DIR *dir;
	int endian4;
	int count = 0;
	int ret;

	dir = opendir(sys);
	if (!dir) {
		warning("can't read directory '%s'", sys);
		return -1;
	}

	while ((dent = readdir(dir))) {
		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;
		format = malloc_or_die(strlen(sys) + strlen(dent->d_name) + 10);
		if (!format)
			return -1;
		sprintf(format, "%s/%s/format", sys, dent->d_name);
		ret = stat(format, &st);
		free(format);
		if (ret < 0)
			continue;
		count++;
	}

	endian4 = convert_endian_4(handle, count);
	if (do_write_check(handle, &endian4, 4))
		return -1;

	rewinddir(dir);
	while ((dent = readdir(dir))) {
		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;
		format = malloc_or_die(strlen(sys) + strlen(dent->d_name) + 10);
		if (!format)
			return -1;
		sprintf(format, "%s/%s/format", sys, dent->d_name);
		ret = stat(format, &st);

		if (ret >= 0) {
			/* unfortunately, you can not stat debugfs files for size */
			size = get_size(format);
			endian8 = convert_endian_8(handle, size);
			if (do_write_check(handle, &endian8, 8))
				goto out_free;
			check_size = copy_file(handle, format);
			if (size != check_size) {
				warning("error in size of file '%s'", format);
				goto out_free;
			}
		}

		free(format);
	}

	return 0;

 out_free:
	free(format);
	return -1;
}

static int read_ftrace_files(struct tracecmd_output *handle)
{
	char *path;
	int ret;

	path = get_tracing_file(handle, "events/ftrace");
	if (!path)
		return -1;

	ret = copy_event_system(handle, path);

	put_tracing_file(path);

	return ret;
}

static int read_event_files(struct tracecmd_output *handle)
{
	struct dirent *dent;
	struct stat st;
	char *path;
	char *sys;
	DIR *dir;
	int count = 0;
	int endian4;
	int ret;

	path = get_tracing_file(handle, "events");
	if (!path)
		return -1;

	dir = opendir(path);
	if (!dir)
		die("can't read directory '%s'", path);

	while ((dent = readdir(dir))) {
		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0 ||
		    strcmp(dent->d_name, "ftrace") == 0)
			continue;
		ret = -1;
		sys = malloc_or_die(strlen(path) + strlen(dent->d_name) + 2);
		if (!sys)
			goto out_close_dir;
		sprintf(sys, "%s/%s", path, dent->d_name);
		ret = stat(sys, &st);
		free(sys);
		if (ret < 0)
			continue;
		if (S_ISDIR(st.st_mode))
			count++;
	}

	ret = -1;
	endian4 = convert_endian_4(handle, count);
	if (do_write_check(handle, &endian4, 4))
		goto out_close_dir;

	rewinddir(dir);
	while ((dent = readdir(dir))) {
		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0 ||
		    strcmp(dent->d_name, "ftrace") == 0)
			continue;
		ret = -1;
		sys = malloc_or_die(strlen(path) + strlen(dent->d_name) + 2);
		if (!sys)
			goto out_close_dir;

		sprintf(sys, "%s/%s", path, dent->d_name);
		ret = stat(sys, &st);
		if (ret >= 0) {
			if (S_ISDIR(st.st_mode)) {
				if (do_write_check(handle, dent->d_name,
						   strlen(dent->d_name) + 1)) {
					free(sys);
					ret = -1;
					goto out_close_dir;
				}
				copy_event_system(handle, sys);
			}
		}
		free(sys);
	}

	put_tracing_file(path);

	ret = 0;

 out_close_dir:
	closedir(dir);
	return ret;
}

static int read_proc_kallsyms(struct tracecmd_output *handle)
{
	unsigned int size, check_size, endian4;
	const char *path = "/proc/kallsyms";
	struct stat st;
	int ret;

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
	const char *path;
	struct stat st;
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

static struct tracecmd_output *
create_file_fd(int fd, int cpus, struct tracecmd_input *ihandle)
{
	struct tracecmd_output *handle;
	unsigned long long endian8;
	struct pevent *pevent;
	char buf[BUFSIZ];
	char *file = NULL;
	struct stat st;
	off64_t check_size;
	off64_t size;
	int endian4;
	int ret;

	handle = malloc(sizeof(*handle));
	if (!handle)
		return NULL;
	memset(handle, 0, sizeof(*handle));

	handle->fd = fd;

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
	if (read_event_files(handle))
		goto out_free;
	if (read_proc_kallsyms(handle))
		goto out_free;
	if (read_ftrace_printk(handle))
		goto out_free;

	/*
	 * Save the command lines;
	 */
	file = get_tracing_file(handle, "saved_cmdlines");
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
	put_tracing_file(file);
	file = NULL;

	return handle;

 out_free:
	tracecmd_output_close(handle);
	return NULL;
}

static struct tracecmd_output *create_file(const char *output_file, int cpus,
					   struct tracecmd_input *ihandle)
{
	struct tracecmd_output *handle;
	int fd;

	fd = open(output_file, O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
	if (fd < 0)
		return NULL;

	handle = create_file_fd(fd, cpus, ihandle);
	if (!handle) {
		close(fd);
		unlink(output_file);
	}

	return handle;
}

static int add_options(struct tracecmd_output *handle)
{
	unsigned short option;

	if (do_write_check(handle, "options  ", 10))
		return -1;

	/*
	 * Right now we have no options, but this is where options
	 * will be added in the future.
	 */

	option = TRACECMD_OPTION_DONE;

	if (do_write_check(handle, &option, 2))
		return -1;

	return 0;
}

struct tracecmd_output *tracecmd_create_file_latency(const char *output_file, int cpus)
{
	struct tracecmd_output *handle;
	char *path;

	handle = create_file(output_file, cpus, NULL);
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

int tracecmd_append_cpu_data(struct tracecmd_output *handle,
			     int cpus, char * const *cpu_data_files)
{
	off64_t *offsets = NULL;
	unsigned long long *sizes = NULL;
	off64_t offset;
	unsigned long long endian8;
	off64_t check_size;
	char *file;
	struct stat st;
	int endian4;
	int ret;
	int i;

	endian4 = convert_endian_4(handle, cpus);
	if (do_write_check(handle, &endian4, 4))
		goto out_free;

	if (add_options(handle) < 0)
		goto out_free;

	if (do_write_check(handle, "flyrecord", 10))
		goto out_free;

	offsets = malloc_or_die(sizeof(*offsets) * cpus);
	if (!offsets)
		goto out_free;
	sizes = malloc_or_die(sizeof(*sizes) * cpus);
	if (!sizes)
		goto out_free;

	offset = lseek64(handle->fd, 0, SEEK_CUR);

	/* hold any extra data for data */
	offset += cpus * (16);
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

	for (i = 0; i < cpus; i++) {
		fprintf(stderr, "offset=%llx\n", offsets[i]);
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
	}

	free(offsets);
	free(sizes);

	return 0;

 out_free:
	free(offsets);
	free(sizes);

	tracecmd_output_close(handle);
	return -1;
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
		return -1;
	memset(handle, 0, sizeof(*handle));

	handle->fd = fd;

	/* get endian and page size */
	pevent = tracecmd_get_pevent(ihandle);
	/* Use the pevent of the ihandle for later writes */
	handle->pevent = tracecmd_get_pevent(ihandle);
	pevent_ref(pevent);
	handle->page_size = tracecmd_page_size(ihandle);

	if (tracecmd_append_cpu_data(handle, cpus, cpu_data_files) < 0)
		goto out_free;

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

struct tracecmd_output *tracecmd_create_file(const char *output_file,
					     int cpus, char * const *cpu_data_files)
{
	struct tracecmd_output *handle;

	handle = create_file(output_file, cpus, NULL);
	if (!handle)
		return NULL;

	if (tracecmd_append_cpu_data(handle, cpus, cpu_data_files) < 0)
		return NULL;

	return handle;
}

struct tracecmd_output *
tracecmd_create_init_fd(int fd, int cpus)
{
	struct tracecmd_output *handle;

	handle = create_file_fd(fd, cpus, NULL);
	if (!handle)
		return NULL;

	return handle;
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

	handle = create_file(file, tracecmd_cpus(ihandle), ihandle);
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
