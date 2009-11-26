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

#include "trace-cmd.h"

struct tracecmd_handle {
	int		fd;
	int		long_size;
	int		page_size;
	int		print_events;
};

static int do_read(struct tracecmd_handle *handle, void *data, int size)
{
	int tot = 0;
	int r;

	do {
		r = read(handle->fd, data, size);
		tot += r;

		if (!r)
			break;
		if (r < 0)
			return r;
	} while (tot != size);

	return tot;
}

static int
do_read_check(struct tracecmd_handle *handle, void *data, int size)
{
	int ret;

	ret = do_read(handle, data, size);
	if (ret < 0)
		return ret;
	if (ret != size)
		return -1;

	return 0;
}

static char *read_string(struct tracecmd_handle *handle)
{
	char buf[BUFSIZ];
	char *str = NULL;
	int size = 0;
	int i;
	int r;

	for (;;) {
		r = do_read(handle, buf, BUFSIZ);
		if (r < 0)
			goto fail;
		if (!r)
			goto fail;

		for (i = 0; i < r; i++) {
			if (!buf[i])
				break;
		}
		if (i < r)
			break;
			
		if (str) {
			size += BUFSIZ;
			str = realloc(str, size);
			if (!str)
				return NULL;
			memcpy(str + (size - BUFSIZ), buf, BUFSIZ);
		} else {
			size = BUFSIZ;
			str = malloc(size);
			if (!str)
				return NULL;
			memcpy(str, buf, size);	
		}
	}

	/* move the file descriptor to the end of the string */
	r = lseek(handle->fd, -(r - (i+1)), SEEK_CUR);
	if (r < 0)
		goto fail;

	if (str) {
		size += i + 1;
		str = realloc(str, size);
		if (!str)
			return NULL;
		memcpy(str + (size - i), buf, i);
		str[size] = 0;
	} else {
		size = i + 1;
		str = malloc(i);
		if (!str)
			return NULL;
		memcpy(str, buf, i);
		str[i] = 0;
	}

	return str;

 fail:
	if (str)
		free(str);
	return NULL;
}

static unsigned int read4(struct tracecmd_handle *handle)
{
	unsigned int data;

	if (do_read_check(handle, &data, 4))
		return -1;

	return __data2host4(data);
}

static unsigned long long read8(struct tracecmd_handle *handle)
{
	unsigned long long data;

	if (do_read_check(handle, &data, 8))
		return -1;

	return __data2host8(data);
}

static int read_header_files(struct tracecmd_handle *handle)
{
	long long size;
	char *header;
	char buf[BUFSIZ];

	if (do_read_check(handle, buf, 12))
		return -1;

	if (memcmp(buf, "header_page", 12) != 0)
		return -1;

	size = read8(handle);
	if (size < 0)
		return -1;

	header = malloc(size);
	if (!header)
		return -1;

	if (do_read_check(handle, header, size))
		goto failed_read;

	pevent_parse_header_page(header, size);
	free(header);

	/*
	 * The size field in the page is of type long,
	 * use that instead, since it represents the kernel.
	 */
	handle->long_size = header_page_size_size;

	if (do_read_check(handle, buf, 13))
		return -1;

	if (memcmp(buf, "header_event", 13) != 0)
		return -1;

	size = read8(handle);
	if (size < 0)
		return -1;

	header = malloc(size);
	if (!header)
		return -1;

	if (do_read_check(handle, header, size))
		goto failed_read;

	free(header);

	return 0;

 failed_read:
	free(header);
	return -1;
}

static int read_ftrace_file(struct tracecmd_handle *handle,
			    unsigned long long size)
{
	char *buf;

	buf = malloc(size);
	if (!buf)
		return -1;
	if (do_read_check(handle, buf, size)) {
		free(buf);
		return -1;
	}

	pevent_parse_event(buf, size, "ftrace");
	free(buf);

	return 0;
}

static int read_event_file(struct tracecmd_handle *handle,
			   char *system, unsigned long long size)
{
	char *buf;

	buf = malloc(size+1);
	if (!buf)
		return -1;

	if (do_read_check(handle,buf, size)) {
		free(buf);
		return -1;
	}

	buf[size] = 0;
	if (handle->print_events)
		printf("%s\n", buf);
	pevent_parse_event(buf, size, system);
	free(buf);

	return 0;
}

static int read_ftrace_files(struct tracecmd_handle *handle)
{
	unsigned long long size;
	int count;
	int ret;
	int i;

	count = read4(handle);
	if (count < 0)
		return -1;

	for (i = 0; i < count; i++) {
		size = read8(handle);
		if (size < 0)
			return -1;
		ret = read_ftrace_file(handle, size);
		if (ret < 0)
			return -1;
	}

	return 0;
}

static int read_event_files(struct tracecmd_handle *handle)
{
	unsigned long long size;
	char *system;
	int systems;
	int count;
	int ret;
	int i,x;

	systems = read4(handle);
	if (systems < 0)
		return -1;

	for (i = 0; i < systems; i++) {
		system = read_string(handle);
		if (!system)
			return -1;

		count = read4(handle);
		if (count < 0)
			goto failed;

		for (x=0; x < count; x++) {
			size = read8(handle);
			if (size < 0)
				goto failed;

			ret = read_event_file(handle, system, size);
			if (ret < 0)
				goto failed;
		}
		free(system);
	}

	return 0;

 failed:
	free(system);
	return -1;
}

static int read_proc_kallsyms(struct tracecmd_handle *handle)
{
	int size;
	char *buf;

	size = read4(handle);
	if (!size)
		return 0; /* OK? */

	if (size < 0)
		return -1;

	buf = malloc(size);
	if (!buf)
		return -1;
	if (do_read_check(handle, buf, size)){
		free(buf);
		return -1;
	}

	parse_proc_kallsyms(buf, size);

	free(buf);
	return 0;
}

static int read_ftrace_printk(struct tracecmd_handle *handle)
{
	int size;
	char *buf;

	size = read4(handle);
	if (!size)
		return 0; /* OK? */

	if (size < 0)
		return -1;

	buf = malloc(size);
	if (!buf)
		return -1;
	if (do_read_check(handle, buf, size)) {
		free(buf);
		return -1;
	}

	parse_ftrace_printk(buf, size);

	free(buf);

	return 0;
}

int tracecmd_read_headers(struct tracecmd_handle *handle)
{
	int ret;

	ret = read_header_files(handle);
	if (ret < 0)
		return -1;

	ret = read_ftrace_files(handle);
	if (ret < 0)
		return -1;

	ret = read_event_files(handle);
	if (ret < 0)
		return -1;

	ret = read_proc_kallsyms(handle);
	if (ret < 0)
		return -1;

	ret = read_ftrace_printk(handle);
	if (ret < 0)
		return -1;


	trace_load_plugins();

	return 0;
}

struct tracecmd_handle *tracecmd_open(int fd)
{
	struct tracecmd_handle *handle;
	char test[] = { 23, 8, 68 };
	char *version;
	char buf[BUFSIZ];

	handle = malloc(sizeof(*handle));
	if (!handle)
		return NULL;

	handle->fd = fd;

	if (do_read_check(handle, buf, 3))
		goto failed_read;

	if (memcmp(buf, test, 3) != 0)
		goto failed_read;

	if (do_read_check(handle, buf, 7))
		goto failed_read;
	if (memcmp(buf, "tracing", 7) != 0)
		goto failed_read;

	version = read_string(handle);
	if (!version)
		goto failed_read;
	printf("version = %s\n", version);
	free(version);

	if (do_read_check(handle, buf, 1))
		goto failed_read;

	/*
	 * TODO:
	 *  Need to make these part of the handle.
	 *  But they are currently used by parsevent.
	 *  That may need a handler too.
	 */ 
	file_bigendian = buf[0];
	host_bigendian = bigendian();

	do_read_check(handle, buf, 1);
	handle->long_size = buf[0];

	handle->page_size = read4(handle);

	return handle;

 failed_read:
	free(handle);

	return NULL;
}

int tracecmd_long_size(struct tracecmd_handle *handle)
{
	return handle->long_size;
}

int tracecmd_page_size(struct tracecmd_handle *handle)
{
	return handle->page_size;
}
