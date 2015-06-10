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
#include <stdbool.h>
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
#include <regex.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "trace-cmd-local.h"
#include "kbuffer.h"
#include "list.h"

#define MISSING_EVENTS (1 << 31)
#define MISSING_STORED (1 << 30)

#define COMMIT_MASK ((1 << 27) - 1)

/* for debugging read instead of mmap */
static int force_read = 0;

struct page {
	struct list_head	list;
	off64_t			offset;
	struct tracecmd_input	*handle;
	void			*map;
	int			ref_count;
	long long		lost_events;
#if DEBUG_RECORD
	struct pevent_record	*records;
#endif
};

struct cpu_data {
	/* the first two never change */
	unsigned long long	file_offset;
	unsigned long long	file_size;
	unsigned long long	offset;
	unsigned long long	size;
	unsigned long long	timestamp;
	struct list_head	pages;
	struct pevent_record	*next;
	struct page		*page;
	struct kbuffer		*kbuf;
	int			cpu;
	int			pipe_fd;
};

struct input_buffer_instance {
	char			*name;
	size_t			offset;
};

struct tracecmd_input {
	struct pevent		*pevent;
	struct plugin_list	*plugin_list;
	struct tracecmd_input	*parent;
	unsigned long		flags;
	int			fd;
	int			long_size;
	int			page_size;
	int			cpus;
	int			ref;
	int			nr_buffers;	/* buffer instances */
	bool			use_trace_clock;
	bool			read_page;
	bool			use_pipe;
	struct cpu_data 	*cpu_data;
	unsigned long long	ts_offset;
	char *			cpustats;
	char *			uname;
	struct input_buffer_instance	*buffers;

	struct tracecmd_ftrace	finfo;

	struct hook_list	*hooks;
	/* file information */
	size_t			header_files_start;
	size_t			ftrace_files_start;
	size_t			event_files_start;
	size_t			total_file_size;
};

__thread struct tracecmd_input *tracecmd_curr_thread_handle;

void tracecmd_set_flag(struct tracecmd_input *handle, int flag)
{
	handle->flags |= flag;
}

void tracecmd_clear_flag(struct tracecmd_input *handle, int flag)
{
	handle->flags &= ~flag;
}

unsigned long tracecmd_get_flags(struct tracecmd_input *handle)
{
	return handle->flags;
}

#if DEBUG_RECORD
static void remove_record(struct page *page, struct pevent_record *record)
{
	if (record->prev)
		record->prev->next = record->next;
	else
		page->records = record->next;
	if (record->next)
		record->next->prev = record->prev;
}
static void add_record(struct page *page, struct pevent_record *record)
{
	if (page->records)
		page->records->prev = record;
	record->next = page->records;
	record->prev = NULL;
	page->records = record;
}
static const char *show_records(struct list_head *pages)
{
	static char buf[BUFSIZ + 1];
	struct pevent_record *record;
	struct page *page;
	int len;

	memset(buf, 0, sizeof(buf));
	len = 0;
	list_for_each_entry(page, pages, list) {
		for (record = page->records; record; record = record->next) {
			int n;
			n = snprintf(buf+len, BUFSIZ - len, " 0x%lx", record->alloc_addr);
			len += n;
			if (len >= BUFSIZ)
				break;
		}
	}
	return buf;
}
#else
static inline void remove_record(struct page *page, struct pevent_record *record) {}
static inline void add_record(struct page *page, struct pevent_record *record) {}
static const char *show_records(struct list_head *pages)
{
	return "";
}
#endif

static int init_cpu(struct tracecmd_input *handle, int cpu);

static int do_read(struct tracecmd_input *handle, void *data, int size)
{
	int tot = 0;
	int r;

	do {
		r = read(handle->fd, data, size - tot);
		tot += r;

		if (!r)
			break;
		if (r < 0)
			return r;
	} while (tot != size);

	return tot;
}

static int
do_read_check(struct tracecmd_input *handle, void *data, int size)
{
	int ret;

	ret = do_read(handle, data, size);
	if (ret < 0)
		return ret;
	if (ret != size)
		return -1;

	return 0;
}

static char *read_string(struct tracecmd_input *handle)
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
		str = malloc(size);
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

static unsigned int read4(struct tracecmd_input *handle)
{
	struct pevent *pevent = handle->pevent;
	unsigned int data;

	if (do_read_check(handle, &data, 4))
		return -1;

	return __data2host4(pevent, data);
}

static unsigned long long read8(struct tracecmd_input *handle)
{
	struct pevent *pevent = handle->pevent;
	unsigned long long data;

	if (do_read_check(handle, &data, 8))
		return -1;

	return __data2host8(pevent, data);
}

static int read_header_files(struct tracecmd_input *handle)
{
	struct pevent *pevent = handle->pevent;
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

	pevent_parse_header_page(pevent, header, size, handle->long_size);
	free(header);

	/*
	 * The size field in the page is of type long,
	 * use that instead, since it represents the kernel.
	 */
	handle->long_size = pevent->header_page_size_size;

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

	handle->ftrace_files_start =
		lseek64(handle->fd, 0, SEEK_CUR);

	return 0;

 failed_read:
	free(header);
	return -1;
}

static int regex_event_buf(const char *file, int size, regex_t *epreg)
{
	char *buf;
	char *line;
	int ret;

	buf = malloc(size + 1);
	if (!buf)
		die("malloc");

	strncpy(buf, file, size);
	buf[size] = 0;

	/* get the name from the first line */
	line = strtok(buf, "\n");
	if (!line) {
		warning("No newline found in '%s'", buf);
		return 0;
	}
	/* skip name if it is there */
	if (strncmp(line, "name: ", 6) == 0)
		line += 6;

	ret = regexec(epreg, line, 0, NULL, 0) == 0;

	free(buf);

	return ret;
}

static int read_ftrace_file(struct tracecmd_input *handle,
			    unsigned long long size,
			    int print, regex_t *epreg)
{
	struct pevent *pevent = handle->pevent;
	char *buf;

	buf = malloc(size);
	if (!buf)
		return -1;
	if (do_read_check(handle, buf, size)) {
		free(buf);
		return -1;
	}

	if (epreg) {
		if (print || regex_event_buf(buf, size, epreg))
			printf("%.*s\n", (int)size, buf);
	} else {
		if (pevent_parse_event(pevent, buf, size, "ftrace"))
			pevent->parsing_failures = 1;
	}
	free(buf);

	return 0;
}

static int read_event_file(struct tracecmd_input *handle,
			   char *system, unsigned long long size,
			   int print, int *sys_printed,
			   regex_t *epreg)
{
	struct pevent *pevent = handle->pevent;
	char *buf;

	buf = malloc(size);
	if (!buf)
		return -1;

	if (do_read_check(handle, buf, size)) {
		free(buf);
		return -1;
	}

	if (epreg) {
		if (print || regex_event_buf(buf, size, epreg)) {
			if (!*sys_printed) {
				printf("\nsystem: %s\n", system);
				*sys_printed = 1;
			}
			printf("%.*s\n", (int)size, buf);
		}
	} else {
		if (pevent_parse_event(pevent, buf, size, system))
			pevent->parsing_failures = 1;
	}
	free(buf);

	return 0;
}

static int make_preg_files(const char *regex, regex_t *system,
			   regex_t *event, int *unique)
{
	char *buf;
	char *sstr;
	char *estr;
	int ret;

	/* unique is set if a colon is found */
	*unique = 0;

	/* split "system:event" into "system" and "event" */

	buf = strdup(regex);
	if (!buf)
		die("malloc");

	sstr = strtok(buf, ":");
	estr = strtok(NULL, ":");

	/* If no colon is found, set event == system */
	if (!estr)
		estr = sstr;
	else
		*unique = 1;

	ret = regcomp(system, sstr, REG_ICASE|REG_NOSUB);
	if (ret) {
		warning("Bad regular expression '%s'", sstr);
		goto out;
	}

	ret = regcomp(event, estr, REG_ICASE|REG_NOSUB);
	if (ret) {
		warning("Bad regular expression '%s'", estr);
		goto out;
	}

 out:
	free(buf);
	return ret;
}

static int read_ftrace_files(struct tracecmd_input *handle, const char *regex)
{
	unsigned long long size;
	regex_t spreg;
	regex_t epreg;
	regex_t *sreg = NULL;
	regex_t *ereg = NULL;
	int print_all = 0;
	int unique;
	int count;
	int ret;
	int i;

	if (regex) {
		sreg = &spreg;
		ereg = &epreg;
		ret = make_preg_files(regex, sreg, ereg, &unique);
		if (ret)
			return -1;

		if (regexec(sreg, "ftrace", 0, NULL, 0) == 0) {
			/*
			 * If the system matches a regex that did
			 * not contain a colon, then print all events.
			 */
			if (!unique)
				print_all = 1;
		} else if (unique) {
			/*
			 * The user specified a unique event that did
			 * not match the ftrace system. Don't print any
			 * events here.
			 */
			regfree(sreg);
			regfree(ereg);
			sreg = NULL;
			ereg = NULL;
		}
	}

	count = read4(handle);
	if (count < 0)
		return -1;

	for (i = 0; i < count; i++) {
		size = read8(handle);
		if (size < 0)
			return -1;
		ret = read_ftrace_file(handle, size, print_all, ereg);
		if (ret < 0)
			return -1;
	}

	handle->event_files_start =
		lseek64(handle->fd, 0, SEEK_CUR);

	if (sreg) {
		regfree(sreg);
		regfree(ereg);
	}

	return 0;
}

static int read_event_files(struct tracecmd_input *handle, const char *regex)
{
	unsigned long long size;
	char *system;
	regex_t spreg;
	regex_t epreg;
	regex_t *sreg = NULL;
	regex_t *ereg = NULL;
	regex_t *reg;
	int systems;
	int print_all;
	int sys_printed;
	int count;
	int unique;
	int ret;
	int i,x;

	if (regex) {
		sreg = &spreg;
		ereg = &epreg;
		ret = make_preg_files(regex, sreg, ereg, &unique);
		if (ret)
			return -1;
	}

	systems = read4(handle);
	if (systems < 0)
		return -1;

	for (i = 0; i < systems; i++) {
		system = read_string(handle);
		if (!system)
			return -1;

		sys_printed = 0;
		print_all = 0;
		reg = ereg;

		if (sreg) {
			if (regexec(sreg, system, 0, NULL, 0) == 0) {
				/*
				 * If the user passed in a regex that
				 * did not contain a colon, then we can
				 * print all the events of this system.
				 */
				if (!unique)
					print_all = 1;
			} else if (unique) {
				/*
				 * The user passed in a unique event that
				 * specified a specific system and event.
				 * Since this system doesn't match this
				 * event, then we don't print any events
				 * for this system.
				 */
				reg = NULL;
			}
		}

		count = read4(handle);
		if (count < 0)
			goto failed;

		for (x=0; x < count; x++) {
			size = read8(handle);
			if (size < 0)
				goto failed;

			ret = read_event_file(handle, system, size,
					      print_all, &sys_printed,
					      reg);
			if (ret < 0)
				goto failed;
		}
		free(system);
	}

	if (sreg) {
		regfree(sreg);
		regfree(ereg);
	}

	return 0;

 failed:
	if (sreg) {
		regfree(sreg);
		regfree(ereg);
	}

	free(system);
	return -1;
}

static int read_proc_kallsyms(struct tracecmd_input *handle)
{
	struct pevent *pevent = handle->pevent;
	int size;
	char *buf;

	size = read4(handle);
	if (!size)
		return 0; /* OK? */

	if (size < 0)
		return -1;

	buf = malloc(size+1);
	if (!buf)
		return -1;
	if (do_read_check(handle, buf, size)){
		free(buf);
		return -1;
	}
	buf[size] = 0;

	parse_proc_kallsyms(pevent, buf, size);

	free(buf);
	return 0;
}

static int read_ftrace_printk(struct tracecmd_input *handle)
{
	int size;
	char *buf;

	size = read4(handle);
	if (!size)
		return 0; /* OK? */

	if (size < 0)
		return -1;

	buf = malloc(size + 1);
	if (!buf)
		return -1;
	if (do_read_check(handle, buf, size)) {
		free(buf);
		return -1;
	}

	buf[size] = 0;

	parse_ftrace_printk(handle->pevent, buf, size);

	free(buf);

	return 0;
}

static int read_and_parse_cmdlines(struct tracecmd_input *handle);

/**
 * tracecmd_read_headers - read the header information from trace.dat
 * @handle: input handle for the trace.dat file
 *
 * This reads the trace.dat file for various information. Like the
 * format of the ring buffer, event formats, ftrace formats, kallsyms
 * and printk.
 */
int tracecmd_read_headers(struct tracecmd_input *handle)
{
	int ret;

	ret = read_header_files(handle);
	if (ret < 0)
		return -1;

	ret = read_ftrace_files(handle, NULL);
	if (ret < 0)
		return -1;

	ret = read_event_files(handle, NULL);
	if (ret < 0)
		return -1;

	ret = read_proc_kallsyms(handle);
	if (ret < 0)
		return -1;

	ret = read_ftrace_printk(handle);
	if (ret < 0)
		return -1;

	if (read_and_parse_cmdlines(handle) < 0)
		return -1;

	pevent_set_long_size(handle->pevent, handle->long_size);

	return 0;
}

static unsigned long long calc_page_offset(struct tracecmd_input *handle,
					   unsigned long long offset)
{
	return offset & ~(handle->page_size - 1);
}

static int read_page(struct tracecmd_input *handle, off64_t offset,
		     int cpu, void *map)
{
	off64_t save_seek;
	off64_t ret;

	if (handle->use_pipe) {
		ret = read(handle->cpu_data[cpu].pipe_fd, map, handle->page_size);
		/* Set EAGAIN if the pipe is empty */
		if (ret < 0) {
			errno = EAGAIN;
			return -1;

		} else if (ret == 0) {
			/* Set EINVAL when the pipe has closed */
			errno = EINVAL;
			return -1;
		}
		return 0;
	}

	/* other parts of the code may expect the pointer to not move */
	save_seek = lseek64(handle->fd, 0, SEEK_CUR);

	ret = lseek64(handle->fd, offset, SEEK_SET);
	if (ret < 0)
		return -1;
	ret = read(handle->fd, map, handle->page_size);
	if (ret < 0)
		return -1;

	/* reset the file pointer back */
	lseek64(handle->fd, save_seek, SEEK_SET);

	return 0;
}

static struct page *allocate_page(struct tracecmd_input *handle,
				  int cpu, off64_t offset)
{
	struct cpu_data *cpu_data = &handle->cpu_data[cpu];
	struct page *page;
	int ret;

	list_for_each_entry(page, &cpu_data->pages, list) {
		if (page->offset == offset) {
			page->ref_count++;
			return page;
		}
	}

	page = malloc(sizeof(*page));
	if (!page)
		return NULL;

	memset(page, 0, sizeof(*page));
	page->offset = offset;
	page->handle = handle;

	if (handle->read_page) {
		page->map = malloc(handle->page_size);
		if (page->map) {
			ret = read_page(handle, offset, cpu, page->map);
			if (ret < 0) {
				free(page->map);
				page->map = NULL;
			}
		}
	} else {
		page->map = mmap(NULL, handle->page_size, PROT_READ, MAP_PRIVATE,
				 handle->fd, offset);
		if (page->map == MAP_FAILED)
			page->map = NULL;
	}

	if (!page->map) {
		free(page);
		return NULL;
	}

	list_add(&page->list, &cpu_data->pages);
	page->ref_count = 1;

	return page;
}

static void __free_page(struct tracecmd_input *handle, struct page *page)
{
	if (!page->ref_count)
		die("Page ref count is zero!\n");

	page->ref_count--;
	if (page->ref_count)
		return;

	if (handle->read_page)
		free(page->map);
	else
		munmap(page->map, handle->page_size);

	list_del(&page->list);
	free(page);
}

static void free_page(struct tracecmd_input *handle, int cpu)
{
	if (!handle->cpu_data || cpu >= handle->cpus ||
	    !handle->cpu_data[cpu].page)
		return;

	__free_page(handle, handle->cpu_data[cpu].page);

	handle->cpu_data[cpu].page = NULL;
}

static void __free_record(struct pevent_record *record)
{
	if (record->priv) {
		struct page *page = record->priv;
		remove_record(page, record);
		__free_page(page->handle, page);
	}

	free(record);
}

void free_record(struct pevent_record *record)
{
	if (!record)
		return;

	if (!record->ref_count)
		die("record ref count is zero!");

	record->ref_count--;

	if (record->ref_count)
		return;

	if (record->locked)
		die("freeing record when it is locked!");

	record->data = NULL;

	__free_record(record);
}

void tracecmd_record_ref(struct pevent_record *record)
{
	record->ref_count++;
#if DEBUG_RECORD
	/* Update locating of last reference */
	record->alloc_addr = (unsigned long)__builtin_return_address(0);
#endif
}

static void free_next(struct tracecmd_input *handle, int cpu)
{
	struct pevent_record *record;

	if (!handle->cpu_data || cpu >= handle->cpus)
		return;

	record = handle->cpu_data[cpu].next;
	if (!record)
		return;

	handle->cpu_data[cpu].next = NULL;

	record->locked = 0;
	free_record(record);
}

/*
 * Page is mapped, now read in the page header info.
 */
static int update_page_info(struct tracecmd_input *handle, int cpu)
{
	struct pevent *pevent = handle->pevent;
	void *ptr = handle->cpu_data[cpu].page->map;
	struct kbuffer *kbuf = handle->cpu_data[cpu].kbuf;

	/* FIXME: handle header page */
	if (pevent->header_page_ts_size != 8) {
		warning("expected a long long type for timestamp");
		return -1;
	}

	kbuffer_load_subbuffer(kbuf, ptr);
	if (kbuffer_subbuffer_size(kbuf) > handle->page_size)
		die("bad page read, with size of %d",
		    kbuffer_subbuffer_size(kbuf));
	handle->cpu_data[cpu].timestamp = kbuffer_timestamp(kbuf) + handle->ts_offset;

	return 0;
}

/*
 * get_page maps a page for a given cpu.
 *
 * Returns 1 if the page was already mapped,
 *         0 if it mapped successfully
 *        -1 on error
 */
static int get_page(struct tracecmd_input *handle, int cpu,
		    off64_t offset)
{
	/* Don't map if the page is already where we want */
	if (handle->cpu_data[cpu].offset == offset &&
	    handle->cpu_data[cpu].page)
		return 1;

	/* Do not map no data for CPU */
	if (!handle->cpu_data[cpu].size)
		return -1;

	if (offset & (handle->page_size - 1)) {
		errno = -EINVAL;
		die("bad page offset %llx", offset);
		return -1;
	}

	if (offset < handle->cpu_data[cpu].file_offset ||
	    offset > handle->cpu_data[cpu].file_offset +
	    handle->cpu_data[cpu].file_size) {
		errno = -EINVAL;
		die("bad page offset %llx", offset);
		return -1;
	}

	handle->cpu_data[cpu].offset = offset;
	handle->cpu_data[cpu].size = (handle->cpu_data[cpu].file_offset +
				      handle->cpu_data[cpu].file_size) -
					offset;

	free_page(handle, cpu);

	handle->cpu_data[cpu].page = allocate_page(handle, cpu, offset);
	if (!handle->cpu_data[cpu].page)
		return -1;

	if (update_page_info(handle, cpu))
		return -1;

	return 0;
}

static int get_next_page(struct tracecmd_input *handle, int cpu)
{
	off64_t offset;

	if (!handle->cpu_data[cpu].page && !handle->use_pipe)
		return 0;

	free_page(handle, cpu);

	if (handle->cpu_data[cpu].size <= handle->page_size) {
		handle->cpu_data[cpu].offset = 0;
		return 0;
	}

	offset = handle->cpu_data[cpu].offset + handle->page_size;

	return get_page(handle, cpu, offset);
}

static struct pevent_record *
peek_event(struct tracecmd_input *handle, unsigned long long offset,
	   int cpu)
{
	struct pevent_record *record = NULL;

	/*
	 * Since the timestamp is calculated from the beginning
	 * of the page and through each event, we reset the
	 * page to the beginning. This is just used by
	 * tracecmd_read_at.
	 */
	update_page_info(handle, cpu);

	do {
		free_next(handle, cpu);
		record = tracecmd_peek_data(handle, cpu);
		if (record && (record->offset + record->record_size) > offset)
			break;
        } while (record);

	return record;
}

static struct pevent_record *
read_event(struct tracecmd_input *handle, unsigned long long offset,
	   int cpu)
{
	struct pevent_record *record;

	record = peek_event(handle, offset, cpu);
	if (record)
		record = tracecmd_read_data(handle, cpu);
	return record;
}

static struct pevent_record *
find_and_peek_event(struct tracecmd_input *handle, unsigned long long offset,
		    int *pcpu)
{
	unsigned long long page_offset;
	int cpu;

	/* find the cpu that this offset exists in */
	for (cpu = 0; cpu < handle->cpus; cpu++) {
		if (offset >= handle->cpu_data[cpu].file_offset &&
		    offset < handle->cpu_data[cpu].file_offset +
		    handle->cpu_data[cpu].file_size)
			break;
	}

	/* Not found? */
	if (cpu == handle->cpus)
		return NULL;

	/* Move this cpu index to point to this offest */
	page_offset = calc_page_offset(handle, offset);

	if (get_page(handle, cpu, page_offset) < 0)
		return NULL;

	if (pcpu)
		*pcpu = cpu;

	return peek_event(handle, offset, cpu);
}


static struct pevent_record *
find_and_read_event(struct tracecmd_input *handle, unsigned long long offset,
		    int *pcpu)
{
	struct pevent_record *record;
	int cpu;

	record = find_and_peek_event(handle, offset, &cpu);
	if (record) {
		record = tracecmd_read_data(handle, cpu);
		if (pcpu)
			*pcpu = cpu;
	}
	return record;
}

/**
 * tracecmd_read_at - read a record from a specific offset
 * @handle: input handle for the trace.dat file
 * @offset: the offset into the file to find the record
 * @pcpu: pointer to a variable to store the CPU id the record was found in
 *
 * This function is useful when looking for a previous record.
 * You can store the offset of the record "record->offset" and use that
 * offset to retreive the record again without needing to store any
 * other information about the record.
 *
 * The record returned must be freed.
 */
struct pevent_record *
tracecmd_read_at(struct tracecmd_input *handle, unsigned long long offset,
		 int *pcpu)
{
	unsigned long long page_offset;
	int cpu;

	page_offset = calc_page_offset(handle, offset);

	/* check to see if we have this page already */
	for (cpu = 0; cpu < handle->cpus; cpu++) {
		if (handle->cpu_data[cpu].offset == page_offset &&
		    handle->cpu_data[cpu].file_size)
			break;
	}

	if (cpu < handle->cpus) {
		if (pcpu)
			*pcpu = cpu;
		return read_event(handle, offset, cpu);
	} else
		return find_and_read_event(handle, offset, pcpu);
}

/**
 * tracecmd_refresh_record - remaps the records data
 * @handle: input handle for the trace.dat file
 * @record: the record to be refreshed
 *
 * A record data points to a mmap section of memory.
 * by reading new records the mmap section may be unmapped.
 * This will refresh the record's data mapping.
 *
 * ===== OBSOLETED BY PAGE REFERENCES =====
 *
 * Returns 1 if page is still mapped (does not modify CPU iterator)
 *         0 on successful mapping (was not mapped before,
 *                      This will update CPU iterator to point to
 *                      the next record)
 *        -1 on error.
 */
int tracecmd_refresh_record(struct tracecmd_input *handle,
			    struct pevent_record *record)
{
	unsigned long long page_offset;
	int cpu = record->cpu;
	struct cpu_data *cpu_data = &handle->cpu_data[cpu];
	int index;
	int ret;

	page_offset = calc_page_offset(handle, record->offset);
	index = record->offset & (handle->page_size - 1);

	ret = get_page(handle, record->cpu, page_offset);
	if (ret < 0)
		return -1;

	/* If the page is still mapped, there's nothing to do */
	if (ret)
		return 1;

	record->data = kbuffer_read_at_offset(cpu_data->kbuf, index, &record->ts);
	cpu_data->timestamp = record->ts;

	return 0;
}

/**
 * tracecmd_read_cpu_first - get the first record in a CPU
 * @handle: input handle for the trace.dat file
 * @cpu: the CPU to search
 *
 * This returns the first (by time) record entry in a given CPU.
 *
 * The record returned must be freed.
 */
struct pevent_record *
tracecmd_read_cpu_first(struct tracecmd_input *handle, int cpu)
{
	int ret;

	ret = get_page(handle, cpu, handle->cpu_data[cpu].file_offset);
	if (ret < 0)
		return NULL;

	/* If the page was already mapped, we need to reset it */
	if (ret)
		update_page_info(handle, cpu);
		
	free_next(handle, cpu);

	return tracecmd_read_data(handle, cpu);
}

/**
 * tracecmd_read_cpu_last - get the last record in a CPU
 * @handle: input handle for the trace.dat file
 * @cpu: the CPU to search
 *
 * This returns the last (by time) record entry in a given CPU.
 *
 * The record returned must be freed.
 */
struct pevent_record *
tracecmd_read_cpu_last(struct tracecmd_input *handle, int cpu)
{
	struct pevent_record *record = NULL;
	off64_t offset, page_offset;

	offset = handle->cpu_data[cpu].file_offset +
		handle->cpu_data[cpu].file_size;

	if (offset & (handle->page_size - 1))
		offset &= ~(handle->page_size - 1);
	else
		offset -= handle->page_size;

	page_offset = offset;

 again:
	if (get_page(handle, cpu, page_offset) < 0)
		return NULL;

	offset = page_offset;

	do {
		free_record(record);
		record = tracecmd_read_data(handle, cpu);
		if (record)
			offset = record->offset;
	} while (record);

	record = tracecmd_read_at(handle, offset, NULL);

	/*
	 * It is possible that a page has just a timestamp
	 * or just padding on it.
	 */
	if (!record) {
		if (page_offset == handle->cpu_data[cpu].file_offset)
			return NULL;
		page_offset -= handle->page_size;
		goto again;
	}

	return record;
}

/**
 * tracecmd_set_cpu_to_timestamp - set the CPU iterator to a given time
 * @handle: input handle for the trace.dat file
 * @cpu: the CPU pointer to set
 * @ts: the timestamp to set the CPU at.
 *
 * This sets the CPU iterator used by tracecmd_read_data and
 * tracecmd_peek_data to a location in the CPU storage near
 * a given timestamp. It will try to set the iterator to a time before
 * the time stamp and not actually at a given time.
 *
 * To use this to find a record in a time field, call this function
 * first, than iterate with tracecmd_read_data to find the records
 * you need.
 */
int
tracecmd_set_cpu_to_timestamp(struct tracecmd_input *handle, int cpu,
			      unsigned long long ts)
{
	struct cpu_data *cpu_data = &handle->cpu_data[cpu];
	off64_t start, end, next;

	if (cpu < 0 || cpu >= handle->cpus) {
		errno = -EINVAL;
		return -1;
	}

	if (!cpu_data->size)
		return -1;

	if (!cpu_data->page) {
		if (init_cpu(handle, cpu))
		    return -1;
	}

	if (cpu_data->timestamp == ts) {
		/*
		 * If a record is cached, then that record is most
		 * likely the matching timestamp. Otherwise we need
		 * to start from the beginning of the index;
		 */
		if (!cpu_data->next ||
		    cpu_data->next->ts != ts)
			update_page_info(handle, cpu);
		return 0;
	}

	/* Set to the first record on current page */
	update_page_info(handle, cpu);

	if (cpu_data->timestamp < ts) {
		start = cpu_data->offset;
		end = cpu_data->file_offset + cpu_data->file_size;
		if (end & (handle->page_size - 1))
			end &= ~(handle->page_size - 1);
		else
			end -= handle->page_size;
		next = end;
	} else {
		end = cpu_data->offset;
		start = cpu_data->file_offset;
		next = start;
	}

	while (start < end) {
		if (get_page(handle, cpu, next) < 0)
			return -1;

		if (cpu_data->timestamp == ts)
			break;

		if (cpu_data->timestamp < ts)
			start = next;
		else
			end = next;

		next = start + (end - start) / 2;
		next = calc_page_offset(handle, next);

		/* Prevent an infinite loop if start and end are a page off */
		if (next == start)
			start = next += handle->page_size;
	}

	/*
	 * We need to end up on a page before the time stamp.
	 * We go back even if the timestamp is the same. This is because
	 * we want the event with the timestamp, not the page. The page
	 * can start with the timestamp we are looking for, but the event
	 * may be on the previous page.
	 */
	if (cpu_data->timestamp >= ts &&
	    cpu_data->offset > cpu_data->file_offset)
		get_page(handle, cpu, cpu_data->offset - handle->page_size);

	return 0;
}

/**
 * tracecmd_set_all_cpus_to_timestamp - set all CPUs iterator to a given time
 * @handle: input handle for the trace.dat file
 * @cpu: the CPU pointer to set
 * @ts: the timestamp to set the CPU at.
 *
 * This sets the CPU iterator used by tracecmd_read_data and
 * tracecmd_peek_data to a location in the CPU storage near
 * a given timestamp. It will try to set the iterator to a time before
 * the time stamp and not actually at a given time.
 *
 * To use this to find a record in a time field, call this function
 * first, than iterate with tracecmd_read_next_data to find the records
 * you need.
 */
void
tracecmd_set_all_cpus_to_timestamp(struct tracecmd_input *handle,
				   unsigned long long time)
{
	int cpu;

	for (cpu = 0; cpu < handle->cpus; cpu++)
		tracecmd_set_cpu_to_timestamp(handle, cpu, time);
}

/**
 * tracecmd_set_cursor - set the offset for the next tracecmd_read_data
 * @handle: input handle for the trace.dat file
 * @cpu: the CPU pointer to set
 * @offset: the offset to place the cursor
 *
 * Set the pointer to the next read or peek. This is useful when
 * needing to read sequentially and then look at another record
 * out of sequence without breaking the iteration. This is done with:
 *
 *  record = tracecmd_peek_data()
 *  offset = record->offset;
 *  record = tracecmd_read_at();
 *   - do what ever with record -
 *  tracecmd_set_cursor(handle, cpu, offset);
 *
 *  Now the next tracecmd_peek_data or tracecmd_read_data will return
 *  the original record.
 */
int tracecmd_set_cursor(struct tracecmd_input *handle,
			int cpu, unsigned long long offset)
{
	struct cpu_data *cpu_data = &handle->cpu_data[cpu];
	unsigned long long page_offset;

	if (cpu < 0 || cpu >= handle->cpus)
		return -1;

	if (offset < cpu_data->file_offset ||
	    offset > cpu_data->file_offset + cpu_data->file_size)
		return -1; 	/* cpu does not have this offset. */

	/* Move this cpu index to point to this offest */
	page_offset = calc_page_offset(handle, offset);

	if (get_page(handle, cpu, page_offset) < 0)
		return -1;

	peek_event(handle, offset, cpu);

	return 0;
}

/**
 * tracecmd_get_cursor - get the offset for the next tracecmd_read_data
 * @handle: input handle for the trace.dat file
 * @cpu: the CPU pointer to get the cursor from
 *
 * Returns the offset of the next record that would be read.
 */
unsigned long long
tracecmd_get_cursor(struct tracecmd_input *handle, int cpu)
{
	struct cpu_data *cpu_data = &handle->cpu_data[cpu];
	struct kbuffer *kbuf = cpu_data->kbuf;

	if (cpu < 0 || cpu >= handle->cpus)
		return 0;

	/*
	 * Use the next pointer if it exists and matches the
	 * current timestamp.
	 */
	if (cpu_data->next &&
	    cpu_data->next->ts == cpu_data->timestamp)
		return cpu_data->next->offset;

	/*
	 * Either the next point does not exist, or it does
	 * not match the timestamp. The next read will use the
	 * current page.
	 *
	 * If the offset is at the end, then return that.
	 */
	if (cpu_data->offset >= cpu_data->file_offset +
	    cpu_data->file_size)
		return cpu_data->offset;

	return cpu_data->offset + kbuffer_curr_offset(kbuf);
}

/**
 * tracecmd_translate_data - create a record from raw data
 * @handle: input handle for the trace.dat file
 * @ptr: raw data to read
 * @size: the size of the data
 *
 * This function tries to create a record from some given
 * raw data. The data does not need to be from the trace.dat file.
 * It can be stored from another location.
 *
 * Note, since the timestamp is calculated from within the trace
 * buffer, the timestamp for the record will be zero, since it
 * can't calculate it.
 *
 * The record returned must be freed.
 */
struct pevent_record *
tracecmd_translate_data(struct tracecmd_input *handle,
			void *ptr, int size)
{
	struct pevent *pevent = handle->pevent;
	struct pevent_record *record;
	unsigned int length;
	int swap = 1;

	/* minimum record read is 8, (warn?) (TODO: make 8 into macro) */
	if (size < 8)
		return NULL;

	record = malloc(sizeof(*record));
	if (!record)
		return NULL;
	memset(record, 0, sizeof(*record));

	record->ref_count = 1;
	if (pevent->host_bigendian == pevent->file_bigendian)
		swap = 0;
	record->data = kbuffer_translate_data(swap, ptr, &length);
	record->size = length;
	if (record->data)
		record->record_size = record->size + (record->data - ptr);

	return record;
}

/**
 * tracecmd_read_page_record - read a record off of a page
 * @pevent: pevent used to parse the page
 * @page: the page to read
 * @size: the size of the page
 * @last_record: last record read from this page.
 *
 * If a ring buffer page is available, and the need to parse it
 * without having a handle, then this function can be used.
 *
 * The @pevent needs to be initialized to have the page header information
 * already available.
 *
 * The @last_record is used to know where to read the next record from.
 * If @last_record is NULL, the first record on the page will be read.
 *
 * Returns:
 *  A newly allocated record that must be freed with free_record() if
 *  a record is found. Otherwise NULL is returned if the record is bad
 *  or no more records exist.
 */
struct pevent_record *
tracecmd_read_page_record(struct pevent *pevent, void *page, int size,
			  struct pevent_record *last_record)
{
	unsigned long long ts;
	struct kbuffer *kbuf;
	struct pevent_record *record = NULL;
	enum kbuffer_long_size long_size;
	enum kbuffer_endian endian;
	void *ptr;

	if (pevent->file_bigendian)
		endian = KBUFFER_ENDIAN_BIG;
	else
		endian = KBUFFER_ENDIAN_LITTLE;

	if (pevent->header_page_size_size == 8)
		long_size = KBUFFER_LSIZE_8;
	else
		long_size = KBUFFER_LSIZE_4;

	kbuf = kbuffer_alloc(long_size, endian);
	if (!kbuf)
		return NULL;

	kbuffer_load_subbuffer(kbuf, page);
	if (kbuffer_subbuffer_size(kbuf) > size) {
		warning("tracecmd_read_page_record: page_size > size");
		goto out_free;
	}

	if (last_record) {
		if (last_record->data < page || last_record->data >= (page + size)) {
			warning("tracecmd_read_page_record: bad last record (size=%u)",
				last_record->size);
			goto out_free;
		}

		do {
			ptr = kbuffer_next_event(kbuf, NULL);
			if (!ptr)
				break;
		} while (ptr < last_record->data);
		if (ptr != last_record->data) {
			warning("tracecmd_read_page_record: could not find last_record");
			goto out_free;
		}
	}

	ptr = kbuffer_read_event(kbuf, &ts);
	if (!ptr)
		goto out_free;

	record = malloc(sizeof(*record));
	if (!record)
		return NULL;
	memset(record, 0, sizeof(*record));

	record->ts = ts;
	record->size = kbuffer_event_size(kbuf);
	record->record_size = kbuffer_curr_size(kbuf);
	record->cpu = 0;
	record->data = ptr;
	record->ref_count = 1;

 out_free:
	kbuffer_free(kbuf);
	return record;
}

/**
 * tracecmd_peek_data - return the record at the current location.
 * @handle: input handle for the trace.dat file
 * @cpu: the CPU to pull from
 *
 * This returns the record at the current location of the CPU
 * iterator. It does not increment the CPU iterator.
 */
struct pevent_record *
tracecmd_peek_data(struct tracecmd_input *handle, int cpu)
{
	struct pevent_record *record;
	unsigned long long ts;
	struct kbuffer *kbuf;
	struct page *page;
	int index;
	void *data;

	if (cpu >= handle->cpus)
		return NULL;

	page = handle->cpu_data[cpu].page;
	kbuf = handle->cpu_data[cpu].kbuf;

	/* Hack to work around function graph read ahead */
	tracecmd_curr_thread_handle = handle;

	if (handle->cpu_data[cpu].next) {

		record = handle->cpu_data[cpu].next;
		if (!record->data)
			die("Something freed the record");

		if (handle->cpu_data[cpu].timestamp == record->ts)
			return record;

		/*
		 * The timestamp changed, which means the cached
		 * record is no longer valid. Reread a new record.
		 */
		free_next(handle, cpu);
	}

read_again:
	if (!page) {
		if (handle->use_pipe) {
			get_next_page(handle, cpu);
			page = handle->cpu_data[cpu].page;
		}
		if (!page)
			return NULL;
	}

	data = kbuffer_read_event(kbuf, &ts);
	if (!data) {
		if (get_next_page(handle, cpu))
			return NULL;
		page = handle->cpu_data[cpu].page;
		goto read_again;
	}

	handle->cpu_data[cpu].timestamp = ts + handle->ts_offset;

	index = kbuffer_curr_offset(kbuf);

	record = malloc(sizeof(*record));
	if (!record)
		return NULL;
	memset(record, 0, sizeof(*record));

	record->ts = handle->cpu_data[cpu].timestamp;
	record->size = kbuffer_event_size(kbuf);
	record->cpu = cpu;
	record->data = data;
	record->offset = handle->cpu_data[cpu].offset + index;
	record->missed_events = kbuffer_missed_events(kbuf);
	record->ref_count = 1;
	record->locked = 1;

	handle->cpu_data[cpu].next = record;

	record->record_size = kbuffer_curr_size(kbuf);
	record->priv = page;
	add_record(page, record);
	page->ref_count++;

	kbuffer_next_event(kbuf, NULL);

	return record;
}

/**
 * tracecmd_read_data - read the next record and increment
 * @handle: input handle for the trace.dat file
 * @cpu: the CPU to pull from
 *
 * This returns the record at the current location of the CPU
 * iterator and increments the CPU iterator.
 *
 * The record returned must be freed.
 */
struct pevent_record *
tracecmd_read_data(struct tracecmd_input *handle, int cpu)
{
	struct pevent_record *record;

	record = tracecmd_peek_data(handle, cpu);
	handle->cpu_data[cpu].next = NULL;
	if (record) {
		record->locked = 0;
#if DEBUG_RECORD
		record->alloc_addr = (unsigned long)__builtin_return_address(0);
#endif
	}
	return record;
}

/**
 * tracecmd_read_next_data - read the next record
 * @handle: input handle to the trace.dat file
 * @rec_cpu: return pointer to the CPU that the record belongs to
 *
 * This returns the next record by time. This is different than
 * tracecmd_read_data in that it looks at all CPUs. It does a peek
 * at each CPU and the record with the earliest time stame is
 * returned. If @rec_cpu is not NULL it gets the CPU id the record was
 * on. The CPU cursor of the returned record is moved to the
 * next record.
 *
 * Multiple reads of this function will return a serialized list
 * of all records for all CPUs in order of time stamp.
 *
 * The record returned must be freed.
 */
struct pevent_record *
tracecmd_read_next_data(struct tracecmd_input *handle, int *rec_cpu)
{
	unsigned long long ts;
	struct pevent_record *record;
	int first_record = 1;
	int next;
	int cpu;

	if (rec_cpu)
		*rec_cpu = -1;

	next = -1;
	ts = 0;

	for (cpu = 0; cpu < handle->cpus; cpu++) {
		record = tracecmd_peek_data(handle, cpu);
		if (record && (first_record || record->ts < ts)) {
			ts = record->ts;
			next = cpu;
			first_record = 0;
		}
	}

	if (next >= 0) {
		if (rec_cpu)
			*rec_cpu = next;
		return tracecmd_read_data(handle, next);
	}

	return NULL;
}

/**
 * tracecmd_read_prev - read the record before the given record
 * @handle: input handle to the trace.dat file
 * @record: the record to use to find the previous record.
 *
 * This returns the record before the @record on its CPU. If
 * @record is the first record, NULL is returned. The cursor is set
 * as if the previous record was read by tracecmd_read_data().
 *
 * @record can not be NULL, otherwise NULL is returned; the
 * record ownership goes to this function.
 *
 * Note, this is not that fast of an algorithm, since it needs
 * to build the timestamp for the record.
 *
 * The record returned must be freed with free_record().
 */
struct pevent_record *
tracecmd_read_prev(struct tracecmd_input *handle, struct pevent_record *record)
{
	unsigned long long offset, page_offset;;
	struct cpu_data *cpu_data;
	int index;
	int cpu;

	if (!record)
		return NULL;

	cpu = record->cpu;
	offset = record->offset;
	cpu_data = &handle->cpu_data[cpu];

	page_offset = calc_page_offset(handle, offset);
	index = offset - page_offset;

	/* Note, the record passed in could have been a peek */
	free_next(handle, cpu);

	/* Reset the cursor */
	/* Should not happen */
	if (get_page(handle, cpu, page_offset) < 0)
		return NULL;

	update_page_info(handle, cpu);

	/* Find the record before this record */
	index = 0;
	for (;;) {
		record = tracecmd_read_data(handle, cpu);
		/* Should not happen! */
		if (!record)
			return NULL;
		if (record->offset == offset)
			break;
		index = record->offset - page_offset;
		free_record(record);
	}
	free_record(record);

	if (index)
		/* we found our record */
		return tracecmd_read_at(handle, page_offset + index, NULL);

	/* reset the index to start at the beginning of the page */
	update_page_info(handle, cpu);

	/* The previous record is on the previous page */
	for (;;) {
		/* check if this is the first page */
		if (page_offset == cpu_data->file_offset)
			return NULL;
		page_offset -= handle->page_size;

		/* Updating page to a new page will reset index to 0 */
		get_page(handle, cpu, page_offset);

		record = NULL;
		index = 0;
		do {
			if (record) {
				index = record->offset - page_offset;
				free_record(record);
			}
			record = tracecmd_read_data(handle, cpu);
			/* Should not happen */
			if (!record)
				return NULL;
		} while (record->offset != offset);
		free_record(record);

		if (index)
			/* we found our record */
			return tracecmd_read_at(handle, page_offset + index, NULL);
	}

	/* Not reached */
}

static int init_cpu(struct tracecmd_input *handle, int cpu)
{
	struct cpu_data *cpu_data = &handle->cpu_data[cpu];
	int i;

	cpu_data->offset = cpu_data->file_offset;
	cpu_data->size = cpu_data->file_size;
	cpu_data->timestamp = 0;

	list_head_init(&cpu_data->pages);

	if (!cpu_data->size) {
		printf("CPU %d is empty\n", cpu);
		return 0;
	}

	if (handle->use_pipe) {
		/* Just make a page, it will be nuked later */
		cpu_data->page = malloc(sizeof(*cpu_data->page));
		if (!cpu_data->page)
			return -1;

		memset(cpu_data->page, 0, sizeof(*cpu_data->page));
		list_add(&cpu_data->page->list, &cpu_data->pages);
		cpu_data->page->ref_count = 1;
		return 0;
	}

	cpu_data->page = allocate_page(handle, cpu, cpu_data->offset);
	if (!cpu_data->page && !handle->read_page) {
		perror("mmap");
		fprintf(stderr, "Can not mmap file, will read instead\n");

		if (cpu) {
			/*
			 * If the other CPUs had size and was able to mmap
			 * then bail.
			 */
			for (i = 0; i < cpu; i++) {
				if (handle->cpu_data[i].size)
					return -1;
			}
		}

		/* try again without mmapping, just read it directly */
		handle->read_page = true;
		cpu_data->page = allocate_page(handle, cpu, cpu_data->offset);
		if (!cpu_data->page)
			/* Still no luck, bail! */
			return -1;
	}

	if (update_page_info(handle, cpu))
		return -1;

	return 0;
}

static int handle_options(struct tracecmd_input *handle)
{
	unsigned long long offset;
	unsigned short option;
	unsigned int size;
	char *cpustats = NULL;
	unsigned int cpustats_size = 0;
	struct input_buffer_instance *buffer;
	struct hook_list *hook;
	char *buf;

	for (;;) {
		if (do_read_check(handle, &option, 2))
			return -1;

		if (option == TRACECMD_OPTION_DONE)
			break;

		/* next 4 bytes is the size of the option */
		if (do_read_check(handle, &size, 4))
			return -1;
		size = __data2host4(handle->pevent, size);
		buf = malloc_or_die(size);
		if (do_read_check(handle, buf, size))
			return -1;

		switch (option) {
		case TRACECMD_OPTION_DATE:
			/*
			 * A time has been mapped that is the
			 * difference between the timestamps and
			 * gtod. It is stored as ASCII with '0x'
			 * appended.
			 */
			if (handle->flags & TRACECMD_FL_IGNORE_DATE)
				break;
			offset = strtoll(buf, NULL, 0);
			/* Convert from micro to nano */
			offset *= 1000;
			handle->ts_offset = offset;
			break;
		case TRACECMD_OPTION_CPUSTAT:
			buf[size-1] = '\n';
			cpustats = realloc(cpustats, cpustats_size + size + 1);
			if (!cpustats)
				die("realloc");
			memcpy(cpustats + cpustats_size, buf, size);
			cpustats_size += size;
			cpustats[cpustats_size] = 0;
			break;
		case TRACECMD_OPTION_BUFFER:
			/* A buffer instance is saved at the end of the file */
			handle->nr_buffers++;
			handle->buffers = realloc(handle->buffers,
						  sizeof(*handle->buffers) * handle->nr_buffers);
			if (!handle->buffers)
				die("realloc");
			buffer = &handle->buffers[handle->nr_buffers - 1];
			buffer->name = strdup(buf + 8);
			if (!buffer->name)
				die("strdup");
			offset = *(unsigned long long *)buf;
			buffer->offset = __data2host8(handle->pevent, offset);
			break;
		case TRACECMD_OPTION_TRACECLOCK:
			handle->use_trace_clock = true;
			break;
		case TRACECMD_OPTION_UNAME:
			handle->uname = strdup(buf);
			break;
		case TRACECMD_OPTION_HOOK:
			hook = tracecmd_create_event_hook(buf);
			hook->next = handle->hooks;
			handle->hooks = hook;
			break;
		default:
			warning("unknown option %d", option);
			break;
		}

		free(buf);

	}

	handle->cpustats = cpustats;

	return 0;
}

static int read_cpu_data(struct tracecmd_input *handle)
{
	struct pevent *pevent = handle->pevent;
	enum kbuffer_long_size long_size;
	enum kbuffer_endian endian;
	unsigned long long size;
	char buf[10];
	int cpu;

	if (do_read_check(handle, buf, 10))
		return -1;

	/* check if this handles options */
	if (strncmp(buf, "options", 7) == 0) {
		if (handle_options(handle) < 0)
			return -1;
		if (do_read_check(handle, buf, 10))
			return -1;
	}

	/*
	 * Check if this is a latency report or not.
	 */
	if (strncmp(buf, "latency", 7) == 0) {
		handle->flags |= TRACECMD_FL_LATENCY;
		return 1;
	}

	/* We expect this to be flyrecord */
	if (strncmp(buf, "flyrecord", 9) != 0)
		return -1;

	handle->cpu_data = malloc(sizeof(*handle->cpu_data) * handle->cpus);
	if (!handle->cpu_data)
		return -1;
	memset(handle->cpu_data, 0, sizeof(*handle->cpu_data) * handle->cpus);

	if (force_read)
		handle->read_page = true;

	if (handle->long_size == 8)
		long_size = KBUFFER_LSIZE_8;
	else
		long_size = KBUFFER_LSIZE_4;

	if (handle->pevent->file_bigendian)
		endian = KBUFFER_ENDIAN_BIG;
	else
		endian = KBUFFER_ENDIAN_LITTLE;

	for (cpu = 0; cpu < handle->cpus; cpu++) {
		unsigned long long offset;

		handle->cpu_data[cpu].cpu = cpu;

		handle->cpu_data[cpu].kbuf = kbuffer_alloc(long_size, endian);
		if (!handle->cpu_data[cpu].kbuf)
			goto out_free;
		if (pevent->old_format)
			kbuffer_set_old_format(handle->cpu_data[cpu].kbuf);

		offset = read8(handle);
		size = read8(handle);

		handle->cpu_data[cpu].file_offset = offset;
		handle->cpu_data[cpu].file_size = size;

		if (size && (offset + size > handle->total_file_size)) {
			/* this happens if the file got truncated */
			printf("File possibly truncated. "
				"Need at least %llu, but file size is %zu.\n",
				offset + size, handle->total_file_size);
			errno = EINVAL;
			goto out_free;
		}

		if (init_cpu(handle, cpu))
			goto out_free;
	}

	return 0;

 out_free:
	for ( ; cpu >= 0; cpu--) {
		free_page(handle, cpu);
		kbuffer_free(handle->cpu_data[cpu].kbuf);
		handle->cpu_data[cpu].kbuf = NULL;
	}
	return -1;
}

static int read_data_and_size(struct tracecmd_input *handle,
				     char **data, unsigned long long *size)
{
	*size = read8(handle);
	if (*size < 0)
		return -1;
	*data = malloc(*size + 1);
	if (!*data)
		return -1;
	if (do_read_check(handle, *data, *size)) {
		free(*data);
		return -1;
	}

	return 0;
}

static int read_and_parse_cmdlines(struct tracecmd_input *handle)
{
	struct pevent *pevent = handle->pevent;
	unsigned long long size;
	char *cmdlines;

	if (read_data_and_size(handle, &cmdlines, &size) < 0)
		return -1;
	cmdlines[size] = 0;
	parse_cmdlines(pevent, cmdlines, size);
	free(cmdlines);
	return 0;
}

static int read_and_parse_trace_clock(struct tracecmd_input *handle,
							struct pevent *pevent)
{
	unsigned long long size;
	char *trace_clock;

	if (read_data_and_size(handle, &trace_clock, &size) < 0)
		return -1;
	trace_clock[size] = 0;
	parse_trace_clock(pevent, trace_clock, size);
	free(trace_clock);
	return 0;
}

/**
 * tracecmd_init_data - prepare reading the data from trace.dat
 * @handle: input handle for the trace.dat file
 *
 * This prepares reading the data from trace.dat. This is called
 * after tracecmd_read_headers() and before tracecmd_read_data().
 */
int tracecmd_init_data(struct tracecmd_input *handle)
{
	struct pevent *pevent = handle->pevent;
	int ret;

	handle->cpus = read4(handle);
	if (handle->cpus < 0)
		return -1;

	pevent_set_cpus(pevent, handle->cpus);

	ret = read_cpu_data(handle);
	if (ret < 0)
		return ret;

	if (handle->use_trace_clock) {
		/*
		 * There was a bug in the original setting of
		 * the trace_clock file which let it get
		 * corrupted. If it fails to read, force local
		 * clock.
		 */
		if (read_and_parse_trace_clock(handle, pevent) < 0) {
			char clock[] = "[local]";
			warning("File has trace_clock bug, using local clock");
			parse_trace_clock(pevent, clock, 8);
		}
	}

	tracecmd_blk_hack(handle);

	return ret;
}

/**
 * tracecmd_make_pipe - Have the handle read a pipe instead of a file
 * @handle: input handle to read from a pipe
 * @cpu: the cpu that the pipe represents
 * @fd: the read end of the pipe
 * @cpus: the total number of cpus for this handle
 *
 * In order to stream data from the binary trace files and produce
 * output or analyze the data, a tracecmd_input descriptor needs to
 * be created, and then converted into a form that can act on a
 * pipe.
 *
 * Note, there are limitations to what this descriptor can do.
 * Most notibly, it can not read backwards. Once a page is read
 * it can not be read at a later time (except if a record is attached
 * to it and is holding the page ref).
 *
 * It is expected that the handle has already been created and
 * tracecmd_read_headers() has run on it.
 */
int tracecmd_make_pipe(struct tracecmd_input *handle, int cpu, int fd, int cpus)
{
	enum kbuffer_long_size long_size;
	enum kbuffer_endian endian;

	handle->read_page = true;
	handle->use_pipe = true;

	if (!handle->cpus) {
		handle->cpus = cpus;
		handle->cpu_data = malloc(sizeof(*handle->cpu_data) * handle->cpus);
		if (!handle->cpu_data)
			return -1;
	}

	if (cpu >= handle->cpus)
		return -1;


	if (handle->long_size == 8)
		long_size = KBUFFER_LSIZE_8;
	else
		long_size = KBUFFER_LSIZE_4;

	if (handle->pevent->file_bigendian)
		endian = KBUFFER_ENDIAN_BIG;
	else
		endian = KBUFFER_ENDIAN_LITTLE;

	memset(&handle->cpu_data[cpu], 0, sizeof(handle->cpu_data[cpu]));
	handle->cpu_data[cpu].pipe_fd = fd;
	handle->cpu_data[cpu].cpu = cpu;

	handle->cpu_data[cpu].kbuf = kbuffer_alloc(long_size, endian);
	if (!handle->cpu_data[cpu].kbuf)
		return -1;
	if (handle->pevent->old_format)
		kbuffer_set_old_format(handle->cpu_data[cpu].kbuf);

	handle->cpu_data[cpu].file_offset = 0;
	handle->cpu_data[cpu].file_size = -1;

	init_cpu(handle, cpu);

	return 0;
}

/**
 * tracecmd_print_events - print the events that are stored in trace.dat
 * @handle: input handle for the trace.dat file
 * @regex: regex of events to print (NULL is all events)
 *
 * This is a debugging routine to print out the events that
 * are stored in a given trace.dat file.
 */
void tracecmd_print_events(struct tracecmd_input *handle, const char *regex)
{
	int ret;

	if (!regex)
		regex = ".*";

	if (!handle->ftrace_files_start) {
		lseek64(handle->fd, handle->header_files_start, SEEK_SET);
		read_header_files(handle);
	}
	ret = read_ftrace_files(handle, regex);
	if (ret < 0)
		return;

	read_event_files(handle, regex);
	return;
}

/* Show the cpu data stats */
static void show_cpu_stats(struct tracecmd_input *handle)
{
	struct cpu_data *cpu_data;
	int i;

	for (i = 0; i < handle->cpus; i++) {
		cpu_data = &handle->cpu_data[i];
		printf("CPU%d data recorded at offset=0x%llx\n",
		       i, cpu_data->file_offset);
		printf("    %lld bytes in size\n", cpu_data->file_size);
	}
}

/**
 * tracecmd_print_stats - prints the stats recorded in the options.
 * @handle: input handle for the trace.dat file
 *
 * Looks for the option TRACECMD_OPTION_CPUSTAT and prints out what's
 * stored there, if it is found. Otherwise it prints that none were found.
 */
void tracecmd_print_stats(struct tracecmd_input *handle)
{
	if (handle->cpustats)
		printf("%s\n", handle->cpustats);
	else
		printf(" No stats in this file\n");

	show_cpu_stats(handle);
}

/**
 * tracecmd_print_uname - prints the recorded uname if it was recorded
 * @handle: input handle for the trace.dat file
 *
 * Looks for the option TRACECMD_OPTION_UNAME and prints out what's
 * stored there, if it is found. Otherwise it prints that none were found.
 */
void tracecmd_print_uname(struct tracecmd_input *handle)
{
	if (handle->uname)
		printf("%s\n", handle->uname);
	else
		printf(" uname was not recorded in this file\n");
}

/**
 * tracecmd_hooks - return the event hooks that were used in record
 * @handle: input handle for the trace.dat file
 *
 * If trace-cmd record used -H to save hooks, they are parsed and
 * presented as hooks here.
 *
 * Returns the hook list (do not free it, they are freed on close)
 */
struct hook_list *tracecmd_hooks(struct tracecmd_input *handle)
{
	return handle->hooks;
}

/**
 * tracecmd_alloc_fd - create a tracecmd_input handle from a file descriptor
 * @fd: the file descriptor for the trace.dat file
 *
 * Allocate a tracecmd_input handle from a file descriptor and open the
 * file. This tests if the file is of trace-cmd format and allocates
 * a parse event descriptor.
 *
 * The returned pointer is not ready to be read yet. A tracecmd_read_headers()
 * and tracecmd_init_data() still need to be called on the descriptor.
 *
 * Unless you know what you are doing with this, you want to use
 * tracecmd_open_fd() instead.
 */
struct tracecmd_input *tracecmd_alloc_fd(int fd)
{
	struct tracecmd_input *handle;
	char test[] = { 23, 8, 68 };
	char *version;
	char buf[BUFSIZ];

	handle = malloc(sizeof(*handle));
	if (!handle)
		return NULL;
	memset(handle, 0, sizeof(*handle));

	handle->fd = fd;
	handle->ref = 1;

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
	pr_stat("version = %s\n", version);
	free(version);

	if (do_read_check(handle, buf, 1))
		goto failed_read;

	handle->pevent = pevent_alloc();
	if (!handle->pevent)
		goto failed_read;

	/* register default ftrace functions first */
	tracecmd_ftrace_overrides(handle, &handle->finfo);

	handle->plugin_list = tracecmd_load_plugins(handle->pevent);

	handle->pevent->file_bigendian = buf[0];
	handle->pevent->host_bigendian = tracecmd_host_bigendian();

	do_read_check(handle, buf, 1);
	handle->long_size = buf[0];

	handle->page_size = read4(handle);

	handle->header_files_start =
		lseek64(handle->fd, 0, SEEK_CUR);

	handle->total_file_size =
		lseek64(handle->fd, 0, SEEK_END);

	handle->header_files_start =
		lseek64(handle->fd, handle->header_files_start, SEEK_SET);

	return handle;

 failed_read:
	free(handle);

	return NULL;
}

/**
 * tracecmd_alloc_fd - create a tracecmd_input handle from a file name
 * @file: the file name of the file that is of tracecmd data type.
 *
 * Allocate a tracecmd_input handle from a given file name and open the
 * file. This tests if the file is of trace-cmd format and allocates
 * a parse event descriptor.
 *
 * The returned pointer is not ready to be read yet. A tracecmd_read_headers()
 * and tracecmd_init_data() still need to be called on the descriptor.
 *
 * Unless you know what you are doing with this, you want to use
 * tracecmd_open() instead.
 */
struct tracecmd_input *tracecmd_alloc(const char *file)
{
	int fd;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return NULL;

	return tracecmd_alloc_fd(fd);
}

/**
 * tracecmd_open_fd - create a tracecmd_handle from the trace.dat file descriptor
 * @fd: the file descriptor for the trace.dat file
 */
struct tracecmd_input *tracecmd_open_fd(int fd)
{
	struct tracecmd_input *handle;
	int ret;

	handle = tracecmd_alloc_fd(fd);
	if (!handle)
		return NULL;

	if (tracecmd_read_headers(handle) < 0)
		goto fail;

	if ((ret = tracecmd_init_data(handle)) < 0)
		goto fail;

	return handle;

fail:
	tracecmd_close(handle);
	return NULL;
}

/**
 * tracecmd_open - create a tracecmd_handle from a given file
 * @file: the file name of the file that is of tracecmd data type.
 */
struct tracecmd_input *tracecmd_open(const char *file)
{
	int fd;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return NULL;

	return tracecmd_open_fd(fd);
}

/**
 * tracecmd_ref - add a reference to the handle
 * @handle: input handle for the trace.dat file
 *
 * Some applications may share a handle between parts of
 * the application. Let those parts add reference counters
 * to the handle, and the last one to close it will free it.
 */
void tracecmd_ref(struct tracecmd_input *handle)
{
	if (!handle)
		return;

	handle->ref++;
}

/**
 * tracecmd_close - close and free the trace.dat handle
 * @handle: input handle for the trace.dat file
 *
 * Close the file descriptor of the handle and frees
 * the resources allocated by the handle.
 */
void tracecmd_close(struct tracecmd_input *handle)
{
	int cpu;

	if (!handle)
		return;

	if (handle->ref <= 0) {
		warning("tracecmd: bad ref count on handle\n");
		return;
	}

	if (--handle->ref)
		return;

	for (cpu = 0; cpu < handle->cpus; cpu++) {
		/* The tracecmd_peek_data may have cached a record */
		free_next(handle, cpu);
		free_page(handle, cpu);
		if (handle->cpu_data && handle->cpu_data[cpu].kbuf) {
			kbuffer_free(handle->cpu_data[cpu].kbuf);

			if (!list_empty(&handle->cpu_data[cpu].pages))
				warning("pages still allocated on cpu %d%s",
					cpu, show_records(&handle->cpu_data[cpu].pages));
		}
	}

	free(handle->cpustats);
	free(handle->cpu_data);
	free(handle->uname);
	close(handle->fd);

	tracecmd_free_hooks(handle->hooks);
	handle->hooks = NULL;

	if (handle->flags & TRACECMD_FL_BUFFER_INSTANCE)
		tracecmd_close(handle->parent);
	else {
		/* Only main handle frees plugins and pevent */
		tracecmd_unload_plugins(handle->plugin_list, handle->pevent);
		pevent_free(handle->pevent);
	}
	free(handle);
}

static long long read_copy_size8(struct tracecmd_input *handle, int fd)
{
	long long size;

	/* read size */
	if (do_read_check(handle, &size, 8))
		return -1;

	if (__do_write_check(fd, &size, 8))
		return -1;

	size = __data2host8(handle->pevent, size);

	return size;
}

static int read_copy_size4(struct tracecmd_input *handle, int fd)
{
	int size;

	/* read size */
	if (do_read_check(handle, &size, 4))
		return -1;

	if (__do_write_check(fd, &size, 4))
		return -1;

	size = __data2host4(handle->pevent, size);

	return size;
}

static int read_copy_data(struct tracecmd_input *handle,
			  unsigned long long size, int fd)
{
	char *buf;

	buf = malloc(size);
	if (!buf)
		return -1;
	if (do_read_check(handle, buf, size))
		goto failed_read;

	if (__do_write_check(fd, buf, size))
		goto failed_read;
	
	free(buf);

	return 0;

 failed_read:
	free(buf);
	return -1;
}

static int copy_header_files(struct tracecmd_input *handle, int fd)
{
	long long size;

	lseek64(handle->fd, handle->header_files_start, SEEK_SET);

	/* "header_page"  */
	if (read_copy_data(handle, 12, fd) < 0)
		return -1;

	size = read_copy_size8(handle, fd);
	if (size < 0)
		return -1;

	if (read_copy_data(handle, size, fd) < 0)
		return -1;

	/* "header_event"  */
	if (read_copy_data(handle, 13, fd) < 0)
		return -1;

	size = read_copy_size8(handle, fd);
	if (size < 0)
		return -1;

	if (read_copy_data(handle, size, fd) < 0)
		return -1;

	return 0;
}

static int copy_ftrace_files(struct tracecmd_input *handle, int fd)
{
	unsigned long long size;
	int count;
	int i;

	count = read_copy_size4(handle, fd);
	if (count < 0)
		return -1;

	for (i = 0; i < count; i++) {

		size = read_copy_size8(handle, fd);
		if (size < 0)
			return -1;

		if (read_copy_data(handle, size, fd) < 0)
			return -1;
	}

	return 0;
}

static int copy_event_files(struct tracecmd_input *handle, int fd)
{
	unsigned long long size;
	char *system;
	int systems;
	int count;
	int ret;
	int i,x;

	systems = read_copy_size4(handle, fd);
	if (systems < 0)
		return -1;

	for (i = 0; i < systems; i++) {
		system = read_string(handle);
		if (!system)
			return -1;
		if (__do_write_check(fd, system, strlen(system) + 1)) {
			free(system);
			return -1;
		}
		free(system);

		count = read_copy_size4(handle, fd);
		if (count < 0)
			return -1;

		for (x=0; x < count; x++) {
			size = read_copy_size8(handle, fd);
			if (size < 0)
				return -1;

			ret = read_copy_data(handle, size, fd);
			if (ret < 0)
				return -1;
		}
	}

	return 0;
}

static int copy_proc_kallsyms(struct tracecmd_input *handle, int fd)
{
	int size;

	size = read_copy_size4(handle, fd);
	if (!size)
		return 0; /* OK? */

	if (size < 0)
		return -1;

	if (read_copy_data(handle, size, fd) < 0)
		return -1;

	return 0;
}

static int copy_ftrace_printk(struct tracecmd_input *handle, int fd)
{
	int size;

	size = read_copy_size4(handle, fd);
	if (!size)
		return 0; /* OK? */

	if (size < 0)
		return -1;

	if (read_copy_data(handle, size, fd) < 0)
		return -1;

	return 0;
}

static int copy_command_lines(struct tracecmd_input *handle, int fd)
{
	unsigned long size;

	size = read_copy_size8(handle, fd);
	if (!size)
		return 0; /* OK? */

	if (size < 0)
		return -1;

	if (read_copy_data(handle, size, fd) < 0)
		return -1;

	return 0;
}

int tracecmd_copy_headers(struct tracecmd_input *handle, int fd)
{
	int ret;

	ret = copy_header_files(handle, fd);
	if (ret < 0)
		return -1;

	ret = copy_ftrace_files(handle, fd);
	if (ret < 0)
		return -1;

	ret = copy_event_files(handle, fd);
	if (ret < 0)
		return -1;

	ret = copy_proc_kallsyms(handle, fd);
	if (ret < 0)
		return -1;

	ret = copy_ftrace_printk(handle, fd);
	if (ret < 0)
		return -1;

	ret = copy_command_lines(handle, fd);
	if (ret < 0)
		return -1;

	return 0;
}

/**
 * tracecmd_record_at_buffer_start - return true if record is first on subbuffer
 * @handle: input handle for the trace.dat file
 * @record: The record to test if it is the first record on page
 *
 * Returns true if the record is the first record on the page.
 */
int tracecmd_record_at_buffer_start(struct tracecmd_input *handle,
				    struct pevent_record *record)
{
	struct page *page = record->priv;
	struct kbuffer *kbuf = handle->cpu_data[record->cpu].kbuf;
	int offset;

	if (!page || !kbuf)
		return 0;

	offset = record->offset - page->offset;
	return offset == kbuffer_start_of_data(kbuf);
}

unsigned long long tracecmd_page_ts(struct tracecmd_input *handle,
				    struct pevent_record *record)
{
	struct page *page = record->priv;
	struct kbuffer *kbuf = handle->cpu_data[record->cpu].kbuf;

	if (!page || !kbuf)
		return 0;

	return kbuffer_subbuf_timestamp(kbuf, page->map);
}

unsigned int tracecmd_record_ts_delta(struct tracecmd_input *handle,
				      struct pevent_record *record)
{
	struct kbuffer *kbuf = handle->cpu_data[record->cpu].kbuf;
	struct page *page = record->priv;
	int offset;

	if (!page || !kbuf)
		return 0;

	offset = record->offset - page->offset;

	return kbuffer_ptr_delta(kbuf, page->map + offset);
}

struct kbuffer *tracecmd_record_kbuf(struct tracecmd_input *handle,
				     struct pevent_record *record)
{
	return handle->cpu_data[record->cpu].kbuf;
}

void *tracecmd_record_page(struct tracecmd_input *handle,
			   struct pevent_record *record)
{
	struct page *page = record->priv;

	return page ? page->map : NULL;
}

void *tracecmd_record_offset(struct tracecmd_input *handle,
			     struct pevent_record *record)
{
	struct page *page = record->priv;
	int offset;

	if (!page)
		return NULL;

	offset = record->offset - page->offset;

	return page->map + offset;
}

int tracecmd_buffer_instances(struct tracecmd_input *handle)
{
	return handle->nr_buffers;
}

const char *tracecmd_buffer_instance_name(struct tracecmd_input *handle, int indx)
{
	if (indx >= handle->nr_buffers)
		return NULL;

	return handle->buffers[indx].name;
}

struct tracecmd_input *
tracecmd_buffer_instance_handle(struct tracecmd_input *handle, int indx)
{
	struct tracecmd_input *new_handle;
	struct input_buffer_instance *buffer = &handle->buffers[indx];
	size_t offset;
	ssize_t ret;

	if (indx >= handle->nr_buffers)
		return NULL;

	/*
	 * We make a copy of the current handle, but we substitute
	 * the cpu data with the cpu data for this buffer.
	 */
	new_handle = malloc(sizeof(*handle));
	if (!new_handle)
		return NULL;

	*new_handle = *handle;
	new_handle->cpu_data = NULL;
	new_handle->nr_buffers = 0;
	new_handle->buffers = NULL;
	new_handle->ref = 1;
	new_handle->parent = handle;
	new_handle->cpustats = NULL;
	new_handle->hooks = NULL;
	if (handle->uname)
		/* Ignore if fails to malloc, no biggy */
		new_handle->uname = strdup(handle->uname);
	tracecmd_ref(handle);

	new_handle->fd = dup(handle->fd);

	new_handle->flags |= TRACECMD_FL_BUFFER_INSTANCE;

	/* Save where we currently are */
	offset = lseek64(handle->fd, 0, SEEK_CUR);

	ret = lseek64(handle->fd, buffer->offset, SEEK_SET);
	if (ret < 0) {
		warning("could not seek to buffer %s offset %ld\n",
			buffer->name, buffer->offset);
		tracecmd_close(new_handle);
		return NULL;
	}

	ret = read_cpu_data(new_handle);
	if (ret < 0) {
		warning("failed to read sub buffer %s\n", buffer->name);
		tracecmd_close(new_handle);
		return NULL;
	}

	ret = lseek64(handle->fd, offset, SEEK_SET);
	if (ret < 0) {
		warning("could not seek to back to offset %ld\n", offset);
		tracecmd_close(new_handle);
		return NULL;
	}

	return new_handle;
}

int tracecmd_is_buffer_instance(struct tracecmd_input *handle)
{
	return handle->flags & TRACECMD_FL_BUFFER_INSTANCE;
}

/**
 * tracecmd_long_size - return the size of "long" for the arch
 * @handle: input handle for the trace.dat file
 */
int tracecmd_long_size(struct tracecmd_input *handle)
{
	return handle->long_size;
}

/**
 * tracecmd_page_size - return the PAGE_SIZE for the arch
 * @handle: input handle for the trace.dat file
 */
int tracecmd_page_size(struct tracecmd_input *handle)
{
	return handle->page_size;
}

/**
 * tracecmd_page_size - return the number of CPUs recorded
 * @handle: input handle for the trace.dat file
 */
int tracecmd_cpus(struct tracecmd_input *handle)
{
	return handle->cpus;
}

/**
 * tracecmd_get_pevent - return the pevent handle
 * @handle: input handle for the trace.dat file
 */
struct pevent *tracecmd_get_pevent(struct tracecmd_input *handle)
{
	return handle->pevent;
}

/**
 * tracecmd_get_use_trace_clock - return use_trace_clock
 * @handle: input handle for the trace.dat file
 */
bool tracecmd_get_use_trace_clock(struct tracecmd_input *handle)
{
	return handle->use_trace_clock;
}
