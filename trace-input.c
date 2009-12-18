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

/* for debugging read instead of mmap */
static int force_read = 0;

struct cpu_data {
	/* the first two never change */
	unsigned long long	file_offset;
	unsigned long long	file_size;
	unsigned long long	offset;
	unsigned long long	size;
	unsigned long long	timestamp;
	struct record		*next;
	char			*page;
	void			*read_page;
	int			cpu;
	int			index;
	int			page_size;
};

struct tracecmd_input {
	struct pevent	*pevent;
	int		fd;
	int		long_size;
	int		page_size;
	int		read_page;
	int		cpus;
	struct cpu_data *cpu_data;

	/* file information */
	size_t		header_files_start;
	size_t		ftrace_files_start;
	size_t		event_files_start;
	
};

__thread struct tracecmd_input *tracecmd_curr_thread_handle;

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

	pevent_parse_header_page(pevent, header, size);
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

static int read_ftrace_file(struct tracecmd_input *handle,
			    unsigned long long size, int print)
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

	if (print)
		printf("%.*s\n", (int)size, buf);
	else
		pevent_parse_event(pevent, buf, size, "ftrace");
	free(buf);

	return 0;
}

static int read_event_file(struct tracecmd_input *handle,
			   char *system, unsigned long long size,
			   int print)
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

	if (print)
		printf("%.*s\n", (int)size, buf);
	else
		pevent_parse_event(pevent, buf, size, system);
	free(buf);

	return 0;
}

static int read_ftrace_files(struct tracecmd_input *handle, int print)
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
		ret = read_ftrace_file(handle, size, print);
		if (ret < 0)
			return -1;
	}

	handle->event_files_start =
		lseek64(handle->fd, 0, SEEK_CUR);

	return 0;
}

static int read_event_files(struct tracecmd_input *handle, int print)
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

		if (print)
			printf("\nsystem: %s\n", system);

		count = read4(handle);
		if (count < 0)
			goto failed;

		for (x=0; x < count; x++) {
			size = read8(handle);
			if (size < 0)
				goto failed;

			ret = read_event_file(handle, system, size, print);
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

	buf = malloc(size);
	if (!buf)
		return -1;
	if (do_read_check(handle, buf, size)){
		free(buf);
		return -1;
	}

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
	struct pevent *pevent = handle->pevent;
	int ret;

	ret = read_header_files(handle);
	if (ret < 0)
		return -1;

	ret = read_ftrace_files(handle, 0);
	if (ret < 0)
		return -1;

	ret = read_event_files(handle, 0);
	if (ret < 0)
		return -1;

	ret = read_proc_kallsyms(handle);
	if (ret < 0)
		return -1;

	ret = read_ftrace_printk(handle);
	if (ret < 0)
		return -1;

	/* register default ftrace functions first */
	tracecmd_ftrace_overrides(handle);

	trace_load_plugins(pevent);

	return 0;
}

static unsigned int type4host(struct tracecmd_input *handle,
			      unsigned int type_len_ts)
{
	struct pevent *pevent = handle->pevent;

	if (pevent->file_bigendian)
		return (type_len_ts >> 29) & 3;
	else
		return type_len_ts & 3;
}

static unsigned int len4host(struct tracecmd_input *handle,
			     unsigned int type_len_ts)
{
	struct pevent *pevent = handle->pevent;

	if (pevent->file_bigendian)
		return (type_len_ts >> 27) & 7;
	else
		return (type_len_ts >> 2) & 7;
}

static unsigned int type_len4host(struct tracecmd_input *handle,
				  unsigned int type_len_ts)
{
	struct pevent *pevent = handle->pevent;

	if (pevent->file_bigendian)
		return (type_len_ts >> 27) & ((1 << 5) - 1);
	else
		return type_len_ts & ((1 << 5) - 1);
}

static unsigned int ts4host(struct tracecmd_input *handle,
			    unsigned int type_len_ts)
{
	struct pevent *pevent = handle->pevent;

	if (pevent->file_bigendian)
		return type_len_ts & ((1 << 27) - 1);
	else
		return type_len_ts >> 5;
}

static int calc_index(struct tracecmd_input *handle,
		      void *ptr, int cpu)
{
	return (unsigned long)ptr - (unsigned long)handle->cpu_data[cpu].page;
}

static void free_page(struct tracecmd_input *handle, int cpu)
{
	if (!handle->cpu_data[cpu].page)
		return;

	if (!handle->read_page)
		munmap(handle->cpu_data[cpu].page, handle->page_size);

	handle->cpu_data[cpu].page = NULL;
}

/*
 * Page is mapped, now read in the page header info.
 */
static int update_page_info(struct tracecmd_input *handle, int cpu)
{
	struct pevent *pevent = handle->pevent;
	void *ptr = handle->cpu_data[cpu].page;

	/* FIXME: handle header page */
	if (pevent->header_page_ts_size != 8) {
		warning("expected a long long type for timestamp");
		return -1;
	}

	handle->cpu_data[cpu].timestamp = data2host8(pevent, ptr);
	ptr += 8;
	switch (pevent->header_page_size_size) {
	case 4:
		handle->cpu_data[cpu].page_size = data2host4(pevent, ptr);
		break;
	case 8:
		handle->cpu_data[cpu].page_size = data2host8(pevent, ptr);
		break;
	default:
		warning("bad long size");
		return -1;
	}

	handle->cpu_data[cpu].index = 0;

	return 0;
}

static int get_read_page(struct tracecmd_input *handle, int cpu,
			 off64_t offset)
{
	off64_t save_seek;
	off64_t ret;

	free_page(handle, cpu);

	handle->cpu_data[cpu].page = handle->cpu_data[cpu].read_page;

	/* other parts of the code may expect the pointer to not move */
	save_seek = lseek64(handle->fd, 0, SEEK_CUR);

	ret = lseek64(handle->fd, offset, SEEK_SET);
	if (ret < 0)
		return -1;
	ret = read(handle->fd, handle->cpu_data[cpu].page, handle->page_size);
	if (ret < 0)
		return -1;

	/* reset the file pointer back */
	lseek64(handle->fd, save_seek, SEEK_SET);

	if (update_page_info(handle, cpu))
		return -1;

	return 0;
}

static int get_page(struct tracecmd_input *handle, int cpu,
		    off64_t offset)
{
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
	handle->cpu_data[cpu].timestamp = 0;
	handle->cpu_data[cpu].index = 0;
	handle->cpu_data[cpu].size = (handle->cpu_data[cpu].file_offset +
				      handle->cpu_data[cpu].file_size) -
					offset;

	if (handle->read_page)
		return get_read_page(handle, cpu, offset);

	if (handle->cpu_data[cpu].page)
		free_page(handle, cpu);

	handle->cpu_data[cpu].page = mmap(NULL, handle->page_size, PROT_READ, MAP_PRIVATE,
					  handle->fd, offset);
	if (handle->cpu_data[cpu].page == MAP_FAILED)
		return -1;

	if (update_page_info(handle, cpu))
		return -1;

	return 0;
}
static int get_next_page(struct tracecmd_input *handle, int cpu)
{
	off64_t offset;

	if (!handle->cpu_data[cpu].page)
		return 0;

	free_page(handle, cpu);

	if (handle->cpu_data[cpu].size <= handle->page_size) {
		handle->cpu_data[cpu].offset = 0;
		handle->cpu_data[cpu].timestamp = 0;
		return 0;
	}

	offset = handle->cpu_data[cpu].offset + handle->page_size;

	return get_page(handle, cpu, offset);
}

enum old_ring_buffer_type {
	OLD_RINGBUF_TYPE_PADDING,
	OLD_RINGBUF_TYPE_TIME_EXTEND,
	OLD_RINGBUF_TYPE_TIME_STAMP,
	OLD_RINGBUF_TYPE_DATA,
};

static struct record *
read_old_format(struct tracecmd_input *handle, void **ptr, int cpu)
{
	struct pevent *pevent = handle->pevent;
	struct record *data;
	unsigned long long extend;
	unsigned int type_len_ts;
	unsigned int type;
	unsigned int len;
	unsigned int delta;
	unsigned int length;
	int index;

	index = calc_index(handle, *ptr, cpu);

	type_len_ts = data2host4(pevent, *ptr);
	*ptr += 4;

	type = type4host(handle, type_len_ts);
	len = len4host(handle, type_len_ts);
	delta = ts4host(handle, type_len_ts);

	switch (type) {
	case OLD_RINGBUF_TYPE_PADDING:
		*ptr = (void *)(((unsigned long)*ptr + (handle->page_size - 1)) &
				~(handle->page_size - 1));
		return NULL;

	case OLD_RINGBUF_TYPE_TIME_EXTEND:
		extend = data2host4(pevent, ptr);
		extend <<= TS_SHIFT;
		extend += delta;
		handle->cpu_data[cpu].timestamp += extend;
		*ptr += 4;
		return NULL;

	case OLD_RINGBUF_TYPE_TIME_STAMP:
		warning("should not be here");
		return NULL;
		break;
	default:
		if (len)
			length = len * 4;
		else {
			length = data2host4(pevent, *ptr);
			length -= 4;
			*ptr += 4;
		}
		break;
	}

	handle->cpu_data[cpu].timestamp += delta;

	data = malloc(sizeof(*data));
	if (!data)
		return NULL;
	memset(data, 0, sizeof(*data));

	data->ts = handle->cpu_data[cpu].timestamp;
	data->size = length;
	data->data = *ptr;
	data->offset = handle->cpu_data[cpu].offset + index;


	*ptr += ((length+3)/4) * 4;

	handle->cpu_data[cpu].index = calc_index(handle, *ptr, cpu);
	handle->cpu_data[cpu].next = data;

	data->record_size = handle->cpu_data[cpu].index - index;

	return data;
}

static struct record *
read_event(struct tracecmd_input *handle, unsigned long long offset,
	   int cpu)
{
	struct record *record = NULL;

	/*
	 * Since the timestamp is calculated from the beginnnig
	 * of the page and through each event, we reset the
	 * page to the beginning. This is just used by
	 * tracecmd_read_at.
	 */
	update_page_info(handle, cpu);
	if (handle->cpu_data[cpu].next) {
		free_record(handle->cpu_data[cpu].next);
		handle->cpu_data[cpu].next = NULL;
	}

	do {
		if (record)
			free_record(record);
		/* Make sure peek returns new data */
		if (handle->cpu_data[cpu].next) {
			free_record(handle->cpu_data[cpu].next);
			handle->cpu_data[cpu].next = NULL;
		}
		record = tracecmd_read_data(handle, cpu);
        } while (record && (record->offset + record->record_size) <= offset);

	return record;
}

static struct record *
find_and_read_event(struct tracecmd_input *handle, unsigned long long offset,
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
	page_offset = offset & ~(handle->page_size - 1);

	if (get_page(handle, cpu, page_offset))
		return NULL;

	if (pcpu)
		*pcpu = cpu;

	return read_event(handle, offset, cpu);
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
struct record *
tracecmd_read_at(struct tracecmd_input *handle, unsigned long long offset,
		 int *pcpu)
{
	unsigned long long page_offset;
	int cpu;

	page_offset = offset & ~(handle->page_size - 1);

	/* check to see if we have this page already */
	for (cpu = 0; cpu < handle->cpus; cpu++) {
		if (handle->cpu_data[cpu].offset == page_offset)
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
 */
int tracecmd_refresh_record(struct tracecmd_input *handle,
			    struct record *record)
{
	unsigned long long page_offset;

	page_offset = record->offset & ~(handle->page_size - 1);
	get_page(handle, record->cpu, page_offset);

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
struct record *
tracecmd_read_cpu_first(struct tracecmd_input *handle, int cpu)
{
	get_page(handle, cpu, handle->cpu_data[cpu].file_offset);

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
struct record *
tracecmd_read_cpu_last(struct tracecmd_input *handle, int cpu)
{
	struct record *record;
	off64_t offset;

	offset = handle->cpu_data[cpu].file_offset +
		handle->cpu_data[cpu].file_size;

	if (offset & (handle->page_size - 1))
		offset &= ~(handle->page_size - 1);
	else
		offset -= handle->page_size;

	get_page(handle, cpu, offset);

	do {
		record = tracecmd_read_data(handle, cpu);
		if (record)
			offset = record->offset;
	} while (record);

	return tracecmd_read_at(handle, offset, NULL);
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

	if (!cpu_data->page) {
		if (init_cpu(handle, cpu))
		    return -1;
	}

	if (cpu_data->timestamp == ts)
		return 0;

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
		if (get_page(handle, cpu, next))
			return -1;

		if (cpu_data->timestamp == ts)
			break;

		if (cpu_data->timestamp < ts)
			start = next;
		else
			end = next;

		next = start + (end - start) / 2;
		next &= ~(handle->page_size - 1);

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

	cpu_data->index = 0;

	return 0;
}

static unsigned int
translate_data(struct tracecmd_input *handle,
	       void **ptr, unsigned long long *delta, int *length)
{
	struct pevent *pevent = handle->pevent;
	unsigned long long extend;
	unsigned int type_len_ts;
	unsigned int type_len;

	type_len_ts = data2host4(pevent, *ptr);
	*ptr += 4;

	type_len = type_len4host(handle, type_len_ts);
	*delta = ts4host(handle, type_len_ts);

	switch (type_len) {
	case RINGBUF_TYPE_PADDING:
		*length = data2host4(pevent, *ptr);
		*ptr += 4;
		*length *= 4;
		*ptr += *length;
		break;

	case RINGBUF_TYPE_TIME_EXTEND:
		extend = data2host4(pevent, *ptr);
		*ptr += 4;
		extend <<= TS_SHIFT;
		extend += *delta;
		*delta = extend;
		break;

	case RINGBUF_TYPE_TIME_STAMP:
		*ptr += 12;
		break;
	case 0:
		*length = data2host4(pevent, *ptr) - 4;
		*length = (*length + 3) & ~3;
		*ptr += 4;
		break;
	default:
		*length = type_len * 4;
		break;
	}

	return type_len;
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
struct record *
tracecmd_translate_data(struct tracecmd_input *handle,
			void *ptr, int size)
{
	struct record *record;
	unsigned int type_len;

	/* minimum record read is 8, (warn?) (TODO: make 8 into macro) */
	if (size < 8)
		return NULL;

	record = malloc(sizeof(*record));
	if (!record)
		return NULL;
	memset(record, 0, sizeof(*record));

	record->data = ptr;
	type_len = translate_data(handle, &record->data, &record->ts, &record->size);
	switch (type_len) {
	case RINGBUF_TYPE_PADDING:
	case RINGBUF_TYPE_TIME_EXTEND:
	case RINGBUF_TYPE_TIME_STAMP:
		record->data = NULL;
		break;
	default:
		break;
	}

	return record;
}

/**
 * tracecmd_peek_data - return the record at the current location.
 * @handle: input handle for the trace.dat file
 * @cpu: the CPU to pull from
 *
 * This returns the record at the current location of the CPU
 * iterator. It does not increment the CPU iterator.
 *
 * NOTE: Do not free the record returned, it is stored in the @handle.
 */
struct record *
tracecmd_peek_data(struct tracecmd_input *handle, int cpu)
{
	struct pevent *pevent = handle->pevent;
	struct record *record;
	void *page = handle->cpu_data[cpu].page;
	int index = handle->cpu_data[cpu].index;
	void *ptr = page + index;
	unsigned long long extend;
	unsigned int type_len;
	int length;

	/* Hack to work around function graph read ahead */
	tracecmd_curr_thread_handle = handle;

	if (handle->cpu_data[cpu].next)
		return handle->cpu_data[cpu].next;

	if (!page)
		return NULL;

	if (!index)
		ptr = handle->cpu_data[cpu].page + pevent->header_page_data_offset;

read_again:
	index = calc_index(handle, ptr, cpu);

	if (index >= handle->cpu_data[cpu].page_size) {
		if (get_next_page(handle, cpu))
			return NULL;
		return tracecmd_peek_data(handle, cpu);
	}

	if (pevent->old_format) {
		record = read_old_format(handle, &ptr, cpu);
		if (!record) {
			if (!ptr)
				return NULL;
			goto read_again;
		}
		record->cpu = cpu;
		return record;
	}

	type_len = translate_data(handle, &ptr, &extend, &length);

	switch (type_len) {
	case RINGBUF_TYPE_PADDING:
		if (!extend) {
			warning("error, hit unexpected end of page");
			return NULL;
		}
		/* fall through */
	case RINGBUF_TYPE_TIME_EXTEND:
		handle->cpu_data[cpu].timestamp += extend;
		/* fall through */
	case RINGBUF_TYPE_TIME_STAMP:
		goto read_again;
	default:
		break;
	}

	handle->cpu_data[cpu].timestamp += extend;

	record = malloc(sizeof(*record));
	if (!record)
		return NULL;
	memset(record, 0, sizeof(*record));

	record->ts = handle->cpu_data[cpu].timestamp;
	record->size = length;
	record->cpu = cpu;
	record->data = ptr;
	record->offset = handle->cpu_data[cpu].offset + index;

	ptr += length;

	handle->cpu_data[cpu].index = calc_index(handle, ptr, cpu);
	handle->cpu_data[cpu].next = record;

	record->record_size = handle->cpu_data[cpu].index - index;

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
struct record *
tracecmd_read_data(struct tracecmd_input *handle, int cpu)
{
	struct record *record;

	record = tracecmd_peek_data(handle, cpu);
	handle->cpu_data[cpu].next = NULL;

	return record;
}

static int init_read(struct tracecmd_input *handle, int cpu)
{
	off64_t ret;
	off64_t save_seek;

	handle->cpu_data[cpu].read_page = malloc(handle->page_size);
	if (!handle->cpu_data[cpu].read_page)
		return -1;

	handle->cpu_data[cpu].page = handle->cpu_data[cpu].read_page;

	/* other parts of the code may expect the pointer to not move */
	save_seek = lseek64(handle->fd, 0, SEEK_CUR);

	ret = lseek64(handle->fd, (off64_t)handle->cpu_data[cpu].offset, SEEK_SET);
	if (ret < 0)
		return -1;
	ret = read(handle->fd, handle->cpu_data[cpu].page, handle->page_size);
	if (ret < 0)
		return -1;

	/* reset the file pointer back */
	lseek64(handle->fd, save_seek, SEEK_SET);

	handle->cpu_data[cpu].timestamp =
		data2host8(handle->pevent, handle->cpu_data[cpu].page);

	return 0;
}

static int init_cpu(struct tracecmd_input *handle, int cpu)
{
	handle->cpu_data[cpu].offset = handle->cpu_data[cpu].file_offset;
	handle->cpu_data[cpu].size = handle->cpu_data[cpu].file_size;
	handle->cpu_data[cpu].timestamp = 0;

	if (!handle->cpu_data[cpu].size) {
		printf("CPU %d is empty\n", cpu);
		return 0;
	}

	if (handle->read_page)
		return init_read(handle, cpu);

	if (!force_read) {
		handle->cpu_data[cpu].page = mmap(NULL, handle->page_size, PROT_READ,
				  MAP_PRIVATE, handle->fd, handle->cpu_data[cpu].offset);
	}
	if (force_read || handle->cpu_data[cpu].page == MAP_FAILED) {
		/* fall back to just reading pages */
		perror("mmap");
		fprintf(stderr, "Can not mmap file, will read instead\n");
		handle->read_page = 1;

		return init_read(handle, cpu);
	}


	if (update_page_info(handle, cpu))
		return -1;

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
	unsigned long long size;
	char *cmdlines;
	char buf[10];
	int cpu;

	size = read8(handle);
	if (size < 0)
		return -1;
	cmdlines = malloc(size);
	if (!cmdlines)
		return -1;
	if (do_read_check(handle, cmdlines, size)) {
		free(cmdlines);
		return -1;
	}
	parse_cmdlines(pevent, cmdlines, size);
	free(cmdlines);

	handle->cpus = read4(handle);
	if (handle->cpus < 0)
		return -1;

	pevent_set_cpus(pevent, handle->cpus);
	pevent_set_long_size(pevent, handle->long_size);

	/*
	 * Check if this is a latency report or not.
	 */
	if (do_read_check(handle, buf, 10))
		return -1;
	if (strncmp(buf, "latency", 7) == 0)
		return 1;

	handle->cpu_data = malloc(sizeof(*handle->cpu_data) * handle->cpus);
	if (!handle->cpu_data)
		return -1;
	memset(handle->cpu_data, 0, sizeof(*handle->cpu_data) * handle->cpus);

	for (cpu = 0; cpu < handle->cpus; cpu++) {
		unsigned long long offset;

		handle->cpu_data[cpu].cpu = cpu;

		offset = read8(handle);
		size = read8(handle);

		handle->cpu_data[cpu].file_offset = offset;
		handle->cpu_data[cpu].file_size = size;

		if (init_cpu(handle, cpu))
			return -1;
	}

	return 0;
}

/**
 * tracecmd_print_events - print the events that are stored in trace.dat
 * @handle: input handle for the trace.dat file
 *
 * This is a debugging routine to print out the events that
 * are stored in a given trace.dat file.
 */
void tracecmd_print_events(struct tracecmd_input *handle)
{
	int ret;

	if (!handle->ftrace_files_start) {
		lseek64(handle->fd, handle->header_files_start, SEEK_SET);
		read_header_files(handle);
	}
	ret = read_ftrace_files(handle, 1);
	if (ret < 0)
		return;

	read_event_files(handle, 1);
	return;
}

/**
 * tracecmd_open_fd - create a tracecmd_handle from the trace.dat file descriptor
 * @fd: the file descriptor for the trace.dat file
 */
struct tracecmd_input *tracecmd_open_fd(int fd)
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

	handle->pevent = pevent_alloc();
	if (!handle->pevent)
		goto failed_read;

	handle->pevent->file_bigendian = buf[0];
	handle->pevent->host_bigendian = tracecmd_host_bigendian();

	do_read_check(handle, buf, 1);
	handle->long_size = buf[0];

	handle->page_size = read4(handle);

	handle->header_files_start =
		lseek64(handle->fd, 0, SEEK_CUR);

	return handle;

 failed_read:
	free(handle);

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

void tracecmd_close(struct tracecmd_input *handle)
{
	/* TODO FREE EVERYTHING!!! %%%% MEMORY LEAK!!! %%%% */
	close(handle->fd);
	free(handle);
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
