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


struct cpu_data {
	/* the first two never change */
	unsigned long long	file_offset;
	unsigned long long	file_size;
	unsigned long long	offset;
	unsigned long long	size;
	unsigned long long	timestamp;
	struct record		*next;
	char			*page;
	int			cpu;
	int			index;
	int			page_size;
};

struct tracecmd_handle {
	int		fd;
	int		long_size;
	int		page_size;
	int		print_events;
	int		read_page;
	int		cpus;
	struct cpu_data *cpu_data;
};

__thread struct tracecmd_handle *tracecmd_curr_thread_handle;

static int init_cpu(struct tracecmd_handle *handle, int cpu);

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

	/* register default ftrace functions first */
	tracecmd_ftrace_overrides();

	trace_load_plugins();

	return 0;
}

static unsigned int type4host(unsigned int type_len_ts)
{
	if (file_bigendian)
		return (type_len_ts >> 29) & 3;
	else
		return type_len_ts & 3;
}

static unsigned int len4host(unsigned int type_len_ts)
{
	if (file_bigendian)
		return (type_len_ts >> 27) & 7;
	else
		return (type_len_ts >> 2) & 7;
}

static unsigned int type_len4host(unsigned int type_len_ts)
{
	if (file_bigendian)
		return (type_len_ts >> 27) & ((1 << 5) - 1);
	else
		return type_len_ts & ((1 << 5) - 1);
}

static unsigned int ts4host(unsigned int type_len_ts)
{
	if (file_bigendian)
		return type_len_ts & ((1 << 27) - 1);
	else
		return type_len_ts >> 5;
}

static int calc_index(struct tracecmd_handle *handle,
		      void *ptr, int cpu)
{
	return (unsigned long)ptr - (unsigned long)handle->cpu_data[cpu].page;
}

static void
update_cpu_data_index(struct tracecmd_handle *handle, int cpu)
{
	handle->cpu_data[cpu].offset += handle->page_size;
	handle->cpu_data[cpu].size -= handle->page_size;
	handle->cpu_data[cpu].index = 0;
}

static int get_next_page(struct tracecmd_handle *handle, int cpu)
{
	off64_t save_seek;
	off64_t ret;

	if (!handle->cpu_data[cpu].page)
		return 0;

	if (handle->read_page) {
		if (handle->cpu_data[cpu].size <= handle->page_size) {
			free(handle->cpu_data[cpu].page);
			handle->cpu_data[cpu].page = NULL;
			return 0;
		}

		update_cpu_data_index(handle, cpu);

		/* other parts of the code may expect the pointer to not move */
		save_seek = lseek64(handle->fd, 0, SEEK_CUR);

		ret = lseek64(handle->fd, handle->cpu_data[cpu].offset, SEEK_SET);
		if (ret < 0)
			return -1;
		ret = read(handle->fd, handle->cpu_data[cpu].page, handle->page_size);
		if (ret < 0)
			return -1;

		/* reset the file pointer back */
		lseek64(handle->fd, save_seek, SEEK_SET);

		return 0;
	}

	munmap(handle->cpu_data[cpu].page, handle->page_size);
	handle->cpu_data[cpu].page = NULL;

	if (handle->cpu_data[cpu].size <= handle->page_size)
		return 0;

	update_cpu_data_index(handle, cpu);
	
	handle->cpu_data[cpu].page = mmap(NULL, handle->page_size, PROT_READ, MAP_PRIVATE,
				  handle->fd, handle->cpu_data[cpu].offset);
	if (handle->cpu_data[cpu].page == MAP_FAILED)
		return -1;

	return 0;
}

enum old_ring_buffer_type {
	OLD_RINGBUF_TYPE_PADDING,
	OLD_RINGBUF_TYPE_TIME_EXTEND,
	OLD_RINGBUF_TYPE_TIME_STAMP,
	OLD_RINGBUF_TYPE_DATA,
};

static struct record *
read_old_format(struct tracecmd_handle *handle, void **ptr, int cpu)
{
	struct record *data;
	unsigned long long extend;
	unsigned int type_len_ts;
	unsigned int type;
	unsigned int len;
	unsigned int delta;
	unsigned int length;
	int index;

	index = calc_index(handle, *ptr, cpu);

	type_len_ts = data2host4(*ptr);
	*ptr += 4;

	type = type4host(type_len_ts);
	len = len4host(type_len_ts);
	delta = ts4host(type_len_ts);

	switch (type) {
	case OLD_RINGBUF_TYPE_PADDING:
		*ptr = (void *)(((unsigned long)*ptr + (handle->page_size - 1)) &
				~(handle->page_size - 1));
		return NULL;

	case OLD_RINGBUF_TYPE_TIME_EXTEND:
		extend = data2host4(ptr);
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
			length = data2host4(*ptr);
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
read_event(struct tracecmd_handle *handle, unsigned long long offset,
	   int cpu)
{
	struct record *record;

	/*
	 * Since the timestamp is calculated from the beginnnig
	 * of the page and through each event, we need to start
	 * with the timestamp. We can't go backwards.
	 * If the offset is behind the current offset then we
	 * need to calculate it again.
	 */
	if (offset < handle->cpu_data[cpu].offset +
	    handle->cpu_data[cpu].index)
		handle->cpu_data[cpu].index = 0;

	do {
		/* Make sure peek returns new data */
		handle->cpu_data[cpu].next = NULL;
		record = tracecmd_read_data(handle, cpu);
        } while (record && (record->offset + record->record_size) <= offset);

	return record;
}

static struct record *
find_and_read_event(struct tracecmd_handle *handle, unsigned long long offset,
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

	if (handle->cpu_data[cpu].page) {
		/*
		 * If a page already exists, then we need to reset
		 * it to point to the page with the data we want.
		 * We update the pointers to point to the previous
		 * page, and call get_next_page which will mmap
		 * the next page after the pointer of the previous
		 * page we want. Which ends up mapping the page we want.
		 */

		page_offset -= handle->page_size;

		handle->cpu_data[cpu].offset = page_offset;
		handle->cpu_data[cpu].size = (handle->cpu_data[cpu].file_offset +
					      handle->cpu_data[cpu].file_size) -
						page_offset;

		if (get_next_page(handle, cpu))
			return NULL;
	} else {
		/*
		 * We need to map a new page. Just set it up the cpu_data
		 * to the position we want.
		 */
		handle->cpu_data[cpu].offset = page_offset;
		handle->cpu_data[cpu].size = (handle->cpu_data[cpu].file_offset +
					      handle->cpu_data[cpu].file_size) -
						page_offset;

		if (init_cpu(handle, cpu))
			return NULL;
	}

	if (pcpu)
		*pcpu = cpu;

	return read_event(handle, offset, cpu);
}


struct record *
tracecmd_read_at(struct tracecmd_handle *handle, unsigned long long offset,
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

static unsigned int
translate_data(void **ptr, unsigned long long *delta, int *length)
{
	unsigned long long extend;
	unsigned int type_len_ts;
	unsigned int type_len;

	type_len_ts = data2host4(*ptr);
	*ptr += 4;

	type_len = type_len4host(type_len_ts);
	*delta = ts4host(type_len_ts);

	switch (type_len) {
	case RINGBUF_TYPE_PADDING:
		*length = data2host4(*ptr);
		*ptr += 4;
		*length *= 4;
		*ptr += *length;
		break;

	case RINGBUF_TYPE_TIME_EXTEND:
		extend = data2host4(*ptr);
		*ptr += 4;
		extend <<= TS_SHIFT;
		extend += *delta;
		*delta = extend;
		break;

	case RINGBUF_TYPE_TIME_STAMP:
		*ptr += 12;
		break;
	case 0:
		*length = data2host4(*ptr) - 4;
		*length = (*length + 3) & ~3;
		*ptr += 4;
		break;
	default:
		*length = type_len * 4;
		break;
	}

	return type_len;
}

struct record *
tracecmd_translate_data(struct tracecmd_handle *handle,
			void *ptr, int size)
{
	struct record *data;
	unsigned int type_len;

	/* minimum record read is 8, (warn?) (TODO: make 8 into macro) */
	if (size < 8)
		return NULL;

	data = malloc(sizeof(*data));
	if (!data)
		return NULL;
	memset(data, 0, sizeof(*data));

	data->data = ptr;
	type_len = translate_data(&data->data, &data->ts, &data->size);
	switch (type_len) {
	case RINGBUF_TYPE_PADDING:
	case RINGBUF_TYPE_TIME_EXTEND:
	case RINGBUF_TYPE_TIME_STAMP:
		data->data = NULL;
		break;
	default:
		break;
	}

	return data;
}

struct record *
tracecmd_peek_data(struct tracecmd_handle *handle, int cpu)
{
	struct record *data;
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

	if (!index) {
		/* FIXME: handle header page */
		if (header_page_ts_size != 8) {
			warning("expected a long long type for timestamp");
			return NULL;
		}
		handle->cpu_data[cpu].timestamp = data2host8(ptr);
		ptr += 8;
		switch (header_page_size_size) {
		case 4:
			handle->cpu_data[cpu].page_size = data2host4(ptr);
			ptr += 4;
			break;
		case 8:
			handle->cpu_data[cpu].page_size = data2host8(ptr);
			ptr += 8;
			break;
		default:
			warning("bad long size");
			return NULL;
		}
		ptr = handle->cpu_data[cpu].page + header_page_data_offset;
	}

read_again:
	index = calc_index(handle, ptr, cpu);

	if (index >= handle->cpu_data[cpu].page_size) {
		if (get_next_page(handle, cpu))
			return NULL;
		return tracecmd_peek_data(handle, cpu);
	}

	if (old_format) {
		data = read_old_format(handle, &ptr, cpu);
		if (!data) {
			if (!ptr)
				return NULL;
			goto read_again;
		}
			
		return data;
	}

	type_len = translate_data(&ptr, &extend, &length);

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

	data = malloc(sizeof(*data));
	if (!data)
		return NULL;
	memset(data, 0, sizeof(*data));

	data->ts = handle->cpu_data[cpu].timestamp;
	data->size = length;
	data->data = ptr;
	data->offset = handle->cpu_data[cpu].offset + index;

	ptr += length;

	handle->cpu_data[cpu].index = calc_index(handle, ptr, cpu);
	handle->cpu_data[cpu].next = data;

	data->record_size = handle->cpu_data[cpu].index - index;

	return data;
}

struct record *
tracecmd_read_data(struct tracecmd_handle *handle, int cpu)
{
	struct record *data;

	data = tracecmd_peek_data(handle, cpu);
	handle->cpu_data[cpu].next = NULL;

	return data;
}

static int init_read(struct tracecmd_handle *handle, int cpu)
{
	off64_t ret;
	off64_t save_seek;

	handle->cpu_data[cpu].page = malloc(handle->page_size);
	if (!handle->cpu_data[cpu].page)
		return -1;

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

	return 0;
}

static int init_cpu(struct tracecmd_handle *handle, int cpu)
{
	if (!handle->cpu_data[cpu].size) {
		printf("CPU %d is empty\n", cpu);
		return 0;
	}

	if (handle->read_page)
		return init_read(handle, cpu);

	handle->cpu_data[cpu].page = mmap(NULL, handle->page_size, PROT_READ,
				  MAP_PRIVATE, handle->fd, handle->cpu_data[cpu].offset);
	if (handle->cpu_data[cpu].page == MAP_FAILED) {
		/* fall back to just reading pages */
		perror("mmap");
		fprintf(stderr, "Can not mmap file, will read instead\n");
		handle->read_page = 1;

		return init_read(handle, cpu);
	}
	return 0;
}

int tracecmd_init_data(struct tracecmd_handle *handle)
{
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
	parse_cmdlines(cmdlines, size);
	free(cmdlines);

	handle->cpus = read4(handle);
	if (handle->cpus < 0)
		return -1;

	parse_set_info(handle->cpus, handle->long_size);

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

		handle->cpu_data[cpu].offset = offset;
		handle->cpu_data[cpu].size = size;
		handle->cpu_data[cpu].file_offset = offset;
		handle->cpu_data[cpu].file_size = size;

		if (init_cpu(handle, cpu))
			return -1;
	}

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

int tracecmd_cpus(struct tracecmd_handle *handle)
{
	return handle->cpus;
}
