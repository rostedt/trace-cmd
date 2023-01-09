// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * Updates:
 * Copyright (C) 2019, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 */
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "trace-local.h"

#define TRACING_STR	"tracing"
#define HEAD_PAGE_STR	"header_page"
#define HEAD_PAGE_EVENT	"header_event"
#define HEAD_OPTIONS	"options  "
#define HEAD_LATENCY	"latency  "
#define HEAD_FLYRECORD	"flyrecord"

#define DUMP_SIZE	1024

static struct tep_handle *tep;
static unsigned int trace_cpus;
static int has_clock;
static unsigned long file_version;
static bool	read_compress;
static struct tracecmd_compression *compress;
static char *meta_strings;
static int meta_strings_size;

enum dump_items {
	SUMMARY		= (1 << 0),
	HEAD_PAGE	= (1 << 1),
	HEAD_EVENT	= (1 << 2),
	FTRACE_FORMAT	= (1 << 3),
	EVENT_SYSTEMS	= (1 << 4),
	EVENT_FORMAT	= (1 << 5),
	KALLSYMS	= (1 << 6),
	TRACE_PRINTK	= (1 << 7),
	CMDLINES	= (1 << 8),
	OPTIONS		= (1 << 9),
	FLYRECORD	= (1 << 10),
	CLOCK		= (1 << 11),
	SECTIONS	= (1 << 12),
	STRINGS		= (1 << 13),
};

struct file_section {
	int id;
	unsigned long long offset;
	struct file_section *next;
	enum dump_items verbosity;
};

static struct file_section *sections;

enum dump_items verbosity;

#define DUMP_CHECK(X) ((X) & verbosity)

#define do_print(ids, fmt, ...)					\
	do {							\
		if (!(ids) || DUMP_CHECK(ids))			\
			tracecmd_plog(fmt, ##__VA_ARGS__);	\
	} while (0)

static int read_fd(int fd, char *dst, int len)
{
	size_t size = 0;
	int r;

	do {
		r = read(fd, dst+size, len);
		if (r > 0) {
			size += r;
			len -= r;
		} else
			break;
	} while (r > 0);

	if (len)
		return -1;
	return size;
}

static int read_compressed(int fd, char *dst, int len)
{

	if (read_compress)
		return tracecmd_compress_buffer_read(compress, dst, len);

	return read_fd(fd, dst, len);
}

static int do_lseek(int fd, int offset, int whence)
{
	if (read_compress)
		return tracecmd_compress_lseek(compress, offset, whence);

	return lseek(fd, offset, whence);
}

static int read_file_string(int fd, char *dst, int len)
{
	size_t size = 0;
	int r;

	do {
		r = read_compressed(fd, dst+size, 1);
		if (r > 0) {
			size++;
			len--;
		} else
			break;
		if (!dst[size - 1])
			break;
	} while (r > 0 && len);

	if (!size || dst[size - 1])
		return -1;
	return 0;
}

static int read_file_bytes(int fd, char *dst, int len)
{
	int ret;

	ret = read_compressed(fd, dst, len);
	return ret < 0 ? ret : 0;
}

static void read_dump_string(int fd, int size, enum dump_items id)
{
	char buf[DUMP_SIZE];
	int lsize;

	while (size) {
		lsize = (size < DUMP_SIZE) ? size : DUMP_SIZE - 1;
		if (read_file_bytes(fd, buf, lsize))
			die("cannot read %d bytes", lsize);
		buf[lsize] = 0;
		do_print(id, "%s", buf);
		size -= lsize;
	}

	do_print(id, "\n");
}

static int read_file_number(int fd, void *digit, int size)
{
	unsigned long long val;
	char buf[8];

	if (size > 8)
		return -1;

	if (read_file_bytes(fd, buf, size))
		return -1;

	val = tep_read_number(tep, buf, size);
	switch (size) {
	case 1:
		*((char *)digit) = val;
		break;
	case 2:
		*((unsigned short *)digit) = val;
		break;
	case 4:
		*((unsigned int *)digit) = val;
		break;
	case 8:
		*((unsigned long long *)digit) = val;
		break;
	default:
		return -1;
	}

	return 0;
}

static const char *get_metadata_string(int offset)
{
	if (!meta_strings || offset < 0 || meta_strings_size <= offset)
		return NULL;

	return meta_strings + offset;
}

static void dump_initial_format(int fd)
{
	char magic[] = TRACECMD_MAGIC;
	char buf[DUMP_SIZE];
	int val4;

	do_print(SUMMARY, "\t[Initial format]\n");

	/* check initial bytes */
	if (read_file_bytes(fd, buf, sizeof(magic)))
		die("cannot read %zu bytes magic", sizeof(magic));
	if (memcmp(buf, magic, sizeof(magic)) != 0)
		die("wrong file magic");

	/* check initial tracing string */
	if (read_file_bytes(fd, buf, strlen(TRACING_STR)))
		die("cannot read %zu bytes tracing string", strlen(TRACING_STR));
	buf[strlen(TRACING_STR)] = 0;
	if (strncmp(buf, TRACING_STR, strlen(TRACING_STR)) != 0)
		die("wrong tracing string: %s", buf);

	/* get file version */
	if (read_file_string(fd, buf, DUMP_SIZE))
		die("no version string");

	do_print(SUMMARY, "\t\t%s\t[Version]\n", buf);
	file_version = strtol(buf, NULL, 10);
	if (!file_version && errno)
		die("Invalid file version string %s", buf);
	if (!tracecmd_is_version_supported(file_version))
		die("Unsupported file version %lu", file_version);

	/* get file endianness*/
	if (read_file_bytes(fd, buf, 1))
		die("cannot read file endianness");
	do_print(SUMMARY, "\t\t%d\t[%s endian]\n", buf[0], buf[0]?"Big":"Little");

	tep_set_file_bigendian(tep, buf[0]);
	tep_set_local_bigendian(tep, tracecmd_host_bigendian());

	/* get file bytes per long*/
	if (read_file_bytes(fd, buf, 1))
		die("cannot read file bytes per long");
	do_print(SUMMARY, "\t\t%d\t[Bytes in a long]\n", buf[0]);

	if (read_file_number(fd, &val4, 4))
		die("cannot read file page size");
	do_print(SUMMARY, "\t\t%d\t[Page size, bytes]\n", val4);
}

static void dump_compress(int fd)
{
	char zname[DUMP_SIZE];
	char zver[DUMP_SIZE];

	if (file_version < FILE_VERSION_COMPRESSION)
		return;

	/* get compression header */
	if (read_file_string(fd, zname, DUMP_SIZE))
		die("no compression header");

	if (read_file_string(fd, zver, DUMP_SIZE))
		die("no compression version");

	do_print((SUMMARY), "\t\t%s\t[Compression algorithm]\n", zname);
	do_print((SUMMARY), "\t\t%s\t[Compression version]\n", zver);

	if (strcmp(zname, "none")) {
		compress = tracecmd_compress_alloc(zname, zver, fd, tep, NULL);
		if (!compress)
			die("cannot uncompress the file");
	}
}

static void dump_header_page(int fd)
{
	unsigned long long size;
	char buf[DUMP_SIZE];

	do_print((SUMMARY | HEAD_PAGE), "\t[Header page, ");

	/* check header string */
	if (read_file_bytes(fd, buf, strlen(HEAD_PAGE_STR) + 1))
		die("cannot read %zu bytes header string", strlen(HEAD_PAGE_STR));
	if (strncmp(buf, HEAD_PAGE_STR, strlen(HEAD_PAGE_STR)) != 0)
		die("wrong header string: %s", buf);

	if (read_file_number(fd, &size, 8))
		die("cannot read the size of the page header information");

	do_print((SUMMARY | HEAD_PAGE), "%lld bytes]\n", size);

	read_dump_string(fd, size, HEAD_PAGE);
}

static void dump_header_event(int fd)
{
	unsigned long long size;
	char buf[DUMP_SIZE];

	do_print((SUMMARY | HEAD_EVENT), "\t[Header event, ");

	/* check header string */
	if (read_file_bytes(fd, buf, strlen(HEAD_PAGE_EVENT) + 1))
		die("cannot read %zu bytes header string", strlen(HEAD_PAGE_EVENT));
	if (strncmp(buf, HEAD_PAGE_EVENT, strlen(HEAD_PAGE_EVENT)) != 0)
		die("wrong header string: %s", buf);

	if (read_file_number(fd, &size, 8))
		die("cannot read the size of the page header information");

	do_print((SUMMARY | HEAD_EVENT), "%lld bytes]\n", size);

	read_dump_string(fd, size, HEAD_EVENT);
}

static void uncompress_reset(void)
{
	if (compress && file_version >= FILE_VERSION_COMPRESSION) {
		read_compress = false;
		tracecmd_compress_reset(compress);
	}
}

static int uncompress_block(void)
{
	int ret = 0;

	if (compress && file_version >= FILE_VERSION_COMPRESSION) {
		ret = tracecmd_uncompress_block(compress);
		if (!ret)
			read_compress = true;

	}

	return ret;
}

static void dump_ftrace_events_format(int fd)
{
	unsigned long long size;
	unsigned int count;

	do_print((SUMMARY | FTRACE_FORMAT), "\t[Ftrace format, ");
	if (read_file_number(fd, &count, 4))
		die("cannot read the count of the ftrace events");

	do_print((SUMMARY | FTRACE_FORMAT), "%d events]\n", count);

	while (count) {
		if (read_file_number(fd, &size, 8))
			die("cannot read the size of the %d ftrace event", count);
		read_dump_string(fd, size, FTRACE_FORMAT);
		count--;
	}
}

static void dump_events_format(int fd)
{
	unsigned long long size;
	unsigned int systems;
	unsigned int events;
	char buf[DUMP_SIZE];

	do_print((SUMMARY | EVENT_FORMAT | EVENT_SYSTEMS), "\t[Events format, ");

	if (read_file_number(fd, &systems, 4))
		die("cannot read the count of the event systems");

	do_print((SUMMARY | EVENT_FORMAT | EVENT_SYSTEMS), "%d systems]\n", systems);

	while (systems) {

		if (read_file_string(fd, buf, DUMP_SIZE))
			die("cannot read the name of the %dth system", systems);
		if (read_file_number(fd, &events, 4))
			die("cannot read the count of the events in system %s",
			     buf);
		do_print(EVENT_SYSTEMS, "\t\t%s %d [system, events]\n", buf, events);
		while (events) {
			if (read_file_number(fd, &size, 8))
				die("cannot read the format size of the %dth event from system %s",
				    events, buf);
			read_dump_string(fd, size, EVENT_FORMAT);
			events--;
		}
		systems--;
	}
}

static void dump_kallsyms(int fd)
{
	unsigned int size;

	do_print((SUMMARY | KALLSYMS), "\t[Kallsyms, ");

	if (read_file_number(fd, &size, 4))
		die("cannot read the size of the kallsyms");

	do_print((SUMMARY | KALLSYMS), "%d bytes]\n", size);

	read_dump_string(fd, size, KALLSYMS);
}

static void dump_printk(int fd)
{
	unsigned int size;

	do_print((SUMMARY | TRACE_PRINTK), "\t[Trace printk, ");

	if (read_file_number(fd, &size, 4))
		die("cannot read the size of the trace printk");

	do_print((SUMMARY | TRACE_PRINTK), "%d bytes]\n", size);

	read_dump_string(fd, size, TRACE_PRINTK);
}

static void dump_cmdlines(int fd)
{
	unsigned long long size;

	do_print((SUMMARY | CMDLINES), "\t[Saved command lines, ");

	if (read_file_number(fd, &size, 8))
		die("cannot read the size of the saved command lines");

	do_print((SUMMARY | CMDLINES), "%d bytes]\n", size);

	read_dump_string(fd, size, CMDLINES);
}

static void dump_cpus_count(int fd)
{
	if (read_file_number(fd, &trace_cpus, 4))
		die("cannot read the cpu count");

	do_print(SUMMARY, "\t%d [CPUs with tracing data]\n", trace_cpus);
}

static void dump_option_string(int fd, int size, char *desc)
{
	do_print(OPTIONS, "\t\t[Option %s, %d bytes]\n", desc, size);
	if (size)
		read_dump_string(fd, size, OPTIONS);
}

static void dump_section_header(int fd, enum dump_items v, unsigned short *flags)
{
	unsigned long long offset, size;
	unsigned short fl;
	unsigned short id;
	const char *desc;
	int desc_id;

	offset = lseek(fd, 0, SEEK_CUR);
	if (read_file_number(fd, &id, 2))
		die("cannot read the section id");

	if (read_file_number(fd, &fl, 2))
		die("cannot read the section flags");

	if (read_file_number(fd, &desc_id, 4))
		die("no section description");

	desc = get_metadata_string(desc_id);
	if (!desc)
		desc = "Unknown";

	if (read_file_number(fd, &size, 8))
		die("cannot read section size");

	do_print(v, "\t[Section %d @ %lld: \"%s\", flags 0x%X, %lld bytes]\n",
		 id, offset, desc, fl, size);

	if (flags)
		*flags = fl;
}

static void dump_option_buffer(int fd, unsigned short option, int size)
{
	unsigned long long total_size = 0;
	unsigned long long data_size;
	unsigned long long current;
	unsigned long long offset;
	unsigned short flags;
	char clock[DUMP_SIZE];
	char name[DUMP_SIZE];
	int page_size;
	int cpus = 0;
	int id;
	int i;

	if (size < 8)
		die("broken buffer option with size %d", size);

	if (read_file_number(fd, &offset, 8))
		die("cannot read the offset of the buffer option");

	if (read_file_string(fd, name, DUMP_SIZE))
		die("cannot read the name of the buffer option");

	if (file_version < FILE_VERSION_SECTIONS) {
		do_print(OPTIONS|FLYRECORD, "\t\t[Option BUFFER, %d bytes]\n", size);
		do_print(OPTIONS|FLYRECORD, "%lld [offset]\n", offset);
		do_print(OPTIONS|FLYRECORD, "\"%s\" [name]\n", name);
		return;
	}

	current = lseek(fd, 0, SEEK_CUR);
	if (lseek(fd, offset, SEEK_SET) == (off_t)-1)
		die("cannot goto buffer offset %lld", offset);

	dump_section_header(fd, FLYRECORD, &flags);

	if (lseek(fd, current, SEEK_SET) == (off_t)-1)
		die("cannot go back to buffer option");

	do_print(OPTIONS|FLYRECORD, "\t\t[Option BUFFER, %d bytes]\n", size);
	do_print(OPTIONS|FLYRECORD, "%lld [offset]\n", offset);
	do_print(OPTIONS|FLYRECORD, "\"%s\" [name]\n", name);

	if (read_file_string(fd, clock, DUMP_SIZE))
		die("cannot read clock of the buffer option");

	do_print(OPTIONS|FLYRECORD, "\"%s\" [clock]\n", clock);
	if (option == TRACECMD_OPTION_BUFFER) {
		if (read_file_number(fd, &page_size, 4))
			die("cannot read the page size of the buffer option");
		do_print(OPTIONS|FLYRECORD, "%d [Page size, bytes]\n", page_size);

		if (read_file_number(fd, &cpus, 4))
			die("cannot read the cpu count of the buffer option");

		do_print(OPTIONS|FLYRECORD, "%d [CPUs]:\n", cpus);
		for (i = 0; i < cpus; i++) {
			if (read_file_number(fd, &id, 4))
				die("cannot read the id of cpu %d from the buffer option", i);

			if (read_file_number(fd, &offset, 8))
				die("cannot read the offset of cpu %d from the buffer option", i);

			if (read_file_number(fd, &data_size, 8))
				die("cannot read the data size of cpu %d from the buffer option", i);

			total_size += data_size;
			do_print(OPTIONS|FLYRECORD, "   %d %lld\t%lld\t[id, data offset and size]\n",
				 id, offset, data_size);
		}
		do_print(SUMMARY, "\t\[buffer \"%s\", \"%s\" clock, %d page size, "
			 "%d cpus, %lld bytes flyrecord data]\n",
			 name, clock, page_size, cpus, total_size);
	} else {
		do_print(SUMMARY, "\t\[buffer \"%s\", \"%s\" clock, latency data]\n", name, clock);
	}

}

static void dump_option_int(int fd, int size, char *desc)
{
	int val;

	do_print(OPTIONS, "\t\t[Option %s, %d bytes]\n", desc, size);
	read_file_number(fd, &val, size);
	do_print(OPTIONS, "%d\n", val);
}

static void dump_option_xlong(int fd, int size, char *desc)
{
	long long val;

	do_print(OPTIONS, "\t\t[Option %s, %d bytes]\n", desc, size);
	read_file_number(fd, &val, size);
	do_print(OPTIONS, "0x%llX\n", val);
}

struct time_shift_cpu {
	unsigned int count;
	long long *scalings;
	long long *frac;
	long long *offsets;
	unsigned long long *times;
};

static void dump_option_timeshift(int fd, int size)
{
	struct time_shift_cpu *cpus_data;
	long long trace_id;
	unsigned int flags;
	unsigned int cpus;
	int i, j;

	/*
	 * long long int (8 bytes) trace session ID
	 * int (4 bytes) count of timestamp offsets.
	 * long long array of size [count] of times,
	 *      when the offsets were calculated.
	 * long long array of size [count] of timestamp offsets.
	 */
	if (size < 12) {
		do_print(OPTIONS, "Broken time shift option, size %s", size);
		return;
	}
	do_print(OPTIONS, "\t\t[Option TimeShift, %d bytes]\n", size);
	read_file_number(fd, &trace_id, 8);
	size -= 8;
	do_print(OPTIONS, "0x%llX [peer's trace id]\n", trace_id);
	read_file_number(fd, &flags, 4);
	size -= 4;
	do_print(OPTIONS, "0x%llX [peer's protocol flags]\n", flags);
	read_file_number(fd, &cpus, 4);
	size -= 4;
	do_print(OPTIONS, "0x%llX [peer's CPU count]\n", cpus);
	cpus_data = calloc(cpus, sizeof(struct time_shift_cpu));
	if (!cpus_data)
		return;
	for (j = 0; j < cpus; j++) {
		if (size < 4)
			goto out;
		read_file_number(fd, &cpus_data[j].count, 4);
		size -= 4;
		do_print(OPTIONS, "%lld [samples count for CPU %d]\n", cpus_data[j].count, j);
		cpus_data[j].times = calloc(cpus_data[j].count, sizeof(long long));
		cpus_data[j].offsets = calloc(cpus_data[j].count, sizeof(long long));
		cpus_data[j].scalings = calloc(cpus_data[j].count, sizeof(long long));
		cpus_data[j].frac = calloc(cpus_data[j].count, sizeof(long long));
		if (!cpus_data[j].times || !cpus_data[j].offsets ||
		    !cpus_data[j].scalings || !cpus_data[j].frac)
			goto out;
		for (i = 0; i < cpus_data[j].count; i++) {
			if (size < 8)
				goto out;
			read_file_number(fd, cpus_data[j].times + i, 8);
			size -= 8;
		}
		for (i = 0; i < cpus_data[j].count; i++) {
			if (size < 8)
				goto out;
			read_file_number(fd, cpus_data[j].offsets + i, 8);
			size -= 8;
		}
		for (i = 0; i < cpus_data[j].count; i++) {
			if (size < 8)
				goto out;
			read_file_number(fd, cpus_data[j].scalings + i, 8);
			size -= 8;
		}
	}

	if (size > 0) {
		for (j = 0; j < cpus; j++) {
			if (!cpus_data[j].frac)
				goto out;
			for (i = 0; i < cpus_data[j].count; i++) {
				if (size < 8)
					goto out;
				read_file_number(fd, cpus_data[j].frac + i, 8);
				size -= 8;
			}
		}
	}

	for (j = 0; j < cpus; j++) {
		for (i = 0; i < cpus_data[j].count; i++)
			do_print(OPTIONS, "\t%lld %lld %llu %llu[offset * scaling >> fraction @ time]\n",
				 cpus_data[j].offsets[i], cpus_data[j].scalings[i],
				 cpus_data[j].frac[i], cpus_data[j].times[i]);

	}

out:
	if (j < cpus)
		do_print(OPTIONS, "Broken time shift option\n");
	for (j = 0; j < cpus; j++) {
		free(cpus_data[j].times);
		free(cpus_data[j].offsets);
		free(cpus_data[j].scalings);
		free(cpus_data[j].frac);
	}
	free(cpus_data);
}

void dump_option_guest(int fd, int size)
{
	unsigned long long trace_id;
	char *buf, *p;
	int cpu, pid;
	int cpus;
	int i;

	do_print(OPTIONS, "\t\t[Option GUEST, %d bytes]\n", size);

	/*
	 * Guest name, null terminated string
	 * long long (8 bytes) trace-id
	 * int (4 bytes) number of guest CPUs
	 * array of size number of guest CPUs:
	 *	int (4 bytes) Guest CPU id
	 *	int (4 bytes) Host PID, running the guest CPU
	 */
	buf = calloc(1, size);
	if (!buf)
		return;
	if (read_file_bytes(fd, buf, size))
		goto out;

	p = buf;
	do_print(OPTIONS, "%s [Guest name]\n", p);
	size -= strlen(buf) + 1;
	p += strlen(buf) + 1;

	if (size < sizeof(long long))
		goto out;
	trace_id = tep_read_number(tep, p, sizeof(long long));
	size -= sizeof(long long);
	p += sizeof(long long);
	do_print(OPTIONS, "0x%llX [trace id]\n", trace_id);

	if (size < sizeof(int))
		goto out;
	cpus = tep_read_number(tep, p, sizeof(int));
	size -= sizeof(int);
	p += sizeof(int);
	do_print(OPTIONS, "%d [Guest CPUs]\n", cpus);

	for (i = 0; i < cpus; i++) {
		if (size < 2 * sizeof(int))
			goto out;
		cpu = tep_read_number(tep, p, sizeof(int));
		size -= sizeof(int);
		p += sizeof(int);
		pid = tep_read_number(tep, p, sizeof(int));
		size -= sizeof(int);
		p += sizeof(int);
		do_print(OPTIONS, "  %d %d [guest cpu, host pid]\n", cpu, pid);
	}

out:
	free(buf);
}

void dump_option_tsc2nsec(int fd, int size)
{
	int mult, shift;
	unsigned long long offset;

	do_print(OPTIONS, "\n\t\t[Option TSC2NSEC, %d bytes]\n", size);

	if (read_file_number(fd, &mult, 4))
		die("cannot read tsc2nsec multiplier");
	if (read_file_number(fd, &shift, 4))
		die("cannot read tsc2nsec shift");
	if (read_file_number(fd, &offset, 8))
		die("cannot read tsc2nsec offset");
	do_print(OPTIONS, "%d %d %llu [multiplier, shift, offset]\n", mult, shift, offset);
}

static void dump_option_section(int fd, unsigned int size,
				unsigned short id, char *desc, enum dump_items v)
{
	struct file_section *sec;

	sec = calloc(1, sizeof(struct file_section));
	if (!sec)
		die("cannot allocate new section");

	sec->next = sections;
	sections = sec;
	sec->id = id;
	sec->verbosity = v;
	if (read_file_number(fd, &sec->offset, 8))
		die("cannot read the option %d offset", id);

	do_print(OPTIONS, "\t\t[Option %s, %d bytes] @ %lld\n", desc, size, sec->offset);
}

static void dump_sections(int fd, int count)
{
	struct file_section *sec = sections;
	unsigned short flags;

	while (sec) {
		if (lseek(fd, sec->offset, SEEK_SET) == (off_t)-1)
			die("cannot goto option offset %lld", sec->offset);

		dump_section_header(fd, sec->verbosity, &flags);

		if ((flags & TRACECMD_SEC_FL_COMPRESS) && uncompress_block())
			die("cannot uncompress section block");

		switch (sec->id) {
		case TRACECMD_OPTION_HEADER_INFO:
			dump_header_page(fd);
			dump_header_event(fd);
			break;
		case TRACECMD_OPTION_FTRACE_EVENTS:
			dump_ftrace_events_format(fd);
			break;
		case TRACECMD_OPTION_EVENT_FORMATS:
			dump_events_format(fd);
			break;
		case TRACECMD_OPTION_KALLSYMS:
			dump_kallsyms(fd);
			break;
		case TRACECMD_OPTION_PRINTK:
			dump_printk(fd);
			break;
		case TRACECMD_OPTION_CMDLINES:
			dump_cmdlines(fd);
			break;
		}
		uncompress_reset();
		sec = sec->next;
	}
	do_print(SUMMARY|SECTIONS, "\t[%d sections]\n", count);
}

static int dump_options_read(int fd);

static int dump_option_done(int fd, int size)
{
	unsigned long long offset;

	do_print(OPTIONS, "\t\t[Option DONE, %d bytes]\n", size);

	if (file_version < FILE_VERSION_SECTIONS || size < 8)
		return 0;

	if (read_file_number(fd, &offset, 8))
		die("cannot read the next options offset");

	do_print(OPTIONS, "%lld\n", offset);
	if (!offset)
		return 0;

	if (lseek(fd, offset, SEEK_SET) == (off_t)-1)
		die("cannot goto next options offset %lld", offset);

	do_print(OPTIONS, "\n\n");

	return dump_options_read(fd);
}

static int dump_options_read(int fd)
{
	unsigned short flags = 0;
	unsigned short option;
	unsigned int size;
	int count = 0;

	if (file_version >= FILE_VERSION_SECTIONS)
		dump_section_header(fd, OPTIONS, &flags);

	if ((flags & TRACECMD_SEC_FL_COMPRESS) && uncompress_block())
		die("cannot uncompress file block");

	for (;;) {
		if (read_file_number(fd, &option, 2))
			die("cannot read the option id");
		if (option == TRACECMD_OPTION_DONE && file_version < FILE_VERSION_SECTIONS)
			break;
		if (read_file_number(fd, &size, 4))
			die("cannot read the option size");

		count++;
		switch (option) {
		case TRACECMD_OPTION_DATE:
			dump_option_string(fd, size, "DATE");
			break;
		case TRACECMD_OPTION_CPUSTAT:
			dump_option_string(fd, size, "CPUSTAT");
			break;
		case TRACECMD_OPTION_BUFFER:
		case TRACECMD_OPTION_BUFFER_TEXT:
			dump_option_buffer(fd, option, size);
			break;
		case TRACECMD_OPTION_TRACECLOCK:
			do_print(OPTIONS, "\t\t[Option TRACECLOCK, %d bytes]\n", size);
			read_dump_string(fd, size, OPTIONS | CLOCK);
			has_clock = 1;
			break;
		case TRACECMD_OPTION_UNAME:
			dump_option_string(fd, size, "UNAME");
			break;
		case TRACECMD_OPTION_HOOK:
			dump_option_string(fd, size, "HOOK");
			break;
		case TRACECMD_OPTION_OFFSET:
			dump_option_string(fd, size, "OFFSET");
			break;
		case TRACECMD_OPTION_CPUCOUNT:
			dump_option_int(fd, size, "CPUCOUNT");
			break;
		case TRACECMD_OPTION_VERSION:
			dump_option_string(fd, size, "VERSION");
			break;
		case TRACECMD_OPTION_PROCMAPS:
			dump_option_string(fd, size, "PROCMAPS");
			break;
		case TRACECMD_OPTION_TRACEID:
			dump_option_xlong(fd, size, "TRACEID");
			break;
		case TRACECMD_OPTION_TIME_SHIFT:
			dump_option_timeshift(fd, size);
			break;
		case TRACECMD_OPTION_GUEST:
			dump_option_guest(fd, size);
			break;
		case TRACECMD_OPTION_TSC2NSEC:
			dump_option_tsc2nsec(fd, size);
			break;
		case TRACECMD_OPTION_HEADER_INFO:
			dump_option_section(fd, size, option, "HEADERS", HEAD_PAGE | HEAD_EVENT);
			break;
		case TRACECMD_OPTION_FTRACE_EVENTS:
			dump_option_section(fd, size, option, "FTRACE EVENTS", FTRACE_FORMAT);
			break;
		case TRACECMD_OPTION_EVENT_FORMATS:
			dump_option_section(fd, size, option,
					    "EVENT FORMATS", EVENT_SYSTEMS | EVENT_FORMAT);
			break;
		case TRACECMD_OPTION_KALLSYMS:
			dump_option_section(fd, size, option, "KALLSYMS", KALLSYMS);
			break;
		case TRACECMD_OPTION_PRINTK:
			dump_option_section(fd, size, option, "PRINTK", TRACE_PRINTK);
			break;
		case TRACECMD_OPTION_CMDLINES:
			dump_option_section(fd, size, option, "CMDLINES", CMDLINES);
			break;
		case TRACECMD_OPTION_DONE:
			uncompress_reset();
			count += dump_option_done(fd, size);
			return count;
		default:
			do_print(OPTIONS, " %d %d\t[Unknown option, size - skipping]\n",
				 option, size);
			do_lseek(fd, size, SEEK_CUR);
			break;
		}
	}
	uncompress_reset();
	return count;
}

static void dump_options(int fd)
{
	int count;

	count = dump_options_read(fd);
	do_print(SUMMARY|OPTIONS, "\t[%d options]\n", count);
}

static void dump_latency(int fd)
{
	do_print(SUMMARY, "\t[Latency tracing data]\n");
}

static void dump_clock(int fd)
{
	long long size;
	char *clock;

	do_print((SUMMARY | CLOCK), "\t[Tracing clock]\n");
	if (!has_clock) {
		do_print((SUMMARY | CLOCK), "\t\t No tracing clock saved in the file\n");
		return;
	}
	if (read_file_number(fd, &size, 8))
		die("cannot read clock size");
	clock = calloc(1, size);
	if (!clock)
		die("cannot allocate clock %lld bytes", size);

	if (read_file_bytes(fd, clock, size))
		die("cannot read clock %lld bytes", size);
	clock[size] = 0;
	do_print((SUMMARY | CLOCK), "\t\t%s\n", clock);
	free(clock);
}

static void dump_flyrecord(int fd)
{
	long long cpu_offset;
	long long cpu_size;
	int i;

	do_print((SUMMARY | FLYRECORD), "\t[Flyrecord tracing data]\n");

	for (i = 0; i < trace_cpus; i++) {
		if (read_file_number(fd, &cpu_offset, 8))
			die("cannot read the cpu %d offset", i);
		if (read_file_number(fd, &cpu_size, 8))
			die("cannot read the cpu %d size", i);
		do_print(FLYRECORD, "\t %10.lld %10.lld\t[offset, size of cpu %d]\n",
			 cpu_offset, cpu_size, i);
	}
	dump_clock(fd);
}

static void dump_therest(int fd)
{
	char str[10];

	for (;;) {
		if (read_file_bytes(fd, str, 10))
			die("cannot read the rest of the header");

		if (strncmp(str, HEAD_OPTIONS, 10) == 0)
			dump_options(fd);
		else if (strncmp(str, HEAD_LATENCY, 10) == 0)
			dump_latency(fd);
		else if (strncmp(str, HEAD_FLYRECORD, 10) == 0)
			dump_flyrecord(fd);
		else {
			lseek(fd, -10, SEEK_CUR);
			break;
		}
	}
}

static void dump_v6_file(int fd)
{
	dump_header_page(fd);
	dump_header_event(fd);
	dump_ftrace_events_format(fd);
	dump_events_format(fd);
	dump_kallsyms(fd);
	dump_printk(fd);
	dump_cmdlines(fd);
	dump_cpus_count(fd);
	dump_therest(fd);
}

static int read_metadata_strings(int fd, unsigned long long size)
{
	char *str, *strings;
	int psize;
	int ret;

	strings = realloc(meta_strings, meta_strings_size + size);
	if (!strings)
		return -1;
	meta_strings = strings;

	ret = read_file_bytes(fd, meta_strings + meta_strings_size, size);
	if (ret < 0)
		return -1;

	do_print(STRINGS, "\t[String @ offset]\n");
	psize = 0;
	while (psize < size) {
		str = meta_strings + meta_strings_size + psize;
		do_print(STRINGS, "\t\t\"%s\" @ %d\n", str, meta_strings_size + psize);
		psize += strlen(str) + 1;
	}

	meta_strings_size += size;

	return 0;
}

static void get_meta_strings(int fd)
{
	unsigned long long offset, size;
	unsigned int csize, rsize;
	unsigned short fl, id;
	int desc_id;

	offset = lseek(fd, 0, SEEK_CUR);
	do {
		if (read_file_number(fd, &id, 2))
			break;
		if (read_file_number(fd, &fl, 2))
			die("cannot read section flags");
		if (read_file_number(fd, &desc_id, 4))
			die("cannot read section description");
		if (read_file_number(fd, &size, 8))
			die("cannot read section size");
		if (id == TRACECMD_OPTION_STRINGS) {
			if ((fl & TRACECMD_SEC_FL_COMPRESS)) {
				read_file_number(fd, &csize, 4);
				read_file_number(fd, &rsize, 4);
				lseek(fd, -8, SEEK_CUR);
				if (uncompress_block())
					break;
			} else {
				rsize = size;
			}
			read_metadata_strings(fd, rsize);
			uncompress_reset();
		} else {
			if (lseek(fd, size, SEEK_CUR) == (off_t)-1)
				break;
		}
	} while (1);

	if (lseek(fd, offset, SEEK_SET) == (off_t)-1)
		die("cannot restore the original file location");
}

static int walk_v7_sections(int fd)
{
	unsigned long long offset, soffset, size;
	unsigned short fl;
	unsigned short id;
	int csize, rsize;
	int count = 0;
	int desc_id;
	const char *desc;

	offset = lseek(fd, 0, SEEK_CUR);
	do {
		soffset = lseek(fd, 0, SEEK_CUR);
		if (read_file_number(fd, &id, 2))
			break;

		if (read_file_number(fd, &fl, 2))
			die("cannot read section flags");

		if (read_file_number(fd, &desc_id, 4))
			die("cannot read section description");

		desc = get_metadata_string(desc_id);
		if (!desc)
			desc = "Unknown";

		if (read_file_number(fd, &size, 8))
			die("cannot read section size");

		if (id >= TRACECMD_OPTION_MAX)
			do_print(SECTIONS, "Unknown section id %d: %s", id, desc);

		count++;
		if (fl & TRACECMD_SEC_FL_COMPRESS) {
			if (id == TRACECMD_OPTION_BUFFER ||
			    id == TRACECMD_OPTION_BUFFER_TEXT) {
				do_print(SECTIONS,
					"\t[Section %2d @ %-16lld\t\"%s\", flags 0x%X, "
					"%lld compressed bytes]\n",
					 id, soffset, desc, fl, size);
			} else {
				if (read_file_number(fd, &csize, 4))
					die("cannot read section size");

				if (read_file_number(fd, &rsize, 4))
					die("cannot read section size");

				do_print(SECTIONS, "\t[Section %2d @ %-16lld\t\"%s\", flags 0x%X, "
					 "%d compressed, %d uncompressed]\n",
					 id, soffset, desc, fl, csize, rsize);
				size -= 8;
			}
		} else {
			do_print(SECTIONS, "\t[Section %2d @ %-16lld\t\"%s\", flags 0x%X, %lld bytes]\n",
				 id, soffset, desc, fl, size);
		}

		if (lseek(fd, size, SEEK_CUR) == (off_t)-1)
			break;
	} while (1);

	if (lseek(fd, offset, SEEK_SET) == (off_t)-1)
		die("cannot restore the original file location");

	return count;
}

static void dump_v7_file(int fd)
{
	long long offset;
	int sections;

	if (read_file_number(fd, &offset, 8))
		die("cannot read offset of the first option section");

	get_meta_strings(fd);
	sections = walk_v7_sections(fd);

	if (lseek(fd, offset, SEEK_SET) == (off_t)-1)
		die("cannot goto options offset %lld", offset);

	dump_options(fd);
	dump_sections(fd, sections);
}

static void free_sections(void)
{
	struct file_section *del;

	while (sections) {
		del = sections;
		sections = sections->next;
		free(del);
	}
}

static void dump_file(const char *file)
{
	int fd;

	tep = tep_alloc();
	if (!tep)
		return;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		die("cannot open '%s'\n", file);

	do_print(SUMMARY, "\n Tracing meta data in file %s:\n", file);

	dump_initial_format(fd);
	dump_compress(fd);
	if (file_version < FILE_VERSION_SECTIONS)
		dump_v6_file(fd);
	else
		dump_v7_file(fd);
	free_sections();
	tep_free(tep);
	tep = NULL;
	close(fd);
}

enum {
	OPT_sections	= 240,
	OPT_strings	= 241,
	OPT_verbose	= 242,
	OPT_clock	= 243,
	OPT_all		= 244,
	OPT_summary	= 245,
	OPT_flyrecord	= 246,
	OPT_options	= 247,
	OPT_cmd_lines	= 248,
	OPT_printk	= 249,
	OPT_kallsyms	= 250,
	OPT_events	= 251,
	OPT_systems	= 252,
	OPT_ftrace	= 253,
	OPT_head_event	= 254,
	OPT_head_page	= 255,
};

void trace_dump(int argc, char **argv)
{
	char *input_file = NULL;
	bool validate = false;
	int c;

	if (argc < 2)
		usage(argv);

	if (strcmp(argv[1], "dump") != 0)
		usage(argv);
	for (;;) {
		int option_index = 0;
		static struct option long_options[] = {
			{"all", no_argument, NULL, OPT_all},
			{"summary", no_argument, NULL, OPT_summary},
			{"head-page", no_argument, NULL, OPT_head_page},
			{"head-event", no_argument, NULL, OPT_head_event},
			{"ftrace-events", no_argument, NULL, OPT_ftrace},
			{"systems", no_argument, NULL, OPT_systems},
			{"events", no_argument, NULL, OPT_events},
			{"kallsyms", no_argument, NULL, OPT_kallsyms},
			{"printk", no_argument, NULL, OPT_printk},
			{"cmd-lines", no_argument, NULL, OPT_cmd_lines},
			{"options", no_argument, NULL, OPT_options},
			{"flyrecord", no_argument, NULL, OPT_flyrecord},
			{"clock", no_argument, NULL, OPT_clock},
			{"strings", no_argument, NULL, OPT_strings},
			{"sections", no_argument, NULL, OPT_sections},
			{"validate", no_argument, NULL, 'v'},
			{"help", no_argument, NULL, '?'},
			{"verbose", optional_argument, NULL, OPT_verbose},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc-1, argv+1, "+hvai:",
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'i':
			input_file = optarg;
			break;
		case 'v':
			validate = true;
			break;
		case OPT_all:
			verbosity = 0xFFFFFFFF;
			break;
		case OPT_summary:
			verbosity |= SUMMARY;
			break;
		case OPT_flyrecord:
			verbosity |= FLYRECORD;
			break;
		case OPT_options:
			verbosity |= OPTIONS;
			break;
		case OPT_cmd_lines:
			verbosity |= CMDLINES;
			break;
		case OPT_printk:
			verbosity |= TRACE_PRINTK;
			break;
		case OPT_kallsyms:
			verbosity |= KALLSYMS;
			break;
		case OPT_events:
			verbosity |= EVENT_FORMAT;
			break;
		case OPT_systems:
			verbosity |= EVENT_SYSTEMS;
			break;
		case OPT_ftrace:
			verbosity |= FTRACE_FORMAT;
			break;
		case OPT_head_event:
			verbosity |= HEAD_EVENT;
			break;
		case OPT_head_page:
			verbosity |= HEAD_PAGE;
			break;
		case OPT_clock:
			verbosity |= CLOCK;
			break;
		case OPT_verbose:
			if (trace_set_verbose(optarg) < 0)
				die("invalid verbose level %s", optarg);
			break;
		case OPT_strings:
			verbosity |= STRINGS;
			break;
		case OPT_sections:
			verbosity |= SECTIONS;
			break;
		default:
			usage(argv);
		}
	}

	if ((argc - optind) >= 2) {
		if (input_file)
			usage(argv);
		input_file = argv[optind + 1];
	}

	if (!input_file)
		input_file = DEFAULT_INPUT_FILE;

	if (!verbosity && !validate)
		verbosity = SUMMARY;

	dump_file(input_file);

	if (validate)
		tracecmd_plog("File %s is a valid trace-cmd file\n", input_file);
}
