/* SPDX-License-Identifier: LGPL-2.1 */
/*
 * Copyright (C) 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#ifndef _TRACE_CMD_LOCAL_H
#define _TRACE_CMD_LOCAL_H

#include <byteswap.h>
#include "trace-cmd-private.h"

/* Can be overridden */
void tracecmd_warning(const char *fmt, ...);
void tracecmd_critical(const char *fmt, ...);
void tracecmd_info(const char *fmt, ...);

/* trace.dat file format version */
#define FILE_VERSION 6

#define _STR(x)	#x
#define STR(x)	_STR(x)
#define FILE_VERSION_STRING STR(FILE_VERSION)

#ifndef htonll
# if __BYTE_ORDER == __LITTLE_ENDIAN
#define htonll(x) __bswap_64(x)
#define ntohll(x) __bswap_64(x)
#else
#define htonll(x) (x)
#define ntohll(x) (x)
#endif
#endif

struct data_file_write {
	unsigned long long	file_size;
	unsigned long long	write_size;
	/* offset in the trace file, where write_size is stored */
	unsigned long long	file_write_size;
	unsigned long long	data_offset;
	/* offset in the trace file, where data_offset is stored */
	unsigned long long	file_data_offset;
};

bool check_file_state(unsigned long file_version, int current_state, int new_state);
bool check_out_state(struct tracecmd_output *handle, int new_state);

struct cpu_data_source {
	int fd;
	int size;
	off64_t offset;
};

int out_write_cpu_data(struct tracecmd_output *handle, int cpus,
		       struct cpu_data_source *data, const char *buff_name);

#endif /* _TRACE_CMD_LOCAL_H */
