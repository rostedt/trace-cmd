/* SPDX-License-Identifier: LGPL-2.1 */
/*
 * Copyright (C) 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#ifndef _TRACE_CMD_LOCAL_H
#define _TRACE_CMD_LOCAL_H

#include <byteswap.h>
#include "trace-cmd-private.h"

#define FILE_VERSION_DEFAULT		6

/* Can be overridden */
void tracecmd_warning(const char *fmt, ...);
void tracecmd_critical(const char *fmt, ...);
void tracecmd_info(const char *fmt, ...);

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

void tracecmd_compress_init(void);
void tracecmd_compress_free(void);

bool check_file_state(unsigned long file_version, int current_state, int new_state);
bool check_out_state(struct tracecmd_output *handle, int new_state);

int out_uncompress_block(struct tracecmd_output *handle);
int out_compression_start(struct tracecmd_output *handle, bool compress);
int out_compression_end(struct tracecmd_output *handle, bool compress);
void out_compression_reset(struct tracecmd_output *handle, bool compress);
unsigned long long out_copy_fd_compress(struct tracecmd_output *handle,
					int fd, unsigned long long max,
					unsigned long long *write_size);
unsigned long long
out_write_section_header(struct tracecmd_output *handle, unsigned short header_id,
			 char *description, int flags, bool option);
int out_update_section_header(struct tracecmd_output *handle, unsigned long long offset);

struct cpu_data_source {
	int fd;
	int size;
	off64_t offset;
};

int out_write_cpu_data(struct tracecmd_output *handle, int cpus,
		       struct cpu_data_source *data, const char *buff_name);
off64_t msg_lseek(struct tracecmd_msg_handle *msg_handle, off_t offset, int whence);
unsigned long long get_last_option_offset(struct tracecmd_input *handle);
unsigned int get_meta_strings_size(struct tracecmd_input *handle);

#endif /* _TRACE_CMD_LOCAL_H */
