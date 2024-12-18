/* SPDX-License-Identifier: LGPL-2.1 */
/*
 * Copyright (C) 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#ifndef _TRACE_CMD_LOCAL_H
#define _TRACE_CMD_LOCAL_H

#include <byteswap.h>
#include "trace-cmd-private.h"

#define FILE_VERSION_DEFAULT		7

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

#ifdef HAVE_ZLIB
int tracecmd_zlib_init(void);
#endif

#ifdef HAVE_ZSTD
int tracecmd_zstd_init(void);
#else
static inline int tracecmd_zstd_init(void)
{
	return 0;
}
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

enum tracecmd_filters tcmd_filter_match(struct tracecmd_filter *filter,
					struct tep_record *record);

void tcmd_set_guest_map(struct tracecmd_input *handle, struct tracecmd_cpu_map *map);
struct tracecmd_cpu_map *tcmd_get_guest_map(struct tracecmd_input *handle);
void tcmd_set_guest_map_cnt(struct tracecmd_input *handle, int count);
int tcmd_get_guest_map_cnt(struct tracecmd_input *handle);
void tcmd_guest_map_free(struct tracecmd_cpu_map *map);

void tracecmd_compress_init(void);
void tracecmd_compress_free(void);

bool tcmd_check_file_state(unsigned long file_version, int current_state, int new_state);
bool tcmd_check_out_state(struct tracecmd_output *handle, int new_state);

int tcmd_out_uncompress_block(struct tracecmd_output *handle);
int tcmd_out_compression_start(struct tracecmd_output *handle, bool compress);
int tcmd_out_compression_end(struct tracecmd_output *handle, bool compress);
void tcmd_out_compression_reset(struct tracecmd_output *handle, bool compress);
bool tcmd_out_check_compression(struct tracecmd_output *handle);

void tcmd_out_set_file_state(struct tracecmd_output *handle, int new_state);
int tcmd_out_save_options_offset(struct tracecmd_output *handle,
				 unsigned long long start);
unsigned long long tcmd_out_copy_fd_compress(struct tracecmd_output *handle,
					     int fd, unsigned long long max,
					     unsigned long long *write_size, int page);
void tcmd_in_uncompress_reset(struct tracecmd_input *handle);
int tcmd_in_uncompress_block(struct tracecmd_input *handle);

unsigned long long
tcmd_out_write_section_header(struct tracecmd_output *handle, unsigned short header_id,
			      char *description, int flags, bool option);
int tcmd_out_update_section_header(struct tracecmd_output *handle, unsigned long long offset);

long long tcmd_do_write_check(struct tracecmd_output *handle, const void *data, long long size);

struct tracecmd_option *
tcmd_out_add_buffer_option(struct tracecmd_output *handle, const char *name,
			   unsigned short id, unsigned long long data_offset,
			   int cpus, struct data_file_write *cpu_data, int page_size);

struct cpu_data_source {
	int fd;
	ssize_t size;
	off_t offset;
};

int tcmd_out_write_cpu_data(struct tracecmd_output *handle, int cpus,
			    struct cpu_data_source *data, const char *buff_name);
int tcmd_out_write_emty_cpu_data(struct tracecmd_output *handle, int cpus);
off_t tcmd_msg_lseek(struct tracecmd_msg_handle *msg_handle, off_t offset, int whence);
unsigned long long tcmd_get_last_option_offset(struct tracecmd_input *handle);
unsigned int tcmd_get_meta_strings_size(struct tracecmd_input *handle);
int tcmd_append_options(struct tracecmd_output *handle, void *buf, size_t len);
void *tcmd_get_options(struct tracecmd_output *handle, size_t *len);

/* filters */
struct tracecmd_filter *tcmd_filter_get(struct tracecmd_input *handle);
void tcmd_filter_set(struct tracecmd_input *handle, struct tracecmd_filter *filter);
void tcmd_filter_free(struct tracecmd_filter *filter);

#endif /* _TRACE_CMD_LOCAL_H */
