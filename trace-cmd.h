#ifndef _TRACE_CMD_H
#define _TRACE_CMD_H

#include "parse-events.h"

extern int input_fd;
extern const char *input_file;

#ifndef PAGE_MASK
#define PAGE_MASK (page_size - 1)
#endif

void parse_cmdlines(char *file, int size);
void parse_proc_kallsyms(char *file, unsigned int size);
void parse_ftrace_printk(char *file, unsigned int size);

int trace_load_plugins(void);

enum {
	RINGBUF_TYPE_PADDING		= 29,
	RINGBUF_TYPE_TIME_EXTEND	= 30,
	RINGBUF_TYPE_TIME_STAMP		= 31,
};

#ifndef TS_SHIFT
#define TS_SHIFT		27
#endif

struct tracecmd_handle;

struct tracecmd_handle *tracecmd_open(int fd);
int tracecmd_read_headers(struct tracecmd_handle *handle);
int tracecmd_long_size(struct tracecmd_handle *handle);
int tracecmd_page_size(struct tracecmd_handle *handle);
int tracecmd_cpus(struct tracecmd_handle *handle);

int tracecmd_init_data(struct tracecmd_handle *handle);

struct record *
tracecmd_peek_data(struct tracecmd_handle *handle, int cpu);

struct record *
tracecmd_read_data(struct tracecmd_handle *handle, int cpu);


#endif /* _TRACE_CMD_H */
