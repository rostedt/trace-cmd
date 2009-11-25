#ifndef _TRACE_CMD_H
#define _TRACE_CMD_H

extern int input_fd;
extern const char *input_file;

extern unsigned int page_size;

#ifndef PAGE_MASK
#define PAGE_MASK (page_size - 1)
#endif

void usage(char **argv);
int read_trace_header(void);
int read_trace_files(void);

void trace_report(int argc, char **argv);

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

#endif /* _TRACE_CMD_H */
