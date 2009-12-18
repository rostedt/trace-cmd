#ifndef _PARSE_EVENTS_H
#define _PARSE_EVENTS_H

#include <stdarg.h>

#ifndef __unused
#define __unused __attribute__ ((unused))
#endif

/* ----------------------- trace_seq ----------------------- */


#ifndef TRACE_SEQ_SIZE
#define TRACE_SEQ_SIZE 4096
#endif

struct record {
	unsigned long long ts;
	unsigned long long offset;
	int record_size;		/* size of binary record */
	int size;			/* size of data */
	void *data;
	int cpu;
};

/*
 * Trace sequences are used to allow a function to call several other functions
 * to create a string of data to use (up to a max of PAGE_SIZE).
 */

struct trace_seq {
	char			buffer[TRACE_SEQ_SIZE];
	unsigned int		len;
	unsigned int		readpos;
	int			full;
};

static inline void
trace_seq_init(struct trace_seq *s)
{
	s->len = 0;
	s->readpos = 0;
	s->full = 0;
}

extern int trace_seq_printf(struct trace_seq *s, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));
extern int trace_seq_vprintf(struct trace_seq *s, const char *fmt, va_list args)
	__attribute__ ((format (printf, 2, 0)));

extern int trace_seq_puts(struct trace_seq *s, const char *str);
extern int trace_seq_putc(struct trace_seq *s, unsigned char c);

extern void trace_seq_terminate(struct trace_seq *s);

extern int trace_seq_do_printf(struct trace_seq *s);


/* ----------------------- pevent ----------------------- */

struct pevent;
struct event_format;

typedef int (*pevent_event_handler_func)(struct trace_seq *s,
					 struct record *record,
					 struct event_format *event);

typedef int (*pevent_plugin_load_func)(struct pevent *pevent);

#define PEVENT_PLUGIN_LOADER pevent_plugin_loader
#define MAKE_STR(x) #x
#define PEVENT_PLUGIN_LOADER_NAME MAKE_STR(pevent_plugin_loader)

#define NSECS_PER_SEC		1000000000ULL
#define NSECS_PER_USEC		1000ULL

enum format_flags {
	FIELD_IS_ARRAY		= 1,
	FIELD_IS_POINTER	= 2,
	FIELD_IS_SIGNED		= 4,
	FIELD_IS_STRING		= 8,
	FIELD_IS_DYNAMIC	= 16,
};

struct format_field {
	struct format_field	*next;
	struct event_format		*event;
	char			*type;
	char			*name;
	int			offset;
	int			size;
	unsigned long		flags;
};

struct format {
	int			nr_common;
	int			nr_fields;
	struct format_field	*common_fields;
	struct format_field	*fields;
};

struct print_arg_atom {
	char			*atom;
};

struct print_arg_string {
	char			*string;
	int			offset;
};

struct print_arg_field {
	char			*name;
	struct format_field	*field;
};

struct print_flag_sym {
	struct print_flag_sym	*next;
	char			*value;
	char			*str;
};

struct print_arg_typecast {
	char 			*type;
	struct print_arg	*item;
};

struct print_arg_flags {
	struct print_arg	*field;
	char			*delim;
	struct print_flag_sym	*flags;
};

struct print_arg_symbol {
	struct print_arg	*field;
	struct print_flag_sym	*symbols;
};

struct print_arg_dynarray {
	struct format_field	*field;
	struct print_arg	*index;
};

struct print_arg;

struct print_arg_op {
	char			*op;
	int			prio;
	struct print_arg	*left;
	struct print_arg	*right;
};

struct print_arg_func {
	char			*name;
	struct print_arg	*args;
};

enum print_arg_type {
	PRINT_NULL,
	PRINT_ATOM,
	PRINT_FIELD,
	PRINT_FLAGS,
	PRINT_SYMBOL,
	PRINT_TYPE,
	PRINT_STRING,
	PRINT_DYNAMIC_ARRAY,
	PRINT_OP,
};

struct print_arg {
	struct print_arg		*next;
	enum print_arg_type		type;
	union {
		struct print_arg_atom		atom;
		struct print_arg_field		field;
		struct print_arg_typecast	typecast;
		struct print_arg_flags		flags;
		struct print_arg_symbol		symbol;
		struct print_arg_func		func;
		struct print_arg_string		string;
		struct print_arg_op		op;
		struct print_arg_dynarray	dynarray;
	};
};

struct print_fmt {
	char			*format;
	struct print_arg	*args;
};

struct event_format {
	struct event_format		*next;
	struct pevent		*pevent;
	char			*name;
	int			id;
	int			flags;
	struct format		format;
	struct print_fmt	print_fmt;
	char			*system;
	pevent_event_handler_func handler;
};

enum {
	EVENT_FL_ISFTRACE	= 0x01,
	EVENT_FL_ISPRINT	= 0x02,
	EVENT_FL_ISBPRINT	= 0x04,
	EVENT_FL_ISFUNCENT	= 0x10,
	EVENT_FL_ISFUNCRET	= 0x20,

	EVENT_FL_FAILED		= 0x80000000
};

enum event_sort_type {
	EVENT_SORT_ID,
	EVENT_SORT_NAME,
	EVENT_SORT_SYSTEM,
};

struct cmdline;
struct cmdline_list;
struct func_map;
struct func_list;

struct pevent {
	int header_page_ts_offset;
	int header_page_ts_size;
	int header_page_size_offset;
	int header_page_size_size;
	int header_page_data_offset;
	int header_page_data_size;

	int file_bigendian;
	int host_bigendian;

	int latency_format;

	int old_format;

	int cpus;
	int long_size;

	struct cmdline *cmdlines;
	struct cmdline_list *cmdlist;
	int cmdline_count;

	struct func_map *func_map;
	struct func_list *funclist;
	unsigned int func_count;

	struct printk_map *printk_map;
	struct printk_list *printklist;
	unsigned int printk_count;

	struct event_format *event_list;
	int nr_events;
	struct event_format **events;
	enum event_sort_type last_type;

	int type_offset;
	int type_size;

	int pid_offset;
	int pid_size;

 	int pc_offset;
	int pc_size;

	int flags_offset;
	int flags_size;

	int ld_offset;
	int ld_size;

	struct format_field *bprint_ip_field;
	struct format_field *bprint_fmt_field;
	struct format_field *bprint_buf_field;
};

void die(char *fmt, ...);
void *malloc_or_die(unsigned int size);
void warning(char *fmt, ...);

static inline unsigned short
__data2host2(struct pevent *pevent, unsigned short data)
{
	unsigned short swap;

	if (pevent->host_bigendian == pevent->file_bigendian)
		return data;

	swap = ((data & 0xffULL) << 8) |
		((data & (0xffULL << 8)) >> 8);

	return swap;
}

static inline unsigned int
__data2host4(struct pevent *pevent, unsigned int data)
{
	unsigned int swap;

	if (pevent->host_bigendian == pevent->file_bigendian)
		return data;

	swap = ((data & 0xffULL) << 24) |
		((data & (0xffULL << 8)) << 8) |
		((data & (0xffULL << 16)) >> 8) |
		((data & (0xffULL << 24)) >> 24);

	return swap;
}

static inline unsigned long long
__data2host8(struct pevent *pevent, unsigned long long data)
{
	unsigned long long swap;

	if (pevent->host_bigendian == pevent->file_bigendian)
		return data;

	swap = ((data & 0xffULL) << 56) |
		((data & (0xffULL << 8)) << 40) |
		((data & (0xffULL << 16)) << 24) |
		((data & (0xffULL << 24)) << 8) |
		((data & (0xffULL << 32)) >> 8) |
		((data & (0xffULL << 40)) >> 24) |
		((data & (0xffULL << 48)) >> 40) |
		((data & (0xffULL << 56)) >> 56);

	return swap;
}

#define data2host2(pevent, ptr)		__data2host2(pevent, *(unsigned short *)ptr)
#define data2host4(pevent, ptr)		__data2host4(pevent, *(unsigned int *)ptr)
#define data2host8(pevent, ptr)		__data2host8(pevent, *(unsigned long long *)ptr)

/* taken from kernel/trace/trace.h */
enum trace_flag_type {
	TRACE_FLAG_IRQS_OFF		= 0x01,
	TRACE_FLAG_IRQS_NOSUPPORT	= 0x02,
	TRACE_FLAG_NEED_RESCHED		= 0x04,
	TRACE_FLAG_HARDIRQ		= 0x08,
	TRACE_FLAG_SOFTIRQ		= 0x10,
};

int pevent_register_comm(struct pevent *pevent, char *comm, int pid);
int pevent_register_function(struct pevent *pevetn, char *name,
			     unsigned long long addr, char *mod);
int pevent_register_print_string(struct pevent *pevent, char *fmt,
				 unsigned long long addr);
int pevent_pid_is_registered(struct pevent *pevent, int pid);

void pevent_print_event(struct pevent *pevent, struct trace_seq *s,
			struct record *record);

int pevent_parse_header_page(struct pevent *pevent, char *buf, unsigned long size);

int pevent_parse_event(struct pevent *pevent, char *buf, unsigned long size, char *sys);

int pevent_register_event_handler(struct pevent *pevent, int id, char *sys_name, char *event_name,
				  pevent_event_handler_func func);

struct format_field *pevent_find_common_field(struct event_format *event, const char *name);
struct format_field *pevent_find_field(struct event_format *event, const char *name);
struct format_field *pevent_find_any_field(struct event_format *event, const char *name);

const char *pevent_find_function(struct pevent *pevent, unsigned long long addr);
unsigned long long pevent_read_number(struct pevent *pevent, const void *ptr, int size);
int pevent_read_number_field(struct format_field *field, const void *data,
			     unsigned long long *value);

struct event_format *pevent_find_event(struct pevent *pevent, int id);

struct event_format *
pevent_find_event_by_name(struct pevent *pevent, const char *sys, const char *name);

void pevent_data_lat_fmt(struct pevent *pevent,
			 struct trace_seq *s, struct record *record);
int pevent_data_type(struct pevent *pevent, struct record *rec);
struct event_format *pevent_data_event_from_type(struct pevent *pevent, int type);
int pevent_data_pid(struct pevent *pevent, struct record *rec);
const char *pevent_data_comm_from_pid(struct pevent *pevent, int pid);
void pevent_event_info(struct trace_seq *s, struct event_format *event,
		       struct record *record);

struct event_format **pevent_list_events(struct pevent *pevent, enum event_sort_type);

static inline int pevent_get_cpus(struct pevent *pevent)
{
	return pevent->cpus;
}

static inline void pevent_set_cpus(struct pevent *pevent, int cpus)
{
	pevent->cpus = cpus;
}

static inline int pevent_get_long_size(struct pevent *pevent)
{
	return pevent->long_size;
}

static inline void pevent_set_long_size(struct pevent *pevent, int long_size)
{
	pevent->long_size = long_size;
}

static inline int pevent_is_file_bigendian(struct pevent *pevent)
{
	return pevent->file_bigendian;
}

static inline void pevent_set_file_bigendian(struct pevent *pevent, int endian)
{
	pevent->file_bigendian = endian;
}

static inline int pevent_is_host_bigendian(struct pevent *pevent)
{
	return pevent->host_bigendian;
}

static inline void pevent_set_host_bigendian(struct pevent *pevent, int endian)
{
	pevent->host_bigendian = endian;
}

static inline int pevent_is_latency_format(struct pevent *pevent)
{
	return pevent->latency_format;
}

static inline void pevent_set_latency_format(struct pevent *pevent, int lat)
{
	pevent->latency_format = lat;
}

struct pevent *pevent_alloc(void);
void pevent_free(struct pevent *pevent);

/* for debugging */
void pevent_print_funcs(struct pevent *pevent);
void pevent_print_printk(struct pevent *pevent);


#endif /* _PARSE_EVENTS_H */
