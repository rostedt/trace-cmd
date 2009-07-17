#ifndef _PARSE_EVENTS_H
#define _PARSE_EVENTS_H

#ifndef PAGE_SIZE
#define PAGE_SIZE		4096ULL
#endif

#ifndef PAGE_MASK
#define PAGE_MASK (PAGE_SIZE - 1)
#endif

enum {
	RINGBUF_TYPE_PADDING		= 29,
	RINGBUF_TYPE_TIME_EXTEND	= 30,
	RINGBUF_TYPE_TIME_STAMP		= 31,
};

#ifndef TS_SHIFT
#define TS_SHIFT		27
#endif

#define NSECS_PER_SEC		1000000000ULL
#define NSECS_PER_USEC		1000ULL

enum format_flags {
	FIELD_IS_ARRAY		= 1,
	FIELD_IS_POINTER	= 2,
};

struct format_field {
	struct format_field	*next;
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
	};
};

struct print_fmt {
	char			*format;
	struct print_arg	*args;
};

struct event {
	struct event		*next;
	char			*name;
	int			id;
	int			flags;
	struct format		format;
	struct print_fmt	print_fmt;
};

enum {
	EVENT_FL_ISFTRACE	= 1,
	EVENT_FL_ISPRINT	= 2,
	EVENT_FL_ISBPRINT	= 4,
	EVENT_FL_ISFUNC		= 8,
	EVENT_FL_ISFUNCENT	= 16,
	EVENT_FL_ISFUNCRET	= 32,
};

struct record {
	unsigned long long ts;
	int size;
	void *data;
};

void usage(char **argv);

struct record *peak_data(int cpu);
struct record *read_data(int cpu);

void parse_set_info(int nr_cpus, int long_sz);

void trace_report(int argc, char **argv);

void die(char *fmt, ...);
void *malloc_or_die(unsigned int size);

void parse_cmdlines(char *file, int size);
void parse_proc_kallsyms(char *file, unsigned int size);

void print_funcs(void);

int parse_ftrace_file(char *buf, unsigned long size);
int parse_event_file(char *buf, unsigned long size, char *system);
void print_event(int cpu, void *data, int size, unsigned long long nsecs);

#endif /* _PARSE_EVENTS_H */
