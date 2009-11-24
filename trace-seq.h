#ifndef _TRACE_SEQ_H
#define _TRACE_SEQ_H

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/*
 * Trace sequences are used to allow a function to call several other functions
 * to create a string of data to use (up to a max of PAGE_SIZE).
 */

struct trace_seq {
	char			buffer[PAGE_SIZE];
	unsigned int		len;
	unsigned int		readpos;
};

static inline void
trace_seq_init(struct trace_seq *s)
{
	s->len = 0;
	s->readpos = 0;
}

extern int trace_seq_printf(struct trace_seq *s, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));
extern int trace_seq_vprintf(struct trace_seq *s, const char *fmt, va_list args)
	__attribute__ ((format (printf, 2, 0)));

extern int trace_seq_puts(struct trace_seq *s, const char *str);
extern int trace_seq_putc(struct trace_seq *s, unsigned char c);

extern int trace_seq_do_printf(struct trace_seq *s);

#endif /* _TRACE_SEQ_H */
