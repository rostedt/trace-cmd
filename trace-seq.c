/*
 * trace_seq.c
 *
 * Copyright (C) 2009 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "parse-events.h"

/**
 * trace_seq_printf - sequence printing of trace information
 * @s: trace sequence descriptor
 * @fmt: printf format string
 *
 * It returns 0 if the trace oversizes the buffer's free
 * space, 1 otherwise.
 *
 * The tracer may use either sequence operations or its own
 * copy to user routines. To simplify formating of a trace
 * trace_seq_printf is used to store strings into a special
 * buffer (@s). Then the output may be either used by
 * the sequencer or pulled into another buffer.
 */
int
trace_seq_printf(struct trace_seq *s, const char *fmt, ...)
{
	int len = (TRACE_SEQ_SIZE - 1) - s->len;
	va_list ap;
	int ret;

	if (!len)
		return 0;

	va_start(ap, fmt);
	ret = vsnprintf(s->buffer + s->len, len, fmt, ap);
	va_end(ap);

	/* If we can't write it all, don't bother writing anything */
	if (ret >= len)
		return 0;

	s->len += ret;

	return 1;
}

/**
 * trace_seq_vprintf - sequence printing of trace information
 * @s: trace sequence descriptor
 * @fmt: printf format string
 *
 * The tracer may use either sequence operations or its own
 * copy to user routines. To simplify formating of a trace
 * trace_seq_printf is used to store strings into a special
 * buffer (@s). Then the output may be either used by
 * the sequencer or pulled into another buffer.
 */
int
trace_seq_vprintf(struct trace_seq *s, const char *fmt, va_list args)
{
	int len = (TRACE_SEQ_SIZE - 1) - s->len;
	int ret;

	if (!len)
		return 0;

	ret = vsnprintf(s->buffer + s->len, len, fmt, args);

	/* If we can't write it all, don't bother writing anything */
	if (ret >= len)
		return 0;

	s->len += ret;

	return len;
}

/**
 * trace_seq_puts - trace sequence printing of simple string
 * @s: trace sequence descriptor
 * @str: simple string to record
 *
 * The tracer may use either the sequence operations or its own
 * copy to user routines. This function records a simple string
 * into a special buffer (@s) for later retrieval by a sequencer
 * or other mechanism.
 */
int trace_seq_puts(struct trace_seq *s, const char *str)
{
	int len = strlen(str);

	if (len > ((TRACE_SEQ_SIZE - 1) - s->len))
		return 0;

	memcpy(s->buffer + s->len, str, len);
	s->len += len;

	return len;
}

int trace_seq_putc(struct trace_seq *s, unsigned char c)
{
	if (s->len >= (TRACE_SEQ_SIZE - 1))
		return 0;

	s->buffer[s->len++] = c;

	return 1;
}

int trace_seq_do_printf(struct trace_seq *s)
{
	char *buf;
	int ret;

	if (!s->len)
		return 0;

	if (s->len < TRACE_SEQ_SIZE) {
		s->buffer[s->len] = 0;
		return printf("%s", s->buffer);
	}

	buf = malloc_or_die(s->len + 1);
	memcpy(buf, s->buffer, s->len);
	buf[s->len] = 0;
	ret = printf("%s", buf);
	free(buf);

	return ret;
}
