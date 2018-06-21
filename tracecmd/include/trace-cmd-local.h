/* SPDX-License-Identifier: LGPL-2.1 */
/*
 * Copyright (C) 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#ifndef _TRACE_CMD_LOCAL_H
#define _TRACE_CMD_LOCAL_H

/* Local for trace-input.c and trace-output.c */

#include "trace-cmd.h"
#include "event-utils.h"

extern int quiet;

static ssize_t __do_write(int fd, const void *data, size_t size)
{
	ssize_t tot = 0;
	ssize_t w;

	do {
		w = write(fd, data + tot, size - tot);
		tot += w;

		if (!w)
			break;
		if (w < 0)
			return w;
	} while (tot != size);

	return tot;
}

static ssize_t
__do_write_check(int fd, const void *data, size_t size)
{
	ssize_t ret;

	ret = __do_write(fd, data, size);
	if (ret < 0)
		return ret;
	if (ret != size)
		return -1;

	return 0;
}

#endif /* _TRACE_CMD_LOCAL_H */
