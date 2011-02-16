/*
 * Copyright (C) 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#ifndef _TRACE_CMD_LOCAL_H
#define _TRACE_CMD_LOCAL_H

/* Local for trace-input.c and trace-output.c */

#include "trace-cmd.h"

static int __do_write(int fd, void *data, int size)
{
	int tot = 0;
	int w;

	do {
		w = write(fd, data, size - tot);
		tot += w;

		if (!w)
			break;
		if (w < 0)
			return w;
	} while (tot != size);

	return tot;
}

static int
__do_write_check(int fd, void *data, int size)
{
	int ret;

	ret = __do_write(fd, data, size);
	if (ret < 0)
		return ret;
	if (ret != size)
		return -1;

	return 0;
}

#endif /* _TRACE_CMD_LOCAL_H */
