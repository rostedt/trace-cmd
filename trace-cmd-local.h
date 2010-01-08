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
