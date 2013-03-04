/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
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
 * License along with this program; if not,  see <http://www.gnu.org/licenses>
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#define _LARGEFILE64_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "trace-cmd.h"

struct tracecmd_recorder {
	int		fd;
	int		trace_fd;
	int		brass[2];
	int		page_size;
	int		cpu;
	int		stop;
	unsigned	flags;
};

void tracecmd_free_recorder(struct tracecmd_recorder *recorder)
{
	if (!recorder)
		return;

	if (recorder->trace_fd >= 0)
		close(recorder->trace_fd);

	if (recorder->fd >= 0)
		close(recorder->fd);

	free(recorder);
}

struct tracecmd_recorder *tracecmd_create_recorder_fd(int fd, int cpu, unsigned flags)
{
	struct tracecmd_recorder *recorder;
	char *tracing = NULL;
	char *path = NULL;
	int ret;

	recorder = malloc_or_die(sizeof(*recorder));
	if (!recorder)
		return NULL;

	recorder->cpu = cpu;
	recorder->flags = flags;

	/* Init to know what to free and release */
	recorder->trace_fd = -1;
	recorder->brass[0] = -1;
	recorder->brass[1] = -1;

	recorder->page_size = getpagesize();

	recorder->fd = fd;

	tracing = tracecmd_find_tracing_dir();
	if (!tracing) {
		errno = ENODEV;
		goto out_free;
	}

	path = malloc_or_die(strlen(tracing) + 40);
	if (!path)
		goto out_free;

	sprintf(path, "%s/per_cpu/cpu%d/trace_pipe_raw", tracing, cpu);
	recorder->trace_fd = open(path, O_RDONLY);
	if (recorder->trace_fd < 0)
		goto out_free;

	free(tracing);
	free(path);

	if ((recorder->flags & TRACECMD_RECORD_NOSPLICE) == 0) {
		ret = pipe(recorder->brass);
		if (ret < 0)
			goto out_free;
	}

	return recorder;

 out_free:
	free(tracing);
	free(path);

	tracecmd_free_recorder(recorder);
	return NULL;
}

struct tracecmd_recorder *tracecmd_create_recorder(const char *file, int cpu, unsigned flags)
{
	struct tracecmd_recorder *recorder;
	int fd;

	fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
	if (fd < 0)
		return NULL;

	recorder = tracecmd_create_recorder_fd(fd, cpu, flags);
	if (!recorder) {
		close(fd);
		unlink(file);
	}

	return recorder;
}

/*
 * Returns -1 on error.
 *          or bytes of data read.
 */
static long splice_data(struct tracecmd_recorder *recorder)
{
	long ret;

	ret = splice(recorder->trace_fd, NULL, recorder->brass[1], NULL,
		     recorder->page_size, 1 /* SPLICE_F_MOVE */);
	if (ret < 0) {
		if (errno != EAGAIN && errno != EINTR) {
			warning("recorder error in splice input");
			return -1;
		}
	}

	ret = splice(recorder->brass[0], NULL, recorder->fd, NULL,
		     recorder->page_size, 3 /* and NON_BLOCK */);
	if (ret < 0) {
		if (errno != EAGAIN && errno != EINTR) {
			warning("recorder error in splice output");
			return -1;
		}
		ret = 0;
	}

	return ret;
}

/*
 * Returns -1 on error.
 *          or bytes of data read.
 */
static long read_data(struct tracecmd_recorder *recorder)
{
	char buf[recorder->page_size];
	long ret;

	ret = read(recorder->trace_fd, buf, recorder->page_size);
	if (ret < 0) {
		if (errno != EAGAIN && errno != EINTR) {
			warning("recorder error in read output");
			return -1;
		}
		ret = 0;
	}
	if (ret > 0)
		write(recorder->fd, buf, ret);

	return ret;
}

static void set_nonblock(struct tracecmd_recorder *recorder)
{
	long flags;

	/* Do not block on reads for flushing */
	flags = fcntl(recorder->trace_fd, F_GETFL);
	fcntl(recorder->trace_fd, F_SETFL, flags | O_NONBLOCK);
}

long tracecmd_flush_recording(struct tracecmd_recorder *recorder)
{
	char *buf[recorder->page_size];
	long total = 0;
	long ret;

	set_nonblock(recorder);

	do {
		if (recorder->flags & TRACECMD_RECORD_NOSPLICE)
			ret = read_data(recorder);
		else
			ret = splice_data(recorder);
		if (ret < 0)
			return ret;
		total += ret;
	} while (ret);

	/* splice only reads full pages */
	do {
		ret = read(recorder->trace_fd, buf, recorder->page_size);
		if (ret > 0)
			write(recorder->fd, buf, ret);
	} while (ret > 0);

	return total;
}

int tracecmd_start_recording(struct tracecmd_recorder *recorder, unsigned long sleep)
{
	struct timespec req;
	long read = 1;
	long ret;

	recorder->stop = 0;

	do {
		/* Only sleep if we did not read anything last time */
		if (!read && sleep) {
			req.tv_sec = sleep / 1000000;
			req.tv_nsec = (sleep % 1000000) * 1000;
			nanosleep(&req, NULL);
		}
		read = 0;
		do {
			if (recorder->flags & TRACECMD_RECORD_NOSPLICE)
				ret = read_data(recorder);
			else
				ret = splice_data(recorder);
			if (ret < 0)
				return ret;
			read += ret;
		} while (ret);
	} while (!recorder->stop);

	/* Flush out the rest */
	ret = tracecmd_flush_recording(recorder);

	if (ret < 0)
		return ret;

	return 0;
}

void tracecmd_stop_recording(struct tracecmd_recorder *recorder)
{
	if (!recorder)
		return;

	set_nonblock(recorder);

	recorder->stop = 1;
}

/**
 * tracecmd_stat_cpu - show the buffer stats of a particular CPU
 * @s: the trace_seq to record the data in.
 * @cpu: the CPU to stat
 *
 */
void tracecmd_stat_cpu(struct trace_seq *s, int cpu)
{
	char buf[BUFSIZ];
	char *tracing;
	char *path;
	int fd;
	int r;

	tracing = tracecmd_find_tracing_dir();
	if (!tracing) {
		errno = ENODEV;
		goto out_free;
	}

	path = malloc_or_die(strlen(tracing) + 40);
	if (!path)
		goto out_free;

	sprintf(path, "%s/per_cpu/cpu%d/stats", tracing, cpu);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto out_free;

	while ((r = read(fd, buf, BUFSIZ)) > 0)
		trace_seq_printf(s, "%.*s", r, buf);

	close(fd);

 out_free:
	free(path);
	free(tracing);
}
