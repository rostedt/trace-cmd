// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>

#include "tracefs.h"
#include "trace-cmd-private.h"
#include "trace-cmd-local.h"
#include "event-utils.h"

/* F_GETPIPE_SZ was introduced in 2.6.35, older systems don't have it */
#ifndef F_GETPIPE_SZ
# define F_GETPIPE_SZ	1032 /* The Linux number for the option */
#endif

#ifndef SPLICE_F_MOVE
# define SPLICE_F_MOVE		1
# define SPLICE_F_NONBLOCK	2
# define SPLICE_F_MORE		4
# define SPLICE_F_GIFT		8
#endif

#define POLL_TIMEOUT_MS		1000

struct tracecmd_recorder {
	struct tracefs_cpu *tcpu;
	int		fd;
	int		fd1;
	int		fd2;
	int		page_size;
	int		subbuf_size;
	int		cpu;
	int		stop;
	int		max;
	int		pages;
	int		count;
	unsigned	flags;
};

static int append_file(int size, int dst, int src)
{
	char buf[size];
	int r;

	lseek(src, 0, SEEK_SET);

	/* If there's an error, then we are pretty much screwed :-p */
	do {
		r = read(src, buf, size);
		if (r < 0)
			return r;
		r = write(dst, buf, r);
		if (r < 0)
			return r;
	} while (r);
	return 0;
}

void tracecmd_free_recorder(struct tracecmd_recorder *recorder)
{
	if (!recorder)
		return;

	if (recorder->max) {
		/* Need to put everything into fd1 */
		if (recorder->fd == recorder->fd1) {
			int ret;
			/*
			 * Crap, the older data is in fd2, and we need
			 * to append fd1 onto it, and then copy over to fd1
			 */
			ret = append_file(recorder->page_size,
					  recorder->fd2, recorder->fd1);
			/* Error on copying, then just keep fd1 */
			if (ret) {
				lseek(recorder->fd1, 0, SEEK_END);
				goto close;
			}
			lseek(recorder->fd1, 0, SEEK_SET);
			ftruncate(recorder->fd1, 0);
		}
		append_file(recorder->page_size, recorder->fd1, recorder->fd2);
	}
 close:
	tracefs_cpu_close(recorder->tcpu);

	if (recorder->fd1 >= 0)
		close(recorder->fd1);

	if (recorder->fd2 >= 0)
		close(recorder->fd2);

	free(recorder);
}

static int set_nonblock(struct tracecmd_recorder *recorder)
{
	return tracefs_cpu_stop(recorder->tcpu);
}

static struct tracecmd_recorder *
create_buffer_recorder_fd2(int fd, int fd2, int cpu, unsigned flags,
			   struct tracefs_instance *instance, int maxkb, int tfd)
{
	struct tracecmd_recorder *recorder;
	bool nonblock = false;

	recorder = malloc(sizeof(*recorder));
	if (!recorder)
		return NULL;

	recorder->flags = flags;

	recorder->page_size = getpagesize();
	if (maxkb) {
		int kb_per_page = recorder->page_size >> 10;

		if (!kb_per_page)
			kb_per_page = 1;
		recorder->max = maxkb / kb_per_page;
		/* keep max half */
		recorder->max >>= 1;
		if (!recorder->max)
			recorder->max = 1;
	} else
		recorder->max = 0;

	recorder->count = 0;
	recorder->pages = 0;

	/* fd always points to what to write to */
	recorder->fd = fd;
	recorder->fd1 = fd;
	recorder->fd2 = fd2;

	if (recorder->flags & TRACECMD_RECORD_POLL)
		nonblock = true;

	if (tfd >= 0)
		recorder->tcpu = tracefs_cpu_alloc_fd(tfd, recorder->page_size, nonblock);
	else
		recorder->tcpu = tracefs_cpu_open(instance, cpu, nonblock);

	if (!recorder->tcpu)
		goto out_free;

	recorder->subbuf_size = tracefs_cpu_read_size(recorder->tcpu);
	return recorder;

 out_free:
	tracecmd_free_recorder(recorder);
	return NULL;
}

struct tracecmd_recorder *
tracecmd_create_buffer_recorder_fd2(int fd, int fd2, int cpu, unsigned flags,
				    struct tracefs_instance *instance, int maxkb)
{
	return create_buffer_recorder_fd2(fd, fd2, cpu, flags, instance, maxkb, -1);
}

struct tracecmd_recorder *
tracecmd_create_buffer_recorder_fd(int fd, int cpu, unsigned flags, struct tracefs_instance *instance)
{
	return tracecmd_create_buffer_recorder_fd2(fd, -1, cpu, flags, instance, 0);
}

static struct tracecmd_recorder *
__tracecmd_create_buffer_recorder(const char *file, int cpu, unsigned flags,
				  struct tracefs_instance *instance, int tfd)
{
	struct tracecmd_recorder *recorder;
	int fd;

	fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
	if (fd < 0)
		return NULL;

	recorder = create_buffer_recorder_fd2(fd, -1, cpu, flags, instance, 0, tfd);
	if (!recorder) {
		close(fd);
		unlink(file);
	}

	return recorder;
}

struct tracecmd_recorder *
tracecmd_create_buffer_recorder_maxkb(const char *file, int cpu, unsigned flags,
				      struct tracefs_instance *instance, int maxkb)
{
	struct tracecmd_recorder *recorder = NULL;
	char *file2;
	int len;
	int fd;
	int fd2;

	if (!maxkb)
		return tracecmd_create_buffer_recorder(file, cpu, flags, instance);

	len = strlen(file);
	file2 = malloc(len + 3);
	if (!file2)
		return NULL;

	sprintf(file2, "%s.1", file);

	fd = open(file, O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
	if (fd < 0)
		goto out;

	fd2 = open(file2, O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
	if (fd2 < 0)
		goto err;

	recorder = tracecmd_create_buffer_recorder_fd2(fd, fd2, cpu, flags, instance, maxkb);
	if (!recorder)
		goto err2;
 out:
	/* Unlink file2, we need to add everything to file at the end */
	unlink(file2);
	free(file2);

	return recorder;
 err2:
	close(fd2);
 err:
	close(fd);
	unlink(file);
	goto out;
}

struct tracecmd_recorder *
tracecmd_create_buffer_recorder(const char *file, int cpu, unsigned flags,
				struct tracefs_instance *instance)
{
	return __tracecmd_create_buffer_recorder(file, cpu, flags, instance, -1);
}

/**
 * tracecmd_create_recorder_virt - Create a recorder reading tracing data
 * from the trace_fd file descriptor instead of from the local tracefs
 * @file: output filename where tracing data will be written
 * @cpu: which CPU is being traced
 * @flags: flags configuring the recorder (see TRACECMD_RECORDER_* enums)
 * @trace_fd: file descriptor from where tracing data will be read
 */
struct tracecmd_recorder *
tracecmd_create_recorder_virt(const char *file, int cpu, unsigned flags,
			      int trace_fd)
{
	return __tracecmd_create_buffer_recorder(file, cpu, flags, NULL, trace_fd);
}

struct tracecmd_recorder *tracecmd_create_recorder_fd(int fd, int cpu, unsigned flags)
{
	return tracecmd_create_buffer_recorder_fd(fd, cpu, flags, NULL);
}

struct tracecmd_recorder *tracecmd_create_recorder(const char *file, int cpu, unsigned flags)
{
	return tracecmd_create_buffer_recorder(file, cpu, flags, NULL);
}

struct tracecmd_recorder *
tracecmd_create_recorder_maxkb(const char *file, int cpu, unsigned flags, int maxkb)
{
	return tracecmd_create_buffer_recorder_maxkb(file, cpu, flags, NULL, maxkb);
}

static inline void update_fd(struct tracecmd_recorder *recorder, int size)
{
	int fd;

	if (!recorder->max)
		return;

	recorder->count += size;

	if (recorder->count >= recorder->page_size) {
		recorder->pages += recorder->count / recorder->page_size;
		recorder->count = 0;
	}

	if (recorder->pages < recorder->max)
		return;

	recorder->pages = 0;

	fd = recorder->fd;

	/* Swap fd to next file. */
	if (fd == recorder->fd1)
		fd = recorder->fd2;
	else
		fd = recorder->fd1;

	/* Zero out the new file we are writing to */
	lseek(fd, 0, SEEK_SET);
	ftruncate(fd, 0);

	recorder->fd = fd;
}

/*
 * Returns -1 on error.
 *          or bytes of data read.
 */
static long read_data(struct tracecmd_recorder *recorder)
{
	bool nonblock = recorder->stop;
	char buf[recorder->subbuf_size];
	long left;
	long r, w;

	r = tracefs_cpu_read(recorder->tcpu, buf, nonblock);
	if (r < 0)
		return r;

	left = r;
	do {
		w = write(recorder->fd, buf + (r - left), left);
		if (w > 0) {
			left -= w;
			update_fd(recorder, w);
		}
	} while (w >= 0 && left);

	if (w < 0)
		r = w;

	return r;
}

/*
 * Returns -1 on error.
 *          or bytes of data read.
 */
static long direct_splice_data(struct tracecmd_recorder *recorder)
{
	bool nonblock = recorder->stop;
	return tracefs_cpu_pipe(recorder->tcpu, recorder->fd, nonblock);
}

static long move_data(struct tracecmd_recorder *recorder)
{
	bool nonblock = recorder->stop;
	long ret;

	if (recorder->flags & TRACECMD_RECORD_NOSPLICE)
		return read_data(recorder);

	if (recorder->flags & TRACECMD_RECORD_NOBRASS)
		return direct_splice_data(recorder);

	ret = tracefs_cpu_write(recorder->tcpu, recorder->fd, nonblock);
	if (ret > 0)
		update_fd(recorder, ret);
	return ret;
}

long tracecmd_flush_recording(struct tracecmd_recorder *recorder, bool finish)
{
	char buf[recorder->subbuf_size];
	long total = 0;
	long wrote = 0;
	long ret;

	if (!recorder)
		return 0;

	if (!finish)
		return tracefs_cpu_flush_write(recorder->tcpu, recorder->fd);

	set_nonblock(recorder);

	do {
		ret = tracefs_cpu_flush_write(recorder->tcpu, recorder->fd);
		if (ret > 0)
			wrote += ret;
	} while (ret > 0);

	/* Make sure we finish off with a page size boundary */
	wrote &= recorder->subbuf_size - 1;
	if (wrote) {
		memset(buf, 0, recorder->subbuf_size);
		write(recorder->fd, buf, recorder->subbuf_size - wrote);
		total += recorder->subbuf_size;
	}

	return total;
}

int tracecmd_start_recording(struct tracecmd_recorder *recorder, unsigned long sleep)
{
	struct timespec req = {
		.tv_sec = sleep / 1000000,
		.tv_nsec = (sleep % 1000000) * 1000,
	};
	long read = 1;
	long ret;

	recorder->stop = 0;

	do {
		/* Only sleep if we did not read anything last time */
		if (!read && sleep)
			nanosleep(&req, NULL);

		read = 0;
		do {
			ret = move_data(recorder);
			if (ret < 0) {
				if (errno == EINTR)
					continue;
				return ret;
			}
			read += ret;
		} while (ret > 0 && !recorder->stop);
	} while (!recorder->stop);

	/* Flush out the rest */
	ret = tracecmd_flush_recording(recorder, true);

	if (ret < 0)
		return ret;

	return 0;
}

int tracecmd_stop_recording(struct tracecmd_recorder *recorder)
{
	if (!recorder)
		return -1;

	recorder->stop = 1;

	return set_nonblock(recorder);
}
