// SPDX-License-Identifier: LGPL-2.1
/*
 * trace-msg.c : define message protocol for communication between clients and
 *               a server
 *
 * Copyright (C) 2013 Hitachi, Ltd.
 * Created by Yoshihiro YUNOMAE <yoshihiro.yunomae.ez@hitachi.com>
 *
 */

#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <linux/types.h>

#include "trace-cmd-local.h"
#include "trace-local.h"
#include "trace-msg.h"

typedef __u32 u32;
typedef __be32 be32;

static inline void dprint(const char *fmt, ...)
{
	va_list ap;

	if (!debug)
		return;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

/* Two (4k) pages is the max transfer for now */
#define MSG_MAX_LEN			8192

#define MSG_HDR_LEN			sizeof(struct tracecmd_msg_header)

#define MSG_MAX_DATA_LEN		(MSG_MAX_LEN - MSG_HDR_LEN)

unsigned int page_size;

struct tracecmd_msg_tinit {
	be32 cpus;
	be32 page_size;
	be32 opt_num;
} __attribute__((packed));

struct tracecmd_msg_rinit {
	be32 cpus;
} __attribute__((packed));

struct tracecmd_msg_header {
	be32	size;
	be32	cmd;
	be32	cmd_size;
} __attribute__((packed));

#define MSG_MAP								\
	C(CLOSE,	0,	0),					\
	C(TINIT,	1,	sizeof(struct tracecmd_msg_tinit)),	\
	C(RINIT,	2,	sizeof(struct tracecmd_msg_rinit)),	\
	C(SEND_DATA,	3,	0),					\
	C(FIN_DATA,	4,	0),					\
	C(NOT_SUPP,	5,	0),

#undef C
#define C(a,b,c)	MSG_##a = b

enum tracecmd_msg_cmd {
	MSG_MAP
	MSG_NR_COMMANDS
};

#undef C
#define C(a,b,c)	c

static be32 msg_cmd_sizes[] = { MSG_MAP };

#undef C
#define C(a,b,c)	#a

static const char *msg_names[] = { MSG_MAP };

static const char *cmd_to_name(int cmd)
{
	if (cmd < 0 || cmd >= MSG_NR_COMMANDS)
		return "Unknown";
	return msg_names[cmd];
}

struct tracecmd_msg {
	struct tracecmd_msg_header		hdr;
	union {
		struct tracecmd_msg_tinit	tinit;
		struct tracecmd_msg_rinit	rinit;
	};
	char					*buf;
} __attribute__((packed));

static inline int msg_buf_len(struct tracecmd_msg *msg)
{
	return ntohl(msg->hdr.size) - MSG_HDR_LEN - ntohl(msg->hdr.cmd_size);
}

static int msg_write(int fd, struct tracecmd_msg *msg)
{
	int cmd = ntohl(msg->hdr.cmd);
	int msg_size, data_size;
	int ret;

	if (cmd < 0 || cmd >= MSG_NR_COMMANDS)
		return -EINVAL;

	dprint("msg send: %d (%s) [%d]\n",
	       cmd, cmd_to_name(cmd), ntohl(msg->hdr.size));

	msg_size = MSG_HDR_LEN + ntohl(msg->hdr.cmd_size);
	data_size = ntohl(msg->hdr.size) - msg_size;
	if (data_size < 0)
		return -EINVAL;

	ret = __do_write_check(fd, msg, msg_size);
	if (ret < 0)
		return ret;

	if (!data_size)
		return 0;

	return __do_write_check(fd, msg->buf, data_size);
}

static int make_tinit(struct tracecmd_msg_handle *msg_handle,
		      struct tracecmd_msg *msg)
{
	int cpu_count = msg_handle->cpu_count;
	int opt_num = 0;
	int data_size = 0;

	if (msg_handle->flags & TRACECMD_MSG_FL_USE_TCP) {
		opt_num++;
		msg->buf = strdup("tcp");
		data_size += 4;
	}

	msg->tinit.cpus = htonl(cpu_count);
	msg->tinit.page_size = htonl(page_size);
	msg->tinit.opt_num = htonl(opt_num);

	msg->hdr.size = htonl(ntohl(msg->hdr.size) + data_size);

	return 0;
}

static int write_ints(char *buf, size_t buf_len, int *arr, int arr_len)
{
	int i, ret, tot = 0;

	for (i = 0; i < arr_len; i++) {
		ret = snprintf(buf, buf_len, "%d", arr[i]);
		if (ret < 0)
			return ret;

		/* Count the '\0' byte */
		ret++;
		tot += ret;
		if (buf)
			buf += ret;
		if (buf_len >= ret)
			buf_len -= ret;
		else
			buf_len = 0;
	}

	return tot;
}

static int make_rinit(struct tracecmd_msg *msg, int cpus, int *ports)
{
	int data_size;

	data_size = write_ints(NULL, 0, ports, cpus);
	msg->buf = malloc(data_size);
	if (!msg->buf)
		return -ENOMEM;
	write_ints(msg->buf, data_size, ports, cpus);

	msg->rinit.cpus = htonl(cpus);
	msg->hdr.size = htonl(ntohl(msg->hdr.size) + data_size);

	return 0;
}

static void tracecmd_msg_init(u32 cmd, struct tracecmd_msg *msg)
{
	memset(msg, 0, sizeof(*msg));
	msg->hdr.size = htonl(MSG_HDR_LEN + msg_cmd_sizes[cmd]);
	msg->hdr.cmd = htonl(cmd);
	msg->hdr.cmd_size = htonl(msg_cmd_sizes[cmd]);
}

static void msg_free(struct tracecmd_msg *msg)
{
	free(msg->buf);
	memset(msg, 0, sizeof(*msg));
}

static int tracecmd_msg_send(int fd, struct tracecmd_msg *msg)
{
	int ret = 0;

	ret = msg_write(fd, msg);
	if (ret < 0)
		ret = -ECOMM;

	msg_free(msg);

	return ret;
}

static int msg_read(int fd, void *buf, u32 size, int *n)
{
	ssize_t r;

	while (size) {
		r = read(fd, buf + *n, size);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		} else if (!r)
			return -ENOTCONN;
		size -= r;
		*n += r;
	}

	return 0;
}

static char scratch_buf[MSG_MAX_LEN];

static int msg_read_extra(int fd, struct tracecmd_msg *msg,
			  int *n, int size)
{
	int cmd, cmd_size, rsize;
	int ret;

	cmd = ntohl(msg->hdr.cmd);
	if (cmd < 0 || cmd >= MSG_NR_COMMANDS)
		return -EINVAL;

	cmd_size = ntohl(msg->hdr.cmd_size);
	if (cmd_size < 0)
		return -EINVAL;

	if (cmd_size > 0) {
		rsize = cmd_size;
		if (rsize > msg_cmd_sizes[cmd])
			rsize = msg_cmd_sizes[cmd];

		ret = msg_read(fd, msg, rsize, n);
		if (ret < 0)
			return ret;

		ret = msg_read(fd, scratch_buf, cmd_size - rsize, n);
		if (ret < 0)
			return ret;
	}

	if (size > *n) {
		size -= *n;
		msg->buf = malloc(size);
		if (!msg->buf)
			return -ENOMEM;

		*n = 0;
		return msg_read(fd, msg->buf, size, n);
	}

	return 0;
}

/*
 * Read header information of msg first, then read all data
 */
static int tracecmd_msg_recv(int fd, struct tracecmd_msg *msg)
{
	u32 size = 0;
	int n = 0;
	int ret;

	ret = msg_read(fd, msg, MSG_HDR_LEN, &n);
	if (ret < 0)
		return ret;

	dprint("msg received: %d (%s) [%d]\n",
	       ntohl(msg->hdr.cmd), cmd_to_name(ntohl(msg->hdr.cmd)),
	       ntohl(msg->hdr.size));

	size = ntohl(msg->hdr.size);
	if (size > MSG_MAX_LEN)
		/* too big */
		goto error;
	else if (size < MSG_HDR_LEN)
		/* too small */
		goto error;
	else if (size > MSG_HDR_LEN)
		return msg_read_extra(fd, msg, &n, size);

	return 0;
error:
	plog("Receive an invalid message(size=%d)\n", size);
	return -ENOMSG;
}

#define MSG_WAIT_MSEC	5000
static int msg_wait_to = MSG_WAIT_MSEC;

bool tracecmd_msg_done(struct tracecmd_msg_handle *msg_handle)
{
	return (volatile int)msg_handle->done;
}

void tracecmd_msg_set_done(struct tracecmd_msg_handle *msg_handle)
{
	msg_handle->done = true;
}

static void error_operation(struct tracecmd_msg *msg)
{
	warning("Message: cmd=%d size=%d\n",
		ntohl(msg->hdr.cmd), ntohl(msg->hdr.size));
}

/*
 * A return value of 0 indicates time-out
 */
static int tracecmd_msg_recv_wait(int fd, struct tracecmd_msg *msg)
{
	struct pollfd pfd;
	int ret;

	pfd.fd = fd;
	pfd.events = POLLIN;
	ret = poll(&pfd, 1, debug ? -1 : msg_wait_to);
	if (ret < 0)
		return -errno;
	else if (ret == 0)
		return -ETIMEDOUT;

	return tracecmd_msg_recv(fd, msg);
}

static int tracecmd_msg_wait_for_msg(int fd, struct tracecmd_msg *msg)
{
	u32 cmd;
	int ret;

	ret = tracecmd_msg_recv_wait(fd, msg);
	if (ret < 0) {
		if (ret == -ETIMEDOUT)
			warning("Connection timed out\n");
		return ret;
	}

	cmd = ntohl(msg->hdr.cmd);
	if (cmd == MSG_CLOSE)
		return -ECONNABORTED;

	return 0;
}

static int tracecmd_msg_send_notsupp(struct tracecmd_msg_handle *msg_handle)
{
	struct tracecmd_msg msg;

	tracecmd_msg_init(MSG_NOT_SUPP, &msg);
	return tracecmd_msg_send(msg_handle->fd, &msg);
}

static int handle_unexpected_msg(struct tracecmd_msg_handle *msg_handle,
				 struct tracecmd_msg *msg)
{
	/* Don't send MSG_NOT_SUPP back if we just received one */
	if (ntohl(msg->hdr.cmd) == MSG_NOT_SUPP)
		return 0;

	return tracecmd_msg_send_notsupp(msg_handle);

}

int tracecmd_msg_send_init_data(struct tracecmd_msg_handle *msg_handle,
				unsigned int **client_ports)
{
	struct tracecmd_msg msg;
	int fd = msg_handle->fd;
	unsigned int *ports;
	int i, cpus, ret;
	char *p, *buf_end;
	ssize_t buf_len;

	*client_ports = NULL;

	tracecmd_msg_init(MSG_TINIT, &msg);
	ret = make_tinit(msg_handle, &msg);
	if (ret < 0)
		goto out;

	ret = tracecmd_msg_send(fd, &msg);
	if (ret < 0)
		goto out;

	msg_free(&msg);

	ret = tracecmd_msg_wait_for_msg(fd, &msg);
	if (ret < 0)
		goto out;

	if (ntohl(msg.hdr.cmd) != MSG_RINIT) {
		ret = -EOPNOTSUPP;
		goto error;
	}

	buf_len = msg_buf_len(&msg);
	if (buf_len <= 0) {
		ret = -EINVAL;
		goto error;
	}

	if (msg.buf[buf_len-1] != '\0') {
		ret = -EINVAL;
		goto error;
	}

	cpus = ntohl(msg.rinit.cpus);
	ports = malloc_or_die(sizeof(*ports) * cpus);
	if (!ports) {
		ret = -ENOMEM;
		goto out;
	}

	buf_end = msg.buf + buf_len;
	for (i = 0, p = msg.buf; i < cpus; i++, p++) {
		if (p >= buf_end) {
			free(ports);
			ret = -EINVAL;
			goto error;
		}

		ports[i] = atoi(p);
		p = strchr(p, '\0');
	}

	*client_ports = ports;

	msg_free(&msg);
	return 0;

error:
	error_operation(&msg);
	if (ret == -EOPNOTSUPP)
		handle_unexpected_msg(msg_handle, &msg);
out:
	msg_free(&msg);
	return ret;
}

static bool process_option(struct tracecmd_msg_handle *msg_handle,
			   const char *opt)
{
	/* currently the only option we have is to use TCP */
	if (strcmp(opt, "tcp") == 0) {
		msg_handle->flags |= TRACECMD_MSG_FL_USE_TCP;
		return true;
	}
	return false;
}

struct tracecmd_msg_handle *
tracecmd_msg_handle_alloc(int fd, unsigned long flags)
{
	struct tracecmd_msg_handle *handle;

	handle = calloc(1, sizeof(struct tracecmd_msg_handle));
	if (!handle)
		return NULL;

	handle->fd = fd;
	handle->flags = flags;
	return handle;
}

void tracecmd_msg_handle_close(struct tracecmd_msg_handle *msg_handle)
{
	close(msg_handle->fd);
	free(msg_handle);
}

#define MAX_OPTION_SIZE 4096

int tracecmd_msg_initial_setting(struct tracecmd_msg_handle *msg_handle)
{
	struct tracecmd_msg msg;
	char *p, *buf_end;
	ssize_t buf_len;
	int pagesize;
	int options, i;
	int cpus;
	int ret;

	memset(&msg, 0, sizeof(msg));
	ret = tracecmd_msg_recv_wait(msg_handle->fd, &msg);
	if (ret < 0) {
		if (ret == -ETIMEDOUT)
			warning("Connection timed out\n");
		return ret;
	}

	if (ntohl(msg.hdr.cmd) != MSG_TINIT) {
		ret = -EOPNOTSUPP;
		goto error;
	}

	cpus = ntohl(msg.tinit.cpus);
	plog("cpus=%d\n", cpus);
	if (cpus < 0) {
		ret = -EINVAL;
		goto error;
	}

	msg_handle->cpu_count = cpus;

	pagesize = ntohl(msg.tinit.page_size);
	plog("pagesize=%d\n", pagesize);
	if (pagesize <= 0) {
		ret = -EINVAL;
		goto error;
	}

	buf_len = msg_buf_len(&msg);
	if (buf_len < 0) {
		ret = -EINVAL;
		goto error;
	}

	if (buf_len == 0)
		goto no_options;

	if (msg.buf[buf_len-1] != '\0') {
		ret = -EINVAL;
		goto error;
	}

	buf_end = msg.buf + buf_len;
	options = ntohl(msg.tinit.opt_num);
	for (i = 0, p = msg.buf; i < options; i++, p++) {
		if (p >= buf_end) {
			ret = -EINVAL;
			goto error;
		}

		/* do we understand this option? */
		if (!process_option(msg_handle, p))
			plog("Cannot understand option '%s'\n", p);

		p = strchr(p, '\0');
	}

no_options:
	msg_free(&msg);
	return pagesize;

error:
	error_operation(&msg);
	if (ret == -EOPNOTSUPP)
		handle_unexpected_msg(msg_handle, &msg);
	msg_free(&msg);
	return ret;
}

int tracecmd_msg_send_port_array(struct tracecmd_msg_handle *msg_handle,
				 int *ports)
{
	struct tracecmd_msg msg;
	int ret;

	tracecmd_msg_init(MSG_RINIT, &msg);
	ret = make_rinit(&msg, msg_handle->cpu_count, ports);
	if (ret < 0)
		return ret;

	ret = tracecmd_msg_send(msg_handle->fd, &msg);
	if (ret < 0)
		return ret;

	return 0;
}

int tracecmd_msg_send_close_msg(struct tracecmd_msg_handle *msg_handle)
{
	struct tracecmd_msg msg;

	tracecmd_msg_init(MSG_CLOSE, &msg);
	return tracecmd_msg_send(msg_handle->fd, &msg);
}

int tracecmd_msg_data_send(struct tracecmd_msg_handle *msg_handle,
			   const char *buf, int size)
{
	struct tracecmd_msg msg;
	int fd = msg_handle->fd;
	int n;
	int ret;
	int count = 0;

	/* Don't bother doing anything if there's nothing to do */
	if (!size)
		return 0;

	tracecmd_msg_init(MSG_SEND_DATA, &msg);

	msg.buf = malloc(MSG_MAX_DATA_LEN);
	if (!msg.buf)
		return -ENOMEM;

	msg.hdr.size = htonl(MSG_MAX_LEN);

	n = size;
	while (n) {
		if (n > MSG_MAX_DATA_LEN) {
			memcpy(msg.buf, buf + count, MSG_MAX_DATA_LEN);
			n -= MSG_MAX_DATA_LEN;
			count += MSG_MAX_DATA_LEN;
		} else {
			msg.hdr.size = htonl(MSG_HDR_LEN + n);
			memcpy(msg.buf, buf + count, n);
			n = 0;
		}
		ret = msg_write(fd, &msg);
		if (ret < 0)
			break;
	}

	msg_free(&msg);
	return ret;
}

int tracecmd_msg_finish_sending_data(struct tracecmd_msg_handle *msg_handle)
{
	struct tracecmd_msg msg;
	int ret;

	tracecmd_msg_init(MSG_FIN_DATA, &msg);
	ret = tracecmd_msg_send(msg_handle->fd, &msg);
	if (ret < 0)
		return ret;
	return 0;
}

int tracecmd_msg_read_data(struct tracecmd_msg_handle *msg_handle, int ofd)
{
	struct tracecmd_msg msg;
	int t, n, cmd;
	ssize_t s;
	int ret;

	while (!tracecmd_msg_done(msg_handle)) {
		ret = tracecmd_msg_recv_wait(msg_handle->fd, &msg);
		if (ret < 0) {
			if (ret == -ETIMEDOUT)
				warning("Connection timed out\n");
			else
				warning("reading client");
			return ret;
		}

		cmd = ntohl(msg.hdr.cmd);
		if (cmd == MSG_FIN_DATA) {
			/* Finish receiving data */
			break;
		} else if (cmd != MSG_SEND_DATA) {
			ret = handle_unexpected_msg(msg_handle, &msg);
			if (ret < 0)
				goto error;
			goto next;
		}

		n = msg_buf_len(&msg);
		t = n;
		s = 0;
		while (t > 0) {
			s = write(ofd, msg.buf+s, t);
			if (s < 0) {
				if (errno == EINTR)
					continue;
				warning("writing to file");
				ret = -errno;
				goto error;
			}
			t -= s;
			s = n - t;
		}

next:
		msg_free(&msg);
	}

	return 0;

error:
	error_operation(&msg);
	msg_free(&msg);
	return ret;
}

int tracecmd_msg_collect_data(struct tracecmd_msg_handle *msg_handle, int ofd)
{
	int ret;

	ret = tracecmd_msg_read_data(msg_handle, ofd);
	if (ret)
		return ret;

	return tracecmd_msg_wait_close(msg_handle);
}

int tracecmd_msg_wait_close(struct tracecmd_msg_handle *msg_handle)
{
	struct tracecmd_msg msg;
	int ret = -1;

	memset(&msg, 0, sizeof(msg));
	while (!tracecmd_msg_done(msg_handle)) {
		ret = tracecmd_msg_recv(msg_handle->fd, &msg);
		if (ret < 0)
			goto error;

		if (ntohl(msg.hdr.cmd) == MSG_CLOSE)
			return 0;

		error_operation(&msg);
		ret = handle_unexpected_msg(msg_handle, &msg);
		if (ret < 0)
			goto error;

		msg_free(&msg);
	}

error:
	msg_free(&msg);
	return ret;
}
