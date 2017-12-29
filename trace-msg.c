/*
 * trace-msg.c : define message protocol for communication between clients and
 *               a server
 *
 * Copyright (C) 2013 Hitachi, Ltd.
 * Created by Yoshihiro YUNOMAE <yoshihiro.yunomae.ez@hitachi.com>
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <linux/types.h>

#include "trace-cmd-local.h"
#include "trace-local.h"
#include "trace-msg.h"

typedef __u32 u32;
typedef __be32 be32;

/* Two (4k) pages is the max transfer for now */
#define MSG_MAX_LEN			8192

#define MSG_HDR_LEN			sizeof(struct tracecmd_msg_header)

#define MSG_DATA_LEN			(MSG_MAX_LEN - MSG_HDR_LEN)

					/* - header size for error msg */
#define MSG_META_MAX_LEN		(MSG_MAX_LEN - MIN_META_SIZE)


#define MIN_TINIT_SIZE	(sizeof(struct tracecmd_msg_header) + \
			 sizeof(struct tracecmd_msg_tinit))

/* Not really the minimum, but I couldn't think of a better name */
#define MIN_RINIT_SIZE	(sizeof(struct tracecmd_msg_header) + \
			 sizeof(struct tracecmd_msg_rinit))

#define MIN_META_SIZE	(sizeof(struct tracecmd_msg_header) + \
			 sizeof(struct tracecmd_msg_meta))

/* for both client and server */
bool use_tcp;
int cpu_count;

/* for client */
static int psfd;
unsigned int page_size;
int *client_ports;
bool send_metadata;

/* for server */
static int *port_array;
bool done;

struct tracecmd_msg_opt {
	be32 size;
	be32 opt_cmd;
	be32 padding;	/* for backward compatibility */
};

struct tracecmd_msg_tinit {
	be32 cpus;
	be32 page_size;
	be32 opt_num;
} __attribute__((packed));

struct tracecmd_msg_rinit {
	be32 cpus;
} __attribute__((packed));

struct tracecmd_msg_meta {
	be32 size;
} __attribute__((packed));

enum tracecmd_msg_cmd {
	MSG_CLOSE	= 1,
	MSG_TINIT	= 4,
	MSG_RINIT	= 5,
	MSG_SENDMETA	= 6,
	MSG_FINMETA	= 7,
};

struct tracecmd_msg_header {
	be32	size;
	be32	cmd;
} __attribute__((packed));

struct tracecmd_msg {
	struct tracecmd_msg_header		hdr;
	union {
		struct tracecmd_msg_tinit	tinit;
		struct tracecmd_msg_rinit	rinit;
		struct tracecmd_msg_meta	meta;
	};
	union {
		struct tracecmd_msg_opt		*opt;
		be32				*port_array;
		void				*buf;
	};
} __attribute__((packed));

struct tracecmd_msg *errmsg;

static int msg_write(int fd, struct tracecmd_msg *msg, int size)
{
	int ret;

	ret = __do_write_check(fd, msg, size);
	if (ret < 0)
		return ret;
	if (ntohl(msg->hdr.size) <= size)
		return 0;
	return __do_write_check(fd, msg->buf, ntohl(msg->hdr.size) - size);
}

static ssize_t msg_do_write_check(int fd, struct tracecmd_msg *msg)
{
	int ret;

	switch (ntohl(msg->hdr.cmd)) {
	case MSG_TINIT:
		ret = msg_write(fd, msg, MIN_TINIT_SIZE);
		break;
	case MSG_RINIT:
		ret = msg_write(fd, msg, MIN_RINIT_SIZE);
		break;
	case MSG_SENDMETA:
		ret = msg_write(fd, msg, MIN_META_SIZE);
		break;
	default:
		ret = __do_write_check(fd, msg, ntohl(msg->hdr.size));
	}

	return ret;
}

enum msg_opt_command {
	MSGOPT_USETCP = 1,
};

static int make_tinit(struct tracecmd_msg *msg)
{
	struct tracecmd_msg_opt *opt;
	int opt_num = 0;
	int size = MIN_TINIT_SIZE;

	if (use_tcp) {
		opt_num++;
		opt = malloc(sizeof(*opt));
		if (!opt)
			return -ENOMEM;
		opt->size = htonl(sizeof(*opt));
		opt->opt_cmd = htonl(MSGOPT_USETCP);
		msg->opt = opt;
		size += sizeof(*opt);
	}

	msg->tinit.cpus = htonl(cpu_count);
	msg->tinit.page_size = htonl(page_size);
	msg->tinit.opt_num = htonl(opt_num);

	msg->hdr.size = htonl(size);

	return 0;
}

static int make_rinit(struct tracecmd_msg *msg)
{
	int size = MIN_RINIT_SIZE;
	be32 *ptr;
	be32 port;
	int i;

	msg->rinit.cpus = htonl(cpu_count);

	msg->port_array = malloc(sizeof(*port_array) * cpu_count);
	if (!msg->port_array)
		return -ENOMEM;

	size += sizeof(*port_array) * cpu_count;

	ptr = msg->port_array;

	for (i = 0; i < cpu_count; i++) {
		/* + rrqports->cpus or rrqports->port_array[i] */
		port = htonl(port_array[i]);
		*ptr = port;
		ptr++;
	}

	msg->hdr.size = htonl(size);

	return 0;
}

static int tracecmd_msg_create(u32 cmd, struct tracecmd_msg *msg)
{
	int ret = 0;

	if (cmd > MSG_FINMETA) {
		plog("Unsupported command: %d\n", cmd);
		return -EINVAL;
	}

	memset(msg, 0, sizeof(*msg));
	msg->hdr.cmd = htonl(cmd);

	switch (cmd) {
	case MSG_TINIT:
		return make_tinit(msg);
	case MSG_RINIT:
		return make_rinit(msg);
	case MSG_CLOSE:
	case MSG_SENDMETA: /* meta data is not stored here. */
	case MSG_FINMETA:
		break;
	}

	msg->hdr.size = htonl(MSG_HDR_LEN);

	return ret;
}

static void msg_free(struct tracecmd_msg *msg)
{
	switch (ntohl(msg->hdr.cmd)) {
	case MSG_TINIT:
		free(msg->opt);
		break;
	case MSG_RINIT:
		free(msg->port_array);
		break;
	case MSG_SENDMETA:
		free(msg->buf);
		break;
	}
}

static int tracecmd_msg_send(int fd, struct tracecmd_msg *msg)
{
	int ret = 0;

	ret = msg_do_write_check(fd, msg);
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

static int msg_read_extra(int fd, void *buf, int *n,
			  int size, int min_size, void **addr)
{
	int rsize;
	int ret;

	rsize = min_size - *n;
	ret = msg_read(fd, buf, rsize, n);
	if (ret < 0)
		return ret;
	size -= *n;
	if (size < 0)
		return -ENOMSG;
	*addr = malloc(size);
	if (!*addr)
		return -ENOMEM;
	*n = 0;
	return msg_read(fd, *addr, size, n);
}

static int tracecmd_msg_read_extra(int fd, struct tracecmd_msg *msg, int *n)
{
	int size = ntohl(msg->hdr.size);
	int rsize;
	int ret;

	switch (ntohl(msg->hdr.cmd)) {
	case MSG_TINIT:
		msg->opt = NULL;

		rsize = MIN_TINIT_SIZE - *n;

		ret = msg_read(fd, msg, rsize, n);
		if (ret < 0)
			return ret;

		if (size > *n) {
			size -= *n;
			msg->opt = malloc(size);
			if (!msg->opt)
				return -ENOMEM;
			*n = 0;
			return msg_read(fd, msg->opt, size, n);
		}
		return 0;
	case MSG_RINIT:
		return msg_read_extra(fd, msg, n, size, MIN_RINIT_SIZE,
				      (void **)&msg->port_array);
	case MSG_SENDMETA:
		return msg_read_extra(fd, msg, n, size, MIN_META_SIZE,
				      (void **)&msg->buf);
	}

	return msg_read(fd, msg, size - MSG_HDR_LEN, n);
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

	size = ntohl(msg->hdr.size);
	if (size > MSG_MAX_LEN)
		/* too big */
		goto error;
	else if (size < MSG_HDR_LEN)
		/* too small */
		goto error;
	else if (size > MSG_HDR_LEN)
		return tracecmd_msg_read_extra(fd, msg, &n);

	return 0;
error:
	plog("Receive an invalid message(size=%d)\n", size);
	return -ENOMSG;
}

#define MSG_WAIT_MSEC	5000
static int msg_wait_to = MSG_WAIT_MSEC;

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

int tracecmd_msg_send_init_data(int fd)
{
	struct tracecmd_msg send_msg;
	struct tracecmd_msg recv_msg;
	int i, cpus;
	int ret;

	ret = tracecmd_msg_create(MSG_TINIT, &send_msg);
	if (ret < 0)
		return ret;

	ret = tracecmd_msg_send(fd, &send_msg);
	if (ret < 0)
		return ret;

	ret = tracecmd_msg_wait_for_msg(fd, &recv_msg);
	if (ret < 0)
		return ret;

	cpus = ntohl(recv_msg.rinit.cpus);
	client_ports = malloc_or_die(sizeof(int) * cpus);
	for (i = 0; i < cpus; i++)
		client_ports[i] = ntohl(recv_msg.port_array[i]);

	/* Next, send meta data */
	send_metadata = true;

	return 0;
}

static bool process_option(struct tracecmd_msg_opt *opt)
{
	/* currently the only option we have is to us TCP */
	if (ntohl(opt->opt_cmd) == MSGOPT_USETCP) {
		use_tcp = true;
		return true;
	}
	return false;
}

static void error_operation_for_server(struct tracecmd_msg *msg)
{
	u32 cmd;

	cmd = ntohl(msg->hdr.cmd);

	warning("Message: cmd=%d size=%d\n", cmd, ntohl(msg->hdr.size));
}

#define MAX_OPTION_SIZE 4096

int tracecmd_msg_initial_setting(int fd, int *cpus, int *pagesize)
{
	struct tracecmd_msg_opt *opt;
	struct tracecmd_msg msg;
	int options, i, s;
	int ret;
	int offset = 0;
	u32 size = MIN_TINIT_SIZE;
	u32 cmd;

	ret = tracecmd_msg_recv_wait(fd, &msg);
	if (ret < 0) {
		if (ret == -ETIMEDOUT)
			warning("Connection timed out\n");
		return ret;
	}

	cmd = ntohl(msg.hdr.cmd);
	if (cmd != MSG_TINIT) {
		ret = -EINVAL;
		goto error;
	}

	*cpus = ntohl(msg.tinit.cpus);
	plog("cpus=%d\n", *cpus);
	if (*cpus < 0) {
		ret = -EINVAL;
		goto error;
	}

	*pagesize = ntohl(msg.tinit.page_size);
	plog("pagesize=%d\n", *pagesize);
	if (*pagesize <= 0) {
		ret = -EINVAL;
		goto error;
	}

	options = ntohl(msg.tinit.opt_num);
	for (i = 0; i < options; i++) {
		if (size + sizeof(*opt) > ntohl(msg.hdr.size)) {
			plog("Not enough message for options\n");
			ret = -EINVAL;
			goto error;
		}
		opt = (void *)msg.opt + offset;
		offset += ntohl(opt->size);
		size += ntohl(opt->size);
		if (ntohl(msg.hdr.size) < size) {
			plog("Not enough message for options\n");
			ret = -EINVAL;
			goto error;
		}
		/* prevent a client from killing us */
		if (ntohl(opt->size) > MAX_OPTION_SIZE) {
			plog("Exceed MAX_OPTION_SIZE\n");
			ret = -EINVAL;
			goto error;
		}
		s = process_option(opt);
		/* do we understand this option? */
		if (!s) {
			plog("Cannot understand(%d:%d:%d)\n",
			     i, ntohl(opt->size), ntohl(opt->opt_cmd));
			ret = -EINVAL;
			goto error;
		}
	}

	return 0;

error:
	error_operation_for_server(&msg);
	return ret;
}

int tracecmd_msg_send_port_array(int fd, int total_cpus, int *ports)
{
	struct tracecmd_msg msg;
	int ret;

	cpu_count = total_cpus;
	port_array = ports;

	ret = tracecmd_msg_create(MSG_RINIT, &msg);
	if (ret < 0)
		return ret;

	ret = tracecmd_msg_send(fd, &msg);
	if (ret < 0)
		return ret;

	return 0;
}

void tracecmd_msg_send_close_msg(void)
{
	struct tracecmd_msg msg;
	int ret;

	ret = tracecmd_msg_create(MSG_CLOSE, &msg);
	if (ret < 0)
		return;

	tracecmd_msg_send(psfd, &msg);
}

int tracecmd_msg_metadata_send(int fd, const char *buf, int size)
{
	struct tracecmd_msg msg;
	int n;
	int ret;
	int count = 0;

	ret = tracecmd_msg_create(MSG_SENDMETA, &msg);
	if (ret < 0)
		return ret;

	msg.buf = malloc(MSG_META_MAX_LEN);
	if (!msg.buf)
		return -ENOMEM;

	msg.meta.size = htonl(MSG_META_MAX_LEN);
	msg.hdr.size = htonl(MIN_META_SIZE + MSG_META_MAX_LEN);

	n = size;
	do {
		if (n > MSG_META_MAX_LEN) {
			memcpy(msg.buf, buf+count, MSG_META_MAX_LEN);
			n -= MSG_META_MAX_LEN;
			count += MSG_META_MAX_LEN;
		} else {
			msg.hdr.size = htonl(MIN_META_SIZE + n);
			msg.meta.size = htonl(n);
			memcpy(msg.buf, buf+count, n);
			n = 0;
		}
		ret = msg_do_write_check(fd, &msg);
		if (ret < 0)
			break;
	} while (n);

	msg_free(&msg);
	return ret;
}

int tracecmd_msg_finish_sending_metadata(int fd)
{
	struct tracecmd_msg msg;
	int ret;

	ret = tracecmd_msg_create(MSG_FINMETA, &msg);
	if (ret < 0)
		return ret;

	ret = tracecmd_msg_send(fd, &msg);
	if (ret < 0)
		return ret;

	/* psfd will be used for closing */
	psfd = fd;
	return 0;
}

int tracecmd_msg_collect_metadata(int ifd, int ofd)
{
	struct tracecmd_msg msg;
	u32 t, n, cmd;
	ssize_t s;
	int ret;

	do {
		ret = tracecmd_msg_recv_wait(ifd, &msg);
		if (ret < 0) {
			if (ret == -ETIMEDOUT)
				warning("Connection timed out\n");
			else
				warning("reading client");
			return ret;
		}

		cmd = ntohl(msg.hdr.cmd);
		if (cmd == MSG_FINMETA) {
			/* Finish receiving meta data */
			break;
		} else if (cmd != MSG_SENDMETA)
			goto error;

		n = ntohl(msg.meta.size);
		t = n;
		s = 0;
		do {
			s = write(ofd, msg.buf+s, t);
			if (s < 0) {
				if (errno == EINTR)
					continue;
				warning("writing to file");
				return -errno;
			}
			t -= s;
			s = n - t;
		} while (t);
	} while (cmd == MSG_SENDMETA);

	/* check the finish message of the client */
	while (!done) {
		ret = tracecmd_msg_recv(ifd, &msg);
		if (ret < 0) {
			warning("reading client");
			return ret;
		}

		cmd = ntohl(msg.hdr.cmd);
		if (cmd == MSG_CLOSE)
			/* Finish this connection */
			break;
		else {
			warning("Not accept the message %d", ntohl(msg.hdr.cmd));
			ret = -EINVAL;
			goto error;
		}
	}

	return 0;

error:
	error_operation_for_server(&msg);
	return ret;
}
