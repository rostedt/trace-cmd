// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018 VMware Inc, Slavomir Kaslev <kaslevs@vmware.com>
 *
 * based on prior implementation by Yoshihiro Yunomae
 * Copyright (C) 2013 Hitachi, Ltd.
 * Yoshihiro YUNOMAE <yoshihiro.yunomae.ez@hitachi.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>

#include "trace-local.h"
#include "trace-msg.h"

#define GUEST_NAME	"::GUEST::"

#define dprint(fmt, ...)	tracecmd_debug(fmt, ##__VA_ARGS__)

static void make_vsocks(int nr, int *fds, unsigned int *ports)
{
	unsigned int port;
	int i, fd, ret;

	for (i = 0; i < nr; i++) {
		fd = trace_vsock_make_any();
		if (fd < 0)
			die("Failed to open vsocket");

		ret = trace_vsock_get_port(fd, &port);
		if (ret < 0)
			die("Failed to get vsocket address");

		fds[i] = fd;
		ports[i] = port;
	}
}

static void make_net(int nr, int *fds, unsigned int *ports)
{
	int port;
	int i, fd;
	int start_port = START_PORT_SEARCH;

	for (i = 0; i < nr; i++) {
		port = trace_net_search(start_port, &fd, USE_TCP);
		if (port < 0)
			die("Failed to open socket");
		if (listen(fd, 5) < 0)
			die("Failed to listen on port %d\n", port);
		fds[i] = fd;
		ports[i] = port;
		dprint("CPU[%d]: fd:%d port:%d\n", i, fd, port);
		start_port = port + 1;
	}
}

static void make_sockets(int nr, int *fds, unsigned int *ports,
			 const char * network)
{
	if (network)
		return make_net(nr, fds, ports);
	else
		return make_vsocks(nr, fds, ports);
}

static int open_agent_fifos(int nr_cpus, int *fds)
{
	char path[PATH_MAX];
	int i, fd, ret;

	for (i = 0; i < nr_cpus; i++) {
		snprintf(path, sizeof(path), VIRTIO_FIFO_FMT, i);
		fd = open(path, O_WRONLY);
		if (fd < 0) {
			ret = -errno;
			goto cleanup;
		}

		fds[i] = fd;
	}

	return 0;

cleanup:
	while (--i >= 0)
		close(fds[i]);

	return ret;
}

static char *get_clock(int argc, char **argv)
{
	int i;

	if (!argc || !argv)
		return NULL;

	for (i = 0; i < argc - 1; i++) {
		if (!strcmp("-C", argv[i]))
			return argv[i+1];
	}
	return NULL;
}

static void trace_print_connection(int fd, const char *network)
{
	int ret;

	if (network)
		ret = trace_net_print_connection(fd);
	else
		ret = trace_vsock_print_connection(fd);
	if (ret < 0)
		tracecmd_debug("Could not print connection fd:%d\n", fd);
}

static int wait_for_connection(int fd)
{
	int sd;

	if (fd < 0)
		return -1;

	while (true) {
		tracecmd_debug("Listening on fd:%d\n", fd);
		sd = accept(fd, NULL, NULL);
		tracecmd_debug("Accepted fd:%d\n", sd);
		if (sd < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		break;
	}
	close(fd);
	return sd;
}

static void agent_handle(int sd, int nr_cpus, int page_size,
			 int cid, int rcid, const char *network)
{
	struct tracecmd_tsync_protos *tsync_protos = NULL;
	struct tracecmd_time_sync *tsync = NULL;
	struct tracecmd_msg_handle *msg_handle;
	const char *tsync_proto = NULL;
	struct trace_guest *guest;
	unsigned long long peer_trace_id;
	unsigned long long trace_id;
	unsigned long flags = rcid >= 0 ? TRACECMD_MSG_FL_PROXY : 0;
	enum tracecmd_time_sync_role tsync_role = TRACECMD_TIME_SYNC_ROLE_GUEST;
	unsigned int remote_id;
	unsigned int local_id;
	unsigned int tsync_port = 0;
	unsigned int *ports;
	unsigned int client_cpus = 0;
	unsigned int guests = 0;
	char **argv = NULL;
	int argc = 0;
	bool use_fifos;
	int *fds;
	int ret;
	int fd;

	fds = calloc(nr_cpus, sizeof(*fds));
	ports = calloc(nr_cpus, sizeof(*ports));
	if (!fds || !ports)
		die("Failed to allocate memory");

	msg_handle = tracecmd_msg_handle_alloc(sd, flags);
	if (!msg_handle)
		die("Failed to allocate message handle");

	if (rcid >= 0) {
		tsync_role = TRACECMD_TIME_SYNC_ROLE_HOST;
		ret = tracecmd_msg_recv_trace_proxy(msg_handle, &argc, &argv,
						    &use_fifos, &peer_trace_id,
						    &tsync_protos,
						    &client_cpus,
						    &guests);
		/* Update the guests peer_trace_id */
		guest = trace_get_guest(rcid, NULL);
		if (guest)
			guest->trace_id = peer_trace_id;
	} else {
		ret = tracecmd_msg_recv_trace_req(msg_handle, &argc, &argv,
						  &use_fifos, &peer_trace_id,
						  &tsync_protos);
	}
	if (ret < 0)
		die("Failed to receive trace request");

	tsync_proto = tracecmd_tsync_get_proto(tsync_protos, get_clock(argc, argv),
					       tsync_role);

	if (use_fifos && open_agent_fifos(nr_cpus, fds))
		use_fifos = false;

	if (!use_fifos)
		make_sockets(nr_cpus, fds, ports, network);
	if (tsync_proto) {
		if (network) {
			/* For now just use something */
			remote_id = 2;
			local_id = 1;
			tsync_port = trace_net_search(START_PORT_SEARCH, &fd, USE_TCP);
			if (listen(fd, 5) < 0)
				die("Failed to listen on %d\n", tsync_port);
		} else {
			if (get_vsocket_params(msg_handle->fd, &local_id,
					       &remote_id)) {
				warning("Failed to get local and remote ids");
				/* Just make something up */
				remote_id = -1;
				local_id = -2;
			}
			fd = trace_vsock_make_any();
			if (fd >= 0 &&
			    trace_vsock_get_port(fd, &tsync_port) < 0) {
				close(fd);
				fd = -1;
			}
		}
	}
	trace_id = tracecmd_generate_traceid();
	ret = tracecmd_msg_send_trace_resp(msg_handle, nr_cpus, page_size,
					   ports, use_fifos, trace_id,
					   tsync_proto, tsync_port);
	if (ret < 0)
		die("Failed to send trace response");

	if (tsync_proto) {
		fd = wait_for_connection(fd);

		if (rcid >= 0) {
			tsync = trace_tsync_as_host(fd, trace_id, 0, rcid,
						    client_cpus, tsync_proto,
						    get_clock(argc, argv));
		} else {
			tsync = trace_tsync_as_guest(fd, tsync_proto,
						     get_clock(argc, argv),
						     remote_id, local_id);
		}
		if (!tsync)
			close(fd);
	}

	trace_record_agent(msg_handle, nr_cpus, fds, argc, argv,
			   use_fifos, tsync, trace_id, rcid, network);

	if (tsync) {
		if (rcid < 0)
			tracecmd_tsync_with_host_stop(tsync);
		tracecmd_tsync_free(tsync);
	}

	if (tsync_protos) {
		free(tsync_protos->names);
		free(tsync_protos);
	}
	free(argv[0]);
	free(argv);
	free(ports);
	free(fds);
	tracecmd_msg_handle_close(msg_handle);
	exit(0);
}

static volatile pid_t handler_pid;

static void handle_sigchld(int sig)
{
	int wstatus;
	pid_t pid;

	for (;;) {
		pid = waitpid(-1, &wstatus, WNOHANG);
		if (pid <= 0)
			break;

		if (pid == handler_pid)
			handler_pid = 0;
	}
}

static pid_t do_fork()
{
	/* in debug mode, we do not fork off children */
	if (tracecmd_get_debug())
		return 0;

	return fork();
}

static void agent_serve(unsigned int port, bool do_daemon, int proxy_id,
			const char *network)
{
	struct sockaddr_storage net_addr;
	struct sockaddr *addr = NULL;
	socklen_t *addr_len_p = NULL;
	socklen_t addr_len = sizeof(net_addr);
	int sd, cd, nr_cpus;
	unsigned int cid = -1, rcid = -1;
	pid_t pid;

	signal(SIGCHLD, handle_sigchld);

	if (network) {
		addr = (struct sockaddr *)&net_addr;
		addr_len_p = &addr_len;
	}

	nr_cpus = tracecmd_count_cpus();
	page_size = getpagesize();

	if (network) {
		sd = trace_net_make(port, USE_TCP);
		if (listen(sd, 5) < 0)
			die("Failed to listen on %d\n", port);
	} else
		sd = trace_vsock_make(port);
	if (sd < 0)
		die("Failed to open socket");
	tracecmd_tsync_init();

	if (!network) {
		cid = trace_vsock_local_cid();
		if (cid >= 0)
			printf("listening on @%u:%u\n", cid, port);
	}

	if (do_daemon && daemon(1, 0))
		die("daemon");

	for (;;) {
		cd = accept(sd, addr, addr_len_p);
		if (cd < 0) {
			if (errno == EINTR)
				continue;
			die("accept");
		}
		if (proxy_id >= 0) {
			/* Only works with vsockets */
			if (get_vsocket_params(cd, NULL, &rcid) < 0) {
				dprint("Failed to find connected cid");
				close(cd);
				continue;
			}
			if (rcid != proxy_id) {
				dprint("Cid %d does not match expected cid %d\n",
				       rcid, proxy_id);
				close(cd);
				continue;
			}
		}

		if (tracecmd_get_debug())
			trace_print_connection(cd, network);

		if (network && !trace_net_cmp_connection(&net_addr, network)) {
			dprint("Client does not match '%s'\n", network);
			close(cd);
			continue;
		}

		if (handler_pid)
			goto busy;

		pid = do_fork();
		if (pid == 0) {
			close(sd);
			signal(SIGCHLD, SIG_DFL);
			agent_handle(cd, nr_cpus, page_size, cid, rcid, network);
		}
		if (pid > 0)
			handler_pid = pid;

busy:
		close(cd);
	}
}

enum {
	OPT_verbose	= 254,
	DO_DEBUG	= 255
};

void trace_agent(int argc, char **argv)
{
	struct trace_guest *guest;
	bool do_daemon = false;
	unsigned int port = TRACE_AGENT_DEFAULT_PORT;
	const char *network = NULL;
	int proxy_id = -1;

	if (argc < 2)
		usage(argv);

	if (strcmp(argv[1], "agent") != 0)
		usage(argv);

	for (;;) {
		int c, option_index = 0;
		static struct option long_options[] = {
			{"port", required_argument, NULL, 'p'},
			{"help", no_argument, NULL, '?'},
			{"debug", no_argument, NULL, DO_DEBUG},
			{"verbose", optional_argument, NULL, OPT_verbose},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long(argc-1, argv+1, "+hp:DN:P:",
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'N':
			network = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			if (proxy_id >= 0)
				die("-N cannot be used with -P");
			break;
		case 'D':
			do_daemon = true;
			break;
		case 'P':
			proxy_id = atoi(optarg);

			guest = trace_get_guest(proxy_id, GUEST_NAME);
			if (!guest)
				die("Failed to allocate guest instance");

			break;
		case DO_DEBUG:
			tracecmd_set_debug(true);
			break;
		case OPT_verbose:
			if (trace_set_verbose(optarg) < 0)
				die("invalid verbose level %s", optarg);
			break;
		default:
			usage(argv);
		}
	}

	if (optind < argc-1)
		usage(argv);

	agent_serve(port, do_daemon, proxy_id, network);
}
