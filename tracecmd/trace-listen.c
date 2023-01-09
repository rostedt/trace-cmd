// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#ifdef VSOCK
#include <linux/vm_sockets.h>
#endif

#include "trace-local.h"
#include "trace-msg.h"

#define dprint(fmt, ...)	tracecmd_debug(fmt, ##__VA_ARGS__)

#define MAX_OPTION_SIZE 4096

#define _VAR_DIR_Q(dir)		#dir
#define VAR_DIR_Q(dir)		_VAR_DIR_Q(dir)

#define VAR_RUN_DIR		VAR_DIR_Q(VAR_DIR) "/run"

static char *default_output_dir = ".";
static char *output_dir;
static char *default_output_file = "trace";
static char *output_file;

static bool use_vsock;

static int backlog = 5;

static int do_daemon;

/* Used for signaling INT to finish */
static struct tracecmd_msg_handle *stop_msg_handle;
static bool done;

#define pdie(fmt, ...)					\
	do {						\
		tracecmd_plog_error(fmt, ##__VA_ARGS__);\
		remove_pid_file();			\
		exit(-1);				\
	} while (0)

#define  TEMP_FILE_STR "%s.%s:%s.cpu%d", output_file, host, port, cpu
static char *get_temp_file(const char *host, const char *port, int cpu)
{
	char *file = NULL;
	int size;

	size = snprintf(file, 0, TEMP_FILE_STR);
	file = malloc(size + 1);
	if (!file)
		return NULL;
	sprintf(file, TEMP_FILE_STR);

	return file;
}

static void put_temp_file(char *file)
{
	free(file);
}

static void signal_setup(int sig, sighandler_t handle)
{
	struct sigaction action;

	sigaction(sig, NULL, &action);
	/* Make accept return EINTR */
	action.sa_flags &= ~SA_RESTART;
	action.sa_handler = handle;
	sigaction(sig, &action, NULL);
}

static void delete_temp_file(const char *host, const char *port, int cpu)
{
	char file[PATH_MAX];

	snprintf(file, PATH_MAX, TEMP_FILE_STR);
	unlink(file);
}

static int read_string(int fd, char *buf, size_t size)
{
	size_t i;
	int n;

	for (i = 0; i < size; i++) {
		n = read(fd, buf+i, 1);
		if (!buf[i] || n <= 0)
			break;
	}

	return i;
}

static int process_option(struct tracecmd_msg_handle *msg_handle, char *option)
{
	/* currently the only option we have is to us TCP */
	if (strcmp(option, "TCP") == 0) {
		msg_handle->flags |= TRACECMD_MSG_FL_USE_TCP;
		return 1;
	}
	return 0;
}

static void finish(int sig)
{
	if (stop_msg_handle)
		tracecmd_msg_set_done(stop_msg_handle);
	done = true;
}

static void make_pid_name(int mode, char *buf)
{
	snprintf(buf, PATH_MAX, VAR_RUN_DIR "/trace-cmd-net.pid");
}

static void remove_pid_file(void)
{
	char buf[PATH_MAX];
	int mode = do_daemon;

	if (!do_daemon)
		return;

	make_pid_name(mode, buf);

	unlink(buf);
}

static int process_child(int sfd, const char *host, const char *port,
			 int cpu, int page_size, enum port_type type)
{
	struct sockaddr_storage peer_addr;
#ifdef VSOCK
	struct sockaddr_vm vm_addr;
#endif
	struct sockaddr *addr;
	socklen_t addr_len;
	char buf[page_size];
	char *tempfile;
	int left;
	int cfd;
	int fd;
	int r, w;
	int once = 0;

	signal_setup(SIGUSR1, finish);

	tempfile = get_temp_file(host, port, cpu);
	if (!tempfile)
		return -ENOMEM;

	fd = open(tempfile, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if (fd < 0)
		pdie("creating %s", tempfile);

	if (type == USE_TCP) {
		addr = (struct sockaddr *)&peer_addr;
		addr_len = sizeof(peer_addr);
#ifdef VSOCK
	} else if (type == USE_VSOCK) {
		addr = (struct sockaddr *)&vm_addr;
		addr_len = sizeof(vm_addr);
#endif
	}

	if (type == USE_TCP || type == USE_VSOCK) {
		if (listen(sfd, backlog) < 0)
			pdie("listen");

		cfd = accept(sfd, addr, &addr_len);
		if (cfd < 0 && errno == EINTR)
			goto done;
		if (cfd < 0)
			pdie("accept");
		close(sfd);
		sfd = cfd;
	}

	for (;;) {
		/* TODO, make this copyless! */
		r = read(sfd, buf, page_size);
		if (r < 0) {
			if (errno == EINTR)
				break;
			pdie("reading pages from client");
		}
		if (!r)
			break;
		/* UDP requires that we get the full size in one go */
		if (type == USE_UDP && r < page_size && !once) {
			once = 1;
			warning("read %d bytes, expected %d", r, page_size);
		}

		left = r;
		do {
			w = write(fd, buf + (r - left), left);
			if (w > 0)
				left -= w;
		} while (w >= 0 && left);
	}

 done:
	put_temp_file(tempfile);
	exit(0);
}

static int setup_vsock_port(int start_port, int *sfd)
{
	int sd;

	sd = trace_vsock_make(start_port);
	if (sd < 0)
		return -errno;
	*sfd = sd;

	return start_port;
}

int trace_net_make(int port, enum port_type type)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	char buf[BUFSIZ];
	int sd;
	int s;

	snprintf(buf, BUFSIZ, "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_PASSIVE;

	switch (type) {
	case USE_TCP:
		hints.ai_socktype = SOCK_STREAM;
		break;
	case USE_UDP:
		hints.ai_socktype = SOCK_DGRAM;
		break;
	default:
		return -1;
	}

	s = getaddrinfo(NULL, buf, &hints, &result);
	if (s != 0)
		pdie("getaddrinfo: error opening socket");

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sd = socket(rp->ai_family, rp->ai_socktype,
			    rp->ai_protocol);
		if (sd < 0)
			continue;

		if (bind(sd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;

		close(sd);
	}
	freeaddrinfo(result);

	if (rp == NULL)
		return -1;

	dprint("Create listen port: %d fd:%d\n", port, sd);

	return sd;
}

int trace_net_search(int start_port, int *sfd, enum port_type type)
{
	int num_port = start_port;

	if (type == USE_VSOCK)
		return setup_vsock_port(start_port, sfd);
 again:
	*sfd = trace_net_make(num_port, type);
	if (*sfd < 0) {
		if (++num_port > MAX_PORT_SEARCH)
			pdie("No available ports to bind");
		goto again;
	}

	return num_port;
}

static void fork_reader(int sfd, const char *node, const char *port,
			int *pid, int cpu, int pagesize, enum port_type type)
{
	int ret;

	*pid = fork();

	if (*pid < 0)
		pdie("creating reader");

	if (!*pid) {
		ret = process_child(sfd, node, port, cpu, pagesize, type);
		if (ret < 0)
			pdie("Problem with reader %d", ret);
	}

	close(sfd);
}

static int open_port(const char *node, const char *port, int *pid,
		     int cpu, int pagesize, int start_port, enum port_type type)
{
	int sfd;
	int num_port;

	/*
	 * trace_net_search() currently does not return an error, but if that
	 * changes in the future, we have a check for it now.
	 */
	num_port = trace_net_search(start_port, &sfd, type);
	if (num_port < 0)
		return num_port;

	fork_reader(sfd, node, port, pid, cpu, pagesize, type);

	return num_port;
}

static int communicate_with_client(struct tracecmd_msg_handle *msg_handle)
{
	char *last_proto = NULL;
	char buf[BUFSIZ];
	char *option;
	int pagesize = 0;
	int options;
	int size;
	int cpus;
	int n, s, t, i;
	int ret = -EINVAL;
	int fd = msg_handle->fd;

	/* Let the client know what we are */
	write(fd, "tracecmd", 8);

 try_again:
	/* read back the CPU count */
	n = read_string(fd, buf, BUFSIZ);
	if (n == BUFSIZ)
		/** ERROR **/
		return -EINVAL;

	cpus = atoi(buf);

	/* Is the client using the new protocol? */
	if (cpus == -1) {
		if (memcmp(buf, V3_CPU, n) != 0) {
			/* If it did not send a version, then bail */
			if (memcmp(buf, "-1V", 3)) {
				tracecmd_plog("Unknown string %s\n", buf);
				goto out;
			}
			/* Skip "-1" */
			tracecmd_plog("Cannot handle the protocol %s\n", buf+2);

			/* If it returned the same command as last time, bail! */
			if (last_proto && strncmp(last_proto, buf, n) == 0) {
				tracecmd_plog("Repeat of version %s sent\n", last_proto);
				goto out;
			}
			free(last_proto);
			last_proto = malloc(n + 1);
			if (last_proto) {
				memcpy(last_proto, buf, n);
				last_proto[n] = 0;
			}
			/* Return the highest protocol we can use */
			write(fd, "V3", 3);
			goto try_again;
		}

		/* Let the client know we use v3 protocol */
		write(fd, "V3", 3);

		/* read the rest of dummy data */
		n = read(fd, buf, sizeof(V3_MAGIC));
		if (memcmp(buf, V3_MAGIC, n) != 0)
			goto out;

		/* We're off! */
		write(fd, "OK", 2);

		msg_handle->version = V3_PROTOCOL;

		/* read the CPU count, the page size, and options */
		if ((pagesize = tracecmd_msg_initial_setting(msg_handle)) < 0)
			goto out;
	} else {
		/* The client is using the v1 protocol */

		tracecmd_plog("cpus=%d\n", cpus);
		if (cpus < 0)
			goto out;

		msg_handle->cpu_count = cpus;

		/* next read the page size */
		n = read_string(fd, buf, BUFSIZ);
		if (n == BUFSIZ)
			/** ERROR **/
			goto out;

		pagesize = atoi(buf);

		tracecmd_plog("pagesize=%d\n", pagesize);
		if (pagesize <= 0)
			goto out;

		/* Now the number of options */
		n = read_string(fd, buf, BUFSIZ);
 		if (n == BUFSIZ)
			/** ERROR **/
			return -EINVAL;

		options = atoi(buf);

		for (i = 0; i < options; i++) {
			/* next is the size of the options */
			n = read_string(fd, buf, BUFSIZ);
			if (n == BUFSIZ)
				/** ERROR **/
				goto out;
			size = atoi(buf);
			/* prevent a client from killing us */
			if (size > MAX_OPTION_SIZE)
				goto out;

			ret = -ENOMEM;
			option = malloc(size);
			if (!option)
				goto out;

			ret = -EIO;
			do {
				t = size;
				s = 0;
				s = read(fd, option+s, t);
				if (s <= 0)
					goto out;
				t -= s;
				s = size - t;
			} while (t);

			s = process_option(msg_handle, option);
			free(option);
			/* do we understand this option? */
			ret = -EINVAL;
			if (!s)
				goto out;
		}
	}

	if (msg_handle->flags & TRACECMD_MSG_FL_USE_TCP)
		tracecmd_plog("Using TCP for live connection\n");

	ret = pagesize;
 out:
	free(last_proto);

	return ret;
}

static int create_client_file(const char *node, const char *port)
{
	char buf[BUFSIZ];
	int ofd;

	snprintf(buf, BUFSIZ, "%s.%s:%s.dat", output_file, node, port);

	ofd = open(buf, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (ofd < 0)
		pdie("Can not create file %s", buf);
	return ofd;
}

static void destroy_all_readers(int cpus, int *pid_array, const char *node,
				const char *port)
{
	int cpu;

	for (cpu = 0; cpu < cpus; cpu++) {
		if (pid_array[cpu] > 0) {
			kill(pid_array[cpu], SIGKILL);
			waitpid(pid_array[cpu], NULL, 0);
			delete_temp_file(node, port, cpu);
			pid_array[cpu] = 0;
		}
	}

	free(pid_array);
}

static int *create_all_readers(const char *node, const char *port,
			       int pagesize, struct tracecmd_msg_handle *msg_handle)
{
	enum port_type port_type = USE_UDP;
	char buf[BUFSIZ];
	unsigned int *port_array;
	int *pid_array;
	unsigned int start_port;
	unsigned int connect_port;
	int cpus = msg_handle->cpu_count;
	int cpu;
	int pid;

	if (!pagesize)
		return NULL;

	if (msg_handle->flags & TRACECMD_MSG_FL_USE_TCP)
		port_type = USE_TCP;
	else if (msg_handle->flags & TRACECMD_MSG_FL_USE_VSOCK)
		port_type = USE_VSOCK;

	port_array = malloc(sizeof(*port_array) * cpus);
	if (!port_array)
		return NULL;

	pid_array = malloc(sizeof(*pid_array) * cpus);
	if (!pid_array) {
		free(port_array);
		return NULL;
	}

	memset(pid_array, 0, sizeof(int) * cpus);

	start_port = START_PORT_SEARCH;

	/* Now create a port for each CPU */
	for (cpu = 0; cpu < cpus; cpu++) {
		connect_port = open_port(node, port, &pid, cpu,
					 pagesize, start_port, port_type);
		if (connect_port < 0)
			goto out_free;
		port_array[cpu] = connect_port;
		pid_array[cpu] = pid;
		/*
		 * Due to some bugging finding ports,
		 * force search after last port
		 */
		start_port = connect_port + 1;
	}

	if (msg_handle->version == V3_PROTOCOL) {
		/* send set of port numbers to the client */
		if (tracecmd_msg_send_port_array(msg_handle, port_array) < 0) {
			tracecmd_plog("Failed sending port array\n");
			goto out_free;
		}
	} else {
		/* send the client a comma deliminated set of port numbers */
		for (cpu = 0; cpu < cpus; cpu++) {
			snprintf(buf, BUFSIZ, "%s%d",
				 cpu ? "," : "", port_array[cpu]);
			write(msg_handle->fd, buf, strlen(buf));
		}
		/* end with null terminator */
		write(msg_handle->fd, "\0", 1);
	}

	free(port_array);
	return pid_array;

 out_free:
	free(port_array);
	destroy_all_readers(cpus, pid_array, node, port);
	return NULL;
}

static int
collect_metadata_from_client(struct tracecmd_msg_handle *msg_handle,
			     int ofd)
{
	char buf[BUFSIZ];
	int n, s, t;
	int ifd = msg_handle->fd;
	int ret = 0;

	do {
		n = read(ifd, buf, BUFSIZ);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			ret = -errno;
			break;
		}
		t = n;
		s = 0;
		do {
			s = write(ofd, buf+s, t);
			if (s < 0) {
				if (errno == EINTR)
					break;
				ret = -errno;
				goto out;
			}
			t -= s;
			s = n - t;
		} while (t);
	} while (n > 0 && !tracecmd_msg_done(msg_handle));

out:
	return ret;
}

static void stop_all_readers(int cpus, int *pid_array)
{
	int cpu;

	for (cpu = 0; cpu < cpus; cpu++) {
		if (pid_array[cpu] > 0)
			kill(pid_array[cpu], SIGUSR1);
	}
}

static int put_together_file(int cpus, int ofd, const char *node,
			     const char *port, bool write_options)
{
	struct tracecmd_output *handle = NULL;
	char **temp_files;
	int cpu;
	int ret = -ENOMEM;

	/* Now put together the file */
	temp_files = malloc(sizeof(*temp_files) * cpus);
	if (!temp_files)
		return -ENOMEM;

	for (cpu = 0; cpu < cpus; cpu++) {
		temp_files[cpu] = get_temp_file(node, port, cpu);
		if (!temp_files[cpu])
			goto out;
	}

	handle = tracecmd_get_output_handle_fd(ofd);
	if (!handle) {
		ret = -1;
		goto out;
	}

	if (write_options) {
		ret = tracecmd_write_cpus(handle, cpus);
		if (ret)
			goto out;
		ret = tracecmd_write_buffer_info(handle);
		if (ret)
			goto out;
		ret = tracecmd_write_options(handle);
		if (ret)
			goto out;
	}
	ret = tracecmd_write_cpu_data(handle, cpus, temp_files, NULL);

out:
	tracecmd_output_close(handle);
	for (cpu--; cpu >= 0; cpu--) {
		put_temp_file(temp_files[cpu]);
	}
	free(temp_files);
	return ret;
}

static int process_client(struct tracecmd_msg_handle *msg_handle,
			  const char *node, const char *port)
{
	int *pid_array;
	int pagesize;
	int cpus;
	int ofd;
	int ret;

	pagesize = communicate_with_client(msg_handle);
	if (pagesize < 0)
		return pagesize;

	ofd = create_client_file(node, port);

	pid_array = create_all_readers(node, port, pagesize, msg_handle);
	if (!pid_array)
		return -ENOMEM;

	/* on signal stop this msg */
	stop_msg_handle = msg_handle;

	/* Now we are ready to start reading data from the client */
	if (msg_handle->version == V3_PROTOCOL)
		ret = tracecmd_msg_collect_data(msg_handle, ofd);
	else
		ret = collect_metadata_from_client(msg_handle, ofd);
	stop_msg_handle = NULL;

	/* wait a little to let our readers finish reading */
	sleep(1);

	cpus = msg_handle->cpu_count;

	/* stop our readers */
	stop_all_readers(cpus, pid_array);

	/* wait a little to have the readers clean up */
	sleep(1);

	if (!ret)
		ret = put_together_file(cpus, ofd, node, port,
					msg_handle->version < V3_PROTOCOL);

	destroy_all_readers(cpus, pid_array, node, port);

	return ret;
}

static int do_fork(int cfd)
{
	pid_t pid;

	/* in debug mode, we do not fork off children */
	if (tracecmd_get_debug())
		return 0;

	pid = fork();
	if (pid < 0) {
		warning("failed to create child");
		return -1;
	}

	if (pid > 0) {
		close(cfd);
		return pid;
	}

	signal_setup(SIGINT, finish);

	return 0;
}

bool trace_net_cmp_connection(struct sockaddr_storage *addr, const char *name)
{
	char host[NI_MAXHOST], nhost[NI_MAXHOST];
	char service[NI_MAXSERV];
	socklen_t addr_len = sizeof(*addr);
	struct addrinfo *result, *rp;
	struct addrinfo hints;
	bool found = false;
	int s;

	if (getnameinfo((struct sockaddr *)addr, addr_len,
			host, NI_MAXHOST,
			service, NI_MAXSERV, NI_NUMERICSERV))
		return -1;

	if (strcmp(host, name) == 0)
		return true;

	/* Check other IPs that name could be for */

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	/* Check other IPs that name could be for */
	s = getaddrinfo(name, NULL, &hints, &result);
	if (s != 0)
		return false;

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		if (getnameinfo(rp->ai_addr, rp->ai_addrlen,
				nhost, NI_MAXHOST,
				service, NI_MAXSERV, NI_NUMERICSERV))
			continue;
		if (strcmp(host, nhost) == 0) {
			found = 1;
			break;
		}
	}

	freeaddrinfo(result);
	return found;
}

bool trace_net_cmp_connection_fd(int fd, const char *name)
{
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);

	if (getpeername(fd, (struct sockaddr *)&addr, &addr_len))
		return false;

	return trace_net_cmp_connection(&addr, name);
};

int trace_net_print_connection(int fd)
{
	char host[NI_MAXHOST], service[NI_MAXSERV];
	struct sockaddr_storage net_addr;
	socklen_t addr_len;

	addr_len = sizeof(net_addr);
	if (getpeername(fd, (struct sockaddr *)&net_addr, &addr_len))
		return -1;

	if (getnameinfo((struct sockaddr *)&net_addr, addr_len,
			host, NI_MAXHOST,
			service, NI_MAXSERV, NI_NUMERICSERV))
		return -1;

	if (tracecmd_get_debug())
		tracecmd_debug("Connected to %s:%s fd:%d\n", host, service, fd);
	else
		tracecmd_plog("Connected to %s:%s\n", host, service);
	return 0;
}

static int do_connection(int cfd, struct sockaddr *addr,
			  socklen_t addr_len)
{
	struct tracecmd_msg_handle *msg_handle;
	char host[NI_MAXHOST], service[NI_MAXSERV];
	int s;
	int ret;

	ret = do_fork(cfd);
	if (ret)
		return ret;

	msg_handle = tracecmd_msg_handle_alloc(cfd, 0);

	if (use_vsock) {
#ifdef VSOCK
		struct sockaddr_vm *vm_addr = (struct sockaddr_vm *)addr;
		snprintf(host, NI_MAXHOST, "V%d", vm_addr->svm_cid);
		snprintf(service, NI_MAXSERV, "%d", vm_addr->svm_port);
#endif
	} else {
		s = getnameinfo((struct sockaddr *)addr, addr_len,
				host, NI_MAXHOST,
				service, NI_MAXSERV, NI_NUMERICSERV);

		if (s == 0)
			tracecmd_plog("Connected with %s:%s\n", host, service);
		else {
			tracecmd_plog("Error with getnameinfo: %s\n", gai_strerror(s));
			close(cfd);
			tracecmd_msg_handle_close(msg_handle);
			return -1;
		}
	}

	process_client(msg_handle, host, service);

	tracecmd_msg_handle_close(msg_handle);

	if (!tracecmd_get_debug())
		exit(0);

	return 0;
}

static int *client_pids;
static int free_pids;
static int saved_pids;

static void add_process(int pid)
{
	int *client = NULL;
	int i;

	if (free_pids) {
		for (i = 0; i < saved_pids; i++) {
			if (!client_pids[i]) {
				client = &client_pids[i];
				break;
			}
		}
		free_pids--;
		if (!client)
			warning("Could not find free pid");
	}
	if (!client) {
		client_pids = realloc(client_pids,
				      sizeof(*client_pids) * (saved_pids + 1));
		if (!client_pids)
			pdie("allocating pids");
		client = &client_pids[saved_pids++];
	}
	*client = pid;
}

static void remove_process(int pid)
{
	int i;

	for (i = 0; i < saved_pids; i++) {
		if (client_pids[i] == pid)
			break;
	}

	if (i == saved_pids)
		return;

	client_pids[i] = 0;
	free_pids++;
}

static void kill_clients(void)
{
	int status;
	int i;

	for (i = 0; i < saved_pids; i++) {
		if (!client_pids[i])
			continue;
		/* Only kill the clients if we received SIGINT or SIGTERM */
		if (done)
			kill(client_pids[i], SIGINT);
		waitpid(client_pids[i], &status, 0);
	}

	saved_pids = 0;
}

static void clean_up(void)
{
	int status;
	int ret;

	/* Clean up any children that has started before */
	do {
		ret = waitpid(0, &status, WNOHANG);
		if (ret > 0)
			remove_process(ret);
	} while (ret > 0);
}

static void do_accept_loop(int sfd)
{
	struct sockaddr_storage peer_addr;
#ifdef VSOCK
	struct sockaddr_vm vm_addr;
#endif
	struct sockaddr *addr;
	socklen_t addr_len;
	int cfd, pid;

	if (use_vsock) {
#ifdef VSOCK
		addr = (struct sockaddr *)&vm_addr;
		addr_len = sizeof(vm_addr);
#endif
	} else {
		addr = (struct sockaddr *)&peer_addr;
		addr_len = sizeof(peer_addr);
	}

	do {
		cfd = accept(sfd, addr, &addr_len);
		if (cfd < 0 && errno == EINTR) {
			clean_up();
			continue;
		}
		if (cfd < 0)
			pdie("connecting");

		pid = do_connection(cfd, addr, addr_len);
		if (pid > 0)
			add_process(pid);

	} while (!done);
	/* Get any final stragglers */
	clean_up();
}

static void make_pid_file(void)
{
	char buf[PATH_MAX];
	int mode = do_daemon;
	int fd;

	if (!do_daemon)
		return;

	make_pid_name(mode, buf);

	fd = open(buf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror(buf);
		return;
	}

	sprintf(buf, "%d\n", getpid());
	write(fd, buf, strlen(buf));
	close(fd);
}

static void sigstub(int sig)
{
}

static int get_vsock(const char *port)
{
	unsigned int cid;
	int sd;

	sd = trace_vsock_make(atoi(port));
	if (sd < 0)
		return sd;

	cid = trace_vsock_local_cid();
	if (cid >= 0)
		printf("listening on @%u:%s\n", cid, port);

	return sd;
}

static int get_network(char *port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	s = getaddrinfo(NULL, port, &hints, &result);
	if (s != 0)
		pdie("getaddrinfo: error opening %s", port);

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype,
			     rp->ai_protocol);
		if (sfd < 0)
			continue;

		if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;

		close(sfd);
	}

	if (rp == NULL)
		pdie("Could not bind");

	freeaddrinfo(result);

	return sfd;
}

static void do_listen(char *port)
{
	int sfd;

	if (!tracecmd_get_debug())
		signal_setup(SIGCHLD, sigstub);

	make_pid_file();

	if (use_vsock)
		sfd = get_vsock(port);
	else
		sfd = get_network(port);


	if (listen(sfd, backlog) < 0)
		pdie("listen");

	do_accept_loop(sfd);

	kill_clients();

	remove_pid_file();
}

static void start_daemon(void)
{
	do_daemon = 1;

	if (daemon(1, 0) < 0)
		die("starting daemon");
}

enum {
	OPT_verbose	= 254,
	OPT_debug	= 255,
};

void trace_listen(int argc, char **argv)
{
	char *logfile = NULL;
	char *port = NULL;
	int daemon = 0;
	int c;

	if (argc < 2)
		usage(argv);

	if (strcmp(argv[1], "listen") != 0)
		usage(argv);

	for (;;) {
		int option_index = 0;
		static struct option long_options[] = {
			{"port", required_argument, NULL, 'p'},
			{"help", no_argument, NULL, '?'},
			{"debug", no_argument, NULL, OPT_debug},
			{"verbose", optional_argument, NULL, OPT_verbose},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc-1, argv+1, "+hp:Vo:d:l:D",
			long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'p':
			port = optarg;
			break;
		case 'd':
			output_dir = optarg;
			break;
		case 'V':
			use_vsock = true;
			break;
		case 'o':
			output_file = optarg;
			break;
		case 'l':
			logfile = optarg;
			break;
		case 'D':
			daemon = 1;
			break;
		case OPT_debug:
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

	if (!port)
		usage(argv);

	if ((argc - optind) >= 2)
		usage(argv);

	if (!output_file)
		output_file = default_output_file;

	if (!output_dir)
		output_dir = default_output_dir;

	if (logfile) {
		/* set the writes to a logfile instead */
		if (tracecmd_set_logfile(logfile) < 0)
			die("creating log file %s", logfile);
	}

	if (chdir(output_dir) < 0)
		die("Can't access directory %s", output_dir);

	if (daemon)
		start_daemon();

	signal_setup(SIGINT, finish);
	signal_setup(SIGTERM, finish);

	do_listen(port);

	return;
}
