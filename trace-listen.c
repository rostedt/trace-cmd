/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#define _LARGEFILE64_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#include "trace-local.h"

#define MAX_OPTION_SIZE 4096

static char *default_output_dir = ".";
static char *output_dir;
static char *default_output_file = "trace";
static char *output_file;

static FILE *logfp;

static int debug;

static int use_tcp;

static int backlog = 5;

#define  TEMP_FILE_STR "%s.%s:%s.cpu%d", output_file, host, port, cpu
static char *get_temp_file(const char *host, const char *port, int cpu)
{
	char *file = NULL;
	int size;

	size = snprintf(file, 0, TEMP_FILE_STR);
	file = malloc_or_die(size + 1);
	sprintf(file, TEMP_FILE_STR);

	return file;
}

static void put_temp_file(char *file)
{
	free(file);
}

#define MAX_PATH 1024

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
	char file[MAX_PATH];

	snprintf(file, MAX_PATH, TEMP_FILE_STR);
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

static int process_option(char *option)
{
	/* currently the only option we have is to us TCP */
	if (strcmp(option, "TCP") == 0) {
		use_tcp = 1;
		return 1;
	}
	return 0;
}

static int done;
static void finish(int sig)
{
	done = 1;
}

#define LOG_BUF_SIZE 1024
static void __plog(const char *prefix, const char *fmt, va_list ap,
		   FILE *fp)
{
	static int newline = 1;
	char buf[LOG_BUF_SIZE];
	int r;

	r = vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);

	if (r > LOG_BUF_SIZE)
		r = LOG_BUF_SIZE;

	if (logfp) {
		if (newline)
			fprintf(logfp, "[%d]%s%.*s", getpid(), prefix, r, buf);
		else
			fprintf(logfp, "[%d]%s%.*s", getpid(), prefix, r, buf);
		newline = buf[r - 1] == '\n';
		fflush(logfp);
		return;
	}

	fprintf(fp, "%.*s", r, buf);
}

static void plog(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__plog("", fmt, ap, stdout);
	va_end(ap);
}

static void pdie(const char *fmt, ...)
{
	va_list ap;
	char *str = "";

	va_start(ap, fmt);
	__plog("Error: ", fmt, ap, stderr);
	va_end(ap);
	if (errno)
		str = strerror(errno);
	if (logfp)
		fprintf(logfp, "\n%s\n", str);
	else
		fprintf(stderr, "\n%s\n", str);
	exit(-1);
}

static void process_udp_child(int sfd, const char *host, const char *port,
			      int cpu, int page_size)
{
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	char buf[page_size];
	char *tempfile;
	int cfd;
	int fd;
	int n;
	int once = 0;

	signal_setup(SIGUSR1, finish);

	tempfile = get_temp_file(host, port, cpu);
	fd = open(tempfile, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if (fd < 0)
		pdie("creating %s", tempfile);

	if (use_tcp) {
		if (listen(sfd, backlog) < 0)
			pdie("listen");
		peer_addr_len = sizeof(peer_addr);
		cfd = accept(sfd, (struct sockaddr *)&peer_addr, &peer_addr_len);
		if (cfd < 0 && errno == EINTR)
			goto done;
		if (cfd < 0)
			pdie("accept");
		close(sfd);
		sfd = cfd;
	}

	do {
		/* TODO, make this copyless! */
		n = read(sfd, buf, page_size);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			pdie("reading client");
		}
		if (!n)
			break;
		/* UDP requires that we get the full size in one go */
		if (!use_tcp && n < page_size && !once) {
			once = 1;
			warning("read %d bytes, expected %d", n, page_size);
		}
		write(fd, buf, n);
	} while (!done);

 done:
	put_temp_file(tempfile);
	exit(0);
}

#define START_PORT_SEARCH 1500
#define MAX_PORT_SEARCH 6000

static int open_udp(const char *node, const char *port, int *pid,
		    int cpu, int pagesize, int start_port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s;
	char buf[BUFSIZ];
	int num_port = start_port;

 again:
	snprintf(buf, BUFSIZ, "%d", num_port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = use_tcp ? SOCK_STREAM : SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	s = getaddrinfo(NULL, buf, &hints, &result);
	if (s != 0)
		pdie("getaddrinfo: error opening udp socket");

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype,
			     rp->ai_protocol);
		if (sfd < 0)
			continue;

		if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;

		close(sfd);
	}

	if (rp == NULL) {
		freeaddrinfo(result);
		if (++num_port > MAX_PORT_SEARCH)
			pdie("No available ports to bind");
		goto again;
	}

	freeaddrinfo(result);

	*pid = fork();

	if (*pid < 0)
		pdie("creating udp reader");

	if (!*pid)
		process_udp_child(sfd, node, port, cpu, pagesize);

	close(sfd);

	return num_port;
}

static void process_client(const char *node, const char *port, int fd)
{
	char **temp_files;
	char buf[BUFSIZ];
	char *option;
	int *port_array;
	int *pid_array;
	int pagesize;
	int start_port;
	int udp_port;
	int options;
	int size;
	int cpus;
	int cpu;
	int pid;
	int ofd;
	int n, s, t, i;

	/* Let the client know what we are */
	write(fd, "tracecmd", 8);

	/* read back the CPU count */
	n = read_string(fd, buf, BUFSIZ);
	if (n == BUFSIZ)
		/** ERROR **/
		return;

	cpus = atoi(buf);

	plog("cpus=%d\n", cpus);
	if (cpus < 0)
		return;

	/* next read the page size */
	n = read_string(fd, buf, BUFSIZ);
	if (n == BUFSIZ)
		/** ERROR **/
		return;

	pagesize = atoi(buf);

	plog("pagesize=%d\n", pagesize);
	if (pagesize <= 0)
		return;

	/* Now the number of options */
	n = read_string(fd, buf, BUFSIZ);
	if (n == BUFSIZ)
		/** ERROR **/
		return;

	options = atoi(buf);

	for (i = 0; i < options; i++) {
		/* next is the size of the options */
		n = read_string(fd, buf, BUFSIZ);
		if (n == BUFSIZ)
			/** ERROR **/
			return;
		size = atoi(buf);
		/* prevent a client from killing us */
		if (size > MAX_OPTION_SIZE)
			return;
		option = malloc_or_die(size);
		do {
			t = size;
			s = 0;
			s = read(fd, option+s, t);
			if (s <= 0)
				return;
			t -= s;
			s = size - t;
		} while (t);

		s = process_option(option);
		free(option);
		/* do we understand this option? */
		if (!s)
			return;
	}

	if (use_tcp)
		plog("Using TCP for live connection\n");

	/* Create the client file */
	snprintf(buf, BUFSIZ, "%s.%s:%s.dat", output_file, node, port);

	ofd = open(buf, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (ofd < 0)
		pdie("Can not create file %s", buf);

	port_array = malloc_or_die(sizeof(int) * cpus);
	pid_array = malloc_or_die(sizeof(int) * cpus);
	memset(pid_array, 0, sizeof(int) * cpus);

	start_port = START_PORT_SEARCH;

	/* Now create a UDP port for each CPU */
	for (cpu = 0; cpu < cpus; cpu++) {
		udp_port = open_udp(node, port, &pid, cpu, pagesize, start_port);
		if (udp_port < 0)
			goto out_free;
		port_array[cpu] = udp_port;
		pid_array[cpu] = pid;
		/* due to some bugging finding ports, force search after last port */
		start_port = udp_port+1;
	}

	/* send the client a comma deliminated set of port numbers */
	for (cpu = 0; cpu < cpus; cpu++) {
		snprintf(buf, BUFSIZ, "%s%d",
			 cpu ? "," : "", port_array[cpu]);
		write(fd, buf, strlen(buf));
	}
	/* end with null terminator */
	write(fd, "\0", 1);

	/* Now we are ready to start reading data from the client */
	do {
		n = read(fd, buf, BUFSIZ);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			pdie("reading client");
		}
		t = n;
		s = 0;
		do {
			s = write(ofd, buf+s, t);
			if (s < 0) {
				if (errno == EINTR)
					break;
				pdie("writing to file");
			}
			t -= s;
			s = n - t;
		} while (t);
	} while (n > 0 && !done);

	/* wait a little to let our readers finish reading */
	sleep(1);

	/* stop our readers */
	for (cpu = 0; cpu < cpus; cpu++) {
		if (pid_array[cpu] > 0)
			kill(pid_array[cpu], SIGUSR1);
	}

	/* wait a little to have the readers clean up */
	sleep(1);

	/* Now put together the file */
	temp_files = malloc_or_die(sizeof(*temp_files) * cpus);

	for (cpu = 0; cpu < cpus; cpu++)
		temp_files[cpu] = get_temp_file(node, port, cpu);

	tracecmd_attach_cpu_data_fd(ofd, cpus, temp_files);

 out_free:
	for (cpu = 0; cpu < cpus; cpu++) {
		if (pid_array[cpu] > 0) {
			kill(pid_array[cpu], SIGKILL);
			delete_temp_file(node, port, cpu);
			pid_array[cpu] = 0;
		}
	}
}

static int do_fork(int cfd)
{
	pid_t pid;

	/* in debug mode, we do not fork off children */
	if (debug)
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

static int do_connection(int cfd, struct sockaddr_storage *peer_addr,
			  socklen_t peer_addr_len)
{
	char host[NI_MAXHOST], service[NI_MAXSERV];
	int s;
	int ret;

	ret = do_fork(cfd);
	if (ret)
		return ret;

	s = getnameinfo((struct sockaddr *)peer_addr, peer_addr_len,
			host, NI_MAXHOST,
			service, NI_MAXSERV, NI_NUMERICSERV);

	if (s == 0)
		plog("Connected with %s:%s\n",
		       host, service);
	else {
		plog("Error with getnameinfo: %s\n",
		       gai_strerror(s));
		close(cfd);
		return -1;
	}

	process_client(host, service, cfd);

	close(cfd);

	if (!debug)
		exit(0);

	return 0;
}

static int *client_pids;
static int saved_pids;
static int size_pids;
#define PIDS_BLOCK 32

static void add_process(int pid)
{
	if (!client_pids) {
		size_pids = PIDS_BLOCK;
		client_pids = malloc_or_die(sizeof(*client_pids) * size_pids);
	} else if (!(saved_pids % PIDS_BLOCK)) {
		size_pids += PIDS_BLOCK;
		client_pids = realloc(client_pids,
				      sizeof(*client_pids) * size_pids);
		if (!client_pids)
			pdie("realloc of pids");
	}
	client_pids[saved_pids++] = pid;
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

	saved_pids--;

	if (saved_pids == i)
		return;

	memmove(&client_pids[i], &client_pids[i+1],
		sizeof(*client_pids) * (saved_pids - i));

}

static void kill_clients(void)
{
	int status;
	int i;

	for (i = 0; i < saved_pids; i++) {
		kill(client_pids[i], SIGINT);
		waitpid(client_pids[i], &status, 0);
	}

	saved_pids = 0;
}

static void clean_up(int sig)
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

static void do_listen(char *port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s, cfd;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	int pid;

	if (!debug)
		signal_setup(SIGCHLD, clean_up);

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

	if (listen(sfd, backlog) < 0)
		pdie("listen");

	peer_addr_len = sizeof(peer_addr);

	do {
		cfd = accept(sfd, (struct sockaddr *)&peer_addr, &peer_addr_len);
		printf("connected!\n");
		if (cfd < 0 && errno == EINTR)
			continue;
		if (cfd < 0)
			pdie("connecting");

		pid = do_connection(cfd, &peer_addr, peer_addr_len);
		if (pid > 0)
			add_process(pid);

	} while (!done);

	kill_clients();
}

static void start_daemon(void)
{
	if (daemon(1, 0) < 0)
		die("starting daemon");
}

enum {
	OPT_debug	= 255,
};

void trace_listen(int argc, char **argv)
{
	char *logfile = NULL;
	char *port = NULL;
	char *iface;
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
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc-1, argv+1, "+hp:o:d:i:l:D",
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
		case 'i':
			iface = optarg;
			break;
		case 'd':
			output_dir = optarg;
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
			debug = 1;
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
		logfp = fopen(logfile, "w");
		if (!logfp)
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
