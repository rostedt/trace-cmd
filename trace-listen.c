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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#include "trace-local.h"

static char *default_output_dir = ".";
static char *output_dir;
static char *default_output_file = "trace";
static char *output_file;

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

static int done;
static void finish(int sig)
{
	done = 1;
}

static void process_udp_child(int sfd, const char *host, const char *port,
			      int cpu, int page_size)
{
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	char buf[page_size];
	char *tempfile;
	int fd;
	int n;
	int once = 0;

	signal(SIGUSR1, finish);

	tempfile = get_temp_file(host, port, cpu);
	fd = open(tempfile, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if (fd < 0)
		die("creating %s", tempfile);

	do {
		peer_addr_len = sizeof(peer_addr);
		/* TODO, make this copyless! */
		n = read(sfd, buf, page_size);
		if (!n)
			break;
		if (n < page_size && !once) {
			once = 1;
			warning("read %d bytes, expected %d", n, page_size);
		}
		write(fd, buf, n);
	} while (!done);

	put_temp_file(tempfile);
	exit(0);
}

#define START_PORT_SEARCH 1500
#define MAX_PORT_SEARCH 6000

static int open_udp(const char *node, const char *port, int *pid,
		    int cpu, int pagesize)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s;
	char buf[BUFSIZ];
	int num_port = START_PORT_SEARCH;

 again:
	snprintf(buf, BUFSIZ, "%d", num_port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	s = getaddrinfo(NULL, buf, &hints, &result);
	if (s != 0)
		die("getaddrinfo: error opening udp socket");

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
			die("No available ports to bind");
		goto again;
	}

	freeaddrinfo(result);

	*pid = fork();

	if (*pid < 0)
		die("creating udp reader");

	if (!*pid)
		process_udp_child(sfd, node, port, cpu, pagesize);

	close(sfd);

	return num_port;
}

static void process_client(const char *node, const char *port, int fd)
{
	char **temp_files;
	char buf[BUFSIZ];
	int *port_array;
	int *pid_array;
	int pagesize;
	int udp_port;
	int cpus;
	int cpu;
	int pid;
	int ofd;
	int n, s, t;

	/* Let the client know what we are */
	write(fd, "tracecmd", 8);

	/* read back the CPU count */
	n = read_string(fd, buf, BUFSIZ);
	if (n == BUFSIZ)
		/** ERROR **/
		return;

	cpus = atoi(buf);

	printf("cpus=%d\n", cpus);
	if (cpus < 0)
		return;

	/* next read the page size */
	n = read_string(fd, buf, BUFSIZ);
	if (n == BUFSIZ)
		/** ERROR **/
		return;

	pagesize = atoi(buf);

	printf("pagesize=%d\n", pagesize);
	if (pagesize <= 0)
		return;

	/* Create the client file */
	snprintf(buf, BUFSIZ, "%s.%s:%s.dat", output_file, node, port);

	ofd = open(buf, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (ofd < 0)
		die("Can not create file %s", buf);

	port_array = malloc_or_die(sizeof(int) * cpus);
	pid_array = malloc_or_die(sizeof(int) * cpus);
	memset(pid_array, 0, sizeof(int) * cpus);

	/* Now create a UDP port for each CPU */
	for (cpu = 0; cpu < cpus; cpu++) {
		udp_port = open_udp(node, port, &pid, cpu, pagesize);
		if (udp_port < 0)
			goto out_free;
		port_array[cpu] = udp_port;
		pid_array[cpu] = pid;
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
		t = n;
		s = 0;
		do {
			s = write(ofd, buf+s, t);
			if (s < 0)
				die("writing to file");
			t -= s;
			s = n - t;
		} while (t);
	} while (n > 0);

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

static void do_listen(char *port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s, cfd;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len;
	ssize_t nread;
	char buf[BUFSIZ];
	char host[NI_MAXHOST], service[NI_MAXSERV];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	s = getaddrinfo(NULL, port, &hints, &result);
	if (s != 0)
		die("getaddrinfo: error opening %s", port);

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
		die("Could not bind");

	freeaddrinfo(result);

	if (listen(sfd, backlog) < 0)
		die("listen");

	peer_addr_len = sizeof(peer_addr);

	do {
		cfd = accept(sfd, (struct sockaddr *)&peer_addr, &peer_addr_len);
		if (cfd < 0)
			die("connecting");
		s = getnameinfo((struct sockaddr *)&peer_addr, peer_addr_len,
				host, NI_MAXHOST,
				service, NI_MAXSERV, NI_NUMERICSERV);

		if (s == 0)
			printf("Connected with %s:%s\n",
			       host, service);
		else {
			printf("Error with getnameinfo: %s\n",
			       gai_strerror(s));
			close(cfd);
			close(sfd);
			return;
		}

		process_client(host, service, cfd);

		do {
			if (nread > 0)
				nread = read(cfd, buf, BUFSIZ);
			if (cfd < 0)
				die("client");
			if (nread > 0)
				write(1, buf, nread);
		} while (nread);

		close(cfd);
	} while (0);
}

static void start_daemon(void)
{
}

void trace_listen(int argc, char **argv)
{
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
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc-1, argv+1, "+hp:o:d:i:D",
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
		case 'D':
			daemon = 1;
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

	if (daemon)
		start_daemon();

	do_listen(port);

	return;
}
