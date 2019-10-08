// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 VMware Inc, Slavomir Kaslev <kaslevs@vmware.com>
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "trace-local.h"
#include "trace-msg.h"

static int make_dir(const char *path, mode_t mode)
{
	char buf[PATH_MAX+2], *p;

	strncpy(buf, path, sizeof(buf));
	if (buf[PATH_MAX])
		return -E2BIG;

	for (p = buf; *p; p++) {
		p += strspn(p, "/");
		p += strcspn(p, "/");
		*p = '\0';
		if (mkdir(buf, mode) < 0 && errno != EEXIST)
			return -errno;
		*p = '/';
	}

	return 0;
}

static int make_fifo(const char *path, mode_t mode)
{
	struct stat st;

	if (!stat(path, &st)) {
		if (S_ISFIFO(st.st_mode))
			return 0;
		return -EEXIST;
	}

	if (mkfifo(path, mode))
		return -errno;
	return 0;
}

static int make_guest_dir(const char *guest)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), GUEST_DIR_FMT, guest);
	return make_dir(path, 0750);
}

static int make_guest_fifo(const char *guest, int cpu, mode_t mode)
{
	static const char *exts[] = {".in", ".out"};
	char path[PATH_MAX];
	int i, ret = 0;

	for (i = 0; i < ARRAY_SIZE(exts); i++) {
		snprintf(path, sizeof(path), GUEST_FIFO_FMT "%s",
			 guest, cpu, exts[i]);
		ret = make_fifo(path, mode);
		if (ret < 0)
			break;
	}

	return ret;
}

static int make_guest_fifos(const char *guest, int nr_cpus, mode_t mode)
{
	int i, ret = 0;
	mode_t mask;

	mask = umask(0);
	for (i = 0; i < nr_cpus; i++) {
		ret = make_guest_fifo(guest, i, mode);
		if (ret < 0)
			break;
	}
	umask(mask);

	return ret;
}

static void do_setup_guest(const char *guest, int nr_cpus, mode_t mode, gid_t gid)
{
	gid_t save_egid;
	int ret;

	if (gid != -1) {
		save_egid = getegid();
		ret = setegid(gid);
		if (ret < 0)
			die("failed to set effective group ID");
	}

	ret = make_guest_dir(guest);
	if (ret < 0)
		die("failed to create guest directory for %s", guest);

	ret = make_guest_fifos(guest, nr_cpus, mode);
	if (ret < 0)
		die("failed to create FIFOs for %s", guest);

	if (gid != -1) {
		ret = setegid(save_egid);
		if (ret < 0)
			die("failed to restore effective group ID");
	}
}

void trace_setup_guest(int argc, char **argv)
{
	struct group *group;
	mode_t mode = 0660;
	int nr_cpus = -1;
	gid_t gid = -1;
	char *guest;

	if (argc < 2)
		usage(argv);

	if (strcmp(argv[1], "setup-guest") != 0)
		usage(argv);

	for (;;) {
		int c, option_index = 0;
		static struct option long_options[] = {
			{"help", no_argument, NULL, '?'},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long(argc-1, argv+1, "+hc:p:g:",
				long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'c':
			nr_cpus = atoi(optarg);
			break;
		case 'p':
			mode = strtol(optarg, NULL, 8);
			break;
		case 'g':
			group = getgrnam(optarg);
			if (!group)
				die("group %s does not exist", optarg);
			gid = group->gr_gid;
			break;
		default:
			usage(argv);
		}
	}

	if (optind != argc-2)
		usage(argv);

	guest = argv[optind+1];

	if (nr_cpus <= 0)
		die("invalid number of cpus for guest %s", guest);

	do_setup_guest(guest, nr_cpus, mode, gid);
}
