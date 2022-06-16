// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2020, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include <tracefs.h>

#include "trace-utest.h"

static char tracecmd_exec[PATH_MAX];

#define TRACECMD_SUITE		"trace-cmd"
#define TRACECMD_FILE		"__trace_test__.dat"
#define TRACECMD_OUT		"-o", TRACECMD_FILE
#define TRACECMD_IN		"-i", TRACECMD_FILE

static void silent_output(void)
{
	close(STDOUT_FILENO);
	open("/dev/null", O_WRONLY);
	close(STDERR_FILENO);
	open("/dev/null", O_WRONLY);
}

static int run_trace(const char *cmd, ...)
{
	const char *param;
	va_list ap;
	char **tmp;
	char **argv;
	int status;
	int ret = -1;
	pid_t pid;

	argv = tracefs_list_add(NULL, tracecmd_exec);
	if (!argv)
		return -1;

	tmp = tracefs_list_add(argv, cmd);
	if (!tmp)
		goto out;
	argv = tmp;

	va_start(ap, cmd);
	for (param = va_arg(ap, const char *);
	     param; param = va_arg(ap, const char *)) {
		tmp = tracefs_list_add(argv, param);
		if (!tmp)
			goto out;
		argv = tmp;
	}
	va_end(ap);

	pid = fork();
	if (pid < 0)
		goto out;
	if (!pid) {
		if (!show_output)
			silent_output();
		ret = execvp(tracecmd_exec, argv);
		exit (ret);
	}

	ret = waitpid(pid, &status, 0);
	if (ret != pid) {
		ret = -1;
		goto out;
	}

	ret = WEXIT_STATUS(status);
 out:
	tracefs_list_free(argv);
	return ret;
}

static void test_trace_record_report(void)
{
	int ret;

	ret = run_trace("record", TRACECMD_OUT, "-e", "sched", "sleep", "1", NULL);
	CU_TEST(ret == 0);
	ret = run_trace("report", TRACECMD_IN, NULL);
	CU_TEST(ret == 0);
}

static int test_suite_destroy(void)
{
	unlink(TRACECMD_FILE);
	return 0;
}

static int test_suite_init(void)
{
	struct stat st;
	const char *p;

	/* The test must be in the utest directory */
	for (p = argv0 + strlen(argv0) - 1; p > argv0 && *p != '/'; p--)
		;

	if (*p == '/')
		snprintf(tracecmd_exec, PATH_MAX, "%.*s/../tracecmd/trace-cmd",
			 (int)(p - argv0), argv0);
	else
		strncpy(tracecmd_exec, "../tracecmd/trace-cmd", PATH_MAX);

	if (stat(tracecmd_exec, &st) < 0) {
		fprintf(stderr, "In tree trace-cmd executable not found\n");
		return 1;
	}

	if (!(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
		fprintf(stderr, "In tree trace-cmd executable not executable\n");
		return 1;
	}

	return 0;
}

void test_tracecmd_lib(void)
{
	CU_pSuite suite = NULL;

	suite = CU_add_suite(TRACECMD_SUITE, test_suite_init, test_suite_destroy);
	if (suite == NULL) {
		fprintf(stderr, "Suite \"%s\" cannot be ceated\n", TRACECMD_SUITE);
		return;
	}
	CU_add_test(suite, "Simple record and report",
		    test_trace_record_report);
}
