// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2020, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "trace-utest.h"

static char tracecmd_exec[PATH_MAX];

#define TRACECMD_SUITE		"trace-cmd"

static void test_trace_record_report(void)
{
}

static int test_suite_destroy(void)
{
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
