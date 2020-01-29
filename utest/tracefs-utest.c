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

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "tracefs.h"

#define TRACEFS_SUITE		"trasefs library"
#define TEST_INSTANCE_NAME	"cunit_test_iter"
#define TEST_ARRAY_SIZE		50

static struct tracefs_instance *test_instance;
static struct tep_handle *test_tep;
static int test_array[TEST_ARRAY_SIZE];
static int test_found;

static int test_callback(struct tep_event *event, struct tep_record *record,
			  int cpu, void *context)
{
	struct tep_format_field *field;
	int val, i;

	field = tep_find_field(event, "buf");
	if (field) {
		val = *((int *)(record->data + field->offset));
		for (i = 0; i < TEST_ARRAY_SIZE; i++) {
			if (test_array[i] == val) {
				test_array[i] = 0;
				test_found++;
				break;
			}
		}
	}

	return 0;
}

static void test_iter_write(void)
{
	char *path;
	int i, fd;
	int ret;

	path = tracefs_instance_get_file(test_instance, "trace_marker");
	CU_TEST(path != NULL);
	fd = open(path, O_WRONLY);
	CU_TEST(fd >= 0);

	for (i = 0; i < TEST_ARRAY_SIZE; i++) {
		test_array[i] = random();
		ret = write(fd, test_array + i, sizeof(int));
		CU_TEST(ret == sizeof(int));
	}

	tracefs_put_tracing_file(path);
	close(fd);
}


static void test_iter_raw_events(void)
{
	int ret;

	ret = tracefs_iterate_raw_events(NULL, test_instance, test_callback, NULL);
	CU_TEST(ret < 0);
	ret = tracefs_iterate_raw_events(test_tep, NULL, test_callback, NULL);
	CU_TEST(ret == 0);
	ret = tracefs_iterate_raw_events(test_tep, test_instance, NULL, NULL);
	CU_TEST(ret < 0);

	test_found = 0;
	test_iter_write();
	ret = tracefs_iterate_raw_events(test_tep, test_instance,
					 test_callback, NULL);
	CU_TEST(ret == 0);
	CU_TEST(test_found == TEST_ARRAY_SIZE);
}

static int test_suite_destroy(void)
{
	tracefs_instance_destroy(test_instance);
	tracefs_instance_free(test_instance);
	tep_free(test_tep);
	return 0;
}

static int test_suite_init(void)
{
	const char *systems[] = {"ftrace", NULL};

	test_tep = tracefs_local_events_system(NULL, systems);
	if (test_tep == NULL)
		return 1;

	test_instance = tracefs_instance_alloc(TEST_INSTANCE_NAME);
	if (test_instance == NULL)
		return 1;

	if (tracefs_instance_create(test_instance) < 0)
		return 1;

	return 0;
}

void test_tracefs_lib(void)
{
	CU_pSuite suite = NULL;

	suite = CU_add_suite(TRACEFS_SUITE, test_suite_init, test_suite_destroy);
	if (suite == NULL) {
		fprintf(stderr, "Suite \"%s\" cannot be ceated\n", TRACEFS_SUITE);
		return;
	}
	CU_add_test(suite, "tracefs_iterate_raw_events API",
		    test_iter_raw_events);
}
