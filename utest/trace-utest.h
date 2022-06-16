/* SPDX-License-Identifier: LGPL-2.1 */
/*
 * Copyright (C) 2020, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */
#ifndef _TRACE_UTEST_H_
#define _TRACE_UTEST_H_

#include <stdbool.h>

extern const char *argv0;
extern bool show_output;

void test_tracecmd_lib(void);

#endif /* _TRACE_UTEST_H_ */
