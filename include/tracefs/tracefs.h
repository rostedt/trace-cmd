/* SPDX-License-Identifier: LGPL-2.1 */
/*
 * Copyright (C) 2019, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */
#ifndef _TRACE_FS_H
#define _TRACE_FS_H

#include "traceevent/event-parse.h"

char *tracefs_get_tracing_file(const char *name);
void tracefs_put_tracing_file(char *name);

/* tracefs_get_tracing_dir must *not* be freed */
const char *tracefs_get_tracing_dir(void);

/* tracefs_find_tracing_dir must be freed */
char *tracefs_find_tracing_dir(void);

#endif /* _TRACE_FS_H */
