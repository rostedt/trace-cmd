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
#ifndef __TRACE_LOCAL_H
#define __TRACE_LOCAL_H

#include "trace-cmd.h"

/* fix stupid glib guint64 typecasts and printf formats */
typedef unsigned long long u64;

/* for local shared information with trace-cmd executable */

void usage(char **argv);

extern int silence_warnings;
extern int show_status;

struct tracecmd_input *read_trace_header(const char *file);
int read_trace_files(void);

void trace_record(int argc, char **argv);

void trace_report(int argc, char **argv);

void trace_split(int argc, char **argv);

void trace_listen(int argc, char **argv);

void trace_restore(int argc, char **argv);

void trace_stack(int argc, char **argv);

void trace_option(int argc, char **argv);

void trace_hist(int argc, char **argv);

void trace_mem(int argc, char **argv);

#endif /* __TRACE_LOCAL_H */
