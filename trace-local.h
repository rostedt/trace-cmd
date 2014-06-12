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

void show_file(const char *name);

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

void trace_snapshot(int argc, char **argv);

void trace_mem(int argc, char **argv);

/* --- instance manipulation --- */

struct func_list {
	struct func_list *next;
	const char *func;
};

struct buffer_instance {
	struct buffer_instance	*next;
	const char		*name;
	const char		*cpumask;
	struct event_list	*events;
	struct event_list	**event_next;

	struct event_list	*sched_switch_event;
	struct event_list	*sched_wakeup_event;
	struct event_list	*sched_wakeup_new_event;

	const char		*plugin;
	struct func_list	*filter_funcs;
	struct func_list	*notrace_funcs;

	struct trace_seq	*s;

	int			tracing_on_init_val;
	int			tracing_on_fd;
	int			keep;
	int			buffer_size;
};

extern struct buffer_instance top_instance;
extern struct buffer_instance *buffer_instances;
extern struct buffer_instance *first_instance;

#define for_each_instance(i) for (i = buffer_instances; i; i = (i)->next)
#define for_all_instances(i) for (i = first_instance; i; \
				  i = i == &top_instance ? buffer_instances : (i)->next)

struct buffer_instance *create_instance(char *name);
void add_instance(struct buffer_instance *instance);
char *get_instance_file(struct buffer_instance *instance, const char *file);

void show_instance_file(struct buffer_instance *instance, const char *name);

#endif /* __TRACE_LOCAL_H */
