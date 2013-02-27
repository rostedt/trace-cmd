/*
 * Copyright (C) 2013 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
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
 *
 * Several of the ideas in this file came from Arnaldo Carvalho de Melo's
 * work on the perf ui.
 */
#define _LARGEFILE64_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>

#include "trace-local.h"
#include "list.h"

static int sched_wakeup_type;
static int sched_wakeup_new_type;
static int sched_switch_type;
static int function_type;
static int function_graph_entry_type;
static int function_graph_exit_type;
static int kernel_stack_type;

static int long_size;

struct format_field *common_type_field;
struct format_field *common_pid_field;
struct format_field *sched_wakeup_comm_field;
struct format_field *sched_wakeup_new_comm_field;
struct format_field *sched_wakeup_pid_field;
struct format_field *sched_wakeup_new_pid_field;
struct format_field *sched_switch_prev_field;
struct format_field *sched_switch_next_field;
struct format_field *sched_switch_prev_pid_field;
struct format_field *sched_switch_next_pid_field;
struct format_field *function_ip_field;
struct format_field *function_parent_ip_field;
struct format_field *function_graph_entry_func_field;
struct format_field *function_graph_entry_depth_field;
struct format_field *function_graph_exit_func_field;
struct format_field *function_graph_exit_depth_field;
struct format_field *function_graph_exit_calltime_field;
struct format_field *function_graph_exit_rettime_field;
struct format_field *function_graph_exit_overrun_field;
struct format_field *kernel_stack_caller_field;

static int compact;

static void *zalloc(size_t size)
{
	return calloc(1, size);
}

static const char **ips;
static int ips_idx;
static int current_pid = -1;

struct stack_save {
	struct stack_save	*next;
	const char		**ips;
	int			ips_idx;
	int			pid;
};

struct stack_save *saved_stacks;

static void reset_stack(void)
{
	current_pid = -1;
	ips_idx = 0;
	/* Don't free here, it may be saved */
	ips = NULL;
}

static void save_stack(void)
{
	struct stack_save *stack;

	stack = zalloc(sizeof(*stack));
	if (!stack)
		die("malloc");

	stack->pid = current_pid;
	stack->ips_idx = ips_idx;
	stack->ips = ips;

	stack->next = saved_stacks;
	saved_stacks = stack;

	reset_stack();
}

static void restore_stack(int pid)
{
	struct stack_save *last = NULL, *stack;

	for (stack = saved_stacks; stack; last = stack, stack = stack->next) {
		if (stack->pid == pid)
			break;
	}

	if (!stack)
		return;

	if (last)
		last->next = stack->next;
	else
		saved_stacks = stack->next;

	current_pid = stack->pid;
	ips_idx = stack->ips_idx;
	free(ips);
	ips = stack->ips;
	free(stack);
}

struct pid_list;

struct chain {
	struct chain		*next;
	struct chain		*sibling;
	const char		*func;
	struct chain		*parents;
	struct pid_list		*pid_list;
	int			nr_parents;
	int			count;
	int			total;
	int			event;
};
static struct chain *chains;
static int nr_chains;
static int total_counts;

struct pid_list {
	struct pid_list		*next;
	struct chain		chain;
	int			pid;
};
static struct pid_list *list_pids;
static struct pid_list all_pid_list;

static void add_chain(struct chain *chain)
{
	if (chain->next)
		die("chain not null?");
	chain->next = chains;
	chains = chain;
	nr_chains++;
}

static void
insert_chain(struct pid_list *pid_list, struct chain *chain_list,
	     const char **chain_str, int size, int event)
{
	struct chain *chain;

	/* Record all counts */
	if (!chain_list->func)
		total_counts++;

	chain_list->count++;

	if (!size--)
		return;

	for (chain = chain_list->parents; chain; chain = chain->sibling) {
		if (chain->func == chain_str[size]) {
			insert_chain(pid_list, chain, chain_str, size, 0);
			return;
		}
	}

	chain_list->nr_parents++;
	chain = zalloc(sizeof(struct chain));
	if (!chain)
		die("malloc");
	chain->sibling = chain_list->parents;
	chain_list->parents = chain;
	chain->func = chain_str[size];
	chain->pid_list = pid_list;
	chain->event = event;

	/* NULL func means this is the top level of the chain. Store it */
	if (!chain_list->func)
		add_chain(chain);

	insert_chain(pid_list, chain, chain_str, size, 0);
}

static void save_call_chain(int pid, const char **chain, int size, int event)
{
	static struct pid_list *pid_list;

	if (compact)
		pid_list = &all_pid_list;

	else if (!pid_list || pid_list->pid != pid) {
		for (pid_list = list_pids; pid_list; pid_list = pid_list->next) {
			if (pid_list->pid == pid)
				break;
		}
		if (!pid_list) {
			pid_list = zalloc(sizeof(*pid_list));
			if (!pid_list)
				die("malloc");
			pid_list->pid = pid;
			pid_list->next = list_pids;
			list_pids = pid_list;
		}
	}
	insert_chain(pid_list, &pid_list->chain, chain, size, event);
}

static void save_stored_stacks(void)
{
	while (saved_stacks) {
		restore_stack(saved_stacks->pid);
		save_call_chain(current_pid, ips, ips_idx, 0);
	}
}

static void flush_stack(void)
{
	if (current_pid < 0)
		return;

	save_call_chain(current_pid, ips, ips_idx, 0);
	free(ips);
	reset_stack();
}

static void push_stack_func(const char *func)
{
	ips_idx++;
	ips = realloc(ips, ips_idx * sizeof(char *));
	ips[ips_idx - 1] = func;
}

static void pop_stack_func(void)
{
	ips_idx--;
	ips[ips_idx] = NULL;
}

static void
process_function(struct pevent *pevent, struct pevent_record *record)
{
	unsigned long long parent_ip;
	unsigned long long ip;
	unsigned long long val;
	const char *parent;
	const char *func;
	int pid;
	int ret;

	ret = pevent_read_number_field(common_pid_field, record->data, &val);
	if (ret < 0)
		die("no pid field for function?");

	ret = pevent_read_number_field(function_ip_field, record->data, &ip);
	if (ret < 0)
		die("no ip field for function?");

	ret = pevent_read_number_field(function_parent_ip_field, record->data, &parent_ip);
	if (ret < 0)
		die("no parent ip field for function?");

	pid = val;

	func = pevent_find_function(pevent, ip);
	parent = pevent_find_function(pevent, parent_ip);

	if (current_pid >= 0 && pid != current_pid) {
		save_stack();
		restore_stack(pid);
	}

	current_pid = pid;

	if (ips_idx) {
		if (ips[ips_idx - 1] == parent)
			push_stack_func(func);
		else {
			save_call_chain(pid, ips, ips_idx, 0);
			while (ips_idx) {
				pop_stack_func();
				if (ips[ips_idx - 1] == parent) {
					push_stack_func(func);
					break;
				}
			}
		}
	}

	/* The above check can set ips_idx to zero again */
	if (!ips_idx) {
		push_stack_func(parent);
		push_stack_func(func);
	}
}

static void
process_function_graph(struct pevent *pevent, struct pevent_record *record)
{
}

static int pending_pid = -1;
static const char **pending_ips;
static int pending_ips_idx;

static void reset_pending_stack(void)
{
	pending_pid = -1;
	pending_ips_idx = 0;
	free(pending_ips);
	pending_ips = NULL;
}

static void copy_stack_to_pending(int pid)
{
	pending_pid = pid;
	pending_ips = zalloc(sizeof(char *) * ips_idx);
	memcpy(pending_ips, ips, sizeof(char *) * ips_idx);
	pending_ips_idx = ips_idx;
}

static void
process_kernel_stack(struct pevent *pevent, struct pevent_record *record)
{
	struct format_field *field = kernel_stack_caller_field;
	unsigned long long val;
	void *data = record->data;
	int do_restore = 0;
	int pid;
	int ret;

	ret = pevent_read_number_field(common_pid_field, record->data, &val);
	if (ret < 0)
		die("no pid field for function?");
	pid = val;

	if (pending_pid >= 0 && pid != pending_pid) {
		reset_pending_stack();
		return;
	}

	if (!field)
		die("no caller field for kernel stack?");

	if (pending_pid >= 0) {
		if (current_pid >= 0) {
			save_stack();
			do_restore = 1;
		}
	} else {
		/* function stack trace? */
		copy_stack_to_pending(current_pid);
		free(ips);
		reset_stack();
	}

	current_pid = pid;

	/* Need to start at the end of the callers and work up */
	for (data += field->offset; data < record->data + record->size;
	     data += long_size) {
		unsigned long long addr;

		addr = pevent_read_number(pevent, data, long_size);

		if ((long_size == 8 && addr == (unsigned long long)-1) ||
		    ((int)addr == -1))
			break;
	}

	for (data -= long_size; data >= record->data + field->offset; data -= long_size) {
		unsigned long long addr;
		const char *func;

		addr = pevent_read_number(pevent, data, long_size);
		func = pevent_find_function(pevent, addr);
		if (func)
			push_stack_func(func);
	}

	push_stack_func(pending_ips[pending_ips_idx - 1]);
	reset_pending_stack();
	save_call_chain(current_pid, ips, ips_idx, 1);
	if (do_restore)
		restore_stack(current_pid);
}

static void
process_sched_wakeup(struct pevent *pevent, struct pevent_record *record, int type)
{
	unsigned long long val;
	const char *comm;
	int pid;
	int ret;

	if (type == sched_wakeup_type) {
		comm = (char *)(record->data + sched_wakeup_comm_field->offset);
		ret = pevent_read_number_field(sched_wakeup_pid_field, record->data, &val);
		if (ret < 0)
			die("no pid field in sched_wakeup?");
	} else {
		comm = (char *)(record->data + sched_wakeup_new_comm_field->offset);
		ret = pevent_read_number_field(sched_wakeup_new_pid_field, record->data, &val);
		if (ret < 0)
			die("no pid field in sched_wakeup_new?");
	}

	pid = val;

	pevent_register_comm(pevent, comm, pid);
}

static void
process_sched_switch(struct pevent *pevent, struct pevent_record *record)
{
	unsigned long long val;
	const char *comm;
	int pid;
	int ret;

	comm = (char *)(record->data + sched_switch_prev_field->offset);
	ret = pevent_read_number_field(sched_switch_prev_pid_field, record->data, &val);
	if (ret < 0)
		die("no prev_pid field in sched_switch?");
	pid = val;
	pevent_register_comm(pevent, comm, pid);

	comm = (char *)(record->data + sched_switch_next_field->offset);
	ret = pevent_read_number_field(sched_switch_next_pid_field, record->data, &val);
	if (ret < 0)
		die("no next_pid field in sched_switch?");
	pid = val;
	pevent_register_comm(pevent, comm, pid);
}

static void
process_event(struct pevent *pevent, struct pevent_record *record, int type)
{
	struct event_format *event;
	const char *event_name;
	unsigned long long val;
	int pid;
	int ret;

	if (pending_pid >= 0) {
		save_call_chain(pending_pid, pending_ips, pending_ips_idx, 1);
		reset_pending_stack();
	}
		
	event = pevent_data_event_from_type(pevent, type);
	event_name = event->name;

	ret = pevent_read_number_field(common_pid_field, record->data, &val);
	if (ret < 0)
		die("no pid field for function?");

	pid = val;

	/*
	 * Even if function or function graph tracer is running,
	 * if the user ran with stack traces on events, we want to use
	 * that instead. But unfortunately, that stack doesn't come
	 * until after the event. Thus, we only add the event into
	 * the pending stack.
	 */
	push_stack_func(event_name);
	copy_stack_to_pending(pid);
	pop_stack_func();
}

static void
process_record(struct pevent *pevent, struct pevent_record *record)
{
	unsigned long long val;
	int type;

	pevent_read_number_field(common_type_field, record->data, &val);
	type = val;

	if (type == function_type)
		return process_function(pevent, record);

	if (type == function_graph_entry_type ||
	    type == function_graph_exit_type)
		return process_function_graph(pevent, record);

	if (type == kernel_stack_type)
		return process_kernel_stack(pevent, record);

	if (type == sched_wakeup_type || type == sched_wakeup_new_type)
		process_sched_wakeup(pevent, record, type);

	else if (type == sched_switch_type)
		process_sched_switch(pevent, record);

	process_event(pevent, record, type);
}

static struct event_format *
update_event(struct pevent *pevent,
	     const char *sys, const char *name, int *id)
{
	struct event_format *event;

	event = pevent_find_event_by_name(pevent, sys, name);
	if (!event)
		return NULL;

	*id = event->id;

	return event;
}

static void update_sched_wakeup(struct pevent *pevent)
{
	struct event_format *event;

	event = update_event(pevent, "sched", "sched_wakeup", &sched_wakeup_type);
	if (!event)
		return;

	sched_wakeup_comm_field = pevent_find_field(event, "comm");
	sched_wakeup_pid_field = pevent_find_field(event, "pid");
}

static void update_sched_wakeup_new(struct pevent *pevent)
{
	struct event_format *event;

	event = update_event(pevent, "sched", "sched_wakeup_new", &sched_wakeup_new_type);
	if (!event)
		return;

	sched_wakeup_new_comm_field = pevent_find_field(event, "comm");
	sched_wakeup_new_pid_field = pevent_find_field(event, "pid");
}

static void update_sched_switch(struct pevent *pevent)
{
	struct event_format *event;

	event = update_event(pevent, "sched", "sched_switch", &sched_switch_type);
	if (!event)
		return;

	sched_switch_prev_field = pevent_find_field(event, "prev_comm");
	sched_switch_next_field = pevent_find_field(event, "next_comm");
	sched_switch_prev_pid_field = pevent_find_field(event, "prev_pid");
	sched_switch_next_pid_field = pevent_find_field(event, "next_pid");
}

static void update_function(struct pevent *pevent)
{
	struct event_format *event;

	event = update_event(pevent, "ftrace", "function", &function_type);
	if (!event)
		return;

	function_ip_field = pevent_find_field(event, "ip");
	function_parent_ip_field = pevent_find_field(event, "parent_ip");
}

static void update_function_graph_entry(struct pevent *pevent)
{
	struct event_format *event;

	event = update_event(pevent, "ftrace", "funcgraph_entry", &function_graph_entry_type);
	if (!event)
		return;

	function_graph_entry_func_field = pevent_find_field(event, "func");
	function_graph_entry_depth_field = pevent_find_field(event, "depth");
}

static void update_function_graph_exit(struct pevent *pevent)
{
	struct event_format *event;

	event = update_event(pevent, "ftrace", "funcgraph_exit", &function_graph_exit_type);
	if (!event)
		return;

	function_graph_exit_func_field = pevent_find_field(event, "func");
	function_graph_exit_depth_field = pevent_find_field(event, "depth");
	function_graph_exit_calltime_field = pevent_find_field(event, "calltime");
	function_graph_exit_rettime_field = pevent_find_field(event, "rettime");
	function_graph_exit_overrun_field = pevent_find_field(event, "overrun");
}

static void update_kernel_stack(struct pevent *pevent)
{
	struct event_format *event;

	event = update_event(pevent, "ftrace", "kernel_stack", &kernel_stack_type);
	if (!event)
		return;

	kernel_stack_caller_field = pevent_find_field(event, "caller");
}

enum field { NEXT_PTR, SIB_PTR };

static struct chain *next_ptr(struct chain *chain, enum field field)
{
	if (field == NEXT_PTR)
		return chain->next;
	return chain->sibling;
}

static struct chain *split_chain(struct chain *orig, int size, enum field field)
{
	struct chain *chain;
	int i;

	if (size < 2)
		return NULL;

	for (i = 1; i < (size + 1) / 2; i++, orig = next_ptr(orig, field))
		;

	if (field == NEXT_PTR) {
		chain = orig->next;
		orig->next = NULL;
	} else {
		chain = orig->sibling;
		orig->sibling = NULL;
	}

	return chain;
}

static struct chain *
merge_chains(struct chain *a, int nr_a, struct chain *b, int nr_b, enum field field)
{
	struct chain *chain;
	struct chain *final;
	struct chain **next = &final;
	int i;

	if (!a)
		return b;
	if (!b)
		return a;

	for (i = 0, chain = a; chain; i++, chain = next_ptr(chain, field))
		;
	if (i != nr_a)
		die("WTF %d %d", i, nr_a);

	chain = split_chain(a, nr_a, field);
	a = merge_chains(chain, nr_a / 2, a, (nr_a + 1) / 2, field);

	chain = split_chain(b, nr_b, field);
	b = merge_chains(chain, nr_b / 2, b, (nr_b + 1) / 2, field);

	while (a && b) {
		if (a->count > b->count) {
			*next = a;
			if (field == NEXT_PTR)
				next = &a->next;
			else
				next = &a->sibling;
			a = *next;
			*next = NULL;
		} else {
			*next = b;
			if (field == NEXT_PTR)
				next = &b->next;
			else
				next = &b->sibling;
			b = *next;
			*next = NULL;
		}
	}
	if (a)
		*next = a;
	else
		*next = b;

	return final;
}

static void sort_chain_parents(struct chain *chain)
{
	struct chain *parent;

	parent = split_chain(chain->parents, chain->nr_parents, SIB_PTR);
	chain->parents = merge_chains(parent, chain->nr_parents / 2,
				      chain->parents, (chain->nr_parents + 1) / 2,
				      SIB_PTR);

	for (chain = chain->parents; chain; chain = chain->sibling)
		sort_chain_parents(chain);
}

static void sort_chains(void)
{
	struct chain *chain;

	chain = split_chain(chains, nr_chains, NEXT_PTR);

	/* The original always has more or equal to the split */
	chains = merge_chains(chain, nr_chains / 2, chains, (nr_chains + 1) / 2, NEXT_PTR);

	for (chain = chains; chain; chain = chain->next)
		sort_chain_parents(chain);
}

static double get_percent(int total, int partial)
{
	return ((double)partial / (double)total) * 100.0;
}

static int single_chain(struct chain *chain)
{
	if (chain->nr_parents > 1)
		return 0;

	if (!chain->parents)
		return 1;

	return single_chain(chain->parents);
}

#define START	"         |\n"
#define TICK	"         --- "
#define BLANK	"          "
#define LINE	"            |"
#define INDENT	"             "

unsigned long long line_mask;
void make_indent(int indent)
{
	int i;

	for (i = 0; i < indent; i++) {
		if (line_mask & (1 << i))
			printf(LINE);
		else
			printf(INDENT);
	}
}

static void
print_single_parent(struct chain *chain, int indent)
{
	make_indent(indent);

	printf(BLANK);
	printf("%s\n", chain->parents->func);
}

static void
dump_chain(struct pevent *pevent, struct chain *chain, int indent)
{
	if (!chain->parents)
		return;

	print_single_parent(chain, indent);
	dump_chain(pevent, chain->parents, indent);
}

static void print_parents(struct pevent *pevent, struct chain *chain, int indent)
{
	struct chain *parent = chain->parents;
	int x;

	if (single_chain(chain)) {
		dump_chain(pevent, chain, indent);
		return;
	}

	line_mask |= 1ULL << (indent);

	for (x = 0; parent; x++, parent = parent->sibling) {
		struct chain *save_parent;

		make_indent(indent + 1);
		printf("\n");

		make_indent(indent + 1);

		printf("--%%%.2f-- %s  # %d\n",
		       get_percent(chain->count, parent->count),
		       parent->func, parent->count);

		if (x == chain->nr_parents - 1)
			line_mask &= (1ULL << indent) - 1;

		if (single_chain(parent))
			dump_chain(pevent, parent, indent + 1);
		else {
			save_parent = parent;

			while (parent && parent->parents && parent->nr_parents < 2 &&
			       parent->parents->count == parent->count) {
				print_single_parent(parent, indent + 1);
				parent = parent->parents;
			}
			if (parent)
				print_parents(pevent, parent, indent + 1);
			parent = save_parent;
		}
	}
}

static void print_chains(struct pevent *pevent)
{
	struct chain *chain = chains;
	int pid;

	for (; chain; chain = chain->next) {
		pid = chain->pid_list->pid;
		if (chain != chains)
			printf("\n");
		if (compact)
			printf("  %%%3.2f <all pids> %30s #%d\n",
			       get_percent(total_counts, chain->count),
			       chain->func,
			       chain->count);
		else
			printf("  %%%3.2f  (%d) %s %30s #%d\n",
			       get_percent(total_counts, chain->count),
			       pid,
			       pevent_data_comm_from_pid(pevent, pid),
			       chain->func,
			       chain->count);
		printf(START);
		if (chain->event)
			printf(TICK "*%s*\n", chain->func);
		else
			printf(TICK "%s\n", chain->func);
		print_parents(pevent, chain, 0);
	}
}

static void do_trace_hist(struct tracecmd_input *handle)
{
	struct pevent *pevent = tracecmd_get_pevent(handle);
	struct event_format *event;
	struct pevent_record *record;
	int cpus;
	int cpu;
	int ret;

	ret = tracecmd_init_data(handle);
	if (ret < 0)
		die("failed to init data");

	if (ret > 0)
		die("trace-cmd hist does not work with latency traces\n");

	cpus = tracecmd_cpus(handle);

	/* Need to get any event */
	for (cpu = 0; cpu < cpus; cpu++) {
		record = tracecmd_peek_data(handle, cpu);
		if (record)
			break;
	}
	if (!record)
		die("No records found in file");

	ret = pevent_data_type(pevent, record);
	event = pevent_data_event_from_type(pevent, ret);

	long_size = tracecmd_long_size(handle);

	common_type_field = pevent_find_common_field(event, "common_type");
	if (!common_type_field)
		die("Can't find a 'type' field?");

	common_pid_field = pevent_find_common_field(event, "common_pid");
	if (!common_pid_field)
		die("Can't find a 'pid' field?");

	update_sched_wakeup(pevent);
	update_sched_wakeup_new(pevent);
	update_sched_switch(pevent);
	update_function(pevent);
	update_function_graph_entry(pevent);
	update_function_graph_exit(pevent);
	update_kernel_stack(pevent);

	for (cpu = 0; cpu < cpus; cpu++) {
		for (;;) {
			struct pevent_record *record;

			record = tracecmd_read_data(handle, cpu);
			if (!record)
				break;

			/* If we missed events, just flush out the current stack */
			if (record->missed_events)
				flush_stack();

			process_record(pevent, record);
			free_record(record);
		}
	}

	if (current_pid >= 0)
		save_call_chain(current_pid, ips, ips_idx, 0);
	if (pending_pid >= 0)
		save_call_chain(pending_pid, pending_ips, pending_ips_idx, 1);

	save_stored_stacks();

	sort_chains();
	print_chains(pevent);
}

void trace_hist(int argc, char **argv)
{
	struct tracecmd_input *handle;
	const char *input_file = NULL;
	int ret;

	for (;;) {
		int c;

		c = getopt(argc-1, argv+1, "+hi:P");
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 'i':
			if (input_file)
				die("Only one input for historgram");
			input_file = optarg;
			break;
		case 'P':
			compact = 1;
			break;
		default:
			usage(argv);
		}
	}

	if ((argc - optind) >= 2) {
		if (input_file)
			usage(argv);
		input_file = argv[optind + 1];
	}

	if (!input_file)
		input_file = "trace.dat";

	handle = tracecmd_alloc(input_file);
	if (!handle)
		die("can't open %s\n", input_file);

	ret = tracecmd_read_headers(handle);
	if (ret)
		return;

	do_trace_hist(handle);

	tracecmd_close(handle);
}
