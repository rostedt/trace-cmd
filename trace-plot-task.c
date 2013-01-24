/*
 * Copyright (C) 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
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
#include <string.h>

#include "trace-graph.h"
#include "trace-filter.h"

#define RED 0xff
#define GREEN (0xff<<16)

struct task_plot_info {
	int			pid;
	struct cpu_data		*cpu_data;
	struct pevent_record	**last_records;
	unsigned long long	last_time;
	unsigned long long	wake_time;
	unsigned long long	display_wake_time;
	int			wake_color;
	int			last_cpu;
};

static void convert_nano(unsigned long long time, unsigned long *sec,
			 unsigned long *usec)
{
	*sec = time / 1000000000ULL;
	*usec = (time / 1000) % 1000000;
}

static gint hash_pid(gint val)
{
	/* idle always gets black */
	if (!val)
		return 0;

	return trace_hash(val);
}

static int hash_cpu(int cpu)
{
	cpu = (cpu << 3) + cpu * 21;
 
	return trace_hash(cpu);
}

static gboolean is_running(struct graph_info *ginfo, struct pevent_record *record)
{
	unsigned long long val;
	int id;

	id = pevent_data_type(ginfo->pevent, record);
	if (id != ginfo->event_sched_switch_id)
		return FALSE;

	pevent_read_number_field(ginfo->event_prev_state, record->data, &val);
	return val ? FALSE : TRUE;
}

static gboolean record_matches_pid(struct graph_info *ginfo,
				   struct pevent_record *record, int match_pid,
				   int *pid, int *sched_pid,
				   gboolean *is_sched,
				   gboolean *wakeup)
{
	const char *comm;

	*is_sched = FALSE;
	*wakeup = FALSE;

	*pid = pevent_data_pid(ginfo->pevent, record);
	*sched_pid = *pid;

	if (trace_graph_check_sched_switch(ginfo, record, sched_pid, &comm)) {
		if (*pid == match_pid || *sched_pid == match_pid) {
			*is_sched = TRUE;
			return TRUE;
		}
	}

	if (trace_graph_check_sched_wakeup(ginfo, record, sched_pid)) {
		if (*sched_pid == match_pid) {
			*wakeup = TRUE;
			return TRUE;
		}
	}

	if (*pid == match_pid)
		return TRUE;

	return FALSE;
}

static void set_cpu_to_time(int cpu, struct graph_info *ginfo, unsigned long long time)
{
	struct pevent_record *record;

	tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, time);

	while ((record = tracecmd_read_data(ginfo->handle, cpu))) {
		if (record->ts >= time)
			break;

		free_record(record);
	}
	if (record) {
		tracecmd_set_cursor(ginfo->handle, cpu, record->offset);
		free_record(record);
	} else
		tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, time);
}

static void set_cpus_to_time(struct graph_info *ginfo, unsigned long long time)
{
	int cpu;

	for (cpu = 0; cpu < ginfo->cpus; cpu++)
		set_cpu_to_time(cpu, ginfo, time);
}

static int task_plot_match_time(struct graph_info *ginfo, struct graph_plot *plot,
			       unsigned long long time)
{
	struct task_plot_info *task_info = plot->private;
	struct pevent_record *record = NULL;
	gboolean is_wakeup;
	gboolean is_sched;
	gboolean match;
	int rec_pid;
	int sched_pid;
	int next_cpu;
	int pid;
	int ret = 0;

	pid = task_info->pid;

	set_cpus_to_time(ginfo, time);

	do {
		free_record(record);

		record = tracecmd_read_next_data(ginfo->handle, &next_cpu);
		if (!record)
			return 0;

		match = record_matches_pid(ginfo, record, pid, &rec_pid,
					   &sched_pid, &is_sched, &is_wakeup);

		/* Use +1 to make sure we have a match first */
	} while ((!match && record->ts < time + 1) ||
		 (match && record->ts < time));

	if (record && record->ts == time)
		ret = 1;
	free_record(record);

	return ret;
}

struct offset_cache {
	guint64 *offsets;
};

static struct offset_cache *save_offsets(struct graph_info *ginfo)
{
	struct offset_cache *offsets;
	struct pevent_record *record;
	int cpu;

	offsets = malloc_or_die(sizeof(*offsets));
	offsets->offsets = malloc_or_die(sizeof(*offsets->offsets) * ginfo->cpus);
	memset(offsets->offsets, 0, sizeof(*offsets->offsets) * ginfo->cpus);

	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		record = tracecmd_peek_data(ginfo->handle, cpu);
		if (record)
			offsets->offsets[cpu] = record->offset;
	}

	return offsets;
}

static void restore_offsets(struct graph_info *ginfo, struct offset_cache *offsets)
{
	struct pevent_record *record;
	int cpu;

	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		if (offsets->offsets[cpu])
			tracecmd_set_cursor(ginfo->handle, cpu, offsets->offsets[cpu]);
		else {
			/* end of cpu, make sure it stays the end */
			record = tracecmd_read_cpu_last(ginfo->handle, cpu);
			free_record(record);
		}
	}

	free(offsets->offsets);
	free(offsets);
}

static struct pevent_record *
find_record(struct graph_info *ginfo, gint pid, guint64 time)
{
	struct pevent_record *record = NULL;
	gboolean is_wakeup;
	gboolean is_sched;
	gboolean match;
	int sched_pid;
	int rec_pid;
	int next_cpu;

	set_cpus_to_time(ginfo, time);

	do {
		free_record(record);

		record = tracecmd_read_next_data(ginfo->handle, &next_cpu);
		if (!record)
			return NULL;

		match = record_matches_pid(ginfo, record, pid, &rec_pid,
					   &sched_pid,  &is_sched, &is_wakeup);

		/* Use +1 to make sure we have a match first */
	} while (!(record->ts > time && match));


	return record;
}

static int task_plot_display_last_event(struct graph_info *ginfo,
					struct graph_plot *plot,
					struct trace_seq *s,
					unsigned long long time)
{
	struct task_plot_info *task_info = plot->private;
	struct event_format *event;
	struct pevent_record *record;
	struct offset_cache *offsets;
	gboolean is_sched;
	gboolean is_wakeup;
	int sched_pid;
	int rec_pid;
	int pid;
	int type;

	pid = task_info->pid;

	/*
	 * Get the next record so we know can save its offset and
	 * reset the cursor, not to mess up the plotting
	 */
	offsets = save_offsets(ginfo);

	record = find_record(ginfo, pid, time);

	restore_offsets(ginfo, offsets);

	if (!record)
		return 0;

	record_matches_pid(ginfo, record, pid, &rec_pid,
			   &sched_pid, &is_sched, &is_wakeup);

	if (is_sched) {
		if (sched_pid == pid) {
			if (task_info->display_wake_time) {
				trace_seq_printf(s, "sched_switch\n"
						 "CPU %d: lat: %.3fus\n",
						 record->cpu,
						 (double)(record->ts -
							  task_info->display_wake_time) / 1000.0);
				task_info->display_wake_time = 0;
			} else {
				trace_seq_printf(s, "sched_switch\n"
						 "CPU %d\n",
						 record->cpu);
			}
		} else {
			trace_seq_printf(s, "sched_switch\n"
					 "CPU %d %s-%d\n",
					 record->cpu,
					 pevent_data_comm_from_pid(ginfo->pevent, pid),
					 pid);
		}
	} else {
			
		/* Must have the record we want */
		type = pevent_data_type(ginfo->pevent, record);
		event = pevent_data_event_from_type(ginfo->pevent, type);
		if (pid == rec_pid)
			trace_seq_printf(s, "CPU %d\n%s\n",
					 record->cpu, event->name);
		else
			trace_seq_printf(s, "%s-%d\n%s\n",
					 pevent_data_comm_from_pid(ginfo->pevent, rec_pid),
					 rec_pid, event->name);
	}
	free_record(record);

	return 1;
}

static void task_plot_start(struct graph_info *ginfo, struct graph_plot *plot,
			    unsigned long long time)
{
	struct task_plot_info *task_info = plot->private;

	memset(task_info->last_records, 0, sizeof(struct pevent_record *) * ginfo->cpus);

	task_info->last_time = 0ULL;
	task_info->last_cpu = -1;
	task_info->wake_time = 0ULL;
	task_info->display_wake_time = 0ULL;
}

static void update_last_record(struct graph_info *ginfo,
			       struct task_plot_info *task_info,
			       struct pevent_record *record)
{
	struct tracecmd_input *handle = ginfo->handle;
	struct pevent_record *trecord, *t2record;
	struct pevent_record *saved;
	unsigned long long ts;
	int sched_pid;
	int pid;
	int rec_pid;
	int is_wakeup;
	int is_sched;
	int this_cpu;
	int cpu;

	pid = task_info->pid;

	if (record) {
		ts = record->ts;
		this_cpu = record->cpu;
	} else {
		ts = ginfo->view_end_time;
		this_cpu = -1;
	}

	for (cpu = 0; cpu < ginfo->cpus; cpu++) {

		if (task_info->last_records[cpu])
			continue;

		if (cpu == this_cpu) {
			static int once;

			trecord = tracecmd_read_prev(handle, record);
			/* Set cpu cursor back to what it was  */
			saved = tracecmd_read_data(handle, cpu);
			if (!once && saved->offset != record->offset) {
				once++;
				warning("failed to reset cursor!");
			}
			free_record(saved);
		} else {
			static int once;

			saved = tracecmd_read_data(handle, cpu);
			set_cpu_to_time(cpu, ginfo, ts);
			t2record = tracecmd_read_data(handle, cpu);
			trecord = tracecmd_read_prev(handle, t2record);
			free_record(t2record);
			/* reset cursor back to what it was */
			if (saved) {
				tracecmd_set_cursor(handle, cpu, saved->offset);
				free_record(saved);
			} else {
				saved = tracecmd_read_data(handle, cpu);
				if (!once && saved) {
					once++;
					warning("failed to reset cursor to end!");
				}
				/* saved should always be NULL */
				free_record(saved);
			}
		}
		if (!trecord)
			continue;

		if (record_matches_pid(ginfo, trecord, pid, &rec_pid,
				       &sched_pid, &is_sched, &is_wakeup) &&
		    !is_wakeup &&
		    (!is_sched || (is_sched && sched_pid == pid))) {
			task_info->last_records[cpu] = trecord;
			task_info->last_cpu = trecord->cpu;
			task_info->last_time = trecord->ts;
			break;
		}

		free_record(trecord);
	}
}

static int task_plot_event(struct graph_info *ginfo,
			   struct graph_plot *plot,
			   struct pevent_record *record,
			   struct plot_info *info)
{
	struct task_plot_info *task_info = plot->private;
	gboolean match;
	int sched_pid;
	int rec_pid;
	int is_wakeup;
	int is_sched;
	int pid;
	int cpu;

	pid = task_info->pid;

	if (!record) {
		update_last_record(ginfo, task_info, record);
		/* no more records, finish a box if one was started */
		if (task_info->last_cpu >= 0) {
			info->box = TRUE;
			info->bstart = task_info->last_time;
			info->bend = ginfo->view_end_time;
			info->bcolor = hash_cpu(task_info->last_cpu);
		}
		for (cpu = 0; cpu < ginfo->cpus; cpu++) {
			free_record(task_info->last_records[cpu]);
			task_info->last_records[cpu] = NULL;
		}
		return 0;
	}

	match = record_matches_pid(ginfo, record, pid, &rec_pid,
				   &sched_pid, &is_sched, &is_wakeup);


	if (!match && record->cpu != task_info->last_cpu) {
		if (!task_info->last_records[record->cpu]) {
			task_info->last_records[record->cpu] = record;
			tracecmd_record_ref(record);
		}
		return 0;
	}

	if (match) {
		info->line = TRUE;
		info->lcolor = hash_pid(rec_pid);
		info->ltime = record->ts;

		/*
		 * Is this our first match?
		 *
		 * If last record is NULL, then it may exist off the
		 * viewable range. Search to see if one exists, and if
		 * it is the record we want to match.
		 */
		update_last_record(ginfo, task_info, record);

		if (is_wakeup) {
			/* Wake up but not task */
			info->ltime = hash_pid(rec_pid);

			/* Another task ? */
			if (task_info->last_cpu == record->cpu) {
				info->box = TRUE;
				info->bcolor = hash_cpu(task_info->last_cpu);
				info->bstart = task_info->last_time;
				info->bend = record->ts;
				task_info->last_cpu = -1;
			}

			task_info->wake_time = record->ts;
			task_info->wake_color = GREEN;
			task_info->display_wake_time = record->ts;

			return 1;
		}

		if (task_info->last_cpu != record->cpu) {
			if (task_info->last_cpu >= 0) {
				/* Switched CPUs */
				info->box = TRUE;
				info->bcolor = hash_cpu(task_info->last_cpu);
				info->bstart = task_info->last_time;
				info->bend = record->ts;
			}
			task_info->last_time = record->ts;
		}

		task_info->last_cpu = record->cpu;
		if (is_sched) {
			if (rec_pid != pid) {
				/* Just got scheduled in */
				task_info->last_cpu = record->cpu;
				task_info->last_time = record->ts;
				if (task_info->wake_time) {
					info->box = TRUE;
					info->bfill = FALSE;
					info->bstart = task_info->wake_time;
					info->bend = record->ts;
					info->bcolor = task_info->wake_color;
				} else
					task_info->wake_time = 0;

			} else if (!info->box) {
				/* just got scheduled out */
				info->box = TRUE;
				info->bcolor = hash_cpu(task_info->last_cpu);
				info->bstart = task_info->last_time;
				info->bend = record->ts;
				task_info->last_cpu = -1;
				if (is_running(ginfo, record)) {
					task_info->wake_time = record->ts;
					task_info->wake_color = RED;
				} else
					task_info->wake_time = 0;
			} else
				task_info->wake_time = 0;
		} else
			task_info->wake_time = 0;

		return 1;
	}

	cpu = record->cpu;

	if (!task_info->last_records[cpu]) {
		task_info->last_records[cpu] = record;
		tracecmd_record_ref(record);
	}
	/* not a match, and on the last CPU, scheduled out? */
	if (task_info->last_cpu >= 0) {
		info->box = TRUE;
		info->bcolor = hash_cpu(task_info->last_cpu);
		info->bstart = task_info->last_time;
		info->bend = record->ts;
		task_info->last_cpu = -1;
	}

	return 1;
}


static struct pevent_record *
task_plot_find_record(struct graph_info *ginfo, struct graph_plot *plot,
		      unsigned long long time)
{
	struct task_plot_info *task_info = plot->private;
	int pid;

	pid = task_info->pid;

	return find_record(ginfo, pid, time);
}

#define MAX_SEARCH 20

static struct pevent_record *
find_previous_record(struct graph_info *ginfo, struct pevent_record *start_record,
		     int pid, int cpu)
{
	struct pevent_record *last_record = start_record;
	struct pevent_record *record;
	gboolean match;
	gboolean is_sched;
	gboolean is_wakeup;
	gint rec_pid;
	gint sched_pid;
	int count = 0;

	if (last_record)
		last_record->ref_count++;
	else
		last_record = tracecmd_read_cpu_last(ginfo->handle, cpu);

	while ((record = tracecmd_read_prev(ginfo->handle, last_record))) {
		count++;

		match = record_matches_pid(ginfo, record, pid, &rec_pid,
					   &sched_pid, &is_sched, &is_wakeup);
		if (match)
			break;

		free_record(last_record);

		if (count > MAX_SEARCH) {
			free_record(record);
			return NULL;
		}
		last_record = record;
	}

	free_record(last_record);

	return record;
}

static struct pevent_record *
get_display_record(struct graph_info *ginfo, int pid, unsigned long long time)
{
	struct pevent_record *record;
	struct pevent_record **records;
	unsigned long long ts;
	int next_cpu;
	int cpu;

	record = find_record(ginfo, pid, time);

	/* If the time is right at this record, use it */
	if (record && record->ts < time + (1 / ginfo->resolution))
		return record;

	if (record) {
		tracecmd_set_cursor(ginfo->handle, record->cpu,
				    record->offset);
		free_record(record);
	}

	/* find a previous record */
	records = malloc_or_die(sizeof(*records) * ginfo->cpus);
	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		record = tracecmd_read_data(ginfo->handle, cpu);
		records[cpu] = find_previous_record(ginfo, record,
						    pid, cpu);
		free_record(record);
	}

	record = NULL;
	for (;;) {
		ts = 0;
		next_cpu = -1;

		for (cpu = 0; cpu < ginfo->cpus; cpu++) {
			if (!records[cpu])
				continue;
			if (records[cpu]->ts > ts) {
				ts = records[cpu]->ts;
				next_cpu = cpu;
			}
		}

		if (next_cpu < 0)
			break;

		if (records[next_cpu]->ts < time + (2 / ginfo->resolution)) {
			record = records[next_cpu];
			break;
		}

		record = find_previous_record(ginfo, records[next_cpu],
					      pid, next_cpu);
		free_record(records[next_cpu]);
		records[next_cpu] = record;
		record = NULL;
	}

	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		if (records[cpu] == record)
			continue;
		free_record(records[cpu]);
	}
	free(records);

	return record;
}

int task_plot_display_info(struct graph_info *ginfo,
			  struct graph_plot *plot,
			  struct trace_seq *s,
			  unsigned long long time)
{
	struct task_plot_info *task_info = plot->private;
	struct event_format *event;
	struct pevent_record *record;
	struct pevent *pevent;
	unsigned long sec, usec;
	const char *comm;
	int cpu;
	int type;
	int sched_pid = -1;
	int pid;

	pid = task_info->pid;
	record = get_display_record(ginfo, pid, time);
	if (!record)
		return 0;

	pevent = ginfo->pevent;

	pid = pevent_data_pid(ginfo->pevent, record);
	cpu = record->cpu;

	convert_nano(record->ts, &sec, &usec);

	if (record->ts > time - 2/ginfo->resolution &&
	    record->ts < time + 2/ginfo->resolution) {

		type = pevent_data_type(pevent, record);
		event = pevent_data_event_from_type(pevent, type);
		if (event) {
			trace_seq_puts(s, event->name);
			trace_seq_putc(s, '\n');
			pevent_data_lat_fmt(pevent, s, record);
			trace_seq_putc(s, '\n');
			pevent_event_info(s, event, record);
			trace_seq_putc(s, '\n');
		} else
			trace_seq_printf(s, "UNKNOW EVENT %d\n", type);
	}
	trace_graph_check_sched_switch(ginfo, record, &sched_pid, &comm);

	trace_seq_printf(s, "%lu.%06lu", sec, usec);
	if (pid == task_info->pid || sched_pid == task_info->pid)
		trace_seq_printf(s, " CPU: %03d", cpu);

	free_record(record);

	return 1;
}

void task_plot_destroy(struct graph_info *ginfo, struct graph_plot *plot)
{
	struct task_plot_info *task_info = plot->private;

	trace_graph_plot_remove_all_recs(ginfo, plot);

	free(task_info->last_records);
	free(task_info);
}

static const struct plot_callbacks task_plot_cb = {
	.match_time		= task_plot_match_time,
	.plot_event		= task_plot_event,
	.start			= task_plot_start,
	.display_last_event	= task_plot_display_last_event,
	.find_record		= task_plot_find_record,
	.display_info		= task_plot_display_info,
	.destroy		= task_plot_destroy
};

/**
 * graph_plot_task_plotted - return what tasks are plotted
 * @ginfo: the graph info structure
 * @plotted: returns an allocated array of gints holding the pids.
 *  the last pid is -1, NULL, if none are.
 *
 * @plotted must be freed with free() after this is called.
 */
void graph_plot_task_plotted(struct graph_info *ginfo,
			     gint **plotted)
{
	struct task_plot_info *task_info;
	struct graph_plot *plot;
	int count = 0;
	int i;

	*plotted = NULL;
	for (i = 0; i < ginfo->plots; i++) {
		plot = ginfo->plot_array[i];
		if (plot->type != PLOT_TYPE_TASK)
			continue;
		task_info = plot->private;
		trace_array_add(plotted, &count, task_info->pid);
	}
}

void graph_plot_task_update_callback(gboolean accept,
				     gint *selected,
				     gint *non_select,
				     gpointer data)
{
	struct graph_info *ginfo = data;
	struct task_plot_info *task_info;
	struct graph_plot *plot;
	gint select_size = 0;
	gint *ptr;
	int i;

	if (!accept)
		return;

	/* The selected and non_select are sorted */
	if (selected) {
		for (i = 0; selected[i] >= 0; i++)
			;
		select_size = i;
	}

	/*
	 * Remove and add task plots.
	 * Go backwards, since removing a plot shifts the
	 * array from current position back.
	 */
	for (i = ginfo->plots - 1; i >= 0; i--) {
		plot = ginfo->plot_array[i];
		if (plot->type != PLOT_TYPE_TASK)
			continue;
		/* If non are selected, then remove all */
		if (!select_size) {
			trace_graph_plot_remove(ginfo, plot);
			continue;
		}
		task_info = plot->private;
		ptr = bsearch(&task_info->pid, selected, select_size,
			      sizeof(gint), id_cmp);
		if (ptr) {
			/*
			 * This plot plot already exists, remove it
			 * from the selected array.
			 */
			memmove(ptr, ptr + 1,
				(unsigned long)(selected + select_size) -
				(unsigned long)(ptr + 1));
			select_size--;
			continue;
		}
		/* Remove the plot */
		trace_graph_plot_remove(ginfo, plot);
	}

	/* Now add any plots that need to be added */
	for (i = 0; i < select_size; i++)
		graph_plot_task(ginfo, selected[i], ginfo->plots);

	trace_graph_refresh(ginfo);
}

void graph_plot_init_tasks(struct graph_info *ginfo)
{
	struct task_plot_info *task_info;
	char label[100];
	struct pevent_record *record;
	int pid;

	/* Just for testing */
	record = tracecmd_read_cpu_first(ginfo->handle, 0);
	while (record) {
		pid = pevent_data_pid(ginfo->pevent, record);
		free_record(record);
		if (pid)
			break;
		record = tracecmd_read_data(ginfo->handle, 0);
	}

	task_info = malloc_or_die(sizeof(*task_info));
	task_info->last_records =
		malloc_or_die(sizeof(struct pevent_record *) * ginfo->cpus);
	task_info->pid = pid;

	snprintf(label, 100, "TASK %d", pid);
	trace_graph_plot_insert(ginfo, 1, label, PLOT_TYPE_TASK,
				&task_plot_cb, task_info);
}

void graph_plot_task(struct graph_info *ginfo, int pid, int pos)
{
	struct task_plot_info *task_info;
	struct graph_plot *plot;
	const char *comm;
	char *label;
	int len;

	task_info = malloc_or_die(sizeof(*task_info));
	task_info->last_records =
		malloc_or_die(sizeof(struct pevent_record *) * ginfo->cpus);
	task_info->pid = pid;
	comm = pevent_data_comm_from_pid(ginfo->pevent, pid);

	len = strlen(comm) + 100;
	label = malloc_or_die(len);
	snprintf(label, len, "%s-%d", comm, pid);
	plot = trace_graph_plot_insert(ginfo, pos, label, PLOT_TYPE_TASK,
				       &task_plot_cb, task_info);
	free(label);

	trace_graph_plot_add_all_recs(ginfo, plot);
}
