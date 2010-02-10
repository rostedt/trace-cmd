#include <string.h>

#include "trace-graph.h"

struct task_plot_info {
	int			pid;
	struct cpu_data		*cpu_data;
	unsigned long long	last_time;
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
	return trace_hash(cpu + 124);
}

static gboolean record_matches_pid(struct graph_info *ginfo,
				   struct record *record, int match_pid,
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

	return FALSE;
}

static void set_cpus_to_time(struct graph_info *ginfo, unsigned long long time)
{
	struct record *record;
	int cpu;

	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
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
}

static int task_plot_match_time(struct graph_info *ginfo, struct graph_plot *plot,
			       unsigned long long time)
{
	struct task_plot_info *task_info = plot->private;
	struct record *record = NULL;
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
	struct record *record;
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
	struct record *record;
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

static struct record *
find_record(struct graph_info *ginfo, gint pid, guint64 time)
{
	struct record *record = NULL;
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
	struct record *record;
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

	set_cpus_to_time(ginfo, time);

	record = find_record(ginfo, pid, time);

	restore_offsets(ginfo, offsets);

	if (!record)
		return 0;

	record_matches_pid(ginfo, record, pid, &rec_pid,
			   &sched_pid, &is_sched, &is_wakeup);

	/* Must have the record we want */
	type = pevent_data_type(ginfo->pevent, record);
	event = pevent_data_event_from_type(ginfo->pevent, type);
	if (is_sched)
		pid = sched_pid;
	trace_seq_printf(s, "%s-%d\n%s\n",
			 pevent_data_comm_from_pid(ginfo->pevent, pid),
			 pid, event->name);
	free_record(record);

	return 1;
}

static void task_plot_start(struct graph_info *ginfo, struct graph_plot *plot,
			    unsigned long long time)
{
	struct task_plot_info *task_info = plot->private;

	set_cpus_to_time(ginfo, time);

	task_info->last_time = 0ULL;
	task_info->last_cpu = -1;
}

static int task_plot_event(struct graph_info *ginfo,
			   struct graph_plot *plot,
			   gboolean *line, int *lcolor,
			   unsigned long long *ltime,
			   gboolean *box, int *bcolor,
			   unsigned long long *bstart,
			   unsigned long long *bend)
{
	struct task_plot_info *task_info = plot->private;
	struct record *record = NULL;
	gboolean match;
	int next_cpu;
	int sched_pid;
	int rec_pid;
	int is_wakeup;
	int is_sched;
	int pid;

	pid = task_info->pid;

	do {
		free_record(record);

		record = tracecmd_read_next_data(ginfo->handle, &next_cpu);

		if (!record) {
			/* no more records, finish a box if one was started */
			if (task_info->last_cpu >= 0) {
				*box = TRUE;
				*bstart = task_info->last_time;
				*bend = ginfo->view_end_time;
				*bcolor = hash_cpu(task_info->last_cpu);
			}
			return 0;
		}

		match = record_matches_pid(ginfo, record, pid, &rec_pid,
					   &sched_pid, &is_sched, &is_wakeup);

	} while (!match && next_cpu != task_info->last_cpu);

	if (match) {
		*line = TRUE;
		*lcolor = hash_pid(rec_pid);
		*ltime = record->ts;

		if (is_wakeup) {
			/* Wake up but not task */
			*ltime = hash_pid(rec_pid);
			free_record(record);

			/* Another task ? */
			if (task_info->last_cpu == next_cpu) {
				*box = TRUE;
				*bcolor = hash_cpu(task_info->last_cpu);
				*bstart = task_info->last_time;
				*bend = record->ts;
				task_info->last_cpu = -1;
			}

			return 1;
		}

		if (task_info->last_cpu != next_cpu) {
			if (task_info->last_cpu >= 0) {
				/* Switched CPUs */
				*box = TRUE;
				*bcolor = hash_cpu(task_info->last_cpu);
				*bstart = task_info->last_time;
				*bend = record->ts;
			}
			task_info->last_time = record->ts;
		}

		task_info->last_cpu = next_cpu;
		if (is_sched) {
			if (rec_pid != pid) {
				/* Just got scheduled in */
				task_info->last_cpu = next_cpu;
				task_info->last_time = record->ts;
			} else if (!*box) {
				/* just got scheduled out */
				*box = TRUE;
				*bcolor = hash_cpu(task_info->last_cpu);
				*bstart = task_info->last_time;
				*bend = record->ts;
				task_info->last_cpu = -1;
			}
		}

		free_record(record);
		return 1;
	}

	/* not a match, and on the last CPU, scheduled out? */
	if (task_info->last_cpu >= 0) {
		*box = TRUE;
		*bcolor = hash_cpu(task_info->last_cpu);
		*bstart = task_info->last_time;
		*bend = record->ts;
		task_info->last_cpu = -1;
	}

	free_record(record);

	return 1;
}


static struct record *
task_plot_find_record(struct graph_info *ginfo, struct graph_plot *plot,
		      unsigned long long time)
{
	struct task_plot_info *task_info = plot->private;
	int pid;

	pid = task_info->pid;

	return find_record(ginfo, pid, time);
}

static struct record *
find_previous_record(struct graph_info *ginfo, struct record *start_record,
		     int pid, int cpu)
{
	struct record *last_record = start_record;
	struct record *record;
	gboolean match;
	gboolean is_sched;
	gboolean is_wakeup;
	gint rec_pid;
	gint sched_pid;

	if (!last_record)
		last_record = tracecmd_read_cpu_last(ginfo->handle, cpu);

	while ((record = tracecmd_read_prev(ginfo->handle, last_record))) {

		match = record_matches_pid(ginfo, record, pid, &rec_pid,
					   &sched_pid, &is_sched, &is_wakeup);
		if (match)
			break;

		if (last_record != start_record)
			free_record(last_record);
		last_record = record;
	}

	if (last_record != start_record)
		free_record(last_record);

	return record;
}

static struct record *
get_display_record(struct graph_info *ginfo, int pid, unsigned long long time)
{
	struct record *record;
	struct record **records;
	unsigned long long ts;
	int next_cpu;
	int cpu;

	set_cpus_to_time(ginfo, time);
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
		records[cpu] = find_previous_record(ginfo, record, pid, cpu);
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

		record = find_previous_record(ginfo, records[next_cpu], pid, next_cpu);
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
	struct record *record;
	struct pevent *pevent;
	unsigned long sec, usec;
	const char *comm;
	int type;
	int pid;

	pid = task_info->pid;
	record = get_display_record(ginfo, pid, time);
	if (!record)
		return 0;

	pevent = ginfo->pevent;

	pid = pevent_data_pid(ginfo->pevent, record);
	comm = pevent_data_comm_from_pid(ginfo->pevent, pid);

	if (record->ts > time - 2/ginfo->resolution &&
	    record->ts < time + 2/ginfo->resolution) {

		convert_nano(record->ts, &sec, &usec);

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
	} else {
		if (record->ts < time)
			trace_graph_check_sched_switch(ginfo, record, &pid, &comm);
	}

	trace_seq_printf(s, "%lu.%06lu", sec, usec);
	if (pid)
		trace_seq_printf(s, " %s-%d", comm, pid);
	else
		trace_seq_puts(s, " <idle>");

	free_record(record);

	return 1;
}

static const struct plot_callbacks task_plot_cb = {
	.match_time		= task_plot_match_time,
	.plot_event		= task_plot_event,
	.start			= task_plot_start,
	.display_last_event	= task_plot_display_last_event,
	.find_record		= task_plot_find_record,
	.display_info		= task_plot_display_info,
};

void graph_plot_init_tasks(struct graph_info *ginfo)
{
	struct task_plot_info *task_info;
	char label[100];
	struct record *record;
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
	task_info->pid = pid;

	snprintf(label, 100, "TASK %d", pid);
	trace_graph_plot_insert(ginfo, 1, label, &task_plot_cb, task_info);
}
