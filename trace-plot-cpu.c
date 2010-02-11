#include <string.h>

#include "trace-graph.h"

struct cpu_plot_info {
	int			cpu;
	unsigned long long	last_time;
	int			last_pid;
};

static gint hash_pid(gint val)
{
	/* idle always gets black */
	if (!val)
		return 0;

	return trace_hash(val);
}

static void convert_nano(unsigned long long time, unsigned long *sec,
			 unsigned long *usec)
{
	*sec = time / 1000000000ULL;
	*usec = (time / 1000) % 1000000;
}

static int cpu_plot_match_time(struct graph_info *ginfo, struct graph_plot *plot,
			       unsigned long long time)
{
	struct cpu_plot_info *cpu_info = plot->private;
	struct record *record;
	long cpu;
	int ret = 0;

	cpu = cpu_info->cpu;

	tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, time);
	record = tracecmd_read_data(ginfo->handle, cpu);
	while (record && record->ts < time) {
		free_record(record);
		record = tracecmd_read_data(ginfo->handle, cpu);
	}
	if (record && record->ts == time)
		ret = 1;
	free_record(record);

	return ret;
}

/*
 * Return 1 if we should skip record, otherwise 0
 *
 * @orig_pid gets the pid of the record
 * @sched_pid gets the pid of the record or if the record is
 *   a sched_switch, it gets the next task
 *   If it is a wakeup, then sched_pid gets the task being woken
 * @is_sched_switch returns 1 on context switch, otherwise 0
 */
static int filter_record(struct graph_info *ginfo,
			 struct record *record,
			 int *orig_pid, int *sched_pid,
			 gboolean *sched_switch)
{
	gboolean is_sched_switch;
	gboolean is_wakeup;
	const char *comm;
	int wake_pid;
	int filter;

	*orig_pid = pevent_data_pid(ginfo->pevent, record);

	filter = trace_graph_filter_on_task(ginfo, *orig_pid);

	if (trace_graph_check_sched_switch(ginfo, record, sched_pid, &comm)) {
		is_sched_switch = TRUE;

		/* Also show the task switching out */
		if (filter)
			filter = trace_graph_filter_on_task(ginfo, *sched_pid);

		if (ginfo->read_comms) {
			/*
			 * First time through, register any missing
			 *  comm / pid mappings.
			 */
			if (!pevent_pid_is_registered(ginfo->pevent, *sched_pid))
				pevent_register_comm(ginfo->pevent,
						     strdup(comm), *sched_pid);
		}
	} else
		*sched_pid = *orig_pid;

	if (filter) {
		/* Lets see if a filtered task is waking up */
		is_wakeup = trace_graph_check_sched_wakeup(ginfo, record, &wake_pid);
		if (is_wakeup) {
			filter = trace_graph_filter_on_task(ginfo, wake_pid);
			if (!filter)
				*sched_pid = wake_pid;
		}
	}

	*sched_switch = is_sched_switch;
	return filter;
}

static int cpu_plot_display_last_event(struct graph_info *ginfo,
				       struct graph_plot *plot,
				       struct trace_seq *s,
				       unsigned long long time)
{
	struct cpu_plot_info *cpu_info = plot->private;
	struct event_format *event;
	struct record *record;
	int cpu = cpu_info->cpu;
	unsigned long long offset = 0;
	gboolean is_sched_switch;
	int sched_pid;
	int pid;
	int type;

	/*
	 * Get the next record so we know can save its offset and
	 * reset the cursor, not to mess up the plotting
	 */
	record = tracecmd_peek_data(ginfo->handle, cpu);
	if (record)
		offset = record->offset;
	/* Don't need to free a peek */

	tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, time);

	/* find the non filtered event */
	while ((record = tracecmd_read_data(ginfo->handle, cpu))) {
		if (!filter_record(ginfo, record, &pid, &sched_pid, &is_sched_switch) &&
		    !trace_graph_filter_on_event(ginfo, record) &&
		    record->ts >= time)
			break;
		free_record(record);
	}

	if (offset)
		tracecmd_set_cursor(ginfo->handle, cpu, offset);

	if (!record)
		return 0;

	/* Must have the record we want */
	type = pevent_data_type(ginfo->pevent, record);
	event = pevent_data_event_from_type(ginfo->pevent, type);
	if (is_sched_switch)
		pid = sched_pid;
	trace_seq_printf(s, "%s-%d\n%s\n",
			 pevent_data_comm_from_pid(ginfo->pevent, pid),
			 pid, event->name);
	free_record(record);

	if (offset)
		return 1;

	/*
	 * We need to stop the iterator, read last record.
	 */
	record = tracecmd_read_cpu_last(ginfo->handle, cpu);
	free_record(record);

	return 1;
}

static void cpu_plot_start(struct graph_info *ginfo, struct graph_plot *plot,
			   unsigned long long time)
{
	struct cpu_plot_info *cpu_info = plot->private;
	struct record *last_record = NULL;
	struct record *record;
	int cpu;

	cpu = cpu_info->cpu;
	cpu_info->last_time = 0ULL;
	cpu_info->last_pid = -1;

	tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, time);

	while ((record = tracecmd_read_data(ginfo->handle, cpu))) {
		if (record->ts >= time)
			break;

		free_record(last_record);
		last_record = record;
	}

	free_record(record);
	/* reset so the next record read is the first record */
	if (last_record) {
		record = tracecmd_read_at(ginfo->handle,
					  last_record->offset,
					  NULL);
		free_record(record);
		free_record(last_record);
	} else
		tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, time);

}

static int cpu_plot_event(struct graph_info *ginfo,
			  struct graph_plot *plot,
			  struct record *record,
			  struct plot_info *info)
{
	struct cpu_plot_info *cpu_info = plot->private;
	int sched_pid;
	int orig_pid;
	int is_sched_switch;
	int filter;
	int box_filter;
	int pid;
	int cpu;
	int ret = 1;

	cpu = cpu_info->cpu;

	if (!record) {
		/* Finish a box if the last record was not idle */
		if (cpu_info->last_pid > 0) {
			info->box = TRUE;
			info->bstart = cpu_info->last_time;
			info->bend = ginfo->view_end_time;
		}
		return 0;
	}

	cpu = cpu_info->cpu;

	filter = filter_record(ginfo, record, &orig_pid, &sched_pid, &is_sched_switch);

	/* set pid to record, or next task on sched_switch */
	pid = is_sched_switch ? sched_pid : orig_pid;

	if (cpu_info->last_pid != pid) {

		if (cpu_info->last_pid < 0) {
			/* if we hit a sched switch, use the original pid for box*/
			if (is_sched_switch)
				cpu_info->last_pid = orig_pid;
			else
				cpu_info->last_pid = pid;
		}

		/* Box should always use the original pid (prev in sched_switch) */
		box_filter = trace_graph_filter_on_task(ginfo, orig_pid);

		if (!box_filter && cpu_info->last_pid) {
			info->bcolor = hash_pid(cpu_info->last_pid);
			info->box = TRUE;
			info->bstart = cpu_info->last_time;
			info->bend = record->ts;
		}

		cpu_info->last_time = record->ts;
	}

	if (!filter && !trace_graph_filter_on_event(ginfo, record)) {
		info->line = TRUE;
		info->ltime = record->ts;
		info->lcolor = hash_pid(pid);
	}

	cpu_info->last_pid = pid;

	if (record->ts > ginfo->view_end_time)
		ret = 0;

	return ret;
}

static struct record *
find_record_on_cpu(struct graph_info *ginfo, gint cpu, guint64 time)
{
	struct record *record = NULL;
	guint64 offset = 0;

	tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, time);
	do {
		if (record) {
			offset = record->offset;
			free_record(record);
		}
		record = tracecmd_read_data(ginfo->handle, cpu);
	} while (record && record->ts <= (time - 1 / ginfo->resolution));

	if (record) {
		if (record->ts > (time + 1 / ginfo->resolution) && offset) {
			free_record(record);
			record = tracecmd_read_at(ginfo->handle, offset, NULL);
		}
	}

	return record;
}

static struct record *
cpu_plot_find_record(struct graph_info *ginfo, struct graph_plot *plot,
		     unsigned long long time)
{
	struct cpu_plot_info *cpu_info = plot->private;
	int cpu;

	cpu = cpu_info->cpu;

	return find_record_on_cpu(ginfo, cpu, time);
}

int cpu_plot_display_info(struct graph_info *ginfo,
			  struct graph_plot *plot,
			  struct trace_seq *s,
			  unsigned long long time)
{
	struct cpu_plot_info *cpu_info = plot->private;
	struct event_format *event;
	struct record *record;
	struct pevent *pevent;
	unsigned long sec, usec;
	const char *comm;
	int type;
	int pid;
	int cpu;
	int ret = 0;

	cpu = cpu_info->cpu;

	record = find_record_on_cpu(ginfo, cpu, time);

	if (!record) {
		/* try last record */
		record = tracecmd_read_cpu_last(ginfo->handle, cpu);
		if (record && record->ts < time) {
			if (!trace_graph_check_sched_switch(ginfo, record, &pid, &comm)) {
				pid = pevent_data_pid(ginfo->pevent, record);
				comm = pevent_data_comm_from_pid(ginfo->pevent, pid);
			}

			trace_seq_printf(s, "%lu.%06lu", sec, usec);
			if (pid)
				trace_seq_printf(s, " %s-%d", comm, pid);
			else
				trace_seq_puts(s, " <idle>");
			ret = 1;
		}
		free_record(record);
		return ret;
	}

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

void cpu_plot_destroy(struct graph_info *ginfo, struct graph_plot *plot)
{
	struct cpu_plot_info *cpu_info = plot->private;

	trace_graph_plot_remove_cpu(ginfo, plot, cpu_info->cpu);
	free(cpu_info);
}

static const struct plot_callbacks cpu_plot_cb = {
	.match_time		= cpu_plot_match_time,
	.plot_event		= cpu_plot_event,
	.start			= cpu_plot_start,
	.display_last_event	= cpu_plot_display_last_event,
	.find_record		= cpu_plot_find_record,
	.display_info		= cpu_plot_display_info,
	.destroy		= cpu_plot_destroy
};

void graph_plot_init_cpus(struct graph_info *ginfo, int cpus)
{
	struct cpu_plot_info *cpu_info;
	struct graph_plot *plot;
	char label[100];
	long cpu;

	for (cpu = 0; cpu < cpus; cpu++) {
		cpu_info = malloc_or_die(sizeof(*cpu_info));
		cpu_info->cpu = cpu;

		snprintf(label, 100, "CPU %ld", cpu);

		plot = trace_graph_plot_append(ginfo, label, &cpu_plot_cb, cpu_info);
		trace_graph_plot_add_cpu(ginfo, plot, cpu);
	}
}
