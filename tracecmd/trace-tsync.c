// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Google Inc, Steven Rostedt <rostedt@goodmis.org>
 * Copyright (C) 2020, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdio.h>
#include <stdlib.h>

#include "trace-local.h"
#include "trace-msg.h"

struct trace_mapping {
	struct tep_event		*kvm_entry;
	struct tep_format_field		*vcpu_id;
	struct tep_format_field		*common_pid;
	int				*pids;
	int				*map;
	int				*vcpu;
	int				max_cpus;
};

static int cmp_tmap_vcpu(const void *A, const void *B)
{
	const int *a = A;
	const int *b = B;

	if (*a < *b)
		return -1;
	return *a > *b;
}

static int map_kvm_vcpus(int guest_pid, struct trace_mapping *tmap)
{
	struct dirent *entry;
	const char *debugfs;
	char *vm_dir_str = NULL;
	char *pid_file = NULL;
	char *kvm_dir;
	int pid_file_len;
	bool found = false;
	DIR *dir;
	int ret = -1;
	int i;

	tmap->vcpu = malloc(sizeof(*tmap->vcpu) * tmap->max_cpus);
	if (!tmap->vcpu)
		return -1;

	memset(tmap->vcpu, -1, sizeof(*tmap->vcpu) * tmap->max_cpus);

	debugfs = tracefs_debug_dir();
	if (!debugfs)
		return -1;

	if (asprintf(&kvm_dir, "%s/kvm", debugfs) < 0)
		return -1;

	dir = opendir(kvm_dir);
	if (!dir)
		goto out;

	if (asprintf(&pid_file, "%d-", guest_pid) <= 0)
		goto out;

	pid_file_len = strlen(pid_file);

	while ((entry = readdir(dir))) {
		if (entry->d_type != DT_DIR ||
		    strncmp(entry->d_name, pid_file, pid_file_len) != 0)
			continue;
		if (asprintf(&vm_dir_str, "%s/%s", kvm_dir, entry->d_name) < 0)
			goto out;
		found = true;
		break;
	}
	if (!found)
		goto out;

	closedir(dir);
	dir = opendir(vm_dir_str);
	if (!dir)
		goto out;
	i = 0;
	while ((entry = readdir(dir))) {
		if (entry->d_type != DT_DIR ||
		    strncmp(entry->d_name, "vcpu", 4))
			continue;
		if (i == tmap->max_cpus)
			goto out;
		tmap->vcpu[i] = strtol(entry->d_name + 4, NULL, 10);
		i++;
	}

	if (i < tmap->max_cpus)
		goto out;

	qsort(tmap->vcpu, tmap->max_cpus, sizeof(*tmap->vcpu), cmp_tmap_vcpu);

	ret = 0;

 out:
	if (dir)
		closedir(dir);
	free(vm_dir_str);
	free(pid_file);
	free(kvm_dir);

	return ret;
}

static int map_vcpus(struct tep_event *event, struct tep_record *record,
		     int cpu, void *context)
{
	struct trace_mapping *tmap = context;
	unsigned long long val;
	int *vcpu;
	int type;
	int pid;
	int ret;
	int i;

	/* Do we have junk in the buffer? */
	type = tep_data_type(event->tep, record);
	if (type != tmap->kvm_entry->id)
		return 0;

	ret = tep_read_number_field(tmap->common_pid, record->data, &val);
	if (ret < 0)
		return 0;
	pid = (int)val;

	for (i = 0; tmap->pids[i] >= 0; i++) {
		if (pid == tmap->pids[i])
			break;
	}
	/* Is this thread one we care about ? */
	if (tmap->pids[i] < 0)
		return 0;

	ret = tep_read_number_field(tmap->vcpu_id, record->data, &val);
	if (ret < 0)
		return 0;

	cpu = (int)val;

	vcpu = bsearch(&cpu, tmap->vcpu, tmap->max_cpus, sizeof(cpu), cmp_tmap_vcpu);
	/* Sanity check, warn? */
	if (!vcpu)
		return 0;

	cpu = vcpu - tmap->vcpu;

	/* Already have this one? Should we check if it is the same? */
	if (tmap->map[cpu] >= 0)
		return 0;

	tmap->map[cpu] = pid;

	/* Did we get them all */
	for (i = 0; i < tmap->max_cpus; i++) {
		if (tmap->map[i] < 0)
			break;
	}

	return i == tmap->max_cpus;
}

static void start_mapping_vcpus(struct trace_guest *guest)
{
	char *pids = NULL;
	char *t;
	int len = 0;
	int s;
	int i;

	if (!guest->task_pids)
		return;

	guest->instance = tracefs_instance_create("map_guest_pids");
	if (!guest->instance)
		return;

	for (i = 0; guest->task_pids[i] >= 0; i++) {
		s = snprintf(NULL, 0, "%d ", guest->task_pids[i]);
		t = realloc(pids, len + s + 1);
		if (!t) {
			free(pids);
			pids = NULL;
			break;
		}
		pids = t;
		sprintf(pids + len, "%d ", guest->task_pids[i]);
		len += s;
	}
	if (pids) {
		tracefs_instance_file_write(guest->instance, "set_event_pid", pids);
		free(pids);
	}
	tracefs_instance_file_write(guest->instance, "events/kvm/kvm_entry/enable", "1");
}

static void stop_mapping_vcpus(int cpu_count, struct trace_guest *guest)
{
	struct trace_mapping tmap = { };
	struct tep_handle *tep;
	const char *systems[] = { "kvm", NULL };
	int i;

	if (!guest->instance)
		return;

	tmap.pids = guest->task_pids;
	tmap.max_cpus = cpu_count;

	tmap.map = malloc(sizeof(*tmap.map) * tmap.max_cpus);
	if (!tmap.map)
		return;

	/* Check if the kvm vcpu mappings are the same */
	if (map_kvm_vcpus(guest->pid, &tmap) < 0)
		goto out;

	for (i = 0; i < tmap.max_cpus; i++)
		tmap.map[i] = -1;

	tracefs_instance_file_write(guest->instance, "events/kvm/kvm_entry/enable", "0");

	tep = tracefs_local_events_system(NULL, systems);
	if (!tep)
		goto out;

	tmap.kvm_entry = tep_find_event_by_name(tep, "kvm", "kvm_entry");
	if (!tmap.kvm_entry)
		goto out_free;

	tmap.vcpu_id = tep_find_field(tmap.kvm_entry, "vcpu_id");
	if (!tmap.vcpu_id)
		goto out_free;

	tmap.common_pid = tep_find_any_field(tmap.kvm_entry, "common_pid");
	if (!tmap.common_pid)
		goto out_free;

	tracefs_iterate_raw_events(tep, guest->instance, NULL, 0, map_vcpus, &tmap);

	for (i = 0; i < tmap.max_cpus; i++) {
		if (tmap.map[i] < 0)
			break;
	}
	/* We found all the mapped CPUs */
	if (i == tmap.max_cpus) {
		guest->cpu_pid = tmap.map;
		guest->cpu_max = tmap.max_cpus;
		tmap.map = NULL;
	}

 out_free:
	tep_free(tep);
 out:
	free(tmap.map);
	tracefs_instance_destroy(guest->instance);
	tracefs_instance_free(guest->instance);
}

/**
 * trace_tsync_as_host - tsync from the host side
 * @fd: The descriptor to the peer for tsync
 * @trace_id: The trace_id of the host
 * @loop_interval: The loop interval for tsyncs that do periodic syncs
 * @guest_id: The id for guests (negative if this is over network)
 * @guest_cpus: The number of CPUs the guest has
 * @proto_name: The protocol name to sync with
 * @clock: The clock name to use for tracing
 *
 * Start the time synchronization from the host side.
 * This will start the mapping of the virtual CPUs to host threads
 * if it is a vsocket connection (not a network).
 *
 * Returns a pointer to the tsync descriptor on success or NULL on error.
 */
struct tracecmd_time_sync *
trace_tsync_as_host(int fd, unsigned long long trace_id,
		    int loop_interval, int guest_id,
		    int guest_cpus, const char *proto_name,
		    const char *clock)
{
	struct tracecmd_time_sync *tsync;
	struct trace_guest *guest;
	int guest_pid = -1;

	if (fd < 0)
		return NULL;

	if (guest_id >= 0) {
		guest = trace_get_guest(guest_id, NULL);
		if (guest == NULL)
			return NULL;
		guest_pid = guest->pid;
		start_mapping_vcpus(guest);
	}

	tsync = tracecmd_tsync_with_guest(trace_id, loop_interval, fd,
					  guest_pid, guest_cpus, proto_name,
					  clock);

	if (guest_id >= 0)
		stop_mapping_vcpus(guest_cpus, guest);

	return tsync;
}

/**
 * trace_tsync_a_guest - tsync from the guest side
 * @fd: The file descriptor to the peer for tsync
 * @tsync_proto: The protocol name to sync with
 * @clock: The clock name to use for tracing
 * @remote_id: The id to differentiate the remote server with
 * @loca_id: The id to differentiate the local machine with
 *
 * Start the time synchronization from the guest side.
 *
 * Returns a pointer to the tsync descriptor on success or NULL on error.
 */
struct tracecmd_time_sync *
trace_tsync_as_guest(int fd, const char *tsync_proto, const char *clock,
	       unsigned int remote_id, unsigned int local_id)
{
	struct tracecmd_time_sync *tsync = NULL;

	if (fd < 0)
		 return NULL;

	tsync = tracecmd_tsync_with_host(fd, tsync_proto,
					 clock, remote_id, local_id);
	if (!tsync) {
		warning("Failed to negotiate timestamps synchronization with the host");
		return NULL;
	}

	return tsync;
}
