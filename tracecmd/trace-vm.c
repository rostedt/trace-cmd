// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2008, 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 * Copyright (C) 2020, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>

#include "trace-local.h"
#include "trace-msg.h"

static struct trace_guest *guests;
static size_t guests_len;

static struct trace_guest *get_guest_by_cid(unsigned int guest_cid)
{
	int i;

	if (!guests)
		return NULL;

	for (i = 0; i < guests_len; i++)
		if (guest_cid == guests[i].cid)
			return guests + i;
	return NULL;
}

static struct trace_guest *get_guest_by_name(const char *name)
{
	int i;

	if (!guests)
		return NULL;

	for (i = 0; i < guests_len; i++)
		if (strcmp(name, guests[i].name) == 0)
			return guests + i;
	return NULL;
}

bool trace_have_guests_pid(void)
{
	for (int i = 0; i < guests_len; i++) {
		if (guests[i].pid < 0)
			return false;
	}

	return true;
}

/* Find all the tasks associated with the guest pid */
static void find_tasks(struct trace_guest *guest)
{
	struct dirent *dent;
	char *path;
	DIR *dir;
	int ret;
	int tasks = 0;

	ret = asprintf(&path, "/proc/%d/task", guest->pid);
	if (ret < 0)
		return;

	dir = opendir(path);
	free(path);
	if (!dir)
		return;

	while ((dent = readdir(dir))) {
		int *pids;
		if (!(dent->d_type == DT_DIR && is_digits(dent->d_name)))
			continue;
		pids = realloc(guest->task_pids, sizeof(int) * (tasks + 2));
		if (!pids)
			break;
		pids[tasks++] = strtol(dent->d_name, NULL, 0);
		pids[tasks] = -1;
		guest->task_pids = pids;
	}
	closedir(dir);
}

static void find_pid_by_cid(struct trace_guest *guest);

static struct trace_guest *add_guest(unsigned int cid, const char *name)
{
	struct trace_guest *guest;

	guests = realloc(guests, (guests_len + 1) * sizeof(*guests));
	if (!guests)
		die("allocating new guest");

	guest = &guests[guests_len++];

	memset(guest, 0, sizeof(*guest));
	guest->name = strdup(name);
	if (!guest->name)
		die("allocating guest name");
	guest->cid = cid;
	guest->pid = -1;

	find_pid_by_cid(guest);
	find_tasks(guest);

	return guest;
}

static struct tracefs_instance *start_trace_connect(void)
{
	struct tracefs_instance *open_instance;

	open_instance = tracefs_instance_create("vsock_find_pid");
	if (!open_instance)
		return NULL;

	tracefs_event_enable(open_instance, "sched", "sched_waking");
	tracefs_event_enable(open_instance, "kvm", "kvm_exit");
	tracefs_trace_on(open_instance);
	return open_instance;
}

struct pids {
	struct pids		*next;
	int			pid;
};

struct trace_fields {
	struct tep_event		*sched_waking;
	struct tep_event		*kvm_exit;
	struct tep_format_field		*common_pid;
	struct tep_format_field		*sched_next;
	struct pids			*pids;
	int				found_pid;
};

static void free_pids(struct pids *pids)
{
	struct pids *next;

	while (pids) {
		next = pids;
		pids = pids->next;
		free(next);
	}
}

static void add_pid(struct pids **pids, int pid)
{
	struct pids *new_pid;

	new_pid = malloc(sizeof(*new_pid));
	if (!new_pid)
		return;

	new_pid->pid = pid;
	new_pid->next = *pids;
	*pids = new_pid;
}

static bool match_pid(struct pids *pids, int pid)
{
	while (pids) {
		if (pids->pid == pid)
			return true;
		pids = pids->next;
	}
	return false;
}

static int callback(struct tep_event *event, struct tep_record *record, int cpu,
		    void *data)
{
	struct trace_fields *fields = data;
	struct tep_handle *tep = event->tep;
	unsigned long long val;
	int flags;
	int type;
	int pid;
	int ret;

	ret = tep_read_number_field(fields->common_pid, record->data, &val);
	if (ret < 0)
		return 0;

	flags = tep_data_flags(tep, record);

	/* Ignore events in interrupts */
	if (flags & (TRACE_FLAG_HARDIRQ | TRACE_FLAG_SOFTIRQ))
		return 0;

	/*
	 * First make sure that this event comes from a PID from
	 * this task (or a task woken by this task)
	 */
	pid = val;
	if (!match_pid(fields->pids, pid))
		return 0;

	type = tep_data_type(tep, record);

	/*
	 * If this event is a kvm_exit, we have our PID
	 * and we can stop processing.
	 */
	if (type == fields->kvm_exit->id) {
		fields->found_pid = pid;
		return -1;
	}

	if (type != fields->sched_waking->id)
		return 0;

	ret = tep_read_number_field(fields->sched_next, record->data, &val);
	if (ret < 0)
		return 0;

	/* This is a task woken by our task or a chain of wake ups */
	add_pid(&fields->pids, (int)val);
	return 0;
}

static int find_tgid(int pid)
{
	FILE *fp;
	char *path;
	char *buf = NULL;
	char *save;
	size_t l = 0;
	int tgid = -1;

	if (asprintf(&path, "/proc/%d/status", pid) < 0)
		return -1;

	fp = fopen(path, "r");
	free(path);
	if (!fp)
		return -1;

	while (getline(&buf, &l, fp) > 0) {
		char *tok;

		if (strncmp(buf, "Tgid:", 5) != 0)
			continue;
		tok = strtok_r(buf, ":", &save);
		if (!tok)
			continue;
		tok = strtok_r(NULL, ":", &save);
		if (!tok)
			continue;
		while (isspace(*tok))
			tok++;
		tgid = strtol(tok, NULL, 0);
		break;
	}
	free(buf);
	fclose(fp);

	return tgid;
}

static int stop_trace_connect(struct tracefs_instance *open_instance)
{
	const char *systems[] = { "kvm", "sched", NULL};
	struct tep_handle *tep;
	struct trace_fields trace_fields;
	int tgid = -1;

	if (!open_instance)
		return -1;

	/* The connection is finished, stop tracing, we have what we want */
	tracefs_trace_off(open_instance);
	tracefs_event_disable(open_instance, NULL, NULL);

	tep = tracefs_local_events_system(NULL, systems);

	trace_fields.sched_waking = tep_find_event_by_name(tep, "sched", "sched_waking");
	if (!trace_fields.sched_waking)
		goto out;
	trace_fields.kvm_exit = tep_find_event_by_name(tep, "kvm", "kvm_exit");
	if (!trace_fields.kvm_exit)
		goto out;
	trace_fields.common_pid = tep_find_common_field(trace_fields.sched_waking,
							"common_pid");
	if (!trace_fields.common_pid)
		goto out;
	trace_fields.sched_next = tep_find_any_field(trace_fields.sched_waking,
							"pid");
	if (!trace_fields.sched_next)
		goto out;

	trace_fields.found_pid = -1;
	trace_fields.pids = NULL;
	add_pid(&trace_fields.pids, getpid());
	tracefs_iterate_raw_events(tep, open_instance, NULL, 0, callback, &trace_fields);
	free_pids(trace_fields.pids);
 out:
	tracefs_instance_destroy(open_instance);
	tracefs_instance_free(open_instance);

	if (trace_fields.found_pid > 0)
		tgid = find_tgid(trace_fields.found_pid);

	return tgid;
}

/*
 * In order to find the guest that is associated to the given cid,
 * trace the sched_waking and kvm_exit events, connect to the cid
 * (doesn't matter what port, use -1 to not connect to anything)
 * and find what task gets woken up from this code and calls kvm_exit,
 * then that is the task that is running the guest.
 * Then look at the /proc/<guest-pid>/status file to find the task group
 * id (Tgid), and this is the PID of the task running all the threads.
 */
static void find_pid_by_cid(struct trace_guest *guest)
{
	struct tracefs_instance *instance;
	int fd;

	instance = start_trace_connect();
	fd = trace_vsock_open(guest->cid, -1);
	guest->pid = stop_trace_connect(instance);
	/* Just in case! */
	if (fd >= 0)
		close(fd);
}

struct trace_guest *trace_get_guest(unsigned int cid, const char *name)
{
	struct trace_guest *guest = NULL;

	if (name) {
		guest = get_guest_by_name(name);
		if (guest)
			return guest;
	}

	if (cid > 0) {
		guest = get_guest_by_cid(cid);
		if (!guest && name)
			guest = add_guest(cid, name);
	}
	return guest;
}

#define VM_CID_CMD	"virsh dumpxml"
#define VM_CID_LINE	"<cid auto="
#define VM_CID_ID	"address='"
static void read_guest_cid(char *name)
{
	char *cmd = NULL;
	char line[512];
	char *cid;
	unsigned int cid_id = 0;
	FILE *f;

	asprintf(&cmd, "%s %s", VM_CID_CMD, name);
	f = popen(cmd, "r");
	free(cmd);
	if (f == NULL)
		return;

	while (fgets(line, sizeof(line), f) != NULL) {
		if (!strstr(line, VM_CID_LINE))
			continue;
		cid = strstr(line, VM_CID_ID);
		if (!cid)
			continue;
		cid_id = strtol(cid + strlen(VM_CID_ID), NULL, 10);
		if ((cid_id == INT_MIN || cid_id == INT_MAX) && errno == ERANGE)
			continue;
		add_guest(cid_id, name);
		break;
	}

	/* close */
	pclose(f);
}

#define VM_NAME_CMD	"virsh list --name"
void read_qemu_guests(void)
{
	char name[256];
	FILE *f;

	f = popen(VM_NAME_CMD, "r");
	if (f == NULL)
		return;

	while (fgets(name, sizeof(name), f) != NULL) {
		if (name[0] == '\n')
			continue;
		if (name[strlen(name) - 1] == '\n')
			name[strlen(name) - 1] = '\0';
		read_guest_cid(name);
	}

	/* close */
	pclose(f);
}

int get_guest_vcpu_pid(unsigned int guest_cid, unsigned int guest_vcpu)
{
	int i;

	if (!guests)
		return -1;

	for (i = 0; i < guests_len; i++) {
		if (guests[i].cpu_pid < 0 || guest_vcpu >= guests[i].cpu_max)
			continue;
		if (guest_cid == guests[i].cid)
			return guests[i].cpu_pid[guest_vcpu];
	}
	return -1;
}

/**
 * trace_add_guest_info - Add the guest info into the trace file option
 * @handle: The file handle that the guest info option is added to
 * @instance: The instance that that represents the guest
 *
 * Adds information about the guest from the @instance into an option
 * for the @instance. It records the trace_id, the number of CPUs,
 * as well as the PIDs of the host that represent the CPUs.
 */
void
trace_add_guest_info(struct tracecmd_output *handle, struct buffer_instance *instance)
{
	unsigned long long trace_id;
	struct trace_guest *guest;
	const char *name;
	char *buf, *p;
	int cpus;
	int size;
	int pid;
	int i;

	if (is_network(instance)) {
		name = instance->name;
		cpus = instance->cpu_count;
		trace_id = instance->trace_id;
	} else {
		guest = trace_get_guest(instance->cid, NULL);
		if (!guest)
			return;
		cpus = guest->cpu_max;
		name = guest->name;
		/*
		 * If this is a proxy, the trace_id of the guest is
		 * in the guest descriptor (added in trace_tsync_as_host().
		 */
		if (guest->trace_id)
			trace_id = guest->trace_id;
		else
			trace_id = instance->trace_id;
	}

	size = strlen(name) + 1;
	size += sizeof(long long);	/* trace_id */
	size += sizeof(int);		/* cpu count */
	size += cpus * 2 * sizeof(int);	/* cpu,pid pair */

	buf = calloc(1, size);
	if (!buf)
		return;
	p = buf;
	strcpy(p, name);
	p += strlen(name) + 1;

	memcpy(p, &trace_id, sizeof(long long));
	p += sizeof(long long);

	memcpy(p, &cpus, sizeof(int));
	p += sizeof(int);
	for (i = 0; i < cpus; i++) {
		if (is_network(instance))
			pid = -1;
		else
			pid = guest->cpu_pid[i];
		memcpy(p, &i, sizeof(int));
		p += sizeof(int);
		memcpy(p, &pid, sizeof(int));
		p += sizeof(int);
	}

	tracecmd_add_option(handle, TRACECMD_OPTION_GUEST, size, buf);
	free(buf);
}
