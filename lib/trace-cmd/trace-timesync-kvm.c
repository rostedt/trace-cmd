// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2020, VMware, Tzvetomir Stoyanov tz.stoyanov@gmail.com>
 *
 */

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>

#include "trace-cmd.h"
#include "trace-cmd-private.h"
#include "tracefs.h"
#include "trace-tsync-local.h"

#define KVM_DEBUG_FS "/sys/kernel/debug/kvm"
#define KVM_DEBUG_OFFSET_FILE	"tsc-offset"
#define KVM_DEBUG_SCALING_FILE	"tsc-scaling-ratio"
#define KVM_DEBUG_FRACTION_FILE	"tsc-scaling-ratio-frac-bits"
#define KVM_DEBUG_VCPU_DIR	"vcpu"

/* default KVM scaling values, taken from the Linux kernel */
#define KVM_SCALING_AMD_DEFAULT		(1ULL<<32)
#define KVM_SCALING_INTEL_DEFAULT	(1ULL<<48)

#define KVM_SYNC_PKT_REQUEST	1
#define KVM_SYNC_PKT_RESPONSE	2

typedef __s64 s64;

#define KVM_ACCURACY	0
#define KVM_NAME	"kvm"

struct kvm_clock_sync {
	int vcpu_count;
	char **vcpu_offsets;
	char **vcpu_scalings;
	char **vcpu_frac;
	int marker_fd;
	struct tep_handle *tep;
	int raw_id;
	unsigned long long ts;
};

struct kvm_clock_offset_msg {
	s64	ts;
	s64	offset;
	s64	scaling;
	s64	frac;
};

static int read_ll_from_file(char *file, long long *res)
{
	char buf[32];
	int ret;
	int fd;

	if (!file)
		return -1;
	fd = open(file, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return -1;
	ret = read(fd, buf, 32);
	close(fd);
	if (ret <= 0)
		return -1;

	*res = strtoll(buf, NULL, 0);

	return 0;
}

static bool kvm_scaling_check_vm_cpu(char *vname, char *cpu)
{
	long long scaling, frac;
	bool has_scaling = false;
	bool has_frac = false;
	char *path;
	int ret;

	if (asprintf(&path, "%s/%s/%s", vname, cpu, KVM_DEBUG_SCALING_FILE) < 0)
		return false;
	ret = read_ll_from_file(path, &scaling);
	free(path);
	if (!ret)
		has_scaling = true;

	if (asprintf(&path, "%s/%s/%s", vname, cpu, KVM_DEBUG_FRACTION_FILE) < 0)
		return false;
	ret = read_ll_from_file(path, &frac);
	free(path);
	if (!ret)
		has_frac = true;

	if (has_scaling != has_frac)
		return false;

	return true;
}

static bool kvm_scaling_check_vm(char *name)
{
	struct dirent *entry;
	char *vdir;
	DIR *dir;

	if (asprintf(&vdir, "%s/%s", KVM_DEBUG_FS, name) < 0)
		return true;

	dir = opendir(vdir);
	if (!dir) {
		free(vdir);
		return true;
	}
	while ((entry = readdir(dir))) {
		if (entry->d_type == DT_DIR && !strncmp(entry->d_name, "vcpu", 4) &&
		    !kvm_scaling_check_vm_cpu(vdir, entry->d_name))
			break;
	}

	closedir(dir);
	free(vdir);
	return entry == NULL;
}
static bool kvm_scaling_check(void)
{
	struct dirent *entry;
	DIR *dir;

	dir = opendir(KVM_DEBUG_FS);
	if (!dir)
		return true;

	while ((entry = readdir(dir))) {
		if (entry->d_type == DT_DIR && isdigit(entry->d_name[0]) &&
		    !kvm_scaling_check_vm(entry->d_name))
			break;
	}
	closedir(dir);
	return entry == NULL;
}

static bool kvm_support_check(bool guest)
{
	struct stat st;
	int ret;

	if (guest)
		return true;

	ret = stat(KVM_DEBUG_FS, &st);
	if (ret < 0)
		return false;

	if (!S_ISDIR(st.st_mode))
		return false;

	return kvm_scaling_check();
}

static int kvm_open_vcpu_dir(struct kvm_clock_sync *kvm, int cpu, char *dir_str)
{
	struct dirent *entry;
	char path[PATH_MAX];
	DIR *dir;

	dir = opendir(dir_str);
	if (!dir)
		goto error;
	while ((entry = readdir(dir))) {
		if (entry->d_type != DT_DIR) {
			if (!strcmp(entry->d_name, KVM_DEBUG_OFFSET_FILE)) {
				snprintf(path, sizeof(path), "%s/%s",
					 dir_str, entry->d_name);
				kvm->vcpu_offsets[cpu] = strdup(path);
			}
			if (!strcmp(entry->d_name, KVM_DEBUG_SCALING_FILE)) {
				snprintf(path, sizeof(path), "%s/%s",
					 dir_str, entry->d_name);
				kvm->vcpu_scalings[cpu] = strdup(path);
			}
			if (!strcmp(entry->d_name, KVM_DEBUG_FRACTION_FILE)) {
				snprintf(path, sizeof(path), "%s/%s",
					 dir_str, entry->d_name);
				kvm->vcpu_frac[cpu] = strdup(path);
			}
		}
	}
	if (!kvm->vcpu_offsets[cpu])
		goto error;
	closedir(dir);
	return 0;

error:
	if (dir)
		closedir(dir);
	free(kvm->vcpu_offsets[cpu]);
	kvm->vcpu_offsets[cpu] = NULL;
	free(kvm->vcpu_scalings[cpu]);
	kvm->vcpu_scalings[cpu] = NULL;
	free(kvm->vcpu_frac[cpu]);
	kvm->vcpu_frac[cpu] = NULL;
	return -1;
}

static int kvm_open_debug_files(struct kvm_clock_sync *kvm, int pid)
{
	char *vm_dir_str = NULL;
	struct dirent *entry;
	char *pid_str = NULL;
	char path[PATH_MAX];
	long vcpu;
	DIR *dir;
	int i;

	dir = opendir(KVM_DEBUG_FS);
	if (!dir)
		goto error;
	if (asprintf(&pid_str, "%d-", pid) <= 0)
		goto error;
	while ((entry = readdir(dir))) {
		if (!(entry->d_type == DT_DIR &&
		    !strncmp(entry->d_name, pid_str, strlen(pid_str))))
			continue;
		asprintf(&vm_dir_str, "%s/%s", KVM_DEBUG_FS, entry->d_name);
		break;
	}
	closedir(dir);
	dir = NULL;
	if (!vm_dir_str)
		goto error;
	dir = opendir(vm_dir_str);
	if (!dir)
		goto error;
	while ((entry = readdir(dir))) {
		if (!(entry->d_type == DT_DIR &&
		    !strncmp(entry->d_name, KVM_DEBUG_VCPU_DIR, strlen(KVM_DEBUG_VCPU_DIR))))
			continue;
		vcpu =  strtol(entry->d_name + strlen(KVM_DEBUG_VCPU_DIR), NULL, 10);
		if (vcpu < 0 || vcpu >= kvm->vcpu_count)
			continue;
		snprintf(path, sizeof(path), "%s/%s", vm_dir_str, entry->d_name);
		if (kvm_open_vcpu_dir(kvm, vcpu, path) < 0)
			goto error;
	}
	for (i = 0; i < kvm->vcpu_count; i++) {
		if (!kvm->vcpu_offsets[i])
			goto error;
	}
	closedir(dir);
	free(pid_str);
	free(vm_dir_str);
	return 0;
error:
	free(pid_str);
	free(vm_dir_str);
	if (dir)
		closedir(dir);
	return -1;
}

static int kvm_clock_sync_init_host(struct tracecmd_time_sync *tsync,
				    struct kvm_clock_sync *kvm)
{
	kvm->vcpu_count = tsync->vcpu_count;
	kvm->vcpu_offsets = calloc(kvm->vcpu_count, sizeof(char *));
	kvm->vcpu_scalings = calloc(kvm->vcpu_count, sizeof(char *));
	kvm->vcpu_frac = calloc(kvm->vcpu_count, sizeof(char *));
	if (!kvm->vcpu_offsets || !kvm->vcpu_scalings || !kvm->vcpu_frac)
		goto error;
	if (kvm_open_debug_files(kvm, tsync->guest_pid) < 0)
		goto error;
	return 0;

error:
	free(kvm->vcpu_offsets);
	free(kvm->vcpu_scalings);
	free(kvm->vcpu_frac);
	return -1;
}

static int kvm_clock_sync_init_guest(struct tracecmd_time_sync *tsync,
				     struct kvm_clock_sync *kvm)
{
	const char *systems[] = {"ftrace", NULL};
	struct clock_sync_context *clock_context;
	struct tep_event *raw;
	char *path;

	clock_context = (struct clock_sync_context *)tsync->context;
	path = tracefs_instance_get_dir(clock_context->instance);
	if (!path)
		goto error;
	kvm->tep = tracefs_local_events_system(path, systems);
	tracefs_put_tracing_file(path);
	if (!kvm->tep)
		goto error;
	raw = tep_find_event_by_name(kvm->tep, "ftrace", "raw_data");
	if (!raw)
		goto error;

	kvm->raw_id = raw->id;
	tep_set_file_bigendian(kvm->tep, tracecmd_host_bigendian());
	tep_set_local_bigendian(kvm->tep, tracecmd_host_bigendian());

	path = tracefs_instance_get_file(clock_context->instance, "trace_marker_raw");
	if (!path)
		goto error;
	kvm->marker_fd = open(path, O_WRONLY);
	tracefs_put_tracing_file(path);

	return 0;

error:
	if (kvm->tep)
		tep_free(kvm->tep);
	if (kvm->marker_fd >= 0)
		close(kvm->marker_fd);

	return -1;
}

static int kvm_clock_sync_init(struct tracecmd_time_sync *tsync)
{
	struct clock_sync_context *clock_context;
	struct kvm_clock_sync *kvm;
	int ret;

	if (!tsync || !tsync->context)
		return -1;
	clock_context = (struct clock_sync_context *)tsync->context;

	if (!kvm_support_check(clock_context->is_guest))
		return -1;
	kvm = calloc(1, sizeof(struct kvm_clock_sync));
	if (!kvm)
		return -1;
	kvm->marker_fd = -1;
	if (clock_context->is_guest)
		ret = kvm_clock_sync_init_guest(tsync, kvm);
	else
		ret = kvm_clock_sync_init_host(tsync, kvm);
	if (ret < 0)
		goto error;

	clock_context->proto_data = kvm;
	return 0;

error:
	free(kvm);
	return -1;
}

static int kvm_clock_sync_free(struct tracecmd_time_sync *tsync)
{
	struct clock_sync_context *clock_context;
	struct kvm_clock_sync *kvm = NULL;
	int i;

	clock_context = (struct clock_sync_context *)tsync->context;
	if (clock_context)
		kvm = (struct kvm_clock_sync *)clock_context->proto_data;
	if (kvm) {
		for (i = 0; i < kvm->vcpu_count; i++) {
			free(kvm->vcpu_offsets[i]);
			kvm->vcpu_offsets[i] = NULL;
			free(kvm->vcpu_scalings[i]);
			kvm->vcpu_scalings[i] = NULL;
			free(kvm->vcpu_frac[i]);
			kvm->vcpu_frac[i] = NULL;
		}
		if (kvm->tep)
			tep_free(kvm->tep);
		if (kvm->marker_fd >= 0)
			close(kvm->marker_fd);
		free(kvm);
	}
	return -1;
}

static int kvm_clock_host(struct tracecmd_time_sync *tsync,
			  long long *offset, long long *scaling, long long *frac,
			  long long *timestamp, unsigned int cpu)
{
	char sync_proto[TRACECMD_TSYNC_PNAME_LENGTH];
	struct clock_sync_context *clock_context;
	struct kvm_clock_offset_msg packet;
	struct kvm_clock_sync *kvm = NULL;
	long long kvm_scaling = 1;
	unsigned int sync_msg;
	long long kvm_offset;
	long long kvm_frac = 0;
	unsigned int size;
	char *msg;
	int ret;

	clock_context = (struct clock_sync_context *)tsync->context;
	if (clock_context)
		kvm = (struct kvm_clock_sync *)clock_context->proto_data;
	if (!kvm || !kvm->vcpu_offsets || !kvm->vcpu_offsets[0])
		return -1;
	if (cpu >= kvm->vcpu_count)
		return -1;
	ret = read_ll_from_file(kvm->vcpu_offsets[cpu], &kvm_offset);
	if (ret < 0)
		return -1;

	if (kvm->vcpu_scalings && kvm->vcpu_scalings[cpu]) {
		read_ll_from_file(kvm->vcpu_scalings[cpu], &kvm_scaling);
		if (kvm_scaling == KVM_SCALING_AMD_DEFAULT ||
		    kvm_scaling == KVM_SCALING_INTEL_DEFAULT)
			kvm_scaling = 1;
	}

	if (kvm->vcpu_frac && kvm->vcpu_frac[cpu] && kvm_scaling != 1)
		ret = read_ll_from_file(kvm->vcpu_frac[cpu], &kvm_frac);
	msg = (char *)&packet;
	size = sizeof(packet);
	ret = tracecmd_msg_recv_time_sync(tsync->msg_handle,
					  sync_proto, &sync_msg,
					  &size, &msg);
	if (ret || strncmp(sync_proto, KVM_NAME, TRACECMD_TSYNC_PNAME_LENGTH) ||
	    sync_msg != KVM_SYNC_PKT_REQUEST)
		return -1;

	packet.offset = -kvm_offset;
	packet.scaling = kvm_scaling;
	packet.frac = kvm_frac;
	ret = tracecmd_msg_send_time_sync(tsync->msg_handle, KVM_NAME,
					  KVM_SYNC_PKT_RESPONSE, sizeof(packet),
					  (char *)&packet);
	if (ret)
		return -1;

	*scaling = packet.scaling;
	*offset = packet.offset;
	*frac = kvm_frac;
	*timestamp = packet.ts;

	return 0;
}

#define KVM_EVENT_MARKER	"kvm sync event"
static int kvm_marker_find(struct tep_event *event, struct tep_record *record,
			   int cpu, void *context)
{
	struct kvm_clock_sync *kvm = (struct kvm_clock_sync *)context;
	struct tep_format_field *field;
	struct tep_format_field *id;
	char *marker;

	/* Make sure this is our event */
	if (event->id != kvm->raw_id)
		return 0;
	id = tep_find_field(event, "id");
	field = tep_find_field(event, "buf");
	if (field && id &&
	    record->size >= (id->offset + strlen(KVM_EVENT_MARKER) + 1)) {
		marker = (char *)(record->data + id->offset);
		if (!strcmp(marker, KVM_EVENT_MARKER)) {
			kvm->ts = record->ts;
			return 1;
		}
	}

	return 0;
}

static int kvm_clock_guest(struct tracecmd_time_sync *tsync,
			   long long *offset,
			   long long *scaling,
			   long long *frac,
			   long long *timestamp)
{
	char sync_proto[TRACECMD_TSYNC_PNAME_LENGTH];
	struct clock_sync_context *clock_context;
	struct kvm_clock_offset_msg packet;
	struct kvm_clock_sync *kvm = NULL;
	unsigned int sync_msg;
	unsigned int size;
	char *msg;
	int ret;

	clock_context = (struct clock_sync_context *)tsync->context;
	if (clock_context)
		kvm = (struct kvm_clock_sync *)clock_context->proto_data;
	if (!kvm)
		return -1;
	kvm->ts = 0;
	memset(&packet, 0, sizeof(packet));
	tracefs_instance_file_write(clock_context->instance, "trace", "\0");
	write(kvm->marker_fd, KVM_EVENT_MARKER, strlen(KVM_EVENT_MARKER) + 1);
	kvm->ts = 0;
	tracefs_iterate_raw_events(kvm->tep, clock_context->instance,
				   NULL, 0, kvm_marker_find, kvm);
	packet.ts = kvm->ts;
	ret = tracecmd_msg_send_time_sync(tsync->msg_handle, KVM_NAME,
					  KVM_SYNC_PKT_REQUEST, sizeof(packet),
					  (char *)&packet);
	if (ret)
		return -1;
	msg = (char *)&packet;
	size = sizeof(packet);
	ret = tracecmd_msg_recv_time_sync(tsync->msg_handle,
					  sync_proto, &sync_msg,
					  &size, &msg);
	if (ret || strncmp(sync_proto, KVM_NAME, TRACECMD_TSYNC_PNAME_LENGTH) ||
	    sync_msg != KVM_SYNC_PKT_RESPONSE)
		return -1;

	*scaling = packet.scaling;
	*offset = packet.offset;
	*frac = packet.frac;
	*timestamp = packet.ts;
	return 0;
}

static int kvm_clock_sync_calc(struct tracecmd_time_sync *tsync,
			       long long *offset, long long *scaling, long long *frac,
			       long long *timestamp, unsigned int cpu)
{
	struct clock_sync_context *clock_context;
	int ret;

	if (!tsync || !tsync->context)
		return -1;

	clock_context = (struct clock_sync_context *)tsync->context;

	if (clock_context->is_guest)
		ret = kvm_clock_guest(tsync, offset, scaling, frac, timestamp);
	else
		ret = kvm_clock_host(tsync, offset, scaling, frac, timestamp, cpu);
	return ret;
}

int kvm_clock_sync_register(void)
{
	int role = TRACECMD_TIME_SYNC_ROLE_GUEST;
	int clock = 0;

	if (kvm_support_check(false)) {
		role |= TRACECMD_TIME_SYNC_ROLE_HOST;
		clock = TRACECMD_CLOCK_X86_TSC;
	}
	return tracecmd_tsync_proto_register(KVM_NAME, KVM_ACCURACY,
					     role, clock, 0,
					     kvm_clock_sync_init,
					     kvm_clock_sync_free,
					     kvm_clock_sync_calc);
}

int kvm_clock_sync_unregister(void)
{
	return tracecmd_tsync_proto_unregister(KVM_NAME);
}
