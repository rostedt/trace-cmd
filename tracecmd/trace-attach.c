// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Google Inc, Steven Rostedt <rostedt@goodmis.org>
 *
 */
#include <stdlib.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>

#include "tracefs.h"
#include "trace-local.h"

struct timeshift_sample {
	struct timeshift_sample *next;
	long long		offset;
	long long		scaling;
	long long		timestamp;
	long long		fract;
};

struct vcpu_pid {
	struct vcpu_pid		*next;
	int			pid;
	int			cpu;
};

static unsigned int num_cpus;

static void *vcpu_pids;

static struct timeshift_sample *tshifts;
static struct timeshift_sample **tshifts_next = &tshifts;

static u64 set_value(const char *str, const char *type, u64 def)
{
	if (str && str[0] != '\0' && str[0] != '-' && !isdigit(str[0]))
		die("Bad %s value", type);

	if (str && str[0])
		return strtoull(str, NULL, 0);

	return def;
}

static void add_timeshift(char *shift)
{
	struct timeshift_sample *tshift;
	char *timestamp_str;
	char *offset_str;
	char *scale_str;
	char *fract_str;
	char *saveptr;
	u64 timestamp;
	u64 offset;
	u64 scale;
	u64 fract;

	offset_str = strparse(shift, ',', &saveptr);
	scale_str = strparse(NULL, ',', &saveptr);
	fract_str = strparse(NULL, ',', &saveptr);
	timestamp_str = strparse(NULL, ',', &saveptr);

	if (!offset_str)
		die("Bad timeshift argument");

	offset = set_value(offset_str, "offset", 0);
	scale = set_value(scale_str, "scaling", 1);
	fract = set_value(fract_str, "fraction", 0);
	timestamp = set_value(timestamp_str, "timestamp", 0);

	tshift = calloc(1, sizeof(*tshift));
	if (!tshift)
		die("Could not allocate timeshift");

	*tshifts_next = tshift;
	tshifts_next = &tshift->next;

	tshift->offset = offset;
	tshift->scaling = scale;
	tshift->fract = fract;
	tshift->timestamp = timestamp;
}

static void free_timeshifts(void)
{
	struct timeshift_sample *tshift;

	while (tshifts) {
		tshift = tshifts;
		tshifts = tshift->next;
		free(tshift);
	}
}

static void add_vcpu_pid(const char *pid)
{
	struct vcpu_pid *vpid;

	vpid = calloc(1, sizeof(*vpid));
	vpid->pid = atoi(pid);
	vpid->cpu = -1;
	vpid->next = vcpu_pids;
	vcpu_pids = vpid;
}

static void free_vcpu_pids(void)
{
	struct vcpu_pid *vpid;

	while (vcpu_pids) {
		vpid = vcpu_pids;
		vcpu_pids = vpid->next;
		free(vpid);
	}
}

static inline int test_vcpu_id(struct tep_format_field **vcpu_id_field,
				struct tep_event *event, struct tep_record *record)
{
	unsigned long long val;
	struct vcpu_pid *vpid;
	bool done = true;
	int pid;
	int cnt = 0;

	if (!*vcpu_id_field) {
		*vcpu_id_field = tep_find_field(event, "vcpu_id");
		 if (!*vcpu_id_field)
			 die("Could not find vcpu_id field");
	}

	pid = tep_data_pid(event->tep, record);
	for (vpid = vcpu_pids; vpid; vpid = vpid->next) {
		if (vpid->cpu < 0) {
			done = false;
		} else {
			cnt++;
			continue;
		}
		if (vpid->pid == pid)
			break;
	}

	if (done || (num_cpus && cnt == num_cpus))
		return -1;

	if (!vpid)
		return 0;

	if (tep_read_number_field(*vcpu_id_field, record->data, &val))
		die("Could not read data vcpu_id field");

	vpid->cpu = (int)val;

	return 0;
}

static int entry_callback(struct tracecmd_input *handle, struct tep_event *event,
			  struct tep_record *record, int cpu, void *data)
{
	static struct tep_format_field *vcpu_id_field;

	return test_vcpu_id(&vcpu_id_field, event, record);
}

static int exit_callback(struct tracecmd_input *handle, struct tep_event *event,
			  struct tep_record *record, int cpu, void *data)
{
	static struct tep_format_field *vcpu_id_field;

	return test_vcpu_id(&vcpu_id_field, event, record);
}

static int cmp_vcpus(const void *A, const void *B)
{
	struct vcpu_pid * const *a = A;
	struct vcpu_pid * const *b = B;

	if ((*a)->cpu < (*b)->cpu)
		return -1;

	return (*a)->cpu > (*b)->cpu;
}

static void update_end(char **end, void *data, int size, const char *stop)
{
	char *str = *end;

	if (str + size > stop)
		die("Error in calculating buffer size");

	memcpy(str, data, size);
	*end = str + size;
}

static void add_guest_to_host(struct tracecmd_output *host_ohandle,
			      struct tracecmd_input *guest_ihandle)
{
	unsigned long long guest_id;
	struct vcpu_pid **vcpu_list;
	struct vcpu_pid *vpid;
	char *name = ""; /* TODO, add name for guest */
	char *stop;
	char *buf;
	char *end;
	int cpus = 0;
	int cpu;
	int size;

	guest_id = tracecmd_get_traceid(guest_ihandle);

	for (vpid = vcpu_pids; vpid ; vpid = vpid->next) {
		if (vpid->cpu < 0)
			continue;
		cpus++;
	}

	vcpu_list = calloc(cpus, sizeof(*vcpu_list));
	if (!vcpu_list)
		die("Could not allocate vCPU list");

	cpus = 0;
	for (vpid = vcpu_pids; vpid ; vpid = vpid->next) {
		if (vpid->cpu < 0)
			continue;
		vcpu_list[cpus++] = vpid;
	}

	qsort(vcpu_list, cpus, sizeof(*vcpu_list), cmp_vcpus);

	size = strlen(name) + 1;
	size += sizeof(int) + sizeof(long long);
	size += cpus * (sizeof(int) * 2);
	buf = calloc(1, size);
	if (!buf)
		die("Failed allocation");

	end = buf;
	stop = buf + size;

	/* TODO match endianess of existing file */
	update_end(&end, name, strlen(name) + 1, stop);
	update_end(&end, &guest_id, sizeof(guest_id), stop);
	update_end(&end, &cpus, sizeof(cpus), stop);

	for (cpu = 0; cpu < cpus; cpu++) {
		int vcpu = vcpu_list[cpu]->cpu;
		int pid = vcpu_list[cpu]->pid;
		update_end(&end, &cpu, sizeof(vcpu), stop);
		update_end(&end, &pid, sizeof(pid), stop);
	}

	if (tracecmd_add_option(host_ohandle, TRACECMD_OPTION_GUEST, size, buf) == NULL)
		die("Failed to add GUEST option to host");

	free(vcpu_list);
	free(buf);
}

static void add_timeshift_to_guest(struct tracecmd_output *guest_ohandle,
				   struct tracecmd_input *host_ihandle)
{
	struct timeshift_sample *tshift = tshifts;
	struct timeshift_sample *last_tshift = NULL;
	unsigned long long host_id;
	char *stop;
	char *end;
	char *buf;
	int proto;
	int size = 0;
	int cpus;
	int cpu;

	host_id = tracecmd_get_traceid(host_ihandle);
	cpus = num_cpus;
	proto = 0; /* For now we just have zero */

	/*
	 * option size is:
	 *   trace id:		8 bytes
	 *   protocol flags:	4 bytes
	 *   CPU count:		4 bytes
	 *
	 * For each CPU:
	 *   sample cnt:	4 bytes
	 *   list of times:	8 bytes * sample cnt
	 *   list of offsets:	8 bytes * sample cnt
	 *   list of scaling:	8 bytes * sample cnt
	 *
	 * For each CPU:
	 *    list of fract:	8 bytes * CPU count
	 */
	size = 8 + 4 + 4;

	/* Include fraction bits here */
	size += 8 * cpus;

	/* We only have one sample per CPU (for now) */
	size += (4 + 8 * 3) * cpus;

	buf = calloc(1, size);
	if (!buf)
		die("Failed to allocate timeshift buffer");

	end = buf;
	stop = buf + size;
	update_end(&end, &host_id, sizeof(host_id), stop);
	update_end(&end, &proto, sizeof(proto), stop);
	update_end(&end, &cpus, sizeof(cpus), stop);

	for (cpu = 0; cpu < cpus; cpu++) {
		struct timeshift_sample *tsample = tshift;
		unsigned long long sample;
		int cnt = 1;

		if (!tsample)
			tsample = last_tshift;

		if (!tsample)
			die("No samples given");

		last_tshift = tsample;

		update_end(&end, &cnt, sizeof(cnt), stop);
		sample = tsample->timestamp;
		update_end(&end, &sample, sizeof(sample), stop);

		sample = tsample->offset;
		update_end(&end, &sample, sizeof(sample), stop);

		sample = tsample->scaling;
		update_end(&end, &sample, sizeof(sample), stop);
	}

	tshift = tshifts;
	last_tshift = NULL;

	for (cpu = 0; cpu < cpus; cpu++) {
		struct timeshift_sample *tsample = tshift;
		unsigned long long sample;

		if (!tsample)
			tsample = last_tshift;
		last_tshift = tsample;

		sample = tsample->fract;

		update_end(&end, &sample, sizeof(sample), stop);
	}

	if (tracecmd_add_option(guest_ohandle, TRACECMD_OPTION_TIME_SHIFT, size, buf) == NULL)
		die("Failed to add TIME SHIFT option");

	free(buf);
}

static void add_tsc2nsec_to_guest(struct tracecmd_output *guest_ohandle,
				  struct tracecmd_input *host_ihandle)
{
	unsigned long long offset;
	int mult;
	int shift;
	int ret;
	char buf[sizeof(int) * 2 + sizeof(long long)];
	char *stop;
	char *end;
	int size = sizeof(buf);

	ret = tracecmd_get_tsc2nsec(host_ihandle, &mult, &shift, &offset);
	if (ret < 0)
		die("Host does not have tsc2nsec info");

	end = buf;
	stop = buf + size;
	update_end(&end, &mult, sizeof(mult), stop);
	update_end(&end, &shift, sizeof(shift), stop);
	update_end(&end, &offset, sizeof(offset), stop);

	if (tracecmd_add_option(guest_ohandle, TRACECMD_OPTION_TSC2NSEC, size, buf) == NULL)
		die("Failed to add TSC2NSEC option");

}

static void map_cpus(struct tracecmd_input *handle)
{
	int entry_ret;
	int exit_ret;

	entry_ret = tracecmd_follow_event(handle, "kvm", "kvm_entry", entry_callback, NULL);
	exit_ret = tracecmd_follow_event(handle, "kvm", "kvm_exit", exit_callback, NULL);

	if (entry_ret < 0 && exit_ret < 0)
		die("Host needs kvm_exit or kvm_entry events to attach");

	tracecmd_iterate_events(handle, NULL, 0, NULL, NULL);
}

void trace_attach(int argc, char **argv)
{
	struct tracecmd_input *guest_ihandle;
	struct tracecmd_input *host_ihandle;
	struct tracecmd_output *guest_ohandle;
	struct tracecmd_output *host_ohandle;
	unsigned long long guest_id;
	char *guest_file;
	char *host_file;
	int ret;
	int fd;

	for (;;) {
		int c;

		c = getopt(argc-1, argv+1, "c:s:h");
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage(argv);
			break;
		case 's':
			add_timeshift(optarg);
			break;
		case 'c':
			num_cpus = atoi(optarg);
			break;
		default:
			usage(argv);
		}
	}

	/* Account for "attach" */
	optind++;

	if ((argc - optind) < 3)
		usage(argv);

	host_file = argv[optind++];
	guest_file = argv[optind++];

	for (; optind < argc; optind++)
		add_vcpu_pid(argv[optind]);


	host_ihandle = tracecmd_open(host_file,TRACECMD_FL_LOAD_NO_PLUGINS );
	guest_ihandle = tracecmd_open(guest_file,TRACECMD_FL_LOAD_NO_PLUGINS );

	if (!host_ihandle)
		die("Could not read %s\n", host_file);

	if (!guest_ihandle)
		die("Could not read %s\n", guest_file);

	guest_id = tracecmd_get_traceid(guest_ihandle);
	if (!guest_id)
		die("Guest data file does not contain traceid");

	map_cpus(host_ihandle);

	ret = tracecmd_get_guest_cpumap(host_ihandle, guest_id,
					NULL, NULL, NULL);
	if (ret == 0) {
		printf("Guest is already mapped in host (id=0x%llx) .. skipping ...\n",
		       guest_id);
	} else {

		fd = open(host_file, O_RDWR);
		if (fd < 0)
			die("Could not write %s", host_file);

		host_ohandle = tracecmd_get_output_handle_fd(fd);
		if (!host_ohandle)
			die("Error setting up %s for write", host_file);

		add_guest_to_host(host_ohandle, guest_ihandle);
		tracecmd_output_close(host_ohandle);
	}

	fd = open(guest_file, O_RDWR);
	if (fd < 0)
		die("Could not write %s", guest_file);

	guest_ohandle = tracecmd_get_output_handle_fd(fd);
	if (!guest_ohandle)
		die("Error setting up %s for write", guest_file);

	add_timeshift_to_guest(guest_ohandle, host_ihandle);
	add_tsc2nsec_to_guest(guest_ohandle, host_ihandle);

	tracecmd_output_close(guest_ohandle);

	tracecmd_close(guest_ihandle);
	tracecmd_close(host_ihandle);

	free_timeshifts();
	free_vcpu_pids();

	return;
}
