// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2019, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/vm_sockets.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>

#include "trace-cmd.h"
#include "tracefs.h"
#include "event-utils.h"
#include "trace-tsync-local.h"

struct tsync_proto {
	struct tsync_proto *next;
	unsigned int proto_id;
	int	weight;

	int (*clock_sync_init)(struct tracecmd_time_sync *clock_context);
	int (*clock_sync_free)(struct tracecmd_time_sync *clock_context);
	int (*clock_sync_calc)(struct tracecmd_time_sync *clock_context,
			       long long *offset, long long *timestamp);
};

static struct tsync_proto *tsync_proto_list;

struct tsync_probe_msg {
	int cpu;
};

static int pin_to_cpu(int cpu, pid_t pid)
{
	static size_t size;
	static int cpus;
	cpu_set_t *mask;
	int ret;

	if (!cpus) {
		cpus = tracecmd_count_cpus();
		size = CPU_ALLOC_SIZE(cpus);
	}
	if (cpu >= cpus)
		return -1;

	mask = CPU_ALLOC(cpus);
	if (!mask)
		return  -1;

	CPU_ZERO_S(size, mask);
	CPU_SET_S(cpu, size, mask);
	ret = pthread_setaffinity_np(pthread_self(), size, mask);
	if (!ret && pid >= 0)
		ret = sched_setaffinity(pid, size, mask);
	CPU_FREE(mask);

	if (ret)
		return -1;
	return 0;
}

static struct tsync_proto *tsync_proto_find(unsigned int proto_id)
{
	struct tsync_proto *proto;

	for (proto = tsync_proto_list; proto; proto = proto->next)
		if (proto->proto_id == proto_id)
			return proto;

	return NULL;
}

int tracecmd_tsync_proto_register(unsigned int proto_id, int weight,
				int (*init)(struct tracecmd_time_sync *),
				int (*free)(struct tracecmd_time_sync *),
				int (*calc)(struct tracecmd_time_sync *,
					    long long *, long long *))
{
	struct tsync_proto *proto;

	if (tsync_proto_find(proto_id))
		return -1;
	proto = calloc(1, sizeof(struct tsync_proto));
	if (!proto)
		return -1;
	proto->proto_id = proto_id;
	proto->weight = weight;
	proto->clock_sync_init = init;
	proto->clock_sync_free = free;
	proto->clock_sync_calc = calc;

	proto->next = tsync_proto_list;
	tsync_proto_list = proto;
	return 0;
}

int tracecmd_tsync_proto_unregister(unsigned int proto_id)
{
	struct tsync_proto **last = &tsync_proto_list;

	for (; *last; last = &(*last)->next) {
		if ((*last)->proto_id == proto_id) {
			struct tsync_proto *proto = *last;

			*last = proto->next;
			free(proto);
			return 0;
		}
	}

	return -1;
}

bool tsync_proto_is_supported(unsigned int proto_id)
{
	if (tsync_proto_find(proto_id))
		return true;
	return false;
}

/**
 * tracecmd_tsync_get_cpu_count - Return the number of CPUs with
 *				  calculated time offsets
 *
 * @tsync: Pointer to time sync context
 * @cpu_count: Returns the number of CPUs with calculated time offsets
 * @max_cpu: Returns the maximum CPU id
 *
 * Retuns -1 in case of an error, or 0 otherwise
 */
int tracecmd_tsync_get_cpu_count(struct tracecmd_time_sync *tsync,
				   int *cpu_count, int *max_cpu)
{
	struct clock_sync_context *tsync_context;
	int i;

	if (!tsync || !tsync->context)
		return -1;
	tsync_context = (struct clock_sync_context *)tsync->context;

	if (max_cpu)
		*max_cpu = tsync_context->cpu_sync_size;
	if (cpu_count) {
		*cpu_count = 0;
		for (i = 0; i < tsync_context->cpu_sync_size; i++) {
			if (!tsync_context->cpu_sync[i].sync_count ||
			    !tsync_context->cpu_sync[i].sync_offsets ||
			    !tsync_context->cpu_sync[i].sync_ts)
				continue;
			(*cpu_count)++;
		}
	}
	return 0;
}

/**
 * tracecmd_tsync_get_offsets - Return the calculated time offsets, per CPU
 *
 * @tsync: Pointer to time sync context
 * @cpu_index: Index of the CPU, number between 0 and the one returned by
 *		tracecmd_tsync_get_cpu_count() API
 * @cpu: Returns the CPU id
 * @count: Returns the number of calculated time offsets
 * @ts: Array of size @count containing timestamps of callculated offsets
 * @offsets: array of size @count, containing offsets for each timestamp
 *
 * Retuns -1 in case of an error, or 0 otherwise
 */
int tracecmd_tsync_get_offsets(struct tracecmd_time_sync *tsync,
				int cpu_index, int *cpu, int *count,
				long long **ts, long long **offsets)
{
	struct clock_sync_context *tsync_context;

	if (!tsync || !tsync->context)
		return -1;
	tsync_context = (struct clock_sync_context *)tsync->context;
	if (cpu_index >= tsync_context->cpu_sync_size)
		return -1;
	if (cpu)
		*cpu = tsync_context->cpu_sync[cpu_index].cpu;
	if (count)
		*count = tsync_context->cpu_sync[cpu_index].sync_count;
	if (ts)
		*ts = tsync_context->cpu_sync[cpu_index].sync_ts;
	if (offsets)
		*offsets = tsync_context->cpu_sync[cpu_index].sync_offsets;
	return 0;
}


#define PROTO_MASK_SIZE (sizeof(char))
#define PROTO_MASK_BITS (PROTO_MASK_SIZE * 8)
/**
 * tracecmd_tsync_proto_select - Select time sync protocol, to be used for
 *		timestamp synchronization with a peer
 *
 * @proto_mask: bitmask array of time sync protocols, supported by the peer
 * @length: size of the @protos array
 *
 * Retuns Id of a time sync protocol, that can be used with the peer, or 0
 *	  in case there is no match with supported protocols
 */
unsigned int tracecmd_tsync_proto_select(char *proto_mask, int length)
{
	struct tsync_proto *selected = NULL;
	struct tsync_proto *proto;
	int word;
	int id;

	for (word = 0; word < length; word++) {
		for (proto = tsync_proto_list; proto; proto = proto->next) {
			if (proto->proto_id < word * PROTO_MASK_SIZE)
				continue;

			id = proto->proto_id - word * PROTO_MASK_SIZE;
			if (id >= PROTO_MASK_BITS)
				continue;

			if ((1 << id) & proto_mask[word]) {
				if (selected) {
					if (selected->weight < proto->weight)
						selected = proto;
				} else
					selected = proto;
			}
		}
	}

	if (selected)
		return selected->proto_id;

	return 0;
}

/**
 * tracecmd_tsync_proto_getall - Returns bitmask of all supported
 *				 time sync protocols
 * @proto_mask: return, allocated bitmask array of time sync protocols,
 *	       supported by the peer. Must be freed by free()
 * @words: return, allocated size of the @protobits array
 *
 * If completed successfully 0 is returned and allocated array in @proto_mask of
 * size @words. In case of an error, -1 is returned.
 * @proto_mask must be freed with free()
 */
int tracecmd_tsync_proto_getall(char **proto_mask, int *words)
{
	struct tsync_proto *proto;
	int proto_max = 0;
	int count = 0;
	char *protos;

	for (proto = tsync_proto_list; proto; proto = proto->next)
		if (proto->proto_id > proto_max)
			proto_max = proto->proto_id;

	count = proto_max / PROTO_MASK_SIZE + 1;
	protos = calloc(count, sizeof(char));
	if (!protos)
		return -1;

	for (proto = tsync_proto_list; proto; proto = proto->next) {
		if ((proto->proto_id / PROTO_MASK_SIZE) >= count)
			continue;
		protos[proto->proto_id / PROTO_MASK_SIZE] |=
				(1 << (proto->proto_id % PROTO_MASK_SIZE));
	}

	*proto_mask = protos;
	*words = count;
	return 0;
}

static int get_vsocket_params(int fd, unsigned int *lcid, unsigned int *lport,
			      unsigned int *rcid, unsigned int *rport)
{
	struct sockaddr_vm addr;
	socklen_t addr_len = sizeof(addr);

	memset(&addr, 0, sizeof(addr));
	if (getsockname(fd, (struct sockaddr *)&addr, &addr_len))
		return -1;
	if (addr.svm_family != AF_VSOCK)
		return -1;
	*lport = addr.svm_port;
	*lcid = addr.svm_cid;

	memset(&addr, 0, sizeof(addr));
	addr_len = sizeof(addr);
	if (getpeername(fd, (struct sockaddr *)&addr, &addr_len))
		return -1;
	if (addr.svm_family != AF_VSOCK)
		return -1;
	*rport = addr.svm_port;
	*rcid = addr.svm_cid;

	return 0;
}

static struct tracefs_instance *
clock_synch_create_instance(const char *clock, unsigned int cid)
{
	struct tracefs_instance *instance;
	char inst_name[256];

	snprintf(inst_name, 256, "clock_synch-%d", cid);

	instance = tracefs_instance_alloc(inst_name);
	if (!instance)
		return NULL;

	tracefs_instance_create(instance);
	tracefs_instance_file_write(instance, "trace", "\0");
	if (clock)
		tracefs_instance_file_write(instance, "trace_clock", clock);
	return instance;
}

static void
clock_synch_delete_instance(struct tracefs_instance *inst)
{
	if (!inst)
		return;
	tracefs_instance_destroy(inst);
	tracefs_instance_free(inst);
}

static int clock_context_init(struct tracecmd_time_sync *tsync, bool server)
{
	struct clock_sync_context *clock = NULL;
	struct tsync_proto *protocol;

	if (tsync->context)
		return 0;

	protocol = tsync_proto_find(tsync->sync_proto);
	if (!protocol)
		return -1;

	clock = calloc(1, sizeof(struct clock_sync_context));
	if (!clock)
		return -1;

	clock->is_server = server;
	if (get_vsocket_params(tsync->msg_handle->fd, &clock->local_cid,
			       &clock->local_port, &clock->remote_cid,
			       &clock->remote_port))
		goto error;

	clock->instance = clock_synch_create_instance(tsync->clock_str,
						      clock->remote_cid);
	if (!clock->instance)
		goto error;

	tsync->context = clock;
	if (protocol->clock_sync_init && protocol->clock_sync_init(tsync) < 0)
		goto error;

	return 0;
error:
	tsync->context = NULL;
	free(clock);
	return -1;
}

/**
 * tracecmd_tsync_free - Free time sync context, allocated by
 *		tracecmd_tsync_with_host() or tracecmd_tsync_with_guest() APIs
 *
 * @tsync: Pointer to time sync context
 *
 */
void tracecmd_tsync_free(struct tracecmd_time_sync *tsync)
{
	struct clock_sync_context *tsync_context;
	struct tsync_proto *proto;
	int i;

	if (!tsync->context)
		return;
	tsync_context = (struct clock_sync_context *)tsync->context;

	proto = tsync_proto_find(tsync->sync_proto);
	if (proto && proto->clock_sync_free)
		proto->clock_sync_free(tsync);

	clock_synch_delete_instance(tsync_context->instance);
	tsync_context->instance = NULL;

	for (i = 0; i < tsync_context->cpu_sync_size; i++) {
		free(tsync_context->cpu_sync[i].sync_ts);
		free(tsync_context->cpu_sync[i].sync_offsets);
	}
	free(tsync_context->cpu_sync);
	tsync_context->cpu_sync = NULL;
	tsync_context->cpu_sync_size = 0;
	pthread_mutex_destroy(&tsync->lock);
	pthread_cond_destroy(&tsync->cond);
	free(tsync->clock_str);
}

int tracecmd_tsync_send(struct tracecmd_time_sync *tsync,
				  struct tsync_proto *proto)
{
	long long timestamp = 0;
	long long offset = 0;
	int ret;

	ret = proto->clock_sync_calc(tsync, &offset, &timestamp);

	return ret;
}

/**
 * tracecmd_tsync_with_host - Synchronize timestamps with host
 *
 * @tsync: Pointer to time sync context
 *
 * This API is supposed to be called in guest context. It waits for a time
 * sync request from the host and replies with a time sample, until time sync
 * stop command is received
 *
 */
void tracecmd_tsync_with_host(struct tracecmd_time_sync *tsync)
{
	struct tsync_probe_msg probe;
	struct tsync_proto *proto;
	unsigned int protocol;
	unsigned int command;
	unsigned int size;
	char *msg;
	int ret;

	proto = tsync_proto_find(tsync->sync_proto);
	if (!proto || !proto->clock_sync_calc)
		return;

	clock_context_init(tsync, true);
	if (!tsync->context)
		return;

	msg = (char *)&probe;
	size = sizeof(probe);
	while (true) {
		ret = tracecmd_msg_recv_time_sync(tsync->msg_handle,
						  &protocol, &command,
						  &size, &msg);
		if (ret ||
		    protocol != TRACECMD_TIME_SYNC_PROTO_NONE ||
		    command != TRACECMD_TIME_SYNC_CMD_PROBE)
			break;
		probe.cpu = ntohl(probe.cpu);
		if (probe.cpu >= 0) {
			if (pin_to_cpu(probe.cpu, -1))
				probe.cpu = -1;
		}
		probe.cpu = htonl(probe.cpu);
		ret = tracecmd_msg_send_time_sync(tsync->msg_handle,
						  TRACECMD_TIME_SYNC_PROTO_NONE,
						  TRACECMD_TIME_SYNC_CMD_PROBE,
						  sizeof(probe), (char *)&probe);
		ret = tracecmd_tsync_send(tsync, proto);
		if (ret)
			break;
	}
}

static int tsync_get_sample(struct tracecmd_time_sync *tsync,
			    struct tsync_proto *proto, int cpu, int vcpu,
			    int array_step)
{
	struct clock_sync_context *clock;
	struct clock_sync_cpu *cpu_sync;
	long long *sync_offsets = NULL;
	struct tsync_probe_msg probe;
	long long *sync_ts = NULL;
	long long timestamp = 0;
	unsigned int protocol;
	unsigned int command;
	long long offset = 0;
	unsigned int size;
	int cpu_index;
	char *msg;
	int ret;
	int i;

	probe.cpu = htonl(vcpu);
	ret = tracecmd_msg_send_time_sync(tsync->msg_handle,
					  TRACECMD_TIME_SYNC_PROTO_NONE,
					  TRACECMD_TIME_SYNC_CMD_PROBE,
					  sizeof(probe), (char *)&probe);
	msg = (char *)&probe;
	size = sizeof(probe);
	ret = tracecmd_msg_recv_time_sync(tsync->msg_handle,
					  &protocol, &command,
					  &size, &msg);
	if (ret ||
	    protocol != TRACECMD_TIME_SYNC_PROTO_NONE ||
	    command != TRACECMD_TIME_SYNC_CMD_PROBE)
		return -1;

	if (!ret)
		ret = proto->clock_sync_calc(tsync, &offset, &timestamp);
	if (ret) {
		warning("Failed to synchronize timestamps with guest");
		return -1;
	}
	if (vcpu != ntohl(probe.cpu)) {
		ret = 1;
		cpu = -1;
	} else
		ret = 0;
	if (!offset || !timestamp)
		return ret;
	clock = tsync->context;
	if (cpu < 0)
		cpu_index = 0;
	else
		cpu_index = cpu;
	if (cpu_index >= clock->cpu_sync_size) {
		cpu_sync = realloc(clock->cpu_sync,
				   (cpu_index + 1) * sizeof(struct clock_sync_cpu));
		if (!cpu_sync)
			return -1;
		for (i = clock->cpu_sync_size; i <= cpu_index; i++)
			memset(&cpu_sync[i], 0, sizeof(struct clock_sync_cpu));
		clock->cpu_sync = cpu_sync;
		clock->cpu_sync_size = cpu_index + 1;
	}
	cpu_sync = &clock->cpu_sync[cpu_index];
	if (cpu_sync->sync_count >= cpu_sync->sync_size) {
		sync_ts = realloc(cpu_sync->sync_ts,
				  (cpu_sync->sync_size + array_step) * sizeof(long long));
		sync_offsets = realloc(cpu_sync->sync_offsets,
				       (cpu_sync->sync_size + array_step) * sizeof(long long));
		if (!sync_ts || !sync_offsets) {
			free(sync_ts);
			free(sync_offsets);
			return -1;
		}
		cpu_sync->sync_size += array_step;
		cpu_sync->sync_ts = sync_ts;
		cpu_sync->sync_offsets = sync_offsets;
	}
	cpu_sync->cpu = cpu;
	cpu_sync->sync_ts[cpu_sync->sync_count] = timestamp;
	cpu_sync->sync_offsets[cpu_sync->sync_count] = offset;
	cpu_sync->sync_count++;

	return ret;
}

#define TIMER_SEC_NANO 1000000000LL
static inline void get_ts_loop_delay(struct timespec *timeout, int delay_ms)
{
	memset(timeout, 0, sizeof(struct timespec));
	clock_gettime(CLOCK_REALTIME, timeout);

	timeout->tv_nsec += ((unsigned long long)delay_ms * 1000000LL);

	if (timeout->tv_nsec >= TIMER_SEC_NANO) {
		timeout->tv_sec += timeout->tv_nsec / TIMER_SEC_NANO;
		timeout->tv_nsec %= TIMER_SEC_NANO;
	}
}

#define CLOCK_TS_ARRAY 5
static int tsync_get_sample_cpu(struct tracecmd_time_sync *tsync,
				struct tsync_proto *proto, int ts_array_size)
{
	static int cpus;
	cpu_set_t *tsync_mask = NULL;
	cpu_set_t *vcpu_mask = NULL;
	cpu_set_t *cpu_save = NULL;
	size_t mask_size;
	int ret;
	int i, j;

	if (!cpus)
		cpus = tracecmd_count_cpus();

	cpu_save = CPU_ALLOC(cpus);
	tsync_mask = CPU_ALLOC(cpus);
	vcpu_mask = CPU_ALLOC(cpus);
	if (!cpu_save || !tsync_mask || !vcpu_mask)
		goto out;
	mask_size = CPU_ALLOC_SIZE(cpus);
	ret = pthread_getaffinity_np(pthread_self(), mask_size, cpu_save);
	if (ret) {
		CPU_FREE(cpu_save);
		cpu_save = NULL;
		goto out;
	}
	CPU_ZERO_S(mask_size, tsync_mask);

	for (i = 0; i < tsync->cpu_max; i++) {
		if (tsync->cpu_pid[i] < 0)
			continue;
		if (sched_getaffinity(tsync->cpu_pid[i], mask_size, vcpu_mask))
			continue;
		for (j = 0; j < cpus; j++) {
			if (!CPU_ISSET_S(j, mask_size, vcpu_mask))
				continue;
			if (CPU_ISSET_S(j, mask_size, tsync_mask))
				continue;
			if (pin_to_cpu(j, tsync->cpu_pid[i]))
				continue;

			ret = tsync_get_sample(tsync, proto, j, i, ts_array_size);
			if (!ret)
				CPU_SET_S(j, mask_size, tsync_mask);
		}
		sched_setaffinity(tsync->cpu_pid[i], mask_size, vcpu_mask);
	}
out:
	ret = -1;
	if (cpu_save) {
		pthread_setaffinity_np(pthread_self(), mask_size, cpu_save);
		CPU_FREE(cpu_save);
	}
	if (tsync_mask) {
		if (CPU_COUNT_S(mask_size, tsync_mask) > 0)
			ret = 0;
		CPU_FREE(tsync_mask);
	}
	if (vcpu_mask)
		CPU_FREE(vcpu_mask);

	return ret;
}

/**
 * tracecmd_tsync_with_guest - Synchronize timestamps with guest
 *
 * @tsync: Pointer to time sync context
 *
 * This API is supposed to be called in host context, in a separate thread
 * It loops infinite, until the timesync semaphore is released
 *
 */
void tracecmd_tsync_with_guest(struct tracecmd_time_sync *tsync)
{
	int ts_array_size = CLOCK_TS_ARRAY;
	struct tsync_proto *proto;
	struct timespec timeout;
	bool end = false;
	int ret;

	proto = tsync_proto_find(tsync->sync_proto);
	if (!proto || !proto->clock_sync_calc)
		return;

	clock_context_init(tsync, false);
	if (!tsync->context)
		return;

	if (tsync->loop_interval > 0 &&
	    tsync->loop_interval < (CLOCK_TS_ARRAY * 1000))
		ts_array_size = (CLOCK_TS_ARRAY * 1000) / tsync->loop_interval;

	while (true) {
		pthread_mutex_lock(&tsync->lock);
		if (tsync->cpu_pid)
			ret = tsync_get_sample_cpu(tsync, proto, ts_array_size);
		else
			ret = tsync_get_sample(tsync, proto, -1, -1, ts_array_size);

		if (ret || end)
			break;
		if (tsync->loop_interval > 0) {
			get_ts_loop_delay(&timeout, tsync->loop_interval);
			ret = pthread_cond_timedwait(&tsync->cond, &tsync->lock, &timeout);
			pthread_mutex_unlock(&tsync->lock);
			if (ret && ret != ETIMEDOUT)
				break;
			else if (!ret)
				end = true;
		} else {
			pthread_cond_wait(&tsync->cond, &tsync->lock);
			end = true;
			pthread_mutex_unlock(&tsync->lock);
		}
	};

	tracecmd_msg_send_time_sync(tsync->msg_handle,
				    TRACECMD_TIME_SYNC_PROTO_NONE,
				    TRACECMD_TIME_SYNC_CMD_STOP,
				    0, NULL);
}
