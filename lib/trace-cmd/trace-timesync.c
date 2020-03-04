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
 * tracecmd_tsync_get_offsets - Return the calculated time offsets
 *
 * @tsync: Pointer to time sync context
 * @count: Returns the number of calculated time offsets
 * @ts: Array of size @count containing timestamps of callculated offsets
 * @offsets: array of size @count, containing offsets for each timestamp
 *
 * Retuns -1 in case of an error, or 0 otherwise
 */
int tracecmd_tsync_get_offsets(struct tracecmd_time_sync *tsync,
				int *count,
				long long **ts, long long **offsets)
{
	struct clock_sync_context *tsync_context;

	if (!tsync || !tsync->context)
		return -1;
	tsync_context = (struct clock_sync_context *)tsync->context;
	if (count)
		*count = tsync_context->sync_count;
	if (ts)
		*ts = tsync_context->sync_ts;
	if (offsets)
		*offsets = tsync_context->sync_offsets;
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

	if (!tsync->context)
		return;
	tsync_context = (struct clock_sync_context *)tsync->context;

	proto = tsync_proto_find(tsync->sync_proto);
	if (proto && proto->clock_sync_free)
		proto->clock_sync_free(tsync);

	clock_synch_delete_instance(tsync_context->instance);
	tsync_context->instance = NULL;

	free(tsync_context->sync_ts);
	free(tsync_context->sync_offsets);
	tsync_context->sync_ts = NULL;
	tsync_context->sync_offsets = NULL;
	tsync_context->sync_count = 0;
	tsync_context->sync_size = 0;
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
	struct tsync_proto *proto;
	unsigned int protocol;
	unsigned int command;
	int ret;

	proto = tsync_proto_find(tsync->sync_proto);
	if (!proto || !proto->clock_sync_calc)
		return;

	clock_context_init(tsync, true);
	if (!tsync->context)
		return;

	while (true) {
		ret = tracecmd_msg_recv_time_sync(tsync->msg_handle,
						  &protocol, &command,
						  NULL, NULL);

		if (ret ||
		    protocol != TRACECMD_TIME_SYNC_PROTO_NONE ||
		    command != TRACECMD_TIME_SYNC_CMD_PROBE)
			break;
		ret = tracecmd_tsync_send(tsync, proto);
		if (ret)
			break;
	}
}

static int tsync_get_sample(struct tracecmd_time_sync *tsync,
			    struct tsync_proto *proto, int array_step)
{
	struct clock_sync_context *clock;
	long long *sync_offsets = NULL;
	long long *sync_ts = NULL;
	long long timestamp = 0;
	long long offset = 0;
	int ret;

	ret = proto->clock_sync_calc(tsync, &offset, &timestamp);
	if (ret) {
		warning("Failed to synchronize timestamps with guest");
		return -1;
	}
	if (!offset || !timestamp)
		return 0;
	clock = tsync->context;
	if (clock->sync_count >= clock->sync_size) {
		sync_ts = realloc(clock->sync_ts,
				  (clock->sync_size + array_step) * sizeof(long long));
		sync_offsets = realloc(clock->sync_offsets,
				       (clock->sync_size + array_step) * sizeof(long long));
		if (!sync_ts || !sync_offsets) {
			free(sync_ts);
			free(sync_offsets);
			return -1;
		}
		clock->sync_size += array_step;
		clock->sync_ts = sync_ts;
		clock->sync_offsets = sync_offsets;
	}

	clock->sync_ts[clock->sync_count] = timestamp;
	clock->sync_offsets[clock->sync_count] = offset;
	clock->sync_count++;

	return 0;
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
		ret = tracecmd_msg_send_time_sync(tsync->msg_handle,
						  TRACECMD_TIME_SYNC_PROTO_NONE,
						  TRACECMD_TIME_SYNC_CMD_PROBE,
						  0, NULL);
		ret = tsync_get_sample(tsync, proto, ts_array_size);
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
