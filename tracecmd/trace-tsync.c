// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/vm_sockets.h>
#include <pthread.h>

#include "tracefs.h"
#include "trace-local.h"
#include "trace-msg.h"

static int get_first_cpu(cpu_set_t **pin_mask, size_t *m_size)
{
	int cpus = tracecmd_count_cpus();
	cpu_set_t *cpu_mask;
	int mask_size;
	int i;

	cpu_mask = CPU_ALLOC(cpus);
	*pin_mask = CPU_ALLOC(cpus);
	if (!cpu_mask || !*pin_mask || 1)
		goto error;

	mask_size = CPU_ALLOC_SIZE(cpus);
	CPU_ZERO_S(mask_size, cpu_mask);
	CPU_ZERO_S(mask_size, *pin_mask);

	if (sched_getaffinity(0, mask_size, cpu_mask) == -1)
		goto error;

	for (i = 0; i < cpus; i++) {
		if (CPU_ISSET_S(i, mask_size, cpu_mask)) {
			CPU_SET_S(i, mask_size, *pin_mask);
			break;
		}
	}

	if (CPU_COUNT_S(mask_size, *pin_mask) < 1)
		goto error;

	CPU_FREE(cpu_mask);
	*m_size = mask_size;
	return 0;

error:
	if (cpu_mask)
		CPU_FREE(cpu_mask);
	if (*pin_mask)
		CPU_FREE(*pin_mask);
	*pin_mask = NULL;
	*m_size = 0;
	return -1;
}

static void *tsync_host_thread(void *data)
{
	struct tracecmd_time_sync *tsync = NULL;

	tsync = (struct tracecmd_time_sync *)data;

	tracecmd_tsync_with_guest(tsync);

	tracecmd_msg_handle_close(tsync->msg_handle);
	tsync->msg_handle = NULL;

	pthread_exit(0);
}

int tracecmd_host_tsync(struct buffer_instance *instance,
			 unsigned int tsync_port)
{
	struct tracecmd_msg_handle *msg_handle = NULL;
	cpu_set_t *pin_mask = NULL;
	pthread_attr_t attrib;
	size_t mask_size = 0;
	int ret;
	int fd;

	if (!instance->tsync.sync_proto)
		return -1;

	fd = trace_open_vsock(instance->cid, tsync_port);
	if (fd < 0) {
		ret = -1;
		goto out;
	}
	msg_handle = tracecmd_msg_handle_alloc(fd, 0);
	if (!msg_handle) {
		ret = -1;
		goto out;
	}

	instance->tsync.msg_handle = msg_handle;
	if (top_instance.clock)
		instance->tsync.clock_str = strdup(top_instance.clock);
	pthread_mutex_init(&instance->tsync.lock, NULL);
	pthread_cond_init(&instance->tsync.cond, NULL);

	pthread_attr_init(&attrib);
	pthread_attr_setdetachstate(&attrib, PTHREAD_CREATE_JOINABLE);
	if (!get_first_cpu(&pin_mask, &mask_size))
		pthread_attr_setaffinity_np(&attrib, mask_size, pin_mask);

	ret = pthread_create(&instance->tsync_thread, &attrib,
			     tsync_host_thread, &instance->tsync);
	if (!ret)
		instance->tsync_thread_running = true;
	if (pin_mask)
		CPU_FREE(pin_mask);
	pthread_attr_destroy(&attrib);

out:
	if (ret) {
		if (msg_handle)
			tracecmd_msg_handle_close(msg_handle);
	}

	return ret;
}

static void write_guest_time_shift(struct buffer_instance *instance)
{
	struct tracecmd_output *handle;
	struct iovec vector[4];
	long long *offsets;
	long long *ts;
	const char *file;
	int count;
	int ret;
	int fd;

	ret = tracecmd_tsync_get_offsets(&instance->tsync, &count, &ts, &offsets);
	if (ret < 0 || !count || !ts || !offsets)
		return;

	file = instance->output_file;
	fd = open(file, O_RDWR);
	if (fd < 0)
		die("error opening %s", file);
	handle = tracecmd_get_output_handle_fd(fd);
	vector[0].iov_len = 8;
	vector[0].iov_base = &top_instance.trace_id;
	vector[1].iov_len = 4;
	vector[1].iov_base = &count;
	vector[2].iov_len = 8 * count;
	vector[2].iov_base = ts;
	vector[3].iov_len = 8 * count;
	vector[3].iov_base = offsets;
	tracecmd_add_option_v(handle, TRACECMD_OPTION_TIME_SHIFT, vector, 4);
	tracecmd_append_options(handle);
	tracecmd_output_close(handle);
#ifdef TSYNC_DEBUG
	if (count > 1)
		printf("Got %d timestamp synch samples for guest %s in %lld ns trace\n\r",
			count, tracefs_instance_get_name(instance->tracefs),
			ts[count - 1] - ts[0]);
#endif
}

void tracecmd_host_tsync_complete(struct buffer_instance *instance)
{
	if (!instance->tsync_thread_running)
		return;

	/* Signal the time synchronization thread to complete and wait for it */
	pthread_mutex_lock(&instance->tsync.lock);
	pthread_cond_signal(&instance->tsync.cond);
	pthread_mutex_unlock(&instance->tsync.lock);
	pthread_join(instance->tsync_thread, NULL);
	write_guest_time_shift(instance);
	tracecmd_tsync_free(&instance->tsync);
}

static void *tsync_agent_thread(void *data)
{
	struct tracecmd_time_sync *tsync = NULL;
	int sd;

	tsync = (struct tracecmd_time_sync *)data;

	while (true) {
		sd = accept(tsync->msg_handle->fd, NULL, NULL);
		if (sd < 0) {
			if (errno == EINTR)
				continue;
			goto out;
		}
		break;
	}
	close(tsync->msg_handle->fd);
	tsync->msg_handle->fd = sd;

	tracecmd_tsync_with_host(tsync);

out:
	tracecmd_msg_handle_close(tsync->msg_handle);
	tracecmd_tsync_free(tsync);
	free(tsync);
	close(sd);

	pthread_exit(0);
}

unsigned int tracecmd_guest_tsync(char *tsync_protos,
				  unsigned int tsync_protos_size, char *clock,
				  unsigned int *tsync_port, pthread_t *thr_id)
{
	struct tracecmd_time_sync *tsync = NULL;
	cpu_set_t *pin_mask = NULL;
	pthread_attr_t attrib;
	size_t mask_size = 0;
	unsigned int proto;
	int ret;
	int fd;

	fd = -1;
	proto = tracecmd_tsync_proto_select(tsync_protos, tsync_protos_size);
	if (!proto)
		return 0;
#ifdef VSOCK
	fd = trace_make_vsock(VMADDR_PORT_ANY);
	if (fd < 0)
		goto error;

	ret = trace_get_vsock_port(fd, tsync_port);
	if (ret < 0)
		goto error;
#else
	return 0;
#endif

	tsync = calloc(1, sizeof(struct tracecmd_time_sync));
	tsync->msg_handle = tracecmd_msg_handle_alloc(fd, 0);
	if (clock)
		tsync->clock_str = strdup(clock);

	pthread_attr_init(&attrib);
	tsync->sync_proto = proto;
	pthread_attr_setdetachstate(&attrib, PTHREAD_CREATE_JOINABLE);
	if (!get_first_cpu(&pin_mask, &mask_size))
		pthread_attr_setaffinity_np(&attrib, mask_size, pin_mask);

	ret = pthread_create(thr_id, &attrib, tsync_agent_thread, tsync);

	if (pin_mask)
		CPU_FREE(pin_mask);
	pthread_attr_destroy(&attrib);

	if (ret)
		goto error;

	return proto;

error:
	if (tsync) {
		if (tsync->msg_handle)
			tracecmd_msg_handle_close(tsync->msg_handle);
		free(tsync->clock_str);
		free(tsync);
	}
	if (fd > 0)
		close(fd);
	return 0;
}
