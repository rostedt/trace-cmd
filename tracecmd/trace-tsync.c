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

#define TSYNC_DEBUG

static void *tsync_host_thread(void *data)
{
	struct tracecmd_time_sync *tsync = NULL;

	tsync = (struct tracecmd_time_sync *)data;

	tracecmd_tsync_with_guest(tsync);

	tracecmd_msg_handle_close(tsync->msg_handle);
	tsync->msg_handle = NULL;

	pthread_exit(0);
}

#define TSYNC_PER_CPU
int tracecmd_host_tsync(struct buffer_instance *instance,
			 unsigned int tsync_port)
{
	struct tracecmd_msg_handle *msg_handle = NULL;
	cpu_set_t *pin_mask = NULL;
	pthread_attr_t attrib;
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

#ifdef TSYNC_PER_CPU
	ret = trace_get_guest_cpu_mapping(instance->cid,
					  &instance->tsync.cpu_max,
					  &instance->tsync.cpu_pid);
#endif

	instance->tsync.msg_handle = msg_handle;
	if (top_instance.clock)
		instance->tsync.clock_str = strdup(top_instance.clock);
	ret = pthread_mutex_init(&instance->tsync.lock, NULL);
	if (!ret)
		ret = pthread_cond_init(&instance->tsync.cond, NULL);

	pthread_attr_init(&attrib);
	pthread_attr_setdetachstate(&attrib, PTHREAD_CREATE_JOINABLE);

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
	struct tracecmd_output *handle = NULL;
	struct iovec *vector = NULL;
	long long *offsets;
	int vector_count;
	int *count = NULL;
	int *cpu = NULL;
	long long *ts;
	int cpu_count;
	int max_cpu;
	const char *file;
	int i, j, k;
	int ret;
	int fd;

	ret = tracecmd_tsync_get_cpu_count(&instance->tsync,
					   &cpu_count, &max_cpu);
	if (ret < 0 || cpu_count < 1)
		return;
	vector_count = 2;
	vector_count += (4 * cpu_count);
	vector = calloc(vector_count, sizeof(struct iovec));
	count = calloc(cpu_count, sizeof(int));
	cpu = calloc(cpu_count, sizeof(int));
	if (!vector || !count || !cpu)
		goto out;

	file = instance->output_file;
	fd = open(file, O_RDWR);
	if (fd < 0)
		die("error opening %s", file);

	i = 0;
	vector[i].iov_len = 8;
	vector[i].iov_base = &top_instance.trace_id;
	i++;
	vector[i].iov_len = 4;
	vector[i].iov_base = &cpu_count;
	i++;
	for (j = 0, k = 0; j < max_cpu && i <= (vector_count - 4) && k < cpu_count; j++) {
		ret = tracecmd_tsync_get_offsets(&instance->tsync, j, &cpu[k],
						 &count[k], &ts, &offsets);
		if (ret < 0)
			return;
		if (!count[k] || !ts || !offsets)
			continue;

		vector[i].iov_len = 4;
		vector[i].iov_base = &cpu[k];
		vector[i + 1].iov_len = 4;
		vector[i + 1].iov_base = &count[k];
		vector[i + 2].iov_len = 8 * count[k];
		vector[i + 2].iov_base = ts;
		vector[i + 3].iov_len = 8 * count[k];
		vector[i + 3].iov_base = offsets;
		i += 4;
#ifdef TSYNC_DEBUG
		printf("Got %d timestamp synch samples for guest %s, host cpu %d in %lld ns trace\n\r",
			count[k], tracefs_instance_get_name(instance->tracefs),
			cpu[k], ts[count[k] - 1] - ts[0]);
#endif
		k++;
	}

	handle = tracecmd_get_output_handle_fd(fd);
	if (!handle) {
		close(fd);
		goto out;
	}
	tracecmd_add_option_v(handle, TRACECMD_OPTION_TIME_SHIFT, vector, i);
	tracecmd_append_options(handle);
out:
	tracecmd_output_close(handle);
	free(vector);
	free(count);
	free(cpu);
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
	pthread_attr_t attrib;
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

	ret = pthread_create(thr_id, &attrib, tsync_agent_thread, tsync);

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
