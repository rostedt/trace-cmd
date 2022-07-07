/* SPDX-License-Identifier: LGPL-2.1 */
/*
 * Copyright (C) 2019, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */
#ifndef _TRACE_TSYNC_LOCAL_H
#define _TRACE_TSYNC_LOCAL_H

#include <stdbool.h>

struct tsync_proto;

struct tracecmd_time_sync {
	pthread_t			thread;
	bool				thread_running;
	unsigned long long		trace_id;
	char				*proto_name;
	int				loop_interval;
	pthread_mutex_t			lock;
	pthread_cond_t			cond;
	pthread_barrier_t		first_sync;
	char				*clock_str;
	struct tracecmd_msg_handle	*msg_handle;
	struct tsync_proto		*proto;
	void				*context;
	int				guest_pid;
	int				vcpu_count;
	int				remote_id;
	int				local_id;
};

struct clock_sync_offsets {
	/* Arrays with calculated time offsets at given time */
	int				sync_size;	/* Allocated size of sync_ts,
							 * sync_offsets, sync_scalings and sync_frac
							 */
	int				sync_count;	/* Number of elements in sync_ts,
							 * sync_offsets, sync_scalings and sync_frac
							 */
	long long			*sync_ts;
	long long			*sync_offsets;
	long long			*sync_scalings;
	long long			*sync_frac;
};

struct clock_sync_context {
	void				*proto_data;	/* time sync protocol specific data */
	bool				is_server;	/* server side time sync role */
	bool				is_guest;	/* guest or host time sync role */
	struct tracefs_instance		*instance;	/* ftrace buffer, used for time sync events */

	int				cpu_count;
	struct clock_sync_offsets	*offsets;	/* Array of size cpu_count
							 * calculated offsets per CPU
							 */

	/* Identifiers of local and remote time sync peers */
	unsigned int			local_id;
	unsigned int			remote_id;
};

int tracecmd_tsync_proto_register(const char *proto_name, int accuracy, int roles,
				  int supported_clocks, unsigned int flags,
				  int (*init)(struct tracecmd_time_sync *),
				  int (*free)(struct tracecmd_time_sync *),
				  int (*calc)(struct tracecmd_time_sync *,
					      long long *, long long *, long long*,
					      long long *, unsigned int));
int tracecmd_tsync_proto_unregister(char *proto_name);
int ptp_clock_sync_register(void);

#ifdef VSOCK
int kvm_clock_sync_register(void);
#else
static inline int kvm_clock_sync_register(void)
{
	return 0;
}
#endif

#endif /* _TRACE_TSYNC_LOCAL_H */
