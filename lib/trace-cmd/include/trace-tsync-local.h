/* SPDX-License-Identifier: LGPL-2.1 */
/*
 * Copyright (C) 2019, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */
#ifndef _TRACE_TSYNC_LOCAL_H
#define _TRACE_TSYNC_LOCAL_H

#include <stdbool.h>

struct clock_sync_context {
	void				*proto_data;	/* time sync protocol specific data */
	bool				is_server;	/* server side time sync role */
	struct tracefs_instance		*instance;	/* ftrace buffer, used for time sync events */

	/* Arrays with calculated time offsets at given time */
	int				sync_size;	/* Allocated size of sync_ts and sync_offsets */
	int				sync_count;	/* Number of elements in sync_ts and sync_offsets */
	long long			*sync_ts;
	long long			*sync_offsets;

	/* Identifiers of local and remote time sync peers: cid and port */
	unsigned int			local_cid;
	unsigned int			local_port;
	unsigned int			remote_cid;
	unsigned int			remote_port;
};

int tracecmd_tsync_proto_register(unsigned int proto_id, int weight,
				int (*init)(struct tracecmd_time_sync *),
				int (*free)(struct tracecmd_time_sync *),
				int (*calc)(struct tracecmd_time_sync *,
					    long long *, long long *));
int tracecmd_tsync_proto_unregister(unsigned int proto_id);

int ptp_clock_sync_register(void);

#endif /* _TRACE_TSYNC_LOCAL_H */
