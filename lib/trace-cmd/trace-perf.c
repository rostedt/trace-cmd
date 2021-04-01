// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2021, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include "trace-cmd-private.h"

static void default_perf_init_pe(struct perf_event_attr *pe)
{
	pe->type = PERF_TYPE_SOFTWARE;
	pe->sample_type = PERF_SAMPLE_CPU;
	pe->size = sizeof(struct perf_event_attr);
	pe->config = PERF_COUNT_HW_CPU_CYCLES;
	pe->disabled = 1;
	pe->exclude_kernel = 1;
	pe->freq = 1;
	pe->sample_freq = 1000;
	pe->inherit = 1;
	pe->mmap = 1;
	pe->comm = 1;
	pe->task = 1;
	pe->precise_ip = 1;
	pe->sample_id_all = 1;
	pe->read_format = PERF_FORMAT_ID |
			PERF_FORMAT_TOTAL_TIME_ENABLED |
			PERF_FORMAT_TOTAL_TIME_RUNNING;
}

/**
 * trace_perf_init - Initialize perf context
 *
 * @perf: structure, representing perf context, that will be initialized.
 * @pages: Number of perf memory mapped pages.
 * @cpu: CPU number, associated with this perf context.
 * @pid: PID, associated with this perf context.
 *
 * The perf context in initialized with default values. The caller can set
 * custom perf parameters in perf->pe, before calling trace_perf_open() API.
 *
 * Returns 0 on success, or -1 in case of an error.
 *
 */
int __hidden trace_perf_init(struct trace_perf *perf, int pages, int cpu, int pid)
{
	if (!perf)
		return -1;

	memset(perf, 0, sizeof(struct trace_perf));
	default_perf_init_pe(&perf->pe);
	perf->cpu = cpu;
	perf->pages = pages;
	perf->pid = pid;
	perf->fd = -1;

	return 0;
}

/**
 * trace_perf_close - Close perf session
 *
 * @perf: structure, representing context of a running perf session, opened
 *	  with trace_perf_open()
 *
 */
void __hidden trace_perf_close(struct trace_perf *perf)
{
	if (perf->fd >= 0)
		close(perf->fd);
	perf->fd = -1;
	if (perf->mmap && perf->mmap != MAP_FAILED)
		munmap(perf->mmap, (perf->pages + 1) * getpagesize());
	perf->mmap = NULL;
}

/**
 * trace_perf_open - Open perf session
 *
 * @perf: structure, representing perf context that will be opened. It must be
 *	  initialized with trace_perf_init().
 *
 * Returns 0 on success, or -1 in case of an error. In case of success, the
 * session must be closed with trace_perf_close()
 */
int __hidden trace_perf_open(struct trace_perf *perf)
{
	perf->fd = syscall(__NR_perf_event_open, &perf->pe, perf->pid, perf->cpu, -1, 0);
	if (perf->fd < 0)
		return -1;
	fcntl(perf->fd, F_SETFL, O_NONBLOCK);

	perf->mmap = mmap(NULL, (perf->pages + 1) * getpagesize(),
			  PROT_READ | PROT_WRITE, MAP_SHARED, perf->fd, 0);
	if (perf->mmap == MAP_FAILED)
		goto error;

	return 0;

error:
	trace_perf_close(perf);
	return -1;
}
