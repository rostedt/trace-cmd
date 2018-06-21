/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2009 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#ifndef _CPU_H
#define _CPU_H

#include <stdint.h>
#include <stdbool.h>

static inline int cpu_isset(uint64_t *cpu_mask, int cpu)
{
	uint64_t mask;

	mask = *(cpu_mask + (cpu >> 6));

	return mask & (1ULL << (cpu & ((1ULL << 6) - 1)));
}

static inline bool cpu_allset(uint64_t *cpu_mask, int max_cpus)
{
	int cpu;

	for (cpu = 0; cpu < max_cpus; cpu++) {
		if (!cpu_isset(cpu_mask, cpu))
			return false;
	}
	return true;
}

static inline void cpu_set(uint64_t *cpu_mask, int cpu)
{
	uint64_t *mask;

	mask = cpu_mask + (cpu >> 6);
	*mask |= (1ULL << (cpu & ((1ULL << 6) - 1)));
}

static inline void cpu_clear(uint64_t *cpu_mask, int cpu)
{
	uint64_t *mask;

	mask = cpu_mask + (cpu >> 6);
	*mask &= ~(1ULL << (cpu & ((1ULL << 6) - 1)));
}

static inline void set_cpus(uint64_t *cpu_mask, int cpus)
{
	int idx;

	for (idx = 0; idx < (cpus >> 6); idx++) {
		*(cpu_mask + idx) = -1ULL;
	}

	*(cpu_mask) = (1ULL << (cpus & ((1ULL << 6) - 1))) - 1;
}

static inline bool cpus_equal(uint64_t *a_mask, uint64_t *b_mask,
				  int cpus)
{
	int idx;

	for (idx = 0; idx < (cpus >> 6) + 1; idx++) {
		if (*(a_mask + idx) != *(b_mask + idx))
			return false;
	}
	return true;
}

/* Hamming weight */
static inline unsigned int hweight(unsigned int mask)
{
	uint64_t w = mask;

	w -= (w >> 1) & 0x5555555555555555ul;
	w =  (w & 0x3333333333333333ul) + ((w >> 2) & 0x3333333333333333ul);
	w =  (w + (w >> 4)) & 0x0f0f0f0f0f0f0f0ful;
	return (w * 0x0101010101010101ul) >> 56;
}

static inline unsigned int cpu_weight(uint64_t *cpu_mask, unsigned int cpus)
{
	unsigned int weight = 0;
	int idx;

	for (idx = 0; idx < (cpus >> 6) + 1; idx++)
		weight += hweight(*(cpu_mask + idx));

	return weight;
}

#endif /* _CPU_H */
