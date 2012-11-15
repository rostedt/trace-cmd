/*
 * Copyright (C) 2009 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#ifndef _CPU_H
#define _CPU_H

static inline int cpu_isset(guint64 *cpu_mask, gint cpu)
{
	guint64 mask;

	mask = *(cpu_mask + (cpu >> 6));

	return mask & (1ULL << (cpu & ((1ULL << 6) - 1)));
}

static inline gboolean cpu_allset(guint64 *cpu_mask, gint max_cpus)
{
	gint cpu;

	for (cpu = 0; cpu < max_cpus; cpu++) {
		if (!cpu_isset(cpu_mask, cpu))
			return FALSE;
	}
	return TRUE;
}

static inline void cpu_set(guint64 *cpu_mask, gint cpu)
{
	guint64 *mask;

	mask = cpu_mask + (cpu >> 6);
	*mask |= (1ULL << (cpu & ((1ULL << 6) - 1)));
}

static inline void cpu_clear(guint64 *cpu_mask, gint cpu)
{
	guint64 *mask;

	mask = cpu_mask + (cpu >> 6);
	*mask &= ~(1ULL << (cpu & ((1ULL << 6) - 1)));
}

static inline void set_cpus(guint64 *cpu_mask, gint cpus)
{
	gint idx;

	for (idx = 0; idx < (cpus >> 6); idx++) {
		*(cpu_mask + idx) = -1ULL;
	}

	*(cpu_mask) = (1ULL << (cpus & ((1ULL << 6) - 1))) - 1;
}

static inline gboolean cpus_equal(guint64 *a_mask, guint64 *b_mask,
				  gint cpus)
{
	gint idx;

	for (idx = 0; idx < (cpus >> 6) + 1; idx++) {
		if (*(a_mask + idx) != *(b_mask + idx))
			return FALSE;
	}
	return TRUE;
}

/* Hamming weight */
static inline guint hweight(guint mask)
{
	guint64 w = mask;

	w -= (w >> 1) & 0x5555555555555555ul;
	w =  (w & 0x3333333333333333ul) + ((w >> 2) & 0x3333333333333333ul);
	w =  (w + (w >> 4)) & 0x0f0f0f0f0f0f0f0ful;
	return (w * 0x0101010101010101ul) >> 56;
}

static inline guint cpu_weight(guint64 *cpu_mask, guint cpus)
{
	guint weight = 0;
	gint idx;

	for (idx = 0; idx < (cpus >> 6) + 1; idx++)
		weight += hweight(*(cpu_mask + idx));

	return weight;
}

#endif /* _CPU_H */
