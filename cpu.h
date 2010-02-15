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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#endif /* _CPU_H */
