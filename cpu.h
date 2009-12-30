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
