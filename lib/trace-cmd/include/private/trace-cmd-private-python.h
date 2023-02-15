/* SPDX-License-Identifier: LGPL-2.1 */
/*
 * Private interface exposed to the python module. See python/ctracecmd.i and
 * python/tracecmd.py.
 */
#ifndef _TRACE_CMD_PRIVATE_PYTHON_H
#define _TRACE_CMD_PRIVATE_PYTHON_H

int tracecmd_long_size(struct tracecmd_input *handle);
int tracecmd_cpus(struct tracecmd_input *handle);

struct tep_record *
tracecmd_read_next_data(struct tracecmd_input *handle, int *rec_cpu);

struct tep_record *
tracecmd_peek_data(struct tracecmd_input *handle, int cpu);

static inline struct tep_record *
tracecmd_peek_data_ref(struct tracecmd_input *handle, int cpu)
{
	struct tep_record *rec = tracecmd_peek_data(handle, cpu);
	if (rec)
		rec->ref_count++;
	return rec;
}

#endif /* _TRACE_CMD_PRIVATE_PYTHON_H */
