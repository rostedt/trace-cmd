#include <stdlib.h>

#include "trace-cmd-local.h"
#include "trace-local.h"

/*
 * Structure to hold the mapping between host and guest.
 * @self - A pointer back to the guest's mapping (for the host copy to use)
 * @host_handle - The handle for the host for this mapping.
 * @guest_handle - The handle for the guest for this mapping.
 * @guest_vcpu - The vCPU # for this mapping.
 * @host_pid - The pid of the task on the host that runs when this vCPU executes.
 * @private - Private data for applications to use.
 */
struct tracecmd_cpu_map {
	struct tracecmd_cpu_map		*self;
	struct tracecmd_input		*host_handle;
	struct tracecmd_input		*guest_handle;
	int				guest_vcpu;
	int				host_pid;
	void				*private;
};

static int cmp_map(const void *A, const void *B)
{
	const struct tracecmd_cpu_map *a = A;
	const struct tracecmd_cpu_map *b = B;

	if (a->host_pid < b->host_pid)
		return -1;
	return a->host_pid > b->host_pid;
}

int tracecmd_map_vcpus(struct tracecmd_input **handles, int nr_handles)
{
	struct tracecmd_input *host_handle = handles[0];
	unsigned long long traceid;
	struct tracecmd_cpu_map *vcpu_maps = NULL;
	struct tracecmd_cpu_map *gmap;
	struct tracecmd_cpu_map *map;
	const int *cpu_pids;
	const char *name;
	int nr_vcpu_maps = 0;
	int vcpu_count;
	int mappings = 0;
	int ret;
	int i, k;

	/* handles[0] is the host handle, do for each guest handle */
	for (i = 1; i < nr_handles; i++) {
		traceid = tracecmd_get_traceid(handles[i]);

		/*
		 * Retrieve the host mapping of the guest for this handle.
		 * cpu_pids is an array of pids that map 1-1 the host vcpus where
		 * cpu_pids[vCPU_num] = host_task_pid
		 */
		ret = tracecmd_get_guest_cpumap(host_handle, traceid,
						&name, &vcpu_count, &cpu_pids);
		if (ret)
			continue;

		mappings++;

		gmap = calloc(sizeof(*gmap), vcpu_count);
		if (!gmap)
			goto fail;

		for (k = 0; k < vcpu_count; k++) {
			gmap[k].host_handle = handles[0];
			gmap[k].guest_handle = handles[i];
			gmap[k].guest_vcpu = k;
			gmap[k].host_pid = cpu_pids[k];
			gmap[k].self = &gmap[k];
		}

		trace_set_guest_map(handles[i], gmap);
		trace_set_guest_map_cnt(handles[i], vcpu_count);

		/* Update the host mapping of all guests to the host */
		map = realloc(vcpu_maps, sizeof(*map) * (nr_vcpu_maps + vcpu_count));
		if (!map)
			goto fail;
		memset(map + nr_vcpu_maps, 0, sizeof(*map) * (vcpu_count - nr_vcpu_maps));

		vcpu_maps = map;
		map += nr_vcpu_maps;
		nr_vcpu_maps += vcpu_count;

		for (k = 0; k < vcpu_count; k++)
			map[k] = gmap[k];
	}
	if (!vcpu_maps)
		return 0;

	/* We want to do a binary search via host_pid to find these mappings */
	qsort(vcpu_maps, nr_vcpu_maps, sizeof(*map), cmp_map);

	trace_set_guest_map(handles[0], vcpu_maps);
	trace_set_guest_map_cnt(handles[0], nr_vcpu_maps);

	return mappings;

 fail:
	free(vcpu_maps);
	return -1;
}

__hidden void trace_guest_map_free(struct tracecmd_cpu_map *map)
{
	free(map);
}

struct tracecmd_cpu_map *tracecmd_map_find_by_host_pid(struct tracecmd_input *handle,
						       int host_pid)
{
	struct tracecmd_cpu_map *map;
	struct tracecmd_cpu_map key;
	int nr_maps;

	map = trace_get_guest_map(handle);
	if (!map)
		return NULL;

	/* The handle could be from the guest, get the host handle */
	handle = map->host_handle;

	/* And again, get the mapping of the host, as it has all the mappings */
	map = trace_get_guest_map(handle);
	if (!map)
		return NULL;

	nr_maps = trace_get_guest_map_cnt(handle);

	key.host_pid = host_pid;

	map = bsearch(&key, map, nr_maps, sizeof(*map), cmp_map);

	return map ? map->self : NULL;
}

void tracecmd_map_set_private(struct tracecmd_cpu_map *map, void *priv)
{
	/* Only set the guest private */
	map = map->self;
	map->private = priv;
}

void *tracecmd_map_get_private(struct tracecmd_cpu_map *map)
{
	/* Return the guest private */
	map = map->self;
	return map->private;
}

struct tracecmd_input *tracecmd_map_get_guest(struct tracecmd_cpu_map *map)
{
	return map->guest_handle;
}

int tracecmd_map_get_host_pid(struct tracecmd_cpu_map *map)
{
	return map->host_pid;
}

struct tracecmd_cpu_map *tracecmd_get_cpu_map(struct tracecmd_input *handle, int cpu)
{
	struct tracecmd_cpu_map *map;
	int cnt;

	map = trace_get_guest_map(handle);
	/* Make sure it's for the guest handle, as this could be a host handle */
	map = map->self;
	cnt = trace_get_guest_map_cnt(map->guest_handle);
	if (cnt <= cpu)
		return NULL;

	return map + cpu;
}
