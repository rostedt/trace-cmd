// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2008, 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * Updates:
 * Copyright (C) 2019, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "tracefs.h"
#include "tracefs-local.h"

struct tracefs_instance {
	char *name;
};

/**
 * tracefs_instance_alloc - allocate a new ftrace instance
 * @name: The name of the instance (instance will point to this)
 *
 * Returns a newly allocated instance, or NULL in case of an error.
 */
struct tracefs_instance *tracefs_instance_alloc(const char *name)
{
	struct tracefs_instance *instance;

	instance = calloc(1, sizeof(*instance));
	if (instance && name) {
		instance->name = strdup(name);
		if (!instance->name) {
			free(instance);
			instance = NULL;
		}
	}

	return instance;
}

/**
 * tracefs_instance_free - Free an instance, previously allocated by
			   tracefs_instance_alloc()
 * @instance: Pointer to the instance to be freed
 *
 */
void tracefs_instance_free(struct tracefs_instance *instance)
{
	if (!instance)
		return;
	free(instance->name);
	free(instance);
}

/**
 * tracefs_instance_create - Create a new ftrace instance
 * @instance: Pointer to the instance to be created
 *
 * Returns 1 if the instance already exist, 0 if the instance
 * is created successful or -1 in case of an error
 */
int tracefs_instance_create(struct tracefs_instance *instance)
{
	struct stat st;
	char *path;
	int ret;

	path = tracefs_instance_get_dir(instance);
	ret = stat(path, &st);
	if (ret < 0)
		ret = mkdir(path, 0777);
	else
		ret = 1;
	tracefs_put_tracing_file(path);
	return ret;
}

/**
 * tracefs_instance_destroy - Remove a ftrace instance
 * @instance: Pointer to the instance to be removed
 *
 * Returns -1 in case of an error, or 0 otherwise.
 */
int tracefs_instance_destroy(struct tracefs_instance *instance)
{
	char *path;
	int ret = -1;

	if (!instance || !instance->name) {
		warning("Cannot remove top instance");
		return -1;
	}

	path = tracefs_instance_get_dir(instance);
	if (path)
		ret = rmdir(path);
	tracefs_put_tracing_file(path);

	return ret;
}

/**
 * tracefs_instance_get_file - return the path to an instance file.
 * @instance: ftrace instance, can be NULL for the top instance
 * @file: name of file to return
 *
 * Returns the path of the @file for the given @instance, or NULL in
 * case of an error.
 *
 * Must use tracefs_put_tracing_file() to free the returned string.
 */
char *
tracefs_instance_get_file(struct tracefs_instance *instance, const char *file)
{
	char *path;
	char *buf;
	int ret;

	if (instance && instance->name) {
		ret = asprintf(&buf, "instances/%s/%s", instance->name, file);
		if (ret < 0)
			return NULL;
		path = tracefs_get_tracing_file(buf);
		free(buf);
	} else
		path = tracefs_get_tracing_file(file);

	return path;
}

/**
 * tracefs_instance_get_dir - return the path to the instance directory.
 * @instance: ftrace instance, can be NULL for the top instance
 *
 * Returns the full path to the instance directory
 *
 * Must use tracefs_put_tracing_file() to free the returned string.
 */
char *tracefs_instance_get_dir(struct tracefs_instance *instance)
{
	char *buf;
	char *path;
	int ret;

	if (instance && instance->name) {
		ret = asprintf(&buf, "instances/%s", instance->name);
		if (ret < 0) {
			warning("Failed to allocate path for instance %s",
				 instance->name);
			return NULL;
		}
		path = tracefs_get_tracing_file(buf);
		free(buf);
	} else
		path = tracefs_find_tracing_dir();

	return path;
}

/**
 * tracefs_instance_get_name - return the name of an instance
 * @instance: ftrace instance
 *
 * Returns the name of the given @instance.
 * The returned string must *not* be freed.
 */
char *tracefs_instance_get_name(struct tracefs_instance *instance)
{
	if (instance)
		return instance->name;
	return NULL;
}

static int write_file(const char *file, const char *str)
{
	int ret;
	int fd;

	fd = open(file, O_WRONLY | O_TRUNC);
	if (fd < 0) {
		warning("Failed to open '%s'", file);
		return -1;
	}
	ret = write(fd, str, strlen(str));
	close(fd);
	return ret;
}


/**
 * tracefs_instance_file_write - Write in trace file of specific instance.
 * @instance: ftrace instance, can be NULL for the top instance
 * @file: name of the file
 * @str: nul terminated string, that will be written in the file.
 *
 * Returns the number of written bytes, or -1 in case of an error
 */
int tracefs_instance_file_write(struct tracefs_instance *instance,
				 const char *file, const char *str)
{
	struct stat st;
	char *path;
	int ret;

	path = tracefs_instance_get_file(instance, file);
	if (!path)
		return -1;
	ret = stat(path, &st);
	if (ret == 0)
		ret = write_file(path, str);
	tracefs_put_tracing_file(path);

	return ret;
}

/**
 * tracefs_instance_file_read - Read from a trace file of specific instance.
 * @instance: ftrace instance, can be NULL for the top instance
 * @file: name of the file
 * @psize: returns the number of bytes read
 *
 * Returns a pointer to a nul terminated string, read from the file, or NULL in
 * case of an error.
 * The return string must be freed by free()
 */
char *tracefs_instance_file_read(struct tracefs_instance *instance,
				  char *file, int *psize)
{
	char *buf = NULL;
	int size = 0;
	char *path;

	path = tracefs_instance_get_file(instance, file);
	if (!path)
		return NULL;

	size = str_read_file(path, &buf);

	tracefs_put_tracing_file(path);
	if (buf && psize)
		*psize = size;

	return buf;
}
