// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2021, VMware, Tzvetomir Stoyanov tz.stoyanov@gmail.com>
 *
 */
#include <stdlib.h>
#include <dlfcn.h>
#include <zlib.h>
#include <errno.h>

#include "trace-cmd-private.h"

#define __ZLIB_NAME		"zlib"
#define __ZLIB_WEIGTH		10

static int zlib_compress(const char *in, unsigned int in_bytes,
			 char *out, unsigned int *out_bytes)
{
	unsigned long out_size = *out_bytes;
	int ret;

	ret = compress2((unsigned char *)out, &out_size,
			(unsigned char *)in, (unsigned long)in_bytes, Z_BEST_COMPRESSION);
	*out_bytes = out_size;
	errno = 0;
	switch (ret) {
	case Z_OK:
		return 0;
	case Z_BUF_ERROR:
		errno = -ENOBUFS;
		break;
	case Z_MEM_ERROR:
		errno = -ENOMEM;
		break;
	case Z_STREAM_ERROR:
		errno = -EINVAL;
		break;
	default:
		errno = -EFAULT;
		break;
	}

	return -1;
}

static int zlib_decompress(const char *in, unsigned int in_bytes,
			   char *out, unsigned int *out_bytes)
{
	unsigned long out_size = *out_bytes;
	int ret;

	ret = uncompress((unsigned char *)out, &out_size,
			 (unsigned char *)in, (unsigned long)in_bytes);
	*out_bytes = out_size;
	errno = 0;
	switch (ret) {
	case Z_OK:
		return 0;
	case Z_BUF_ERROR:
		errno = -ENOBUFS;
		break;
	case Z_MEM_ERROR:
		errno = -ENOMEM;
		break;
	case Z_DATA_ERROR:
		errno = -EINVAL;
		break;
	default:
		errno = -EFAULT;
		break;
	}

	return -1;
}

static unsigned int zlib_compress_bound(unsigned int in_bytes)
{
	return compressBound(in_bytes);
}

static bool zlib_is_supported(const char *name, const char *version)
{
	const char *zver;

	if (!name)
		return false;
	if (strlen(name) != strlen(__ZLIB_NAME) || strcmp(name, __ZLIB_NAME))
		return false;

	if (!version)
		return true;

	zver = zlibVersion();
	if (!zver)
		return false;

	/* Compare the major version number */
	if (atoi(version) <= atoi(zver))
		return true;

	return false;
}

int tracecmd_zlib_init(void)
{
	return tracecmd_compress_proto_register(__ZLIB_NAME, zlibVersion(), __ZLIB_WEIGTH,
						zlib_compress, zlib_decompress,
						zlib_compress_bound, zlib_is_supported);
}