// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2022, Sebastian Andrzej Siewior <sebastian@breakpoint.cc>
 *
 */
#include <stdlib.h>
#include <zstd.h>
#include <errno.h>

#include "trace-cmd-private.h"

#define __ZSTD_NAME		"zstd"
#define __ZSTD_WEIGTH		5

static ZSTD_CCtx *ctx_c;
static ZSTD_DCtx *ctx_d;

static int zstd_compress(const char *in, unsigned int in_bytes,
			 char *out, unsigned int *out_bytes)
{
	size_t ret;

	ret = ZSTD_compress2(ctx_c, out, *out_bytes, in, in_bytes);
	if (ZSTD_isError(ret))
		return -1;
	*out_bytes = ret;
	return 0;
}

static int zstd_decompress(const char *in, unsigned int in_bytes,
			   char *out, unsigned int *out_bytes)
{
	size_t ret;

	ret = ZSTD_decompressDCtx(ctx_d, out, *out_bytes, in, in_bytes);
	if (ZSTD_isError(ret)) {
		errno = -EINVAL;
		return -1;
	}
	*out_bytes = ret;
	errno = 0;
	return 0;
}

static unsigned int zstd_compress_bound(unsigned int in_bytes)
{
	return ZSTD_compressBound(in_bytes);
}

static bool zstd_is_supported(const char *name, const char *version)
{
	if (!name)
		return false;
	if (strcmp(name, __ZSTD_NAME))
		return false;

	return true;
}

int tracecmd_zstd_init(void)
{
	int ret = 0;
	size_t r;

	ctx_c = ZSTD_createCCtx();
	ctx_d = ZSTD_createDCtx();
	if (!ctx_c || !ctx_d)
		goto err;

	r = ZSTD_CCtx_setParameter(ctx_c, ZSTD_c_contentSizeFlag, 0);
	if (ZSTD_isError(r))
		goto err;

	ret = tracecmd_compress_proto_register(__ZSTD_NAME,
					       ZSTD_versionString(),
					       __ZSTD_WEIGTH,
					       zstd_compress,
					       zstd_decompress,
					       zstd_compress_bound,
					       zstd_is_supported);
	if (!ret)
		return 0;
err:
	ZSTD_freeCCtx(ctx_c);
	ZSTD_freeDCtx(ctx_d);
	ctx_c = NULL;
	ctx_d = NULL;
	if (ret < 0)
		return ret;
	return -1;
}
