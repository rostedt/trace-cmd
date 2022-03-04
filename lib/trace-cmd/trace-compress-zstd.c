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

static int zstd_compress(void *ctx, const void *in, int in_bytes, void *out, int out_bytes)
{
	size_t ret;

	ret = ZSTD_compress2(ctx_c, out, out_bytes, in, in_bytes);
	if (ZSTD_isError(ret))
		return -1;

	return ret;
}

static int zstd_decompress(void *ctx, const void *in, int in_bytes, void *out, int out_bytes)
{
	size_t ret;

	ret = ZSTD_decompressDCtx(ctx_d, out, out_bytes, in, in_bytes);
	if (ZSTD_isError(ret)) {
		errno = -EINVAL;
		return -1;
	}

	errno = 0;
	return ret;
}

static unsigned int zstd_compress_bound(void *ctx, unsigned int in_bytes)
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
	struct tracecmd_compression_proto proto;
	int ret = 0;
	size_t r;

	memset(&proto, 0, sizeof(proto));
	proto.name = __ZSTD_NAME;
	proto.version = ZSTD_versionString();
	proto.weight = __ZSTD_WEIGTH;
	proto.compress = zstd_compress;
	proto.uncompress = zstd_decompress;
	proto.is_supported = zstd_is_supported;
	proto.compress_size = zstd_compress_bound;

	ctx_c = ZSTD_createCCtx();
	ctx_d = ZSTD_createDCtx();
	if (!ctx_c || !ctx_d)
		goto err;

	r = ZSTD_CCtx_setParameter(ctx_c, ZSTD_c_contentSizeFlag, 0);
	if (ZSTD_isError(r))
		goto err;

	ret = tracecmd_compress_proto_register(&proto);
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
