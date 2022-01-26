// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 */
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>

#include "trace-local.h"
#include "trace-cmd.h"
#include "trace-cmd-private.h"

static void convert_file(const char *in, const char *out, int file_version, char *compr)
{
	struct tracecmd_input *ihandle;
	struct tracecmd_output *ohandle;

	ihandle = tracecmd_open_head(in, 0);
	if (!ihandle)
		die("error reading %s", in);

	ohandle = tracecmd_copy(ihandle, out, TRACECMD_FILE_CPU_FLYRECORD, file_version, compr);
	if (!ohandle)
		die("error writing %s", out);

	tracecmd_output_close(ohandle);
	tracecmd_close(ihandle);
}

enum {
	OPT_file_version	= 254,
	OPT_compression		= 255,
};

void trace_convert(int argc, char **argv)
{
	char *input_file = NULL;
	char *output_file = NULL;
	char *compression = NULL;
	int file_version = tracecmd_default_file_version();
	int c;

	if (argc < 2)
		usage(argv);

	if (strcmp(argv[1], "convert") != 0)
		usage(argv);

	for (;;) {
		int option_index = 0;
		static struct option long_options[] = {
			{"compression", required_argument, NULL, OPT_compression},
			{"file-version", required_argument, NULL, OPT_file_version},
			{"help", no_argument, NULL, '?'},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc-1, argv+1, "+hi:o:", long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'i':
			if (input_file)
				die("Only one input file is supported, %s already set",
				    input_file);
			input_file = optarg;
			break;
		case 'o':
			if (output_file)
				die("Only one output file is supported, %s already set",
				    output_file);
			output_file = optarg;
			break;
		case OPT_compression:
			if (strcmp(optarg, "any") && strcmp(optarg, "none") &&
			    !tracecmd_compress_is_supported(optarg, NULL))
				die("Compression algorithm  %s is not supported", optarg);
			compression = optarg;
			break;
		case OPT_file_version:
			file_version = atoi(optarg);
			if (file_version < FILE_VERSION_MIN || file_version > FILE_VERSION_MAX)
				die("Unsupported file version %d, "
				    "supported versions are from %d to %d",
				    file_version, FILE_VERSION_MIN, FILE_VERSION_MAX);

			break;
		case 'h':
		case '?':
		default:
			usage(argv);
		}
	}

	if ((argc - optind) >= 2) {
		if (output_file)
			usage(argv);
		output_file = argv[optind + 1];
	}

	if (!input_file)
		input_file = DEFAULT_INPUT_FILE;
	if (!output_file)
		usage(argv);

	convert_file(input_file, output_file, file_version, compression);
}
