#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <tracefs.h>

#include "trace-local.h"

enum action {
	ACTION_DEFAULT	= 0,
	ACTION_SNAPSHOT	= (1 << 0),
	ACTION_TRACE	= (1 << 1),
	ACTION_SAVE	= (1 << 2),
	ACTION_MAX	= (1 << 3),
	ACTION_CHANGE	= (1 << 4),
};

#define ACTIONS ((ACTION_MAX - 1))

static int do_sql(const char *instance_name,
		  const char *buffer, const char *name, const char *var,
		  const char *trace_dir, bool execute, int action,
		  char **save_fields)
{
	struct tracefs_synth *synth;
	struct tep_handle *tep;
	struct trace_seq seq;
	enum tracefs_synth_handler handler;
	char *err;
	int ret;

	if ((action & ACTIONS) && !var)
		die("Error: -s, -S and -T not supported without -m or -c");

	if (!name)
		name = "Anonymous";

	trace_seq_init(&seq);
	tep = tracefs_local_events(trace_dir);
	if (!tep)
		die("Could not read %s", trace_dir ? trace_dir : "tracefs directory");

	synth = tracefs_sql(tep, name, buffer, &err);
	if (!synth)
		die("Failed creating synthetic event!\n%s", err ? err : "");

	if (tracefs_synth_complete(synth)) {
		if (var) {
			if (action & ACTION_MAX)
				handler = TRACEFS_SYNTH_HANDLE_MAX;
			else
				handler = TRACEFS_SYNTH_HANDLE_CHANGE;

			/* Default to trace if other actions are not set */
			if (!(action & (ACTION_SAVE | ACTION_SNAPSHOT)))
				action |= ACTION_TRACE;

			if (action & ACTION_SAVE) {
				ret = tracefs_synth_save(synth, handler, var, save_fields);
				if (ret < 0) {
					err = "adding save";
					goto failed_action;
				}
			}
			if (action & ACTION_TRACE) {
				/*
				 * By doing the trace before snapshot, it will be included
				 * in the snapshot.
				 */
				ret = tracefs_synth_trace(synth, handler, var);
				if (ret < 0) {
					err = "adding trace";
					goto failed_action;
				}
			}
			if (action & ACTION_SNAPSHOT) {
				ret = tracefs_synth_snapshot(synth, handler, var);
				if (ret < 0) {
					err = "adding snapshot";
 failed_action:
					perror(err);
					if (errno == ENODEV)
						fprintf(stderr, "ERROR: '%s' is not a variable\n",
							var);
					exit(-1);
				}
			}
		}
		tracefs_synth_echo_cmd(&seq, synth);
		if (execute) {
			ret = tracefs_synth_create(synth);
			if (ret < 0)
				die("%s\n", tracefs_error_last(NULL));
		}
	} else {
		struct tracefs_instance *instance = NULL;
		struct tracefs_hist *hist;

		hist = tracefs_synth_get_start_hist(synth);
		if (!hist)
			die("get_start_hist");

		if (instance_name) {
			if (execute)
				instance = tracefs_instance_create(instance_name);
			else
				instance = tracefs_instance_alloc(trace_dir,
								  instance_name);
			if (!instance)
				die("Failed to create instance");
		}
		tracefs_hist_echo_cmd(&seq, instance, hist, 0);
		if (execute) {
			ret = tracefs_hist_start(instance, hist);
			if (ret < 0)
				die("%s\n", tracefs_error_last(instance));
		}
	}

	tracefs_synth_free(synth);

	trace_seq_do_printf(&seq);
	trace_seq_destroy(&seq);
	return 0;
}

void trace_sqlhist (int argc, char **argv)
{
	char *trace_dir = NULL;
	char *buffer = NULL;
	char buf[BUFSIZ];
	int buffer_size = 0;
	const char *file = NULL;
	const char *instance = NULL;
	bool execute = false;
	char **save_fields = NULL;
	const char *name;
	const char *var;
	char **save_argv;
	int action = 0;
	char *tok;
	FILE *fp;
	size_t r;
	int c;
	int i;

	/* Remove 'trace-cmd' */
	save_argv = argv;
	argc -= 1;
	argv += 1;

	if (argc < 2)
		usage(save_argv);

	for (;;) {
		c = getopt(argc, argv, "ht:f:en:m:c:sS:TB:");
		if (c == -1)
			break;

		switch(c) {
		case 'h':
			usage(save_argv);
		case 't':
			trace_dir = optarg;
			break;
		case 'f':
			file = optarg;
			break;
		case 'e':
			execute = true;
			break;
		case 'm':
			action |= ACTION_MAX;
			var = optarg;
			break;
		case 'c':
			action |= ACTION_CHANGE;
			var = optarg;
			break;
		case 's':
			action |= ACTION_SNAPSHOT;
			break;
		case 'S':
			action |= ACTION_SAVE;
			tok = strtok(optarg, ",");
			while (tok) {
				save_fields = tracefs_list_add(save_fields, tok);
				tok = strtok(NULL, ",");
			}
			if (!save_fields) {
				perror(optarg);
				exit(-1);
			}
			break;
		case 'T':
			action |= ACTION_TRACE | ACTION_SNAPSHOT;
			break;
		case 'B':
			instance = optarg;
			break;
		case 'n':
			name = optarg;
			break;
		}
	}

	if ((action & (ACTION_MAX|ACTION_CHANGE)) == (ACTION_MAX|ACTION_CHANGE)) {
		fprintf(stderr, "Can not use both -m and -c together\n");
		exit(-1);
	}
	if (file) {
		if (!strcmp(file, "-"))
			fp = stdin;
		else
			fp = fopen(file, "r");
		if (!fp) {
			perror(file);
			exit(-1);
		}
		while ((r = fread(buf, 1, BUFSIZ, fp)) > 0) {
			buffer = realloc(buffer, buffer_size + r + 1);
			strncpy(buffer + buffer_size, buf, r);
			buffer_size += r;
		}
		fclose(fp);
		if (buffer_size)
			buffer[buffer_size] = '\0';
	} else if (argc == optind) {
		usage(save_argv);
	} else {
		for (i = optind; i < argc; i++) {
			r = strlen(argv[i]);
			buffer = realloc(buffer, buffer_size + r + 2);
			if (i != optind)
				buffer[buffer_size++] = ' ';
			strcpy(buffer + buffer_size, argv[i]);
			buffer_size += r;
		}
	}

	do_sql(instance, buffer, name, var, trace_dir, execute, action, save_fields);
	free(buffer);
}

