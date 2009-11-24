#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "parse-events.h"

void parse_cmdlines(char *file, int size __unused)
{
	char *comm;
	char *line;
	char *next = NULL;
	int pid;

	line = strtok_r(file, "\n", &next);
	while (line) {
		sscanf(line, "%d %as", &pid,
		       (float *)(void *)&comm); /* workaround gcc warning */
		pevent_register_comm(comm, pid);
		line = strtok_r(NULL, "\n", &next);
	}
}

void parse_proc_kallsyms(char *file, unsigned int size __unused)
{
	unsigned long long addr;
	char *func;
	char *line;
	char *next = NULL;
	char *addr_str;
	char *mod;
	char ch;
	int ret;

	line = strtok_r(file, "\n", &next);
	while (line) {
		mod = NULL;
		ret = sscanf(line, "%as %c %as\t[%as",
			     (float *)(void *)&addr_str, /* workaround gcc warning */
			     &ch,
			     (float *)(void *)&func,
			     (float *)(void *)&mod);
		addr = strtoull(addr_str, NULL, 16);
		free(addr_str);

		/* truncate the extra ']' */
		if (mod)
			mod[strlen(mod) - 1] = 0;

		pevent_register_function(func, addr, mod);

		line = strtok_r(NULL, "\n", &next);
	}
}
