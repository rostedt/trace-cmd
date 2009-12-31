/*
 * Copyright (C) 2009, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  The parts for function graph printing was taken and modified from the
 *  Linux Kernel that were written by Frederic Weisbecker.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "parse-events.h"

static char *input_buf;
static unsigned long long input_buf_ptr;
static unsigned long long input_buf_siz;

static void init_input_buf(char *buf, unsigned long long size)
{
	input_buf = buf;
	input_buf_siz = size;
	input_buf_ptr = 0;
}

void breakpoint(void)
{
	static int x;
	x++;
}

struct print_arg *alloc_arg(void)
{
	struct print_arg *arg;

	arg = malloc_or_die(sizeof(*arg));
	if (!arg)
		return NULL;
	memset(arg, 0, sizeof(*arg));

	return arg;
}

struct cmdline {
	char *comm;
	int pid;
};

static int cmdline_cmp(const void *a, const void *b)
{
	const struct cmdline *ca = a;
	const struct cmdline *cb = b;

	if (ca->pid < cb->pid)
		return -1;
	if (ca->pid > cb->pid)
		return 1;

	return 0;
}

struct cmdline_list {
	struct cmdline_list	*next;
	char			*comm;
	int			pid;
};

static int cmdline_init(struct pevent *pevent)
{
	struct cmdline_list *cmdlist = pevent->cmdlist;
	struct cmdline_list *item;
	struct cmdline *cmdlines;
	int i;

	cmdlines = malloc_or_die(sizeof(*cmdlines) * pevent->cmdline_count);

	i = 0;
	while (cmdlist) {
		cmdlines[i].pid = cmdlist->pid;
		cmdlines[i].comm = cmdlist->comm;
		i++;
		item = cmdlist;
		cmdlist = cmdlist->next;
		free(item);
	}

	qsort(cmdlines, pevent->cmdline_count, sizeof(*cmdlines), cmdline_cmp);

	pevent->cmdlines = cmdlines;
	pevent->cmdlist = NULL;

	return 0;
}

static char *find_cmdline(struct pevent *pevent, int pid)
{
	const struct cmdline *comm;
	struct cmdline key;

	if (!pid)
		return "<idle>";

	if (!pevent->cmdlines)
		cmdline_init(pevent);

	key.pid = pid;

	comm = bsearch(&key, pevent->cmdlines, pevent->cmdline_count,
		       sizeof(*pevent->cmdlines), cmdline_cmp);

	if (comm)
		return comm->comm;
	return "<...>";
}

/**
 * pevent_pid_is_registered - return if a pid has a cmdline registered
 * @pevent: handle for the pevent
 * @pid: The pid to check if it has a cmdline registered with.
 *
 * Returns 1 if the pid has a cmdline mapped to it
 * 0 otherwise.
 */
int pevent_pid_is_registered(struct pevent *pevent, int pid)
{
	const struct cmdline *comm;
	struct cmdline key;

	if (!pid)
		return 1;

	if (!pevent->cmdlines)
		cmdline_init(pevent);

	key.pid = pid;

	comm = bsearch(&key, pevent->cmdlines, pevent->cmdline_count,
		       sizeof(*pevent->cmdlines), cmdline_cmp);

	if (comm)
		return 1;
	return 0;
}

/*
 * If the command lines have been converted to an array, then
 * we must add this pid. This is much slower than when cmdlines
 * are added before the array is initialized.
 */
static int add_new_comm(struct pevent *pevent, char *comm, int pid)
{
	struct cmdline *cmdlines = pevent->cmdlines;
	const struct cmdline *cmdline;
	struct cmdline key;

	if (!pid)
		return 0;

	/* avoid duplicates */
	key.pid = pid;

	cmdline = bsearch(&key, pevent->cmdlines, pevent->cmdline_count,
		       sizeof(*pevent->cmdlines), cmdline_cmp);
	if (cmdline) {
		errno = EEXIST;
		return -1;
	}

	cmdlines = realloc(cmdlines, sizeof(*cmdlines) * (pevent->cmdline_count + 1));
	if (!cmdlines) {
		errno = ENOMEM;
		return -1;
	}

	cmdlines[pevent->cmdline_count].pid = pid;
	cmdlines[pevent->cmdline_count].comm = comm;
	pevent->cmdline_count++;

	qsort(cmdlines, pevent->cmdline_count, sizeof(*cmdlines), cmdline_cmp);
	pevent->cmdlines = cmdlines;

	return 0;
}

/**
 * pevent_register_comm - register a pid / comm mapping
 * @pevent: handle for the pevent
 * @comm: the command line to register
 * @pid: the pid to map the command line to
 *
 * This adds a mapping to search for command line names with
 * a given pid. The comm is duplicated.
 */
int pevent_register_comm(struct pevent *pevent, char *comm, int pid)
{
	struct cmdline_list *item;

	if (pevent->cmdlines)
		return add_new_comm(pevent, comm, pid);

	item = malloc_or_die(sizeof(*item));
	item->comm = strdup(comm);
	item->pid = pid;
	item->next = pevent->cmdlist;

	pevent->cmdlist = item;
	pevent->cmdline_count++;

	return 0;
}

struct func_map {
	unsigned long long		addr;
	char				*func;
	char				*mod;
};

struct func_list {
	struct func_list	*next;
	unsigned long long	addr;
	char			*func;
	char			*mod;
};

static int func_cmp(const void *a, const void *b)
{
	const struct func_map *fa = a;
	const struct func_map *fb = b;

	if (fa->addr < fb->addr)
		return -1;
	if (fa->addr > fb->addr)
		return 1;

	return 0;
}

/*
 * We are searching for a record in between, not an exact
 * match.
 */
static int func_bcmp(const void *a, const void *b)
{
	const struct func_map *fa = a;
	const struct func_map *fb = b;

	if ((fa->addr == fb->addr) ||

	    (fa->addr > fb->addr &&
	     fa->addr < (fb+1)->addr))
		return 0;

	if (fa->addr < fb->addr)
		return -1;

	return 1;
}

static int func_map_init(struct pevent *pevent)
{
	struct func_list *funclist;
	struct func_list *item;
	struct func_map *func_map;
	int i;

	func_map = malloc_or_die(sizeof(*func_map) * (pevent->func_count + 1));
	funclist = pevent->funclist;

	i = 0;
	while (funclist) {
		func_map[i].func = funclist->func;
		func_map[i].addr = funclist->addr;
		func_map[i].mod = funclist->mod;
		i++;
		item = funclist;
		funclist = funclist->next;
		free(item);
	}

	qsort(func_map, pevent->func_count, sizeof(*func_map), func_cmp);

	/*
	 * Add a special record at the end.
	 */
	func_map[pevent->func_count].func = NULL;
	func_map[pevent->func_count].addr = 0;
	func_map[pevent->func_count].mod = NULL;

	pevent->func_map = func_map;
	pevent->funclist = NULL;

	return 0;
}

static struct func_map *
find_func(struct pevent *pevent, unsigned long long addr)
{
	struct func_map *func;
	struct func_map key;

	if (!pevent->func_map)
		func_map_init(pevent);

	key.addr = addr;

	func = bsearch(&key, pevent->func_map, pevent->func_count,
		       sizeof(*pevent->func_map), func_bcmp);

	return func;
}

/**
 * pevent_find_function - find a function by a given address
 * @pevent: handle for the pevent
 * @addr: the address to find the function with
 *
 * Returns a pointer to the function stored that has the given
 * address. Note, the address does not have to be exact, it
 * will select the function that would contain the address.
 */
const char *pevent_find_function(struct pevent *pevent, unsigned long long addr)
{
	struct func_map *map;

	map = find_func(pevent, addr);
	if (!map)
		return NULL;

	return map->func;
}

/**
 * pevent_register_function - register a function with a given address
 * @pevent: handle for the pevent
 * @function: the function name to register
 * @addr: the address the function starts at
 * @mod: the kernel module the function may be in (NULL for none)
 *
 * This registers a function name with an address and module.
 * The @func passed in is duplicated.
 */
int pevent_register_function(struct pevent *pevent, char *func,
			     unsigned long long addr, char *mod)
{
	struct func_list *item;

	item = malloc_or_die(sizeof(*item));

	item->next = pevent->funclist;
	item->func = strdup(func);
	if (mod)
		item->mod = strdup(mod);
	else
		item->mod = NULL;
	item->addr = addr;

	pevent->funclist = item;

	pevent->func_count++;

	return 0;
}

/**
 * pevent_print_funcs - print out the stored functions
 * @pevent: handle for the pevent
 *
 * This prints out the stored functions.
 */
void pevent_print_funcs(struct pevent *pevent)
{
	int i;

	if (!pevent->func_map)
		func_map_init(pevent);

	for (i = 0; i < (int)pevent->func_count; i++) {
		printf("%016llx %s",
		       pevent->func_map[i].addr,
		       pevent->func_map[i].func);
		if (pevent->func_map[i].mod)
			printf(" [%s]\n", pevent->func_map[i].mod);
		else
			printf("\n");
	}
}

struct printk_map {
	unsigned long long		addr;
	char				*printk;
};

struct printk_list {
	struct printk_list	*next;
	unsigned long long	addr;
	char			*printk;
};

static int printk_cmp(const void *a, const void *b)
{
	const struct func_map *fa = a;
	const struct func_map *fb = b;

	if (fa->addr < fb->addr)
		return -1;
	if (fa->addr > fb->addr)
		return 1;

	return 0;
}

static void printk_map_init(struct pevent *pevent)
{
	struct printk_list *printklist;
	struct printk_list *item;
	struct printk_map *printk_map;
	int i;

	printk_map = malloc_or_die(sizeof(*printk_map) * (pevent->printk_count + 1));

	printklist = pevent->printklist;

	i = 0;
	while (printklist) {
		printk_map[i].printk = printklist->printk;
		printk_map[i].addr = printklist->addr;
		i++;
		item = printklist;
		printklist = printklist->next;
		free(item);
	}

	qsort(printk_map, pevent->printk_count, sizeof(*printk_map), printk_cmp);

	pevent->printk_map = printk_map;
	pevent->printklist = NULL;
}

static struct printk_map *
find_printk(struct pevent *pevent, unsigned long long addr)
{
	struct printk_map *printk;
	struct printk_map key;

	if (!pevent->printk_map)
		printk_map_init(pevent);

	key.addr = addr;

	printk = bsearch(&key, pevent->printk_map, pevent->printk_count,
			 sizeof(*pevent->printk_map), printk_cmp);

	return printk;
}

/**
 * pevent_register_print_string - register a string by its address
 * @pevent: handle for the pevent
 * @fmt: the string format to register
 * @addr: the address the string was located at
 *
 * This registers a string by the address it was stored in the kernel.
 * The @fmt passed in is duplicated.
 */
int pevent_register_print_string(struct pevent *pevent, char *fmt,
				 unsigned long long addr)
{
	struct printk_list *item;

	item = malloc_or_die(sizeof(*item));

	item->next = pevent->printklist;
	pevent->printklist = item;
	item->printk = strdup(fmt);
	item->addr = addr;

	pevent->printk_count++;

	return 0;
}

/**
 * pevent_print_printk - print out the stored strings
 * @pevent: handle for the pevent
 *
 * This prints the string formats that were stored.
 */
void pevent_print_printk(struct pevent *pevent)
{
	int i;

	if (!pevent->printk_map)
		printk_map_init(pevent);

	for (i = 0; i < (int)pevent->printk_count; i++) {
		printf("%016llx %s\n",
		       pevent->printk_map[i].addr,
		       pevent->printk_map[i].printk);
	}
}

static struct event_format *alloc_event(void)
{
	struct event_format *event;

	event = malloc_or_die(sizeof(*event));
	memset(event, 0, sizeof(*event));

	return event;
}

enum event_type {
	EVENT_ERROR,
	EVENT_NONE,
	EVENT_SPACE,
	EVENT_NEWLINE,
	EVENT_OP,
	EVENT_DELIM,
	EVENT_ITEM,
	EVENT_DQUOTE,
	EVENT_SQUOTE,
};

static void add_event(struct pevent *pevent, struct event_format *event)
{
	event->next = pevent->event_list;
	pevent->event_list = event;
	pevent->nr_events++;

	event->pevent = pevent;
}

static int event_item_type(enum event_type type)
{
	switch (type) {
	case EVENT_ITEM ... EVENT_SQUOTE:
		return 1;
	case EVENT_ERROR ... EVENT_DELIM:
	default:
		return 0;
	}
}

static void free_flag_sym(struct print_flag_sym *fsym)
{
	struct print_flag_sym *next;

	while (fsym) {
		next = fsym->next;
		free(fsym->value);
		free(fsym->str);
		free(fsym);
		fsym = next;
	}
}

static void free_arg(struct print_arg *arg)
{
	if (!arg)
		return;

	switch (arg->type) {
	case PRINT_ATOM:
		free(arg->atom.atom);
		break;
	case PRINT_FIELD:
		free(arg->field.name);
		break;
	case PRINT_FLAGS:
		free_arg(arg->flags.field);
		free(arg->flags.delim);
		free_flag_sym(arg->flags.flags);
		break;
	case PRINT_SYMBOL:
		free_arg(arg->symbol.field);
		free_flag_sym(arg->symbol.symbols);
		break;
	case PRINT_TYPE:
		free(arg->typecast.type);
		free_arg(arg->typecast.item);
		break;
	case PRINT_STRING:
		free(arg->string.string);
		break;
	case PRINT_DYNAMIC_ARRAY:
		free(arg->dynarray.index);
		break;
	case PRINT_OP:
		free(arg->op.op);
		free_arg(arg->op.left);
		free_arg(arg->op.right);

	case PRINT_NULL:
	default:
		break;
	}

	free(arg);
}

static enum event_type get_type(int ch)
{
	if (ch == '\n')
		return EVENT_NEWLINE;
	if (isspace(ch))
		return EVENT_SPACE;
	if (isalnum(ch) || ch == '_')
		return EVENT_ITEM;
	if (ch == '\'')
		return EVENT_SQUOTE;
	if (ch == '"')
		return EVENT_DQUOTE;
	if (!isprint(ch))
		return EVENT_NONE;
	if (ch == '(' || ch == ')' || ch == ',')
		return EVENT_DELIM;

	return EVENT_OP;
}

static void __push_char(char c)
{
	if (input_buf_ptr <= 0)
		die("too much pushback");
	input_buf[--input_buf_ptr] = c;
}

static void __push_str(char *s)
{
	char *e = s;

	while (*e++)
		/* nothing */;
	e--;
	while (s != e) {
		e--;
		__push_char(*e);
	}
}

static int __read_char(void)
{
	if (input_buf_ptr >= input_buf_siz)
		return -1;

	return input_buf[input_buf_ptr++];
}

static int __peek_char(void)
{
	if (input_buf_ptr >= input_buf_siz)
		return -1;

	return input_buf[input_buf_ptr];
}

static enum event_type __read_token(char **tok)
{
	char buf[BUFSIZ];
	int ch, last_ch, quote_ch, next_ch;
	int i = 0;
	int tok_size = 0;
	enum event_type type;

	*tok = NULL;


	ch = __read_char();
	if (ch < 0)
		return EVENT_NONE;

	type = get_type(ch);
	if (type == EVENT_NONE)
		return type;

	buf[i++] = ch;

	switch (type) {
	case EVENT_NEWLINE:
	case EVENT_DELIM:
		*tok = malloc_or_die(2);
		(*tok)[0] = ch;
		(*tok)[1] = 0;
		return type;

	case EVENT_OP:
		switch (ch) {
		case '-':
			next_ch = __peek_char();
			if (next_ch == '>') {
				buf[i++] = __read_char();
				break;
			}
			/* fall through */
		case '+':
		case '|':
		case '&':
		case '>':
		case '<':
			last_ch = ch;
			ch = __peek_char();
			if (ch != last_ch)
				goto test_equal;
			buf[i++] = __read_char();
			switch (last_ch) {
			case '>':
			case '<':
				goto test_equal;
			default:
				break;
			}
			break;
		case '!':
		case '=':
			goto test_equal;
		default: /* what should we do instead? */
			break;
		}
		buf[i] = 0;
		*tok = strdup(buf);
		return type;

 test_equal:
		ch = __peek_char();
		if (ch == '=')
			buf[i++] = __read_char();
		break;

	case EVENT_DQUOTE:
	case EVENT_SQUOTE:
		/* don't keep quotes */
		i--;
		quote_ch = ch;
		last_ch = 0;
		do {
			if (i == (BUFSIZ - 1)) {
				buf[i] = 0;
				if (*tok) {
					*tok = realloc(*tok, tok_size + BUFSIZ);
					if (!*tok)
						return EVENT_NONE;
					strcat(*tok, buf);
				} else
					*tok = strdup(buf);

				if (!*tok)
					return EVENT_NONE;
				tok_size += BUFSIZ;
				i = 0;
			}
			last_ch = ch;
			ch = __read_char();
			buf[i++] = ch;
			/* the '\' '\' will cancel itself */
			if (ch == '\\' && last_ch == '\\')
				last_ch = 0;
		} while (ch != quote_ch || last_ch == '\\');
		/* remove the last quote */
		i--;
		goto out;

	case EVENT_ERROR ... EVENT_SPACE:
	case EVENT_ITEM:
	default:
		break;
	}

	while (get_type(__peek_char()) == type) {
		if (i == (BUFSIZ - 1)) {
			buf[i] = 0;
			if (*tok) {
				*tok = realloc(*tok, tok_size + BUFSIZ);
				if (!*tok)
					return EVENT_NONE;
				strcat(*tok, buf);
			} else
				*tok = strdup(buf);

			if (!*tok)
				return EVENT_NONE;
			tok_size += BUFSIZ;
			i = 0;
		}
		ch = __read_char();
		buf[i++] = ch;
	}

 out:
	buf[i] = 0;
	if (*tok) {
		*tok = realloc(*tok, tok_size + i);
		if (!*tok)
			return EVENT_NONE;
		strcat(*tok, buf);
	} else
		*tok = strdup(buf);
	if (!*tok)
		return EVENT_NONE;

	if (type == EVENT_ITEM) {
		/*
		 * Older versions of the kernel has a bug that
		 * creates invalid symbols and will break the mac80211
		 * parsing. This is a work around to that bug.
		 *
		 * See Linux kernel commit:
		 *  811cb50baf63461ce0bdb234927046131fc7fa8b
		 */
		if (strcmp(*tok, "LOCAL_PR_FMT") == 0) {
			free(*tok);
			*tok = NULL;
			__push_str("\"\%s\" ");
			return __read_token(tok);
		} else if (strcmp(*tok, "STA_PR_FMT") == 0) {
			free(*tok);
			*tok = NULL;
			__push_str("\" sta:%pM\" ");
			return __read_token(tok);
		} else if (strcmp(*tok, "VIF_PR_FMT") == 0) {
			free(*tok);
			*tok = NULL;
			__push_str("\" vif:%p(%d)\" ");
			return __read_token(tok);
		}
	}

	return type;
}

static void free_token(char *tok)
{
	if (tok)
		free(tok);
}

static enum event_type read_token(char **tok)
{
	enum event_type type;

	for (;;) {
		type = __read_token(tok);
		if (type != EVENT_SPACE)
			return type;

		free_token(*tok);
	}

	/* not reached */
	*tok = NULL;
	return EVENT_NONE;
}

/* no newline */
static enum event_type read_token_item(char **tok)
{
	enum event_type type;

	for (;;) {
		type = __read_token(tok);
		if (type != EVENT_SPACE && type != EVENT_NEWLINE)
			return type;
		free_token(*tok);
		*tok = NULL;
	}

	/* not reached */
	*tok = NULL;
	return EVENT_NONE;
}

static int test_type(enum event_type type, enum event_type expect)
{
	if (type != expect) {
		warning("Error: expected type %d but read %d",
		    expect, type);
		return -1;
	}
	return 0;
}

static int test_type_token(enum event_type type, const char *token,
		    enum event_type expect, const char *expect_tok)
{
	if (type != expect) {
		warning("Error: expected type %d but read %d",
		    expect, type);
		return -1;
	}

	if (strcmp(token, expect_tok) != 0) {
		warning("Error: expected '%s' but read '%s'",
		    expect_tok, token);
		return -1;
	}
	return 0;
}

static int __read_expect_type(enum event_type expect, char **tok, int newline_ok)
{
	enum event_type type;

	if (newline_ok)
		type = read_token(tok);
	else
		type = read_token_item(tok);
	return test_type(type, expect);
}

static int read_expect_type(enum event_type expect, char **tok)
{
	return __read_expect_type(expect, tok, 1);
}

static int __read_expected(enum event_type expect, const char *str,
			   int newline_ok)
{
	enum event_type type;
	char *token;
	int ret;

	if (newline_ok)
		type = read_token(&token);
	else
		type = read_token_item(&token);

	ret = test_type_token(type, token, expect, str);

	free_token(token);

	return ret;
}

static int read_expected(enum event_type expect, const char *str)
{
	return __read_expected(expect, str, 1);
}

static int read_expected_item(enum event_type expect, const char *str)
{
	return __read_expected(expect, str, 0);
}

static char *event_read_name(void)
{
	char *token;

	if (read_expected(EVENT_ITEM, "name") < 0)
		return NULL;

	if (read_expected(EVENT_OP, ":") < 0)
		return NULL;

	if (read_expect_type(EVENT_ITEM, &token) < 0)
		goto fail;

	return token;

 fail:
	free_token(token);
	return NULL;
}

static int event_read_id(void)
{
	char *token;
	int id;

	if (read_expected_item(EVENT_ITEM, "ID") < 0)
		return -1;

	if (read_expected(EVENT_OP, ":") < 0)
		return -1;

	if (read_expect_type(EVENT_ITEM, &token) < 0)
		goto fail;

	id = strtoul(token, NULL, 0);
	free_token(token);
	return id;

 fail:
	free_token(token);
	return -1;
}

static int field_is_string(struct format_field *field)
{
	if ((field->flags & FIELD_IS_ARRAY) &&
	    (!strstr(field->type, "char") || !strstr(field->type, "u8") ||
	     !strstr(field->type, "s8")))
		return 1;

	return 0;
}

static int field_is_dynamic(struct format_field *field)
{
	if (!strcmp(field->type, "__data_loc"))
		return 1;

	return 0;
}

static int event_read_fields(struct event_format *event, struct format_field **fields)
{
	struct format_field *field = NULL;
	enum event_type type;
	char *token;
	char *last_token;
	int count = 0;

	do {
		type = read_token(&token);
		if (type == EVENT_NEWLINE) {
			free_token(token);
			return count;
		}

		count++;

		if (test_type_token(type, token, EVENT_ITEM, "field"))
			goto fail;
		free_token(token);

		type = read_token(&token);
		/*
		 * The ftrace fields may still use the "special" name.
		 * Just ignore it.
		 */
		if (event->flags & EVENT_FL_ISFTRACE &&
		    type == EVENT_ITEM && strcmp(token, "special") == 0) {
			free_token(token);
			type = read_token(&token);
		}

		if (test_type_token(type, token, EVENT_OP, ":") < 0)
			goto fail;

		free_token(token);
		if (read_expect_type(EVENT_ITEM, &token) < 0)
			goto fail;

		last_token = token;

		field = malloc_or_die(sizeof(*field));
		memset(field, 0, sizeof(*field));
		field->event = event;

		/* read the rest of the type */
		for (;;) {
			type = read_token(&token);
			if (type == EVENT_ITEM ||
			    (type == EVENT_OP && strcmp(token, "*") == 0) ||
			    /*
			     * Some of the ftrace fields are broken and have
			     * an illegal "." in them.
			     */
			    (event->flags & EVENT_FL_ISFTRACE &&
			     type == EVENT_OP && strcmp(token, ".") == 0)) {

				if (strcmp(token, "*") == 0)
					field->flags |= FIELD_IS_POINTER;

				if (field->type) {
					field->type = realloc(field->type,
							      strlen(field->type) +
							      strlen(last_token) + 2);
					strcat(field->type, " ");
					strcat(field->type, last_token);
					free(last_token);
				} else
					field->type = last_token;
				last_token = token;
				continue;
			}

			break;
		}

		if (!field->type) {
			die("no type found");
			goto fail;
		}
		field->name = last_token;

		if (test_type(type, EVENT_OP))
			goto fail;

		if (strcmp(token, "[") == 0) {
			enum event_type last_type = type;
			char *brackets = token;
			int len;

			field->flags |= FIELD_IS_ARRAY;

			type = read_token(&token);
		        while (strcmp(token, "]") != 0) {
				if (last_type == EVENT_ITEM &&
				    type == EVENT_ITEM)
					len = 2;
				else
					len = 1;
				last_type = type;

				brackets = realloc(brackets,
						   strlen(brackets) +
						   strlen(token) + len);
				if (len == 2)
					strcat(brackets, " ");
				strcat(brackets, token);
				free_token(token);
				type = read_token(&token);
				if (type == EVENT_NONE) {
					die("failed to find token");
					goto fail;
				}
			}

			free_token(token);

			brackets = realloc(brackets, strlen(brackets) + 2);
			strcat(brackets, "]");

			/* add brackets to type */

			type = read_token(&token);
			/*
			 * If the next token is not an OP, then it is of
			 * the format: type [] item;
			 */
			if (type == EVENT_ITEM) {
				field->type = realloc(field->type,
						      strlen(field->type) +
						      strlen(field->name) +
						      strlen(brackets) + 2);
				strcat(field->type, " ");
				strcat(field->type, field->name);
				free_token(field->name);
				strcat(field->type, brackets);
				field->name = token;
				type = read_token(&token);
			} else {
				field->type = realloc(field->type,
						      strlen(field->type) +
						      strlen(brackets) + 1);
				strcat(field->type, brackets);
			}
			free(brackets);
		}

		if (field_is_string(field)) {
			field->flags |= FIELD_IS_STRING;
			if (field_is_dynamic(field))
				field->flags |= FIELD_IS_DYNAMIC;
		}

		if (test_type_token(type, token,  EVENT_OP, ";"))
			goto fail;
		free_token(token);

		if (read_expected(EVENT_ITEM, "offset") < 0)
			goto fail_expect;

		if (read_expected(EVENT_OP, ":") < 0)
			goto fail_expect;

		if (read_expect_type(EVENT_ITEM, &token))
			goto fail;
		field->offset = strtoul(token, NULL, 0);
		free_token(token);

		if (read_expected(EVENT_OP, ";") < 0)
			goto fail_expect;

		if (read_expected(EVENT_ITEM, "size") < 0)
			goto fail_expect;

		if (read_expected(EVENT_OP, ":") < 0)
			goto fail_expect;

		if (read_expect_type(EVENT_ITEM, &token))
			goto fail;
		field->size = strtoul(token, NULL, 0);
		free_token(token);

		if (read_expected(EVENT_OP, ";") < 0)
			goto fail_expect;

		type = read_token(&token);
		if (type != EVENT_NEWLINE) {
			/* newer versions of the kernel have a "signed" type */
			if (test_type_token(type, token, EVENT_ITEM, "signed"))
				goto fail;

			free_token(token);

			if (read_expected(EVENT_OP, ":") < 0)
				goto fail_expect;

			if (read_expect_type(EVENT_ITEM, &token))
				goto fail;

			/* add signed type */

			free_token(token);
			if (read_expected(EVENT_OP, ";") < 0)
				goto fail_expect;

			if (read_expect_type(EVENT_NEWLINE, &token))
				goto fail;
		}

		free_token(token);

		*fields = field;
		fields = &field->next;

	} while (1);

	return 0;

fail:
	free_token(token);
fail_expect:
	if (field)
		free(field);
	return -1;
}

static int event_read_format(struct event_format *event)
{
	char *token;
	int ret;

	if (read_expected_item(EVENT_ITEM, "format") < 0)
		return -1;

	if (read_expected(EVENT_OP, ":") < 0)
		return -1;

	if (read_expect_type(EVENT_NEWLINE, &token))
		goto fail;
	free_token(token);

	ret = event_read_fields(event, &event->format.common_fields);
	if (ret < 0)
		return ret;
	event->format.nr_common = ret;

	ret = event_read_fields(event, &event->format.fields);
	if (ret < 0)
		return ret;
	event->format.nr_fields = ret;

	return 0;

 fail:
	free_token(token);
	return -1;
}

static enum event_type
process_arg_token(struct event_format *event, struct print_arg *arg,
		  char **tok, enum event_type type);

static enum event_type
process_arg(struct event_format *event, struct print_arg *arg, char **tok)
{
	enum event_type type;
	char *token;

	type = read_token(&token);
	*tok = token;

	return process_arg_token(event, arg, tok, type);
}

static enum event_type
process_cond(struct event_format *event, struct print_arg *top, char **tok)
{
	struct print_arg *arg, *left, *right;
	enum event_type type;
	char *token = NULL;

	arg = alloc_arg();
	left = alloc_arg();
	right = alloc_arg();

	arg->type = PRINT_OP;
	arg->op.left = left;
	arg->op.right = right;

	*tok = NULL;
	type = process_arg(event, left, &token);
	if (test_type_token(type, token, EVENT_OP, ":"))
		goto out_free;

	arg->op.op = token;

	type = process_arg(event, right, &token);

	top->op.right = arg;

	*tok = token;
	return type;

out_free:
	free_token(*tok);
	*tok = NULL;
	free(right);
	free(left);
	free_arg(arg);
	return EVENT_ERROR;
}

static enum event_type
process_array(struct event_format *event, struct print_arg *top, char **tok)
{
	struct print_arg *arg;
	enum event_type type;
	char *token = NULL;

	arg = alloc_arg();

	*tok = NULL;
	type = process_arg(event, arg, &token);
	if (test_type_token(type, token, EVENT_OP, "]"))
		goto out_free;

	top->op.right = arg;

	free_token(token);
	type = read_token_item(&token);
	*tok = token;

	return type;

out_free:
	free_token(*tok);
	*tok = NULL;
	free_arg(arg);
	return EVENT_ERROR;
}

static int get_op_prio(char *op)
{
	if (!op[1]) {
		switch (op[0]) {
		case '*':
		case '/':
		case '%':
			return 6;
		case '+':
		case '-':
			return 7;
			/* '>>' and '<<' are 8 */
		case '<':
		case '>':
			return 9;
			/* '==' and '!=' are 10 */
		case '&':
			return 11;
		case '^':
			return 12;
		case '|':
			return 13;
		case '?':
			return 16;
		default:
			die("unknown op '%c'", op[0]);
			return -1;
		}
	} else {
		if (strcmp(op, "++") == 0 ||
		    strcmp(op, "--") == 0) {
			return 3;
		} else if (strcmp(op, ">>") == 0 ||
			   strcmp(op, "<<") == 0) {
			return 8;
		} else if (strcmp(op, ">=") == 0 ||
			   strcmp(op, "<=") == 0) {
			return 9;
		} else if (strcmp(op, "==") == 0 ||
			   strcmp(op, "!=") == 0) {
			return 10;
		} else if (strcmp(op, "&&") == 0) {
			return 14;
		} else if (strcmp(op, "||") == 0) {
			return 15;
		} else {
			die("unknown op '%s'", op);
			return -1;
		}
	}
}

static void set_op_prio(struct print_arg *arg)
{

	/* single ops are the greatest */
	if (!arg->op.left || arg->op.left->type == PRINT_NULL) {
		arg->op.prio = 0;
		return;
	}

	arg->op.prio = get_op_prio(arg->op.op);
}

static enum event_type
process_op(struct event_format *event, struct print_arg *arg, char **tok)
{
	struct print_arg *left, *right = NULL;
	enum event_type type;
	char *token;

	/* the op is passed in via tok */
	token = *tok;

	if (arg->type == PRINT_OP && !arg->op.left) {
		/* handle single op */
		if (token[1]) {
			die("bad op token %s", token);
			goto out_free;
		}
		switch (token[0]) {
		case '!':
		case '+':
		case '-':
			break;
		default:
			warning("bad op token %s", token);
			goto out_free;

		}

		/* make an empty left */
		left = alloc_arg();
		left->type = PRINT_NULL;
		arg->op.left = left;

		right = alloc_arg();
		arg->op.right = right;

		free_token(token);
		type = process_arg(event, right, tok);

	} else if (strcmp(token, "?") == 0) {

		left = alloc_arg();
		/* copy the top arg to the left */
		*left = *arg;

		arg->type = PRINT_OP;
		arg->op.op = token;
		arg->op.left = left;
		arg->op.prio = 0;

		type = process_cond(event, arg, tok);

	} else if (strcmp(token, ">>") == 0 ||
		   strcmp(token, "<<") == 0 ||
		   strcmp(token, "&") == 0 ||
		   strcmp(token, "|") == 0 ||
		   strcmp(token, "&&") == 0 ||
		   strcmp(token, "||") == 0 ||
		   strcmp(token, "-") == 0 ||
		   strcmp(token, "+") == 0 ||
		   strcmp(token, "*") == 0 ||
		   strcmp(token, "^") == 0 ||
		   strcmp(token, "/") == 0 ||
		   strcmp(token, "<") == 0 ||
		   strcmp(token, ">") == 0 ||
		   strcmp(token, "==") == 0 ||
		   strcmp(token, "!=") == 0) {

		left = alloc_arg();

		/* copy the top arg to the left */
		*left = *arg;

		arg->type = PRINT_OP;
		arg->op.op = token;
		arg->op.left = left;

		set_op_prio(arg);

		type = read_token_item(&token);
		*tok = token;

		/* could just be a type pointer */
		if ((strcmp(arg->op.op, "*") == 0) &&
		    type == EVENT_DELIM && (strcmp(token, ")") == 0)) {
			if (left->type != PRINT_ATOM)
				die("bad pointer type");
			left->atom.atom = realloc(left->atom.atom,
					    strlen(left->atom.atom) + 3);
			strcat(left->atom.atom, " *");
			free(arg->op.op);
			*arg = *left;
			free(left);

			return type;
		}

		right = alloc_arg();
		type = process_arg_token(event, right, tok, type);
		arg->op.right = right;

	} else if (strcmp(token, "[") == 0) {

		left = alloc_arg();
		*left = *arg;

		arg->type = PRINT_OP;
		arg->op.op = token;
		arg->op.left = left;

		arg->op.prio = 0;

		type = process_array(event, arg, tok);

	} else {
		warning("unknown op '%s'", token);
		event->flags |= EVENT_FL_FAILED;
		/* the arg is now the left side */
		goto out_free;
	}

	if (type == EVENT_OP) {
		int prio;

		/* higher prios need to be closer to the root */
		prio = get_op_prio(*tok);

		if (prio > arg->op.prio)
			return process_op(event, arg, tok);

		return process_op(event, right, tok);
	}

	return type;

 out_free:
	free_token(token);
	*tok = NULL;
	return EVENT_ERROR;
}

static enum event_type
process_entry(struct event_format *event __unused, struct print_arg *arg,
	      char **tok)
{
	enum event_type type;
	char *field;
	char *token;

	if (read_expected(EVENT_OP, "->") < 0)
		goto out_err;

	if (read_expect_type(EVENT_ITEM, &token) < 0)
		goto out_free;
	field = token;

	arg->type = PRINT_FIELD;
	arg->field.name = field;

	type = read_token(&token);
	*tok = token;

	return type;

 out_free:
	free_token(token);
 out_err:
	*tok = NULL;
	return EVENT_ERROR;
}

static char *arg_eval (struct print_arg *arg);

static unsigned long long
eval_type_str(unsigned long long val, const char *type, int pointer)
{
	int sign = 0;
	char *ref;
	int len;

	len = strlen(type);

	if (pointer) {

		if (type[len-1] != '*') {
			warning("pointer expected with non pointer type");
			return val;
		}

		ref = malloc_or_die(len);
		memcpy(ref, type, len);

		/* chop off the " *" */
		ref[len - 2] = 0;

		val = eval_type_str(val, ref, 0);
		free(ref);
		return val;
	}

	/* check if this is a pointer */
	if (type[len - 1] == '*')
		return val;

	/* Try to figure out the arg size*/
	if (strncmp(type, "struct", 6) == 0)
		/* all bets off */
		return val;

	if (strcmp(type, "u8") == 0)
		return val & 0xff;

	if (strcmp(type, "u16") == 0)
		return val & 0xffff;

	if (strcmp(type, "u32") == 0)
		return val & 0xffffffff;

	if (strcmp(type, "u64") == 0 ||
	    strcmp(type, "s64"))
		return val;

	if (strcmp(type, "s8") == 0)
		return (unsigned long long)(char)val & 0xff;

	if (strcmp(type, "s16") == 0)
		return (unsigned long long)(short)val & 0xffff;

	if (strcmp(type, "s32") == 0)
		return (unsigned long long)(int)val & 0xffffffff;

	if (strncmp(type, "unsigned ", 9) == 0) {
		sign = 0;
		type += 9;
	}

	if (strcmp(type, "char") == 0) {
		if (sign)
			return (unsigned long long)(char)val & 0xff;
		else
			return val & 0xff;
	}

	if (strcmp(type, "short") == 0) {
		if (sign)
			return (unsigned long long)(short)val & 0xffff;
		else
			return val & 0xffff;
	}

	if (strcmp(type, "int") == 0) {
		if (sign)
			return (unsigned long long)(int)val & 0xffffffff;
		else
			return val & 0xffffffff;
	}

	return val;
}

/*
 * Try to figure out the type.
 */
static unsigned long long
eval_type(unsigned long long val, struct print_arg *arg, int pointer)
{
	if (arg->type != PRINT_TYPE)
		die("expected type argument");

	return eval_type_str(val, arg->typecast.type, pointer);
}

static long long arg_num_eval(struct print_arg *arg)
{
	long long left, right;
	long long val = 0;

	switch (arg->type) {
	case PRINT_ATOM:
		val = strtoll(arg->atom.atom, NULL, 0);
		break;
	case PRINT_TYPE:
		val = arg_num_eval(arg->typecast.item);
		val = eval_type(val, arg, 0);
		break;
	case PRINT_OP:
		switch (arg->op.op[0]) {
		case '|':
			left = arg_num_eval(arg->op.left);
			right = arg_num_eval(arg->op.right);
			if (arg->op.op[1])
				val = left || right;
			else
				val = left | right;
			break;
		case '&':
			left = arg_num_eval(arg->op.left);
			right = arg_num_eval(arg->op.right);
			if (arg->op.op[1])
				val = left && right;
			else
				val = left & right;
			break;
		case '<':
			left = arg_num_eval(arg->op.left);
			right = arg_num_eval(arg->op.right);
			switch (arg->op.op[1]) {
			case 0:
				val = left < right;
				break;
			case '<':
				val = left << right;
				break;
			case '=':
				val = left <= right;
				break;
			default:
				die("unknown op '%s'", arg->op.op);
			}
			break;
		case '>':
			left = arg_num_eval(arg->op.left);
			right = arg_num_eval(arg->op.right);
			switch (arg->op.op[1]) {
			case 0:
				val = left > right;
				break;
			case '>':
				val = left >> right;
				break;
			case '=':
				val = left >= right;
				break;
			default:
				die("unknown op '%s'", arg->op.op);
			}
			break;
		case '=':
			left = arg_num_eval(arg->op.left);
			right = arg_num_eval(arg->op.right);

			if (arg->op.op[1] != '=')
				die("unknown op '%s'", arg->op.op);

			val = left == right;
			break;
		case '!':
			left = arg_num_eval(arg->op.left);
			right = arg_num_eval(arg->op.right);

			switch (arg->op.op[1]) {
			case '=':
				val = left != right;
				break;
			default:
				die("unknown op '%s'", arg->op.op);
			}
			break;
		case '-':
			/* check for negative */
			if (arg->op.left->type == PRINT_NULL)
				left = 0;
			else
				left = arg_num_eval(arg->op.left);
			right = arg_num_eval(arg->op.right);
			val = left - right;
			break;
		default:
			die("unknown op '%s'", arg->op.op);
		}
		break;

	case PRINT_NULL:
	case PRINT_FIELD ... PRINT_SYMBOL:
	case PRINT_STRING:
	default:
		die("invalid eval type %d", arg->type);

	}
	return val;
}

static char *arg_eval (struct print_arg *arg)
{
	long long val;
	static char buf[20];

	switch (arg->type) {
	case PRINT_ATOM:
		return arg->atom.atom;
	case PRINT_TYPE:
		return arg_eval(arg->typecast.item);
	case PRINT_OP:
		val = arg_num_eval(arg);
		sprintf(buf, "%lld", val);
		return buf;

	case PRINT_NULL:
	case PRINT_FIELD ... PRINT_SYMBOL:
	case PRINT_STRING:
	default:
		die("invalid eval type %d", arg->type);
		break;
	}

	return NULL;
}

static enum event_type
process_fields(struct event_format *event, struct print_flag_sym **list, char **tok)
{
	enum event_type type;
	struct print_arg *arg = NULL;
	struct print_flag_sym *field;
	char *token = *tok;
	char *value;

	do {
		free_token(token);
		type = read_token_item(&token);
		if (test_type_token(type, token, EVENT_OP, "{"))
			break;

		arg = alloc_arg();

		free_token(token);
		type = process_arg(event, arg, &token);
		if (test_type_token(type, token, EVENT_DELIM, ","))
			goto out_free;

		field = malloc_or_die(sizeof(*field));
		memset(field, 0, sizeof(field));

		value = arg_eval(arg);
		field->value = strdup(value);

		free_arg(arg);
		arg = alloc_arg();

		free_token(token);
		type = process_arg(event, arg, &token);
		if (test_type_token(type, token, EVENT_OP, "}"))
			goto out_free;

		value = arg_eval(arg);
		field->str = strdup(value);
		free_arg(arg);
		arg = NULL;

		*list = field;
		list = &field->next;

		free_token(token);
		type = read_token_item(&token);
	} while (type == EVENT_DELIM && strcmp(token, ",") == 0);

	*tok = token;
	return type;

out_free:
	free_arg(arg);
	free_token(token);
	*tok = NULL;

	return EVENT_ERROR;
}

static enum event_type
process_flags(struct event_format *event, struct print_arg *arg, char **tok)
{
	struct print_arg *field;
	enum event_type type;
	char *token;

	memset(arg, 0, sizeof(*arg));
	arg->type = PRINT_FLAGS;

	if (read_expected_item(EVENT_DELIM, "(") < 0)
		goto out_err;

	field = alloc_arg();

	type = process_arg(event, field, &token);
	if (test_type_token(type, token, EVENT_DELIM, ","))
		goto out_free;
	free_token(token);

	arg->flags.field = field;

	type = read_token_item(&token);
	if (event_item_type(type)) {
		arg->flags.delim = token;
		type = read_token_item(&token);
	}

	if (test_type_token(type, token, EVENT_DELIM, ","))
		goto out_free;

	type = process_fields(event, &arg->flags.flags, &token);
	if (test_type_token(type, token, EVENT_DELIM, ")"))
		goto out_free;

	free_token(token);
	type = read_token_item(tok);
	return type;

 out_free:
	free_token(token);
 out_err:
	*tok = NULL;
	return EVENT_ERROR;
}

static enum event_type
process_symbols(struct event_format *event, struct print_arg *arg, char **tok)
{
	struct print_arg *field;
	enum event_type type;
	char *token;

	memset(arg, 0, sizeof(*arg));
	arg->type = PRINT_SYMBOL;

	if (read_expected_item(EVENT_DELIM, "(") < 0)
		goto out_err;

	field = alloc_arg();

	type = process_arg(event, field, &token);
	if (test_type_token(type, token, EVENT_DELIM, ","))
		goto out_free;

	arg->symbol.field = field;

	type = process_fields(event, &arg->symbol.symbols, &token);
	if (test_type_token(type, token, EVENT_DELIM, ")"))
		goto out_free;

	free_token(token);
	type = read_token_item(tok);
	return type;

 out_free:
	free_token(token);
 out_err:
	*tok = NULL;
	return EVENT_ERROR;
}

static enum event_type
process_dynamic_array(struct event_format *event, struct print_arg *arg, char **tok)
{
	struct format_field *field;
	enum event_type type;
	char *token;

	memset(arg, 0, sizeof(*arg));
	arg->type = PRINT_DYNAMIC_ARRAY;

	if (read_expected_item(EVENT_DELIM, "(") < 0)
		goto out_err;

	/*
	 * The item within the parenthesis is another field that holds
	 * the index into where the array starts.
	 */
	type = read_token(&token);
	*tok = token;
	if (type != EVENT_ITEM)
		goto out_free;

	/* Find the field */

	field = pevent_find_field(event, token);
	if (!field)
		goto out_free;

	arg->dynarray.field = field;
	arg->dynarray.index = 0;

	if (read_expected(EVENT_DELIM, ")") < 0)
		goto out_free;

	type = read_token_item(&token);
	*tok = token;
	if (type != EVENT_OP || strcmp(token, "[") != 0)
		return type;

	free_token(token);
	arg = alloc_arg();
	type = process_arg(event, arg, &token);
	if (type == EVENT_ERROR)
		goto out_free;

	if (!test_type_token(type, token, EVENT_OP, "]"))
		goto out_free;

	free_token(token);
	type = read_token_item(tok);
	return type;

 out_free:
	free(arg);
	free_token(token);
 out_err:
	*tok = NULL;
	return EVENT_ERROR;
}

static enum event_type
process_paren(struct event_format *event, struct print_arg *arg, char **tok)
{
	struct print_arg *item_arg;
	enum event_type type;
	char *token;

	type = process_arg(event, arg, &token);

	if (type == EVENT_ERROR)
		goto out_free;

	if (type == EVENT_OP)
		type = process_op(event, arg, &token);

	if (type == EVENT_ERROR)
		goto out_free;

	if (test_type_token(type, token, EVENT_DELIM, ")"))
		goto out_free;

	free_token(token);
	type = read_token_item(&token);

	/*
	 * If the next token is an item or another open paren, then
	 * this was a typecast.
	 */
	if (event_item_type(type) ||
	    (type == EVENT_DELIM && strcmp(token, "(") == 0)) {

		/* make this a typecast and contine */

		/* prevous must be an atom */
		if (arg->type != PRINT_ATOM)
			die("previous needed to be PRINT_ATOM");

		item_arg = alloc_arg();

		arg->type = PRINT_TYPE;
		arg->typecast.type = arg->atom.atom;
		arg->typecast.item = item_arg;
		type = process_arg_token(event, item_arg, &token, type);

	}

	*tok = token;
	return type;

 out_free:
	free_token(token);
	*tok = NULL;
	return EVENT_ERROR;
}


static enum event_type
process_str(struct event_format *event __unused, struct print_arg *arg, char **tok)
{
	enum event_type type;
	char *token;

	if (read_expected(EVENT_DELIM, "(") < 0)
		goto out_err;

	if (read_expect_type(EVENT_ITEM, &token) < 0)
		goto out_free;

	arg->type = PRINT_STRING;
	arg->string.string = token;
	arg->string.offset = -1;

	if (read_expected(EVENT_DELIM, ")") < 0)
		goto out_err;

	type = read_token(&token);
	*tok = token;

	return type;

 out_free:
	free_token(token);
 out_err:
	*tok = NULL;
	return EVENT_ERROR;
}

static enum event_type
process_arg_token(struct event_format *event, struct print_arg *arg,
		  char **tok, enum event_type type)
{
	char *token;
	char *atom;

	token = *tok;

	switch (type) {
	case EVENT_ITEM:
		if (strcmp(token, "REC") == 0) {
			free_token(token);
			type = process_entry(event, arg, &token);
		} else if (strcmp(token, "__print_flags") == 0) {
			free_token(token);
			type = process_flags(event, arg, &token);
		} else if (strcmp(token, "__print_symbolic") == 0) {
			free_token(token);
			type = process_symbols(event, arg, &token);
		} else if (strcmp(token, "__get_str") == 0) {
			free_token(token);
			type = process_str(event, arg, &token);
		} else if (strcmp(token, "__get_dynamic_array") == 0) {
			free_token(token);
			type = process_dynamic_array(event, arg, &token);
		} else {
			atom = token;
			/* test the next token */
			type = read_token_item(&token);

			/* atoms can be more than one token long */
			while (type == EVENT_ITEM) {
				atom = realloc(atom, strlen(atom) + strlen(token) + 2);
				strcat(atom, " ");
				strcat(atom, token);
				free_token(token);
				type = read_token_item(&token);
			}

			/* todo, test for function */

			arg->type = PRINT_ATOM;
			arg->atom.atom = atom;
		}
		break;
	case EVENT_DQUOTE:
	case EVENT_SQUOTE:
		arg->type = PRINT_ATOM;
		arg->atom.atom = token;
		type = read_token_item(&token);
		break;
	case EVENT_DELIM:
		if (strcmp(token, "(") == 0) {
			free_token(token);
			type = process_paren(event, arg, &token);
			break;
		}
	case EVENT_OP:
		/* handle single ops */
		arg->type = PRINT_OP;
		arg->op.op = token;
		arg->op.left = NULL;
		type = process_op(event, arg, &token);

		/* On error, the op is freed */
		if (type == EVENT_ERROR)
			arg->op.op = NULL;

		/* return error type if errored */
		break;

	case EVENT_ERROR ... EVENT_NEWLINE:
	default:
		die("unexpected type %d", type);
	}
	*tok = token;

	return type;
}

static int event_read_print_args(struct event_format *event, struct print_arg **list)
{
	enum event_type type = EVENT_ERROR;
	struct print_arg *arg;
	char *token;
	int args = 0;

	do {
		if (type == EVENT_NEWLINE) {
			type = read_token_item(&token);
			continue;
		}

		arg = alloc_arg();

		type = process_arg(event, arg, &token);

		if (type == EVENT_ERROR) {
			free_token(token);
			free_arg(arg);
			return -1;
		}

		*list = arg;
		args++;

		if (type == EVENT_OP) {
			type = process_op(event, arg, &token);
			free_token(token);
			list = &arg->next;
			continue;
		}

		if (type == EVENT_DELIM && strcmp(token, ",") == 0) {
			free_token(token);
			*list = arg;
			list = &arg->next;
			continue;
		}
		break;
	} while (type != EVENT_NONE);

	if (type != EVENT_NONE && type != EVENT_ERROR)
		free_token(token);

	return args;
}

static int event_read_print(struct event_format *event)
{
	enum event_type type;
	char *token;
	int ret;

	if (read_expected_item(EVENT_ITEM, "print") < 0)
		return -1;

	if (read_expected(EVENT_ITEM, "fmt") < 0)
		return -1;

	if (read_expected(EVENT_OP, ":") < 0)
		return -1;

	if (read_expect_type(EVENT_DQUOTE, &token) < 0)
		goto fail;

 concat:
	event->print_fmt.format = token;
	event->print_fmt.args = NULL;

	/* ok to have no arg */
	type = read_token_item(&token);

	if (type == EVENT_NONE)
		return 0;

	/* Handle concatenation of print lines */
	if (type == EVENT_DQUOTE) {
		char *cat;

		cat = malloc_or_die(strlen(event->print_fmt.format) +
				    strlen(token) + 1);
		strcpy(cat, event->print_fmt.format);
		strcat(cat, token);
		free_token(token);
		free_token(event->print_fmt.format);
		event->print_fmt.format = NULL;
		token = cat;
		goto concat;
	}
			     
	if (test_type_token(type, token, EVENT_DELIM, ","))
		goto fail;

	free_token(token);

	ret = event_read_print_args(event, &event->print_fmt.args);
	if (ret < 0)
		return -1;

	return ret;

 fail:
	free_token(token);
	return -1;
}

/**
 * pevent_find_common_field - return a common field by event
 * @event: handle for the event
 * @name: the name of the common field to return
 *
 * Returns a common field from the event by the given @name.
 * This only searchs the common fields and not all field.
 */
struct format_field *
pevent_find_common_field(struct event_format *event, const char *name)
{
	struct format_field *format;

	for (format = event->format.common_fields;
	     format; format = format->next) {
		if (strcmp(format->name, name) == 0)
			break;
	}

	return format;
}

/**
 * pevent_find_field - find a non-common field
 * @event: handle for the event
 * @name: the name of the non-common field
 *
 * Returns a non-common field by the given @name.
 * This does not search common fields.
 */
struct format_field *
pevent_find_field(struct event_format *event, const char *name)
{
	struct format_field *format;

	for (format = event->format.fields;
	     format; format = format->next) {
		if (strcmp(format->name, name) == 0)
			break;
	}

	return format;
}

/**
 * pevent_find_any_field - find any field by name
 * @event: handle for the event
 * @name: the name of the field
 *
 * Returns a field by the given @name.
 * This searchs the common field names first, then
 * the non-common ones if a common one was not found.
 */
struct format_field *
pevent_find_any_field(struct event_format *event, const char *name)
{
	struct format_field *format;

	format = pevent_find_common_field(event, name);
	if (format)
		return format;
	return pevent_find_field(event, name);
}

/**
 * pevent_read_number - read a number from data
 * @pevent: handle for the pevent
 * @ptr: the raw data
 * @size: the size of the data that holds the number
 *
 * Returns the number (converted to host) from the
 * raw data.
 */
unsigned long long pevent_read_number(struct pevent *pevent,
				      const void *ptr, int size)
{
	switch (size) {
	case 1:
		return *(unsigned char *)ptr;
	case 2:
		return data2host2(pevent, ptr);
	case 4:
		return data2host4(pevent, ptr);
	case 8:
		return data2host8(pevent, ptr);
	default:
		/* BUG! */
		return 0;
	}
}

/**
 * pevent_read_number_field - read a number from data
 * @field: a handle to the field
 * @data: the raw data to read
 * @value: the value to place the number in
 *
 * Reads raw data according to a field offset and size,
 * and translates it into @value.
 *
 * Returns 0 on success, -1 otherwise.
 */
int pevent_read_number_field(struct format_field *field, const void *data,
			     unsigned long long *value)
{
	switch (field->size) {
	case 1:
	case 2:
	case 4:
	case 8:
		*value = pevent_read_number(field->event->pevent,
					    data + field->offset, field->size);
		return 0;
	default:
		return -1;
	}
}

static int get_common_info(struct pevent *pevent,
			   const char *type, int *offset, int *size)
{
	struct event_format *event;
	struct format_field *field;

	/*
	 * All events should have the same common elements.
	 * Pick any event to find where the type is;
	 */
	if (!pevent->event_list)
		die("no event_list!");

	event = pevent->event_list;
	field = pevent_find_common_field(event, type);
	if (!field)
		die("field '%s' not found", type);

	*offset = field->offset;
	*size = field->size;

	return 0;
}

static int __parse_common(struct pevent *pevent, void *data,
			  int *size, int *offset, const char *name)
{
	int ret;

	if (!*size) {
		ret = get_common_info(pevent, name, offset, size);
		if (ret < 0)
			return ret;
	}
	return pevent_read_number(pevent, data + *offset, *size);
}

static int trace_parse_common_type(struct pevent *pevent, void *data)
{
	return __parse_common(pevent, data,
			      &pevent->type_size, &pevent->type_offset,
			      "common_type");
}

static int parse_common_pid(struct pevent *pevent, void *data)
{
	return __parse_common(pevent, data,
			      &pevent->pid_size, &pevent->pid_offset,
			      "common_pid");
}

static int parse_common_pc(struct pevent *pevent, void *data)
{
	return __parse_common(pevent, data,
			      &pevent->pc_size, &pevent->pc_offset,
			      "common_preempt_count");
}

static int parse_common_flags(struct pevent *pevent, void *data)
{
	return __parse_common(pevent, data,
			      &pevent->flags_size, &pevent->flags_offset,
			      "common_flags");
}

static int parse_common_lock_depth(struct pevent *pevent, void *data)
{
	int ret;

	ret = __parse_common(pevent, data,
			     &pevent->ld_size, &pevent->ld_offset,
			     "common_lock_depth");
	if (ret < 0)
		return -1;

	return ret;
}

/**
 * pevent_find_event - find an event by given id
 * @pevent: a handle to the pevent
 * @id: the id of the event
 *
 * Returns an event that has a given @id.
 */
struct event_format *pevent_find_event(struct pevent *pevent, int id)
{
	struct event_format *event;

	for (event = pevent->event_list; event; event = event->next) {
		if (event->id == id)
			break;
	}
	return event;
}

/**
 * pevent_find_event_by_name - find an event by given name
 * @pevent: a handle to the pevent
 * @sys: the system name to search for
 * @name: the name of the event to search for
 *
 * This returns an event with a given @name and under the system
 * @sys. If @sys is NULL the first event with @name is returned.
 */
struct event_format *
pevent_find_event_by_name(struct pevent *pevent,
			  const char *sys, const char *name)
{
	struct event_format *event;

	for (event = pevent->event_list; event; event = event->next) {
		if (strcmp(event->name, name) == 0) {
			if (!sys)
				break;
			if (strcmp(event->system, sys) == 0)
				break;
		}
	}
	return event;
}

static unsigned long long
eval_num_arg(void *data, int size, struct event_format *event, struct print_arg *arg)
{
	struct pevent *pevent = event->pevent;
	unsigned long long val = 0;
	unsigned long long left, right;
	struct print_arg *typearg = NULL;
	struct print_arg *larg;
	unsigned long offset;

	switch (arg->type) {
	case PRINT_NULL:
		/* ?? */
		return 0;
	case PRINT_ATOM:
		return strtoull(arg->atom.atom, NULL, 0);
	case PRINT_FIELD:
		if (!arg->field.field) {
			arg->field.field = pevent_find_any_field(event, arg->field.name);
			if (!arg->field.field)
				die("field %s not found", arg->field.name);
		}
		/* must be a number */
		val = pevent_read_number(pevent, data + arg->field.field->offset,
				arg->field.field->size);
		break;
	case PRINT_FLAGS:
	case PRINT_SYMBOL:
		break;
	case PRINT_TYPE:
		val = eval_num_arg(data, size, event, arg->typecast.item);
		return eval_type(val, arg, 0);
	case PRINT_STRING:
		return 0;
		break;
	case PRINT_OP:
		if (strcmp(arg->op.op, "[") == 0) {
			/*
			 * Arrays are special, since we don't want
			 * to read the arg as is.
			 */
			right = eval_num_arg(data, size, event, arg->op.right);

			/* handle typecasts */
			larg = arg->op.left;
			while (larg->type == PRINT_TYPE) {
				if (!typearg)
					typearg = larg;
				larg = larg->typecast.item;
			}

			switch (larg->type) {
			case PRINT_DYNAMIC_ARRAY:
				offset = pevent_read_number(pevent,
						   data + larg->dynarray.field->offset,
						   larg->dynarray.field->size);
				/*
				 * The actual length of the dynamic array is stored
				 * in the top half of the field, and the offset
				 * is in the bottom half of the 32 bit field.
				 */
				offset &= 0xffff;
				offset += right;
				break;
			case PRINT_FIELD:
				if (!larg->field.field) {
					larg->field.field =
						pevent_find_any_field(event, larg->field.name);
					if (!larg->field.field)
						die("field %s not found", larg->field.name);
				}
				offset = larg->field.field->offset +
					right * pevent->long_size;
				break;
			default:
				goto default_op; /* oops, all bets off */
			}
			val = pevent_read_number(pevent,
						 data + offset, pevent->long_size);
			if (typearg)
				val = eval_type(val, typearg, 1);
			break;
		}
 default_op:
		left = eval_num_arg(data, size, event, arg->op.left);
		right = eval_num_arg(data, size, event, arg->op.right);
		switch (arg->op.op[0]) {
		case '|':
			if (arg->op.op[1])
				val = left || right;
			else
				val = left | right;
			break;
		case '&':
			if (arg->op.op[1])
				val = left && right;
			else
				val = left & right;
			break;
		case '<':
			switch (arg->op.op[1]) {
			case 0:
				val = left < right;
				break;
			case '<':
				val = left << right;
				break;
			case '=':
				val = left <= right;
				break;
			default:
				die("unknown op '%s'", arg->op.op);
			}
			break;
		case '>':
			switch (arg->op.op[1]) {
			case 0:
				val = left > right;
				break;
			case '>':
				val = left >> right;
				break;
			case '=':
				val = left >= right;
				break;
			default:
				die("unknown op '%s'", arg->op.op);
			}
			break;
		case '=':
			if (arg->op.op[1] != '=')
				die("unknown op '%s'", arg->op.op);
			val = left == right;
			break;
		case '-':
			val = left - right;
			break;
		case '+':
			val = left + right;
			break;
		default:
			die("unknown op '%s'", arg->op.op);
		}
		break;
	default: /* not sure what to do there */
		return 0;
	}
	return val;
}

struct flag {
	const char *name;
	unsigned long long value;
};

static const struct flag flags[] = {
	{ "HI_SOFTIRQ", 0 },
	{ "TIMER_SOFTIRQ", 1 },
	{ "NET_TX_SOFTIRQ", 2 },
	{ "NET_RX_SOFTIRQ", 3 },
	{ "BLOCK_SOFTIRQ", 4 },
	{ "BLOCK_IOPOLL_SOFTIRQ", 5 },
	{ "TASKLET_SOFTIRQ", 6 },
	{ "SCHED_SOFTIRQ", 7 },
	{ "HRTIMER_SOFTIRQ", 8 },
	{ "RCU_SOFTIRQ", 9 },

	{ "HRTIMER_NORESTART", 0 },
	{ "HRTIMER_RESTART", 1 },
};

static unsigned long long eval_flag(const char *flag)
{
	int i;

	/*
	 * Some flags in the format files do not get converted.
	 * If the flag is not numeric, see if it is something that
	 * we already know about.
	 */
	if (isdigit(flag[0]))
		return strtoull(flag, NULL, 0);

	for (i = 0; i < (int)(sizeof(flags)/sizeof(flags[0])); i++)
		if (strcmp(flags[i].name, flag) == 0)
			return flags[i].value;

	return 0;
}

static void print_str_arg(struct trace_seq *s, void *data, int size,
			  struct event_format *event, struct print_arg *arg)
{
	struct pevent *pevent = event->pevent;
	struct print_flag_sym *flag;
	unsigned long long val, fval;
	unsigned long addr;
	char *str;
	int print;
	int len;

	switch (arg->type) {
	case PRINT_NULL:
		/* ?? */
		return;
	case PRINT_ATOM:
		trace_seq_puts(s, arg->atom.atom);
		return;
	case PRINT_FIELD:
		if (!arg->field.field) {
			arg->field.field = pevent_find_any_field(event, arg->field.name);
			if (!arg->field.field)
				die("field %s not found", arg->field.name);
		}
		/* Zero sized fields, mean the rest of the data */
		len = arg->field.field->size ? : size;

		/*
		 * Some events pass in pointers. If this is not an array
		 * and the size is the same as long_size, assume that it
		 * is a pointer.
		 */
		if (!(arg->field.field->flags & FIELD_IS_ARRAY) &&
		    len == pevent->long_size) {
			addr = *(unsigned long *)(data + arg->field.field->offset);
			trace_seq_printf(s, "%lx", addr);
			break;
		}
		str = malloc_or_die(len + 1);
		memcpy(str, data + arg->field.field->offset, len);
		str[len] = 0;
		trace_seq_puts(s, str);
		free(str);
		break;
	case PRINT_FLAGS:
		val = eval_num_arg(data, size, event, arg->flags.field);
		print = 0;
		for (flag = arg->flags.flags; flag; flag = flag->next) {
			fval = eval_flag(flag->value);
			if (!val && !fval) {
				trace_seq_puts(s, flag->str);
				break;
			}
			if (fval && (val & fval) == fval) {
				if (print && arg->flags.delim)
					trace_seq_puts(s, arg->flags.delim);
				trace_seq_puts(s, flag->str);
				print = 1;
				val &= ~fval;
			}
		}
		break;
	case PRINT_SYMBOL:
		val = eval_num_arg(data, size, event, arg->symbol.field);
		for (flag = arg->symbol.symbols; flag; flag = flag->next) {
			fval = eval_flag(flag->value);
			if (val == fval) {
				trace_seq_puts(s, flag->str);
				break;
			}
		}
		break;

	case PRINT_TYPE:
		break;
	case PRINT_STRING: {
		int str_offset;

		if (arg->string.offset == -1) {
			struct format_field *f;

			f = pevent_find_any_field(event, arg->string.string);
			arg->string.offset = f->offset;
		}
		str_offset = *(int *)(data + arg->string.offset);
		str_offset &= 0xffff;
		trace_seq_puts(s, ((char *)data) + str_offset);
		break;
	}
	case PRINT_OP:
		/*
		 * The only op for string should be ? :
		 */
		if (arg->op.op[0] != '?')
			return;
		val = eval_num_arg(data, size, event, arg->op.left);
		if (val)
			print_str_arg(s, data, size, event, arg->op.right->op.left);
		else
			print_str_arg(s, data, size, event, arg->op.right->op.right);
		break;
	default:
		/* well... */
		break;
	}
}

static struct print_arg *make_bprint_args(char *fmt, void *data, int size, struct event_format *event)
{
	struct pevent *pevent = event->pevent;
	struct format_field *field, *ip_field;
	struct print_arg *args, *arg, **next;
	unsigned long long ip, val;
	char *ptr;
	void *bptr;

	field = pevent->bprint_buf_field;
	ip_field = pevent->bprint_ip_field;

	if (!field) {
		field = pevent_find_field(event, "buf");
		if (!field)
			die("can't find buffer field for binary printk");
		ip_field = pevent_find_field(event, "ip");
		if (!ip_field)
			die("can't find ip field for binary printk");
		pevent->bprint_buf_field = field;
		pevent->bprint_ip_field = ip_field;
	}

	ip = pevent_read_number(pevent, data + ip_field->offset, ip_field->size);

	/*
	 * The first arg is the IP pointer.
	 */
	args = alloc_arg();
	arg = args;
	arg->next = NULL;
	next = &arg->next;

	arg->type = PRINT_ATOM;
	arg->atom.atom = malloc_or_die(32);
	sprintf(arg->atom.atom, "%lld", ip);

	/* skip the first "%pf : " */
	for (ptr = fmt + 6, bptr = data + field->offset;
	     bptr < data + size && *ptr; ptr++) {
		int ls = 0;

		if (*ptr == '%') {
 process_again:
			ptr++;
			switch (*ptr) {
			case '%':
				break;
			case 'l':
				ls++;
				goto process_again;
			case 'L':
				ls = 2;
				goto process_again;
			case '0' ... '9':
				goto process_again;
			case 'p':
				ls = 1;
				/* fall through */
			case 'd':
			case 'u':
			case 'x':
			case 'i':
				/* the pointers are always 4 bytes aligned */
				bptr = (void *)(((unsigned long)bptr + 3) &
						~3);
				switch (ls) {
				case 0:
				case 1:
					ls = pevent->long_size;
					break;
				case 2:
					ls = 8;
				default:
					break;
				}
				val = pevent_read_number(pevent, bptr, ls);
				bptr += ls;
				arg = alloc_arg();
				arg->next = NULL;
				arg->type = PRINT_ATOM;
				arg->atom.atom = malloc_or_die(32);
				sprintf(arg->atom.atom, "%lld", val);
				*next = arg;
				next = &arg->next;
				break;
			case 's':
				arg = alloc_arg();
				arg->next = NULL;
				arg->type = PRINT_STRING;
				arg->string.string = strdup(bptr);
				bptr += strlen(bptr) + 1;
				*next = arg;
				next = &arg->next;
			default:
				break;
			}
		}
	}

	return args;
}

static void free_args(struct print_arg *args)
{
	struct print_arg *next;

	while (args) {
		next = args->next;

		free_arg(args);
		args = next;
	}
}

static char *
get_bprint_format(void *data, int size __unused, struct event_format *event)
{
	struct pevent *pevent = event->pevent;
	unsigned long long addr;
	struct format_field *field;
	struct printk_map *printk;
	char *format;
	char *p;

	field = pevent->bprint_fmt_field;

	if (!field) {
		field = pevent_find_field(event, "fmt");
		if (!field)
			die("can't find format field for binary printk");
		printf("field->offset = %d size=%d\n", field->offset, field->size);
		pevent->bprint_fmt_field = field;
	}

	addr = pevent_read_number(pevent, data + field->offset, field->size);

	printk = find_printk(pevent, addr);
	if (!printk) {
		format = malloc_or_die(45);
		sprintf(format, "%%pf : (NO FORMAT FOUND at %llx)\n",
			addr);
		return format;
	}

	p = printk->printk;
	/* Remove any quotes. */
	if (*p == '"')
		p++;
	format = malloc_or_die(strlen(p) + 10);
	sprintf(format, "%s : %s", "%pf", p);
	/* remove ending quotes and new line since we will add one too */
	p = format + strlen(format) - 1;
	if (*p == '"')
		*p = 0;

	p -= 2;
	if (strcmp(p, "\\n") == 0)
		*p = 0;

	return format;
}

static void pretty_print(struct trace_seq *s, void *data, int size, struct event_format *event)
{
	struct pevent *pevent = event->pevent;
	struct print_fmt *print_fmt = &event->print_fmt;
	struct print_arg *arg = print_fmt->args;
	struct print_arg *args = NULL;
	const char *ptr = print_fmt->format;
	unsigned long long val;
	struct func_map *func;
	const char *saveptr;
	char *bprint_fmt = NULL;
	char format[32];
	int show_func;
	int len;
	int ls;

	if (event->flags & EVENT_FL_FAILED) {
		trace_seq_printf(s, "EVENT '%s' FAILED TO PARSE",
		       event->name);
		return;
	}

	if (event->flags & EVENT_FL_ISBPRINT) {
		bprint_fmt = get_bprint_format(data, size, event);
		args = make_bprint_args(bprint_fmt, data, size, event);
		arg = args;
		ptr = bprint_fmt;
	}

	for (; *ptr; ptr++) {
		ls = 0;
		if (*ptr == '\\') {
			ptr++;
			switch (*ptr) {
			case 'n':
				trace_seq_putc(s, '\n');
				break;
			case 't':
				trace_seq_putc(s, '\t');
				break;
			case 'r':
				trace_seq_putc(s, '\r');
				break;
			case '\\':
				trace_seq_putc(s, '\\');
				break;
			default:
				trace_seq_putc(s, *ptr);
				break;
			}

		} else if (*ptr == '%') {
			saveptr = ptr;
			show_func = 0;
 cont_process:
			ptr++;
			switch (*ptr) {
			case '%':
				trace_seq_putc(s, '%');
				break;
			case '#':
				/* FIXME: need to handle properly */
				goto cont_process;
			case 'l':
				ls++;
				goto cont_process;
			case 'L':
				ls = 2;
				goto cont_process;
			case '.':
			case 'z':
			case 'Z':
			case '0' ... '9':
				goto cont_process;
			case 'p':
				if (pevent->long_size == 4)
					ls = 1;
				else
					ls = 2;

				if (*(ptr+1) == 'F' ||
				    *(ptr+1) == 'f') {
					ptr++;
					show_func = *ptr;
				} else if (*(ptr+1) == 'M' || *(ptr+1) == 'm') {
					unsigned char *buf;
					char *fmt = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x";
					if (*(ptr+1) == 'm')
						fmt = "%.2x%.2x%.2x%.2x%.2x%.2x";
					if (!arg->field.field) {
						arg->field.field =
							pevent_find_any_field(event, arg->field.name);
						if (!arg->field.field)
							die("field %s not found", arg->field.name);
					}
					if (arg->field.field->size != 6) {
						trace_seq_printf(s, "INVALIDMAC");
						break;
					}
					buf = data + arg->field.field->offset;
					trace_seq_printf(s, fmt, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
					ptr++;
					break;
				}

				/* fall through */
			case 'd':
			case 'i':
			case 'x':
			case 'X':
			case 'u':
				if (!arg)
					die("no argument match");

				len = ((unsigned long)ptr + 1) -
					(unsigned long)saveptr;

				/* should never happen */
				if (len > 32)
					die("bad format!");

				memcpy(format, saveptr, len);
				format[len] = 0;

				val = eval_num_arg(data, size, event, arg);
				arg = arg->next;

				if (show_func) {
					func = find_func(pevent, val);
					if (func) {
						trace_seq_puts(s, func->func);
						if (show_func == 'F')
							trace_seq_printf(s,
							       "+0x%llx",
							       val - func->addr);
						break;
					}
				}
				if (pevent->long_size == 8 && ls) {
					char *p;

					ls = 2;
					/* make %l into %ll */
					p = strchr(format, 'l');
					if (p)
						memmove(p+1, p, strlen(p)+1);
					else if (strcmp(format, "%p") == 0)
						strcpy(format, "0x%llx");
				}
				switch (ls) {
				case 0:
					trace_seq_printf(s, format, (int)val);
					break;
				case 1:
					trace_seq_printf(s, format, (long)val);
					break;
				case 2:
					trace_seq_printf(s, format, (long long)val);
					break;
				default:
					die("bad count (%d)", ls);
				}
				break;
			case 's':
				if (!arg)
					die("no matching argument");

				print_str_arg(s, data, size, event, arg);
				arg = arg->next;
				break;
			default:
				trace_seq_printf(s, ">%c<", *ptr);

			}
		} else
			trace_seq_putc(s, *ptr);
	}

	if (args) {
		free_args(args);
		free(bprint_fmt);
	}
}

/**
 * pevent_data_lat_fmt - parse the data for the latency format
 * @pevent: a handle to the pevent
 * @s: the trace_seq to write to
 * @data: the raw data to read from
 * @size: currently unused.
 *
 * This parses out the Latency format (interrupts disabled,
 * need rescheduling, in hard/soft interrupt, preempt count
 * and lock depth) and places it into the trace_seq.
 */
void pevent_data_lat_fmt(struct pevent *pevent,
			 struct trace_seq *s, struct record *record)
{
	static int check_lock_depth = 1;
	static int lock_depth_exists;
	unsigned int lat_flags;
	unsigned int pc;
	int lock_depth;
	int hardirq;
	int softirq;
	void *data = record->data;

	lat_flags = parse_common_flags(pevent, data);
	pc = parse_common_pc(pevent, data);
	/* lock_depth may not always exist */
	if (check_lock_depth) {
		struct format_field *field;
		struct event_format *event;

		check_lock_depth = 0;
		event = pevent->event_list;
		field = pevent_find_common_field(event, "common_lock_depth");
		if (field)
			lock_depth_exists = 1;
	}
	if (lock_depth_exists)
		lock_depth = parse_common_lock_depth(pevent, data);

	hardirq = lat_flags & TRACE_FLAG_HARDIRQ;
	softirq = lat_flags & TRACE_FLAG_SOFTIRQ;

	trace_seq_printf(s, "%c%c%c",
	       (lat_flags & TRACE_FLAG_IRQS_OFF) ? 'd' :
	       (lat_flags & TRACE_FLAG_IRQS_NOSUPPORT) ?
	       'X' : '.',
	       (lat_flags & TRACE_FLAG_NEED_RESCHED) ?
	       'N' : '.',
	       (hardirq && softirq) ? 'H' :
	       hardirq ? 'h' : softirq ? 's' : '.');

	if (pc)
		trace_seq_printf(s, "%x", pc);
	else
		trace_seq_putc(s, '.');

	if (lock_depth_exists) {
		if (lock_depth < 0)
			trace_seq_putc(s, '.');
		else
			trace_seq_printf(s, "%d", lock_depth);
	}

	trace_seq_terminate(s);
}

/**
 * pevent_data_type - parse out the given event type
 * @pevent: a handle to the pevent
 * @rec: the record to read from
 *
 * This returns the event id from the @rec.
 */
int pevent_data_type(struct pevent *pevent, struct record *rec)
{
	return trace_parse_common_type(pevent, rec->data);
}

/**
 * pevent_data_event_from_type - find the event by a given type
 * @pevent: a handle to the pevent
 * @type: the type of the event.
 *
 * This returns the event form a given @type;
 */
struct event_format *pevent_data_event_from_type(struct pevent *pevent, int type)
{
	return pevent_find_event(pevent, type);
}

/**
 * pevent_data_pid - parse the PID from raw data
 * @pevent: a handle to the pevent
 * @rec: the record to parse
 *
 * This returns the PID from a raw data.
 */
int pevent_data_pid(struct pevent *pevent, struct record *rec)
{
	return parse_common_pid(pevent, rec->data);
}

/**
 * pevent_data_comm_from_pid - return the command line from PID
 * @pevent: a handle to the pevent
 * @pid: the PID of the task to search for
 *
 * This returns a pointer to the command line that has the given
 * @pid.
 */
const char *pevent_data_comm_from_pid(struct pevent *pevent, int pid)
{
	const char *comm;

	comm = find_cmdline(pevent, pid);
	return comm;
}

/**
 * pevent_data_comm_from_pid - parse the data into the print format
 * @s: the trace_seq to write to
 * @event: the handle to the event
 * @cpu: the cpu the event was recorded on
 * @data: the raw data
 * @size: the size of the raw data
 * @nsecs: the timestamp of the event
 *
 * This parses the raw @data using the given @event information and
 * writes the print format into the trace_seq.
 */
void pevent_event_info(struct trace_seq *s, struct event_format *event,
		       struct record *record)
{
	int print_pretty = 1;

	if (event->handler)
		print_pretty = event->handler(s, record, event);

	if (print_pretty)
		pretty_print(s, record->data, record->size, event);

	trace_seq_terminate(s);
}

void pevent_print_event(struct pevent *pevent, struct trace_seq *s,
			struct record *record)
{
	static char *spaces = "                    "; /* 20 spaces */
	struct event_format *event;
	unsigned long secs;
	unsigned long usecs;
	const char *comm;
	void *data = record->data;
	int size = record->size;
	int print_pretty = 1;
	int type;
	int pid;
	int len;

	secs = record->ts / NSECS_PER_SEC;
	usecs = record->ts - secs * NSECS_PER_SEC;
	usecs = usecs / NSECS_PER_USEC;

	type = trace_parse_common_type(pevent, data);

	event = pevent_find_event(pevent, type);
	if (!event) {
		warning("ug! no event found for type %d", type);
		return;
	}

	pid = parse_common_pid(pevent, data);
	comm = find_cmdline(pevent, pid);

	if (pevent->latency_format) {
		trace_seq_printf(s, "%8.8s-%-5d %3d",
		       comm, pid, record->cpu);
		pevent_data_lat_fmt(pevent, s, record);
	} else
		trace_seq_printf(s, "%16s-%-5d [%03d]", comm, pid, record->cpu);

	trace_seq_printf(s, " %5lu.%06lu: %s: ", secs, usecs, event->name);

	/* Space out the event names evenly. */
	len = strlen(event->name);
	if (len < 20)
		trace_seq_printf(s, "%.*s", 20 - len, spaces);
	
	if (event->handler)
		print_pretty = event->handler(s, record, event);

	if (print_pretty)
		pretty_print(s, data, size, event);

	trace_seq_terminate(s);
}

static int events_id_cmp(const void *a, const void *b)
{
	struct event_format * const * ea = a;
	struct event_format * const * eb = b;

	if ((*ea)->id < (*eb)->id)
		return -1;

	if ((*ea)->id > (*eb)->id)
		return 1;

	return 0;
}

static int events_name_cmp(const void *a, const void *b)
{
	struct event_format * const * ea = a;
	struct event_format * const * eb = b;
	int res;

	res = strcmp((*ea)->name, (*eb)->name);
	if (res)
		return res;

	res = strcmp((*ea)->system, (*eb)->system);
	if (res)
		return res;

	return events_id_cmp(a, b);
}

static int events_system_cmp(const void *a, const void *b)
{
	struct event_format * const * ea = a;
	struct event_format * const * eb = b;
	int res;

	res = strcmp((*ea)->system, (*eb)->system);
	if (res)
		return res;

	res = strcmp((*ea)->name, (*eb)->name);
	if (res)
		return res;

	return events_id_cmp(a, b);
}

struct event_format **pevent_list_events(struct pevent *pevent, enum event_sort_type sort_type)
{
	struct event_format **events;
	struct event_format *event;
	int (*sort)(const void *a, const void *b);
	int i = 0;

	events = pevent->events;

	if (events && pevent->last_type == sort_type)
		return events;

	if (!events) {
		events = malloc(sizeof(*events) * (pevent->nr_events + 1));
		if (!events)
			return NULL;

		for (event = pevent->event_list; event; event = event->next) {
			if (i == pevent->nr_events) {
				warning("Wrong event count");
				free(events);
				return NULL;
			}
			events[i++] = event;
		}
		events[i] = NULL;

		pevent->events = events;
	}

	switch (sort_type) {
	case EVENT_SORT_ID:
		sort = events_id_cmp;
		break;
	case EVENT_SORT_NAME:
		sort = events_name_cmp;
		break;
	case EVENT_SORT_SYSTEM:
		sort = events_system_cmp;
		break;
	default:
		return events;
	}

	qsort(events, pevent->nr_events, sizeof(*events), sort);
	pevent->last_type = sort_type;

	return events;
}

static void print_fields(struct trace_seq *s, struct print_flag_sym *field)
{
	trace_seq_printf(s, "{ %s, %s }", field->value, field->str);
	if (field->next) {
		trace_seq_puts(s, ", ");
		print_fields(s, field->next);
	}
}

/* for debugging */
static void print_args(struct print_arg *args)
{
	int print_paren = 1;
	struct trace_seq s;

	switch (args->type) {
	case PRINT_NULL:
		printf("null");
		break;
	case PRINT_ATOM:
		printf("%s", args->atom.atom);
		break;
	case PRINT_FIELD:
		printf("REC->%s", args->field.name);
		break;
	case PRINT_FLAGS:
		printf("__print_flags(");
		print_args(args->flags.field);
		printf(", %s, ", args->flags.delim);
		trace_seq_init(&s);
		print_fields(&s, args->flags.flags);
		trace_seq_do_printf(&s);
		printf(")");
		break;
	case PRINT_SYMBOL:
		printf("__print_symbolic(");
		print_args(args->symbol.field);
		printf(", ");
		trace_seq_init(&s);
		print_fields(&s, args->symbol.symbols);
		trace_seq_do_printf(&s);
		printf(")");
		break;
	case PRINT_STRING:
		printf("__get_str(%s)", args->string.string);
		break;
	case PRINT_TYPE:
		printf("(%s)", args->typecast.type);
		print_args(args->typecast.item);
		break;
	case PRINT_OP:
		if (strcmp(args->op.op, ":") == 0)
			print_paren = 0;
		if (print_paren)
			printf("(");
		print_args(args->op.left);
		printf(" %s ", args->op.op);
		print_args(args->op.right);
		if (print_paren)
			printf(")");
		break;
	default:
		/* we should warn... */
		return;
	}
	if (args->next) {
		printf("\n");
		print_args(args->next);
	}
}

static void parse_header_field(const char *field,
			       int *offset, int *size)
{
	char *token;
	int type;

	if (read_expected(EVENT_ITEM, "field") < 0)
		return;
	if (read_expected(EVENT_OP, ":") < 0)
		return;

	/* type */
	if (read_expect_type(EVENT_ITEM, &token) < 0)
		goto fail;
	free_token(token);

	if (read_expected(EVENT_ITEM, field) < 0)
		return;
	if (read_expected(EVENT_OP, ";") < 0)
		return;
	if (read_expected(EVENT_ITEM, "offset") < 0)
		return;
	if (read_expected(EVENT_OP, ":") < 0)
		return;
	if (read_expect_type(EVENT_ITEM, &token) < 0)
		goto fail;
	*offset = atoi(token);
	free_token(token);
	if (read_expected(EVENT_OP, ";") < 0)
		return;
	if (read_expected(EVENT_ITEM, "size") < 0)
		return;
	if (read_expected(EVENT_OP, ":") < 0)
		return;
	if (read_expect_type(EVENT_ITEM, &token) < 0)
		goto fail;
	*size = atoi(token);
	free_token(token);
	if (read_expected(EVENT_OP, ";") < 0)
		return;
	type = read_token(&token);
	if (type != EVENT_NEWLINE) {
		/* newer versions of the kernel have a "signed" type */
		if (type != EVENT_ITEM)
			goto fail;

		if (strcmp(token, "signed") != 0)
			goto fail;

		free_token(token);

		if (read_expected(EVENT_OP, ":") < 0)
			return;

		if (read_expect_type(EVENT_ITEM, &token))
			goto fail;

		free_token(token);
		if (read_expected(EVENT_OP, ";") < 0)
			return;

		if (read_expect_type(EVENT_NEWLINE, &token))
			goto fail;
	}
 fail:
	free_token(token);
}

/**
 * pevent_parse_header_page - parse the data stored in the header page
 * @pevent: the handle to the pevent
 * @buf: the buffer storing the header page format string
 * @size: the size of @buf
 * @long_size: the long size to use if there is no header
 *
 * This parses the header page format for information on the
 * ring buffer used. The @buf should be copied from
 *
 * /sys/kernel/debug/tracing/events/header_page
 */
int pevent_parse_header_page(struct pevent *pevent, char *buf, unsigned long size,
			     int long_size)
{
	if (!size) {
		/*
		 * Old kernels did not have header page info.
		 * Sorry but we just use what we find here in user space.
		 */
		pevent->header_page_ts_size = sizeof(long long);
		pevent->header_page_size_size = long_size;
		pevent->header_page_data_offset = sizeof(long long) + long_size;
		pevent->old_format = 1;
		return -1;
	}
	init_input_buf(buf, size);

	parse_header_field("timestamp", &pevent->header_page_ts_offset,
			   &pevent->header_page_ts_size);
	parse_header_field("commit", &pevent->header_page_size_offset,
			   &pevent->header_page_size_size);
	parse_header_field("data", &pevent->header_page_data_offset,
			   &pevent->header_page_data_size);

	return 0;
}

/**
 * pevent_parse_event - parse the event format
 * @pevent: the handle to the pevent
 * @buf: the buffer storing the event format string
 * @size: the size of @buf
 * @sys: the system the event belongs to
 *
 * This parses the event format and creates an event structure
 * to quickly parse raw data for a given event.
 *
 * These files currently come from:
 *
 * /sys/kernel/debug/tracing/events/.../.../format
 */
int pevent_parse_event(struct pevent *pevent,
		       char *buf, unsigned long size, char *sys)
{
	struct event_format *event;
	int ret;

	init_input_buf(buf, size);

	event = alloc_event();
	if (!event)
		return -ENOMEM;

	event->name = event_read_name();
	if (!event->name)
		die("failed to read event name");

	if (strcmp(sys, "ftrace") == 0) {

		event->flags |= EVENT_FL_ISFTRACE;

		if (strcmp(event->name, "bprint") == 0)
			event->flags |= EVENT_FL_ISBPRINT;
	}
		
	event->id = event_read_id();
	if (event->id < 0)
		die("failed to read event id");

	event->system = strdup(sys);

	ret = event_read_format(event);
	if (ret < 0) {
		warning("failed to read event format for %s", event->name);
		goto event_failed;
	}

	ret = event_read_print(event);
	if (ret < 0) {
		warning("failed to read event print fmt for %s", event->name);
		goto event_failed;
	}

	add_event(pevent, event);

	if (!ret && (event->flags & EVENT_FL_ISFTRACE)) {
		struct format_field *field;
		struct print_arg *arg, **list;

		/* old ftrace had no args */

		list = &event->print_fmt.args;
		for (field = event->format.fields; field; field = field->next) {
			arg = alloc_arg();
			*list = arg;
			list = &arg->next;
			arg->type = PRINT_FIELD;
			arg->field.name = field->name;
			arg->field.field = field;
		}
		return 0;
	}

#define PRINT_ARGS 0
	if (PRINT_ARGS && event->print_fmt.args)
		print_args(event->print_fmt.args);

	return 0;

 event_failed:
	event->flags |= EVENT_FL_FAILED;
	/* still add it even if it failed */
	add_event(pevent, event);
	return -1;
}

/**
 * pevent_register_event_handle - register a way to parse an event
 * @pevent: the handle to the pevent
 * @id: the id of the event to register
 * @sys_name: the system name the event belongs to
 * @event_name: the name of the event
 * @func: the function to call to parse the event information
 *
 * This function allows a developer to override the parsing of
 * a given event. If for some reason the default print format
 * is not sufficient, this function will register a function
 * for an event to be used to parse the data instead.
 *
 * If @id is >= 0, then it is used to find the event.
 * else @sys_name and @event_name are used.
 */
int pevent_register_event_handler(struct pevent *pevent,
				  int id, char *sys_name, char *event_name,
				  pevent_event_handler_func func)
{
	struct event_format *event;

	if (id >= 0) {
		/* search by id */
		event = pevent_find_event(pevent, id);
		if (!event)
			return -1;
		if (event_name && (strcmp(event_name, event->name) != 0))
			return -1;
		if (sys_name && (strcmp(sys_name, event->system) != 0))
			return -1;
	} else {
		event = pevent_find_event_by_name(pevent, sys_name, event_name);
		if (!event)
			return -1;
	}

	printf("overriding event (%d) %s:%s with new print handler\n",
	       event->id, event->system, event->name);

	event->handler = func;
	return 0;
}

/**
 * pevent_alloc - create a pevent handle
 */
struct pevent *pevent_alloc(void)
{
	struct pevent *pevent;

	pevent = malloc(sizeof(*pevent));
	if (!pevent)
		return NULL;
	memset(pevent, 0, sizeof(*pevent));

	return pevent;
}

static void free_format_fields(struct format_field *field)
{
	struct format_field *next;

	while (field) {
		next = field->next;
		free(field->type);
		free(field->name);
		free(field);
		field = next;
	}
}

static void free_formats(struct format *format)
{
	free_format_fields(format->common_fields);
	free_format_fields(format->fields);
}

static void free_event(struct event_format *event)
{
	free(event->name);
	free(event->system);

	free_formats(&event->format);

	free(event->print_fmt.format);
	free_args(event->print_fmt.args);

	free(event);
}

/**
 * pevent_free - free a pevent handle
 * @pevent: the pevent handle to free
 */
void pevent_free(struct pevent *pevent)
{
	struct event_format *event, *next_event;
	struct cmdline_list *cmdlist = pevent->cmdlist, *cmdnext;
	struct func_list *funclist = pevent->funclist, *funcnext;
	struct printk_list *printklist = pevent->printklist, *printknext;
	int i;

	if (pevent->cmdlines) {
		for (i = 0; i < pevent->cmdline_count; i++)
			free(pevent->cmdlines[i].comm);
		free(pevent->cmdlines);
	}

	while (cmdlist) {
		cmdnext = cmdlist->next;
		free(cmdlist->comm);
		free(cmdlist);
		cmdlist = cmdnext;
	}

	if (pevent->func_map) {
		for (i = 0; i < pevent->func_count; i++) {
			free(pevent->func_map[i].func);
			free(pevent->func_map[i].mod);
		}
		free(pevent->func_map);
	}

	while (funclist) {
		funcnext = funclist->next;
		free(funclist->func);
		free(funclist->mod);
		free(funclist);
		funclist = funcnext;
	}

	if (pevent->printk_map) {
		for (i = 0; i < pevent->printk_count; i++)
			free(pevent->printk_map[i].printk);
		free(pevent->printk_map);
	}

	while (printklist) {
		printknext = printklist->next;
		free(printklist->printk);
		free(printklist);
		printklist = printknext;
	}

	free(pevent->events);

	for (event = pevent->event_list; event; event = next_event) {
		next_event = event->next;

		free_event(event);
	}

	free(pevent);
}
