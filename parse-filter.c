/*
 * Copyright (C) 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>

#include "parse-events.h"
#include "util.h"

struct event_list {
	struct event_list	*next;
	struct event_format	*event;
};

#define MAX_ERR_STR_SIZE 256

static void show_error(char **error_str, const char *fmt, ...)
{
	va_list ap;

	if (!error_str)
		return;

	*error_str = malloc_or_die(MAX_ERR_STR_SIZE);

	va_start(ap, fmt);
	vsnprintf(*error_str, MAX_ERR_STR_SIZE, fmt, ap);
	va_end(ap);
}

static void free_token(char *token)
{
	pevent_free_token(token);
}

static enum event_type read_token(char **tok)
{
	enum event_type type;
	char *token = NULL;

	do {
		free_token(token);
		type = pevent_read_token(&token);
	} while (type == EVENT_NEWLINE || type == EVENT_SPACE);

	/* If token is = or ! check to see if the next char is ~ */
	if (token &&
	    (strcmp(token, "=") == 0 || strcmp(token, "!") == 0) &&
	    pevent_peek_char() == '~') {
		/* append it */
		*tok = malloc(3);
		sprintf(*tok, "%c%c", *token, '~');
		free_token(token);
		/* Now remove the '~' from the buffer */
		pevent_read_token(&token);
		free_token(token);
	} else
		*tok = token;

	return type;
}

static int filter_cmp(const void *a, const void *b)
{
	const struct filter_type *ea = a;
	const struct filter_type *eb = b;

	if (ea->event_id < eb->event_id)
		return -1;

	if (ea->event_id > eb->event_id)
		return 1;

	return 0;
}

static struct filter_type *
find_filter_type(struct event_filter *filter, int id)
{
	struct filter_type *filter_type;
	struct filter_type key;

	key.event_id = id;

	filter_type = bsearch(&key, filter->event_filters,
			      filter->filters,
			      sizeof(*filter->event_filters),
			      filter_cmp);

	return filter_type;
}

static struct filter_type *
add_filter_type(struct event_filter *filter, int id)
{
	struct filter_type *filter_type;
	int i;

	filter_type = find_filter_type(filter, id);
	if (filter_type)
		return filter_type;

	if (!filter->filters)
		filter->event_filters =
			malloc_or_die(sizeof(*filter->event_filters));
	else {
		filter->event_filters =
			realloc(filter->event_filters,
				sizeof(*filter->event_filters) *
				(filter->filters + 1));
		if (!filter->event_filters)
			die("Could not allocate filter");
	}

	for (i = 0; i < filter->filters; i++) {
		if (filter->event_filters[i].event_id > id)
			break;
	}

	if (i < filter->filters)
		memmove(&filter->event_filters[i+1],
			&filter->event_filters[i],
			sizeof(*filter->event_filters) *
			(filter->filters - i));

	filter_type = &filter->event_filters[i];
	filter_type->event_id = id;
	filter_type->event = pevent_find_event(filter->pevent, id);
	filter_type->filter = NULL;

	filter->filters++;

	return filter_type;
}

/**
 * pevent_filter_alloc - create a new event filter
 * @pevent: The pevent that this filter is associated with
 */
struct event_filter *pevent_filter_alloc(struct pevent *pevent)
{
	struct event_filter *filter;

	filter = malloc_or_die(sizeof(*filter));
	memset(filter, 0, sizeof(*filter));
	filter->pevent = pevent;
	pevent_ref(pevent);

	return filter;
}

static struct filter_arg *allocate_arg(void)
{
	struct filter_arg *arg;

	arg = malloc_or_die(sizeof(*arg));
	memset(arg, 0, sizeof(*arg));

	return arg;
}

static void free_arg(struct filter_arg *arg)
{
	if (!arg)
		return;

	switch (arg->type) {
	case FILTER_ARG_NONE:
	case FILTER_ARG_BOOLEAN:
	case FILTER_ARG_NUM:
		break;

	case FILTER_ARG_STR:
		free(arg->str.val);
		regfree(&arg->str.reg);
		free(arg->str.buffer);
		break;

	case FILTER_ARG_OP:
		free_arg(arg->op.left);
		free_arg(arg->op.right);
	default:
		break;
	}

	free(arg);
}

static void add_event(struct event_list **events,
		      struct event_format *event)
{
	struct event_list *list;

	list = malloc_or_die(sizeof(*list));
	list->next = *events;
	*events = list;
	list->event = event;
}

static int event_match(struct event_format *event,
		       regex_t *sreg, regex_t *ereg)
{
	if (sreg) {
		return !regexec(sreg, event->system, 0, NULL, 0) &&
			!regexec(ereg, event->name, 0, NULL, 0);
	}

	return !regexec(ereg, event->system, 0, NULL, 0) ||
		!regexec(ereg, event->name, 0, NULL, 0);
}

static int
find_event(struct pevent *pevent, struct event_list **events,
	   char *sys_name, char *event_name)
{
	struct event_format *event;
	regex_t ereg;
	regex_t sreg;
	int match = 0;
	char *reg;
	int ret;
	int i;

	if (!event_name) {
		/* if no name is given, then swap sys and name */
		event_name = sys_name;
		sys_name = NULL;
	}

	reg = malloc_or_die(strlen(event_name) + 3);
	sprintf(reg, "^%s$", event_name);

	ret = regcomp(&ereg, reg, REG_ICASE|REG_NOSUB);
	free(reg);

	if (ret)
		return -1;

	if (sys_name) {
		reg = malloc_or_die(strlen(sys_name) + 3);
		sprintf(reg, "^%s$", sys_name);
		ret = regcomp(&sreg, reg, REG_ICASE|REG_NOSUB);
		free(reg);
		if (ret) {
			regfree(&ereg);
			return -1;
		}
	}

	for (i = 0; i < pevent->nr_events; i++) {
		event = pevent->events[i];
		if (event_match(event, sys_name ? &sreg : NULL, &ereg)) {
			match = 1;
			add_event(events, event);
		}
	}

	regfree(&ereg);
	if (sys_name)
		regfree(&sreg);

	if (!match)
		return -1;

	return 0;
}

static void free_events(struct event_list *events)
{
	struct event_list *event;

	while (events) {
		event = events;
		events = events->next;
		free(event);
	}
}

static enum event_type
process_paren(struct event_format *event, struct filter_arg **parg,
	      char **tok, char **error_str);

static enum event_type
process_not(struct event_format *event, struct filter_arg **parg,
	    char **tok, char **error_str);

static enum event_type
process_value_token(struct event_format *event, struct filter_arg **parg,
		    enum event_type type, char **tok, char **error_str);

static enum event_type
process_op_token(struct event_format *event, struct filter_arg *larg,
		 struct filter_arg **parg, enum event_type type, char **tok,
		 char **error_str);

/*
 * process_token
 *  Called when a new expression is found. Processes an op, or
 *  ends early if a ')' is found.
 *
 * Output: tok, parg
 */
static enum event_type
process_token(struct event_format *event, struct filter_arg **parg,
	      char **tok, char **error_str)
{
	struct filter_arg *arg = NULL;
	enum event_type type;
	char *token;

	*tok = NULL;
	*parg = NULL;

	type = read_token(&token);

	/*
	 * This is a start of a new expresion. We expect to find
	 * a item or a parenthesis.
	 */
	switch (type) {
	case EVENT_SQUOTE:
	case EVENT_DQUOTE:
	case EVENT_ITEM:
		type = process_value_token(event, &arg, type, &token, error_str);
		if (type == EVENT_ERROR) {
			free_token(token);
			return type;
		}
		type = read_token(&token);
		break;
	case EVENT_DELIM:
		if (strcmp(token, "(") != 0)
			break;

		free_token(token);
		type = process_paren(event, &arg, &token, error_str);
		if (type == EVENT_NONE) {
			*tok = token;
			*parg = arg;
			return type;
		}
		if (arg) {
			/*
			 * If the parenthesis was a full expression,
			 * then just return it. Otherwise, we may still
			 * need to find an op.
			 */
			switch (arg->type) {
			case FILTER_ARG_OP:
			case FILTER_ARG_NUM:
			case FILTER_ARG_STR:
				*tok = token;
				*parg = arg;
				return type;
			default:
				break;
			}
		}
		break;

	case EVENT_OP:
		if (strcmp(token, "!") != 0)
			break;

		/*
		 * A not is its own filter, it just negates,
		 * process it by itself.
		 */
		*tok = token;
		type = process_not(event, parg, tok, error_str);
		return type;

	default:
		break;
	}

	for (;;) {
		if (type == EVENT_NONE) {
			show_error(error_str, "unexpected end of filter");
			type = EVENT_ERROR;

		} else if (type == EVENT_DELIM && strcmp(token, ")") == 0) {
			/* Parenthesis call this and may return at anytime. */
			*tok = token;
			*parg = arg;
			return type;

		} else if (type != EVENT_OP) {
			show_error(error_str, "Expected an OP but found %s", token);
			type = EVENT_ERROR;
		}

		if (type == EVENT_ERROR) {
			free_token(token);
			return type;
		}

		*tok = token;
		*parg = NULL;
		type = process_op_token(event, arg, parg, type, tok, error_str);

		if (type == EVENT_ERROR) {
			free_arg(*parg);
			*parg = NULL;
			return EVENT_ERROR;
		}

		if (!(*parg) || (*parg)->type != FILTER_ARG_EXP)
			break;

		/*
		 * This op was an expression (value return)
		 * It's not fine by itself, there had better be an OP
		 * after it.
		 */
		token = *tok;
		*tok = NULL;
		arg = *parg;
	}

	return type;
}

/*
 * Input: tok
 * Output: parg, tok
 */
static enum event_type
process_bool(struct event_format *event, struct filter_arg *larg,
	     struct filter_arg **parg, char **tok, char **error_str)
{
	struct filter_arg *rarg;
	struct filter_arg *arg;
	enum event_type type;
	enum filter_op_type btype;

	/* Can only be called with '&&' or '||' */
	btype = strcmp(*tok, "&&") == 0 ?
		FILTER_OP_AND : FILTER_OP_OR;

	type = process_token(event, &rarg, tok, error_str);
	if (type == EVENT_ERROR) {
		free_arg(larg);
		*parg = NULL;
		return type;
	}

	/*
	 * If larg or rarg is null then if this is AND, the whole expression
	 * becomes NULL, else if this is an OR, then we use the non NULL
	 * condition.
	 */
	if (!larg || !rarg) {
		if (btype == FILTER_OP_AND ||
		    (!larg && !rarg)) {
			free_arg(larg);
			free_arg(rarg);
			*parg = NULL;
			return type;
		}
		*parg = larg ? larg : rarg;
		return type;
	}

	arg = allocate_arg();
	arg->type = FILTER_ARG_OP;
	arg->op.type = btype;
	arg->op.left = larg;
	arg->op.right = rarg;


	/*
	 * If the next token is also a boolean expression, then
	 * make the next boolean the parent..
	 */
	if (type != EVENT_OP ||
	    (strcmp(*tok, "&&") != 0 && strcmp(*tok, "||") != 0)) {
		*parg = arg;
		return type;
	}

	return process_bool(event, arg, parg, tok, error_str);
}

/*
 * Input: tok
 * Output: parg
 */
static enum event_type
process_value_token(struct event_format *event, struct filter_arg **parg,
		    enum event_type type, char **tok, char **error_str)
{
	struct format_field *field;
	struct filter_arg *arg;
	char *token;

	token = *tok;
	*tok = NULL;

	arg = allocate_arg();

	switch (type) {

	case EVENT_SQUOTE:
	case EVENT_DQUOTE:
		arg->type = FILTER_ARG_VALUE;
		arg->value.type = FILTER_STRING;
		arg->value.str = token;
		break;
	case EVENT_ITEM:
		/* if it is a number, then convert it */
		if (isdigit(token[0])) {
			arg->type = FILTER_ARG_VALUE;
			arg->value.type = FILTER_NUMBER;
			arg->value.val = strtoll(token, NULL, 0);
			free_token(token);
			break;
		}
		/* Consider this a field */
		field = pevent_find_any_field(event, token);
		free_token(token);
		if (!field) {
			/* not a field, so NULL it up */
			free_arg(arg);
			arg = NULL;
			break;
		}

		arg->type = FILTER_ARG_FIELD;
		arg->field.field = field;
		break;
	default:
		free_arg(arg);
		show_error(error_str, "expected a value but found %s",
			   token);
		free_token(token);
		return EVENT_ERROR;
	}

	*parg = arg;
	return type;
}

/*
 * Output: parg, tok
 */
static enum event_type
process_value(struct event_format *event, struct filter_arg **parg,
	      enum event_type *orig_type, char **tok, char **error_str)
{
	enum event_type type;
	char *token;

	*tok = NULL;
	type = read_token(&token);
	*orig_type = type;
	if (type == EVENT_DELIM && strcmp(token, "(") == 0) {
		type = process_paren(event, parg, &token, error_str);
		/* Must be a expression or value */
		if (type == EVENT_ERROR || !(*parg)) {
			free_token(token);
			return type;
		}
		switch ((*parg)->type) {
		case FILTER_ARG_BOOLEAN:
		case FILTER_ARG_VALUE:
		case FILTER_ARG_FIELD:
		case FILTER_ARG_EXP:
			break;
		default:
			show_error(error_str, "expected a value");
			free_token(token);
			return EVENT_ERROR;
		}
	} else {
		type = process_value_token(event, parg, type, &token, error_str);
		free_token(token);
		if (type == EVENT_ERROR)
			return type;
		type = read_token(&token);
	}

	*tok = token;
	return type;
}

/*
 * Input: larg
 * Output: parg, tok
 */
static enum event_type
process_cmp(struct event_format *event, enum filter_cmp_type op_type,
	    struct filter_arg *larg, struct filter_arg **parg,
	    char **tok, char **error_str)
{
	struct filter_arg *arg;
	struct filter_arg *rarg;
	enum event_type orig_type;
	enum event_type type;
	int ret;

	*parg = NULL;

	type = process_value(event, &rarg, &orig_type, tok, error_str);
	if (type == EVENT_ERROR) {
		free_arg(rarg);
		return type;
	}

	arg = allocate_arg();
	/*
	 * If either arg is NULL or right was field not found.
	 * Then make the entire expression NULL. (will turn to FALSE)
	 */
	if (!larg || !rarg) {
		free_arg(larg);
		free_arg(rarg);
		free_arg(arg);
		arg = NULL;
		goto cont;
	}

	switch (orig_type) {
	case EVENT_SQUOTE:
		/* treat this as a character if string is of length 1? */
		if (strlen(rarg->str.val) == 1) {
			switch (op_type) {
			case FILTER_CMP_REGEX:
			case FILTER_CMP_NOT_REGEX:
				/* regex can't be used with ints */
				break;
			default:
				goto as_int;
			}
		}
		/* fall through */
	case EVENT_DQUOTE:
		arg->type = FILTER_ARG_STR;

		if (larg->type != FILTER_ARG_FIELD) {
			free(larg);
			free(rarg);
			show_error(error_str,
				   "Illegal lval for string comparison");
			free_arg(arg);
			return EVENT_ERROR;
		}

		arg->str.field = larg->field.field;
		free_arg(larg);

		/* free the rarg, and use its token */
		arg->str.val = rarg->value.str;
		rarg->value.str = NULL;
		free_arg(rarg);

		/* Make sure this is a valid string compare */
		switch (op_type) {
		case FILTER_CMP_EQ:
			op_type = FILTER_CMP_MATCH;
			break;
		case FILTER_CMP_NE:
			op_type = FILTER_CMP_NOT_MATCH;
			break;

		case FILTER_CMP_REGEX:
		case FILTER_CMP_NOT_REGEX:
			ret = regcomp(&arg->str.reg, arg->str.val, REG_ICASE|REG_NOSUB);
			if (ret) {
				show_error(error_str,
					   "RegEx '%s' did not compute",
					   arg->str.val);
				free_arg(arg);
				return EVENT_ERROR;
			}
			break;
		default:
			show_error(error_str,
				   "Illegal comparison for string");
			free_arg(arg);
			return EVENT_ERROR;
		}

		arg->str.type = op_type;

		/*
		 * Need a buffer to copy data int for tests		 */
		arg->str.buffer = malloc_or_die(arg->str.field->size + 1);
		/* Null terminate this buffer */
		arg->str.buffer[arg->str.field->size] = 0;

		break;
	default:
 as_int:
		switch (op_type) {
		case FILTER_CMP_REGEX:
		case FILTER_CMP_NOT_REGEX:
			show_error(error_str,
				   "Op not allowed with integers");
			free_arg(arg);
			return EVENT_ERROR;
		default:
			break;
		}
		/* numeric compare */
		arg->type = FILTER_ARG_NUM;
		arg->num.type = op_type;
		arg->num.left = larg;
		arg->num.right = rarg;
		break;
	}
 cont:
	*parg = arg;
	return type;
}

/*
 * Input: larg
 * Output: parg, tok
 */
static enum event_type
process_exp(struct event_format *event, enum filter_exp_type etype,
	    struct filter_arg *larg, struct filter_arg **parg,
	    char **tok, char **error_str)
{
	struct filter_arg *rarg;
	struct filter_arg *arg;
	enum event_type orig_type;
	enum event_type type;

	type = process_value(event, &rarg, &orig_type, tok, error_str);
	if (type == EVENT_ERROR) {
		free_arg(rarg);
		return type;
	}

	/* larg can be NULL if a field did not match */
	if (!larg) {
		/* syntax is correct, just return NULL */
		arg = NULL;
		free_arg(rarg);
		goto cont;
	}

	arg = allocate_arg();
	arg->type = FILTER_ARG_EXP;
	arg->op.type = etype;
	arg->op.left = larg;
	arg->op.right = rarg;

 cont:
	/* still need a cmp */
	type = process_op_token(event, arg, parg, type, tok, error_str);
	return type;
}

/*
 * Input: tok
 * Output: parg, tok
 */
static enum event_type
process_op_token(struct event_format *event, struct filter_arg *larg,
		 struct filter_arg **parg, enum event_type type, char **tok,
		 char **error_str)
{
	enum filter_cmp_type ctype;
	enum filter_exp_type etype = FILTER_EXP_NONE;
	char *token;

	token = *tok;
	*parg = NULL;

	if (type != EVENT_OP) {
		*parg = larg;
		return type;
	}

	if (strcmp(token, "&&") == 0 || strcmp(token, "||") == 0) {
		/* handle boolean cases */
		return process_bool(event, larg, parg, tok, error_str);
	}

	/* Check for value expressions */
	if (strcmp(token, "+") == 0) {
		etype = FILTER_EXP_ADD;
	} else if (strcmp(token, "-") == 0) {
		etype = FILTER_EXP_SUB;
	} else if (strcmp(token, "*") == 0) {
		etype = FILTER_EXP_MUL;
	} else if (strcmp(token, "/") == 0) {
		etype = FILTER_EXP_DIV;
	} else if (strcmp(token, "%") == 0) {
		etype = FILTER_EXP_MOD;
	} else if (strcmp(token, ">>") == 0) {
		etype = FILTER_EXP_RSHIFT;
	} else if (strcmp(token, "<<") == 0) {
		etype = FILTER_EXP_LSHIFT;
	} else if (strcmp(token, "&") == 0) {
		etype = FILTER_EXP_AND;
	} else if (strcmp(token, "|") == 0) {
		etype = FILTER_EXP_OR;
	} else if (strcmp(token, "^") == 0) {
		etype = FILTER_EXP_XOR;
	} else if (strcmp(token, "~") == 0)
		etype = FILTER_EXP_NOT;

	if (etype != FILTER_EXP_NONE) {
		free_token(token);
		return process_exp(event, etype, larg, parg, tok, error_str);
	}

	if (strcmp(token, "==") == 0) {
		ctype = FILTER_CMP_EQ;
	} else if (strcmp(token, "!=") == 0) {
		ctype = FILTER_CMP_NE;
	} else if (strcmp(token, "<") == 0) {
		ctype = FILTER_CMP_LT;
	} else if (strcmp(token, ">") == 0) {
		ctype = FILTER_CMP_GT;
	} else if (strcmp(token, "<=") == 0) {
		ctype = FILTER_CMP_LE;
	} else if (strcmp(token, ">=") == 0) {
		ctype = FILTER_CMP_GE;
	} else if (strcmp(token, "=~") == 0) {
		ctype = FILTER_CMP_REGEX;
	} else if (strcmp(token, "!~") == 0) {
		ctype = FILTER_CMP_NOT_REGEX;
	} else {
		show_error(error_str,
			   "Unknown op '%s'", token);
		free_token(token);
		return EVENT_ERROR;
	}

	free_token(token);
	*tok = NULL;
	return process_cmp(event, ctype, larg, parg, tok, error_str);
}

static enum event_type
process_filter(struct event_format *event, struct filter_arg **parg,
	       char **tok, char **error_str)
{
	struct filter_arg *larg = NULL;
	enum event_type type;

	*parg = NULL;
	*tok = NULL;

	type = process_token(event, parg, tok, error_str);

	if (type == EVENT_OP &&
	    (strcmp(*tok, "&&") == 0 || strcmp(*tok, "||") == 0)) {
		larg = *parg;
		*parg = NULL;
		type = process_bool(event, larg, parg, tok, error_str);
	}

	return type;
}

static enum event_type
process_paren(struct event_format *event, struct filter_arg **parg,
	      char **tok, char **error_str)
{
	struct filter_arg *arg;
	enum event_type type;

	*parg = NULL;

	type = process_token(event, &arg, tok, error_str);
	if (type == EVENT_ERROR) {
		free_arg(arg);
		return type;
	}

	if (type == EVENT_OP &&
	    (strcmp(*tok, "&&") == 0 || strcmp(*tok, "||") == 0)) {
		type = process_bool(event, arg, parg, tok, error_str);
	}

	if (type != EVENT_DELIM || strcmp(*tok, ")") != 0) {
		if (*tok)
			show_error(error_str,
				   "Expected ')' but found %s", *tok);
		else
			show_error(error_str,
				   "Unexpected end of filter; Expected ')'");
		free_token(*tok);
		*tok = NULL;
		free_arg(arg);
		return EVENT_ERROR;
	}
	free_token(*tok);
	*tok = NULL;

	*parg = arg;

	return read_token(tok);
}

static enum event_type
process_not(struct event_format *event, struct filter_arg **parg,
	    char **tok, char **error_str)
{
	struct filter_arg *arg;
	enum event_type type;

	arg = allocate_arg();
	arg->type = FILTER_ARG_OP;
	arg->op.type = FILTER_OP_NOT;

	arg->op.left = NULL;
	type = process_token(event, &arg->op.right, tok, error_str);
	if (type == EVENT_ERROR) {
		free_arg(arg);
		*parg = NULL;
		free_token(*tok);
		*tok = NULL;
		return EVENT_ERROR;
	}
	/* If the bool value is NULL, then make this into TRUE */
	if (!arg->op.right) {
		arg->type = FILTER_ARG_BOOLEAN;
		arg->bool.value = FILTER_TRUE;
	}

	free_token(*tok);
	*tok = NULL;

	return type;
}

static int
process_event(struct event_format *event, const char *filter_str,
	      struct filter_arg **parg, char **error_str)
{
	enum event_type type;
	char *token;

	pevent_buffer_init(filter_str, strlen(filter_str));

	type = process_filter(event, parg, &token, error_str);

	if (type == EVENT_ERROR)
		return -1;

	if (type != EVENT_NONE) {
		show_error(error_str,
			   "Expected end where %s was found",
			   token);
		free_token(token);
		free_arg(*parg);
		*parg = NULL;
		return -1;
	}

	/* If parg is NULL, then make it into FALSE */
	if (!*parg) {
		*parg = allocate_arg();
		(*parg)->type = FILTER_ARG_BOOLEAN;
		(*parg)->bool.value = FILTER_FALSE;
	}

	return 0;
}

static int filter_event(struct event_filter *filter,
			struct event_format *event,
			const char *filter_str, char **error_str)
{
	struct filter_type *filter_type;
	struct filter_arg *arg;
	int ret;

	if (filter_str) {
		ret = process_event(event, filter_str, &arg, error_str);
		if (ret < 0)
			return ret;
	} else {
		/* just add a TRUE arg */
		arg = allocate_arg();
		arg->type = FILTER_ARG_BOOLEAN;
		arg->bool.value = FILTER_TRUE;
	}

	filter_type = add_filter_type(filter, event->id);
	if (filter_type->filter)
		free_arg(filter_type->filter);
	filter_type->filter = arg;

	return 0;
}

/**
 * pevent_filter_add_filter_str - add a new filter
 * @filter: the event filter to add to
 * @filter_str: the filter string that contains the filter
 * @error_str: string containing reason for failed filter
 *
 * Returns 0 if the filter was successfully added
 *   -1 if there was an error.
 *
 * On error, if @error_str points to a string pointer,
 * it is set to the reason that the filter failed.
 * This string must be freed with "free".
 */
int pevent_filter_add_filter_str(struct event_filter *filter,
				 const char *filter_str,
				 char **error_str)
{
	struct pevent *pevent = filter->pevent;
	struct event_list *event;
	struct event_list *events = NULL;
	const char *filter_start;
	const char *next_event;
	char *this_event;
	char *event_name = NULL;
	char *sys_name = NULL;
	char *sp;
	int rtn = 0;
	int len;
	int ret;

	if (error_str)
		*error_str = NULL;

	filter_start = strchr(filter_str, ':');
	if (filter_start)
		len = filter_start - filter_str;
	else
		len = strlen(filter_str);


	do {
		next_event = strchr(filter_str, ',');
		if (next_event &&
		    (!filter_start || next_event < filter_start))
			len = next_event - filter_str;
		else if (filter_start)
			len = filter_start - filter_str;
		else
			len = strlen(filter_str);

		this_event = malloc_or_die(len + 1);
		memcpy(this_event, filter_str, len);
		this_event[len] = 0;

		if (next_event)
			next_event++;

		filter_str = next_event;

		sys_name = strtok_r(this_event, "/", &sp);
		event_name = strtok_r(NULL, "/", &sp);

		if (!sys_name) {
			show_error(error_str, "No filter found");
			/* This can only happen when events is NULL, but still */
			free_events(events);
			free(this_event);
			return -1;
		}

		/* Find this event */
		ret = find_event(pevent, &events, strim(sys_name), strim(event_name));
		if (ret < 0) {
			if (event_name)
				show_error(error_str,
					   "No event found under '%s.%s'",
					   sys_name, event_name);
			else
				show_error(error_str,
					   "No event found under '%s'",
					   sys_name);
			free_events(events);
			free(this_event);
			return -1;
		}
		free(this_event);
	} while (filter_str);

	/* Skip the ':' */
	if (filter_start)
		filter_start++;

	/* filter starts here */
	for (event = events; event; event = event->next) {
		ret = filter_event(filter, event->event, filter_start,
				   error_str);
		/* Failures are returned if a parse error happened */
		if (ret < 0)
			rtn = ret;
	}

	free_events(events);

	return rtn;
}

static void free_filter_type(struct filter_type *filter_type)
{
	free_arg(filter_type->filter);
}

/**
 * pevent_filter_remove_event - remove a filter for an event
 * @filter: the event filter to remove from
 * @event_id: the event to remove a filter for
 *
 * Removes the filter saved for an event defined by @event_id
 * from the @filter.
 *
 * Returns 1: if an event was removed
 *   0: if the event was not found
 */
int pevent_filter_remove_event(struct event_filter *filter,
			       int event_id)
{
	struct filter_type *filter_type;
	unsigned long len;

	if (!filter->filters)
		return 0;

	filter_type = find_filter_type(filter, event_id);

	if (!filter_type)
		return 0;

	free_filter_type(filter_type);

	/* The filter_type points into the event_filters array */
	len = (unsigned long)(filter->event_filters + filter->filters) -
		(unsigned long)(filter_type + 1);

	memmove(filter_type, filter_type + 1, len);
	filter->filters--;

	memset(&filter->event_filters[filter->filters], 0,
	       sizeof(*filter_type));

	return 1;
}

/**
 * pevent_filter_reset - clear all filters in a filter
 * @filter: the event filter to reset
 *
 * Removes all filters from a filter and resets it.
 */
void pevent_filter_reset(struct event_filter *filter)
{
	int i;

	for (i = 0; i < filter->filters; i++)
		free_filter_type(&filter->event_filters[i]);

	free(filter->event_filters);
	filter->filters = 0;
	filter->event_filters = NULL;
}

void pevent_filter_free(struct event_filter *filter)
{
	pevent_unref(filter->pevent);

	pevent_filter_reset(filter);

	free(filter);
}

static char *arg_to_str(struct event_filter *filter, struct filter_arg *arg);

static int copy_filter_type(struct event_filter *filter,
			     struct event_filter *source,
			     struct filter_type *filter_type)
{
	struct filter_arg *arg;
	struct event_format *event;
	const char *sys;
	const char *name;
	char *str;

	/* Can't assume that the pevent's are the same */
	sys = filter_type->event->system;
	name = filter_type->event->name;
	event = pevent_find_event_by_name(filter->pevent, sys, name);
	if (!event)
		return -1;

	str = arg_to_str(source, filter_type->filter);
	if (!str)
		return -1;

	if (strcmp(str, "TRUE") == 0 || strcmp(str, "FALSE") == 0) {
		/* Add trivial event */
		arg = allocate_arg();
		arg->type = FILTER_ARG_BOOLEAN;
		if (strcmp(str, "TRUE") == 0)
			arg->bool.value = 1;
		else
			arg->bool.value = 0;

		filter_type = add_filter_type(filter, event->id);
		filter_type->filter = arg;

		free(str);
		return 0;
	}

	filter_event(filter, event, str, NULL);
	free(str);

	return 0;
}

/**
 * pevent_filter_copy - copy a filter using another filter
 * @dest - the filter to copy to
 * @source - the filter to copy from
 *
 * Returns 0 on success and -1 if not all filters were copied
 */
int pevent_filter_copy(struct event_filter *dest, struct event_filter *source)
{
	int ret = 0;
	int i;

	pevent_filter_reset(dest);

	for (i = 0; i < source->filters; i++) {
		if (copy_filter_type(dest, source, &source->event_filters[i]))
			ret = -1;
	}
	return ret;
}


/**
 * pevent_update_trivial - update the trivial filters with the given filter
 * @dest - the filter to update
 * @source - the filter as the source of the update
 * @type - the type of trivial filter to update.
 *
 * Scan dest for trivial events matching @type to replace with the source.
 *
 * Returns 0 on success and -1 if there was a problem updating, but
 *   events may have still been updated on error.
 */
int pevent_update_trivial(struct event_filter *dest, struct event_filter *source,
			  enum filter_trivial_type type)
{
	struct pevent *src_pevent;
	struct pevent *dest_pevent;
	struct event_format *event;
	struct filter_type *filter_type;
	struct filter_arg *arg;
	char *str;
	int i;

	src_pevent = source->pevent;
	dest_pevent = dest->pevent;

	/* Do nothing if either of the filters has nothing to filter */
	if (!dest->filters || !source->filters)
		return 0;

	for (i = 0; i < dest->filters; i++) {
		filter_type = &dest->event_filters[i];
		arg = filter_type->filter;
		if (arg->type != FILTER_ARG_BOOLEAN)
			continue;
		if ((arg->bool.value && type == FILTER_TRIVIAL_FALSE) ||
		    (!arg->bool.value && type == FILTER_TRIVIAL_TRUE))
			continue;

		event = filter_type->event;

		if (src_pevent != dest_pevent) {
			/* do a look up */
			event = pevent_find_event_by_name(src_pevent,
							  event->system,
							  event->name);
			if (!event)
				return -1;
		}

		str = pevent_filter_make_string(source, event->id);
		if (!str)
			continue;

		/* Don't bother if the filter is trivial too */
		if (strcmp(str, "TRUE") != 0 && strcmp(str, "FALSE") != 0)
			filter_event(dest, event, str, NULL);
		free(str);
	}
	return 0;
}

/**
 * pevent_filter_clear_trivial - clear TRUE and FALSE filters
 * @filter: the filter to remove trivial filters from
 * @type: remove only true, false, or both
 *
 * Removes filters that only contain a TRUE or FALES boolean arg.
 */
void pevent_filter_clear_trivial(struct event_filter *filter,
				 enum filter_trivial_type type)
{
	struct filter_type *filter_type;
	int count = 0;
	int *ids;
	int i;

	if (!filter->filters)
		return;

	/*
	 * Two steps, first get all ids with trivial filters.
	 *  then remove those ids.
	 */
	for (i = 0; i < filter->filters; i++) {
		filter_type = &filter->event_filters[i];
		if (filter_type->filter->type != FILTER_ARG_BOOLEAN)
			continue;
		switch (type) {
		case FILTER_TRIVIAL_FALSE:
			if (filter_type->filter->bool.value)
				continue;
		case FILTER_TRIVIAL_TRUE:
			if (!filter_type->filter->bool.value)
				continue;
		default:
			break;
		}
		if (count)
			ids = realloc(ids, sizeof(*ids) * (count + 1));
		else
			ids = malloc(sizeof(*ids));
		if (!ids)
			die("Can't allocate ids");
		ids[count++] = filter_type->event_id;
	}

	if (!count)
		return;

	for (i = 0; i < count; i++)
		pevent_filter_remove_event(filter, ids[i]);

	free(ids);
}

/**
 * pevent_filter_event_has_trivial - return true event contains trivial filter
 * @filter: the filter with the information
 * @event_id: the id of the event to test
 * @type: trivial type to test for (TRUE, FALSE, EITHER)
 *
 * Returns 1 if the event contains a matching trivial type
 *  otherwise 0.
 */
int pevent_filter_event_has_trivial(struct event_filter *filter,
				    int event_id,
				    enum filter_trivial_type type)
{
	struct filter_type *filter_type;

	if (!filter->filters)
		return 0;

	filter_type = find_filter_type(filter, event_id);

	if (!filter_type)
		return 0;

	if (filter_type->filter->type != FILTER_ARG_BOOLEAN)
		return 0;

	switch (type) {
	case FILTER_TRIVIAL_FALSE:
		return !filter_type->filter->bool.value;

	case FILTER_TRIVIAL_TRUE:
		return filter_type->filter->bool.value;
	default:
		return 1;
	}
}

static int test_filter(struct event_format *event,
		       struct filter_arg *arg, struct record *record);

static unsigned long long
get_value(struct format_field *field, struct record *record)
{
	unsigned long long val;

	pevent_read_number_field(field, record->data, &val);

	if (!(field->flags & FIELD_IS_SIGNED))
		return val;

	switch (field->size) {
	case 1:
		return (char)val;
	case 2:
		return (short)val;
	case 4:
		return (int)val;
	case 8:
		return (long long)val;
	}
	return val;
}

static unsigned long long
get_arg_value(struct event_format *event, struct filter_arg *arg, struct record *record);

static unsigned long long
get_exp_value(struct event_format *event, struct filter_arg *arg, struct record *record)
{
	unsigned long long lval, rval;

	lval = get_arg_value(event, arg->op.left, record);
	rval = get_arg_value(event, arg->op.right, record);

	switch (arg->op.type) {
	case FILTER_EXP_ADD:
		return lval + rval;

	case FILTER_EXP_SUB:
		return lval - rval;

	case FILTER_EXP_MUL:
		return lval * rval;

	case FILTER_EXP_DIV:
		return lval / rval;

	case FILTER_EXP_MOD:
		return lval % rval;

	case FILTER_EXP_RSHIFT:
		return lval >> rval;

	case FILTER_EXP_LSHIFT:
		return lval << rval;

	case FILTER_EXP_AND:
		return lval & rval;

	case FILTER_EXP_OR:
		return lval | rval;

	case FILTER_EXP_XOR:
		return lval ^ rval;

	case FILTER_EXP_NOT:
	default:
		die("error in exp");
	}
	return 0;
}

static unsigned long long
get_arg_value(struct event_format *event, struct filter_arg *arg, struct record *record)
{
	switch (arg->type) {
	case FILTER_ARG_FIELD:
		return get_value(arg->field.field, record);

	case FILTER_ARG_VALUE:
		if (arg->value.type != FILTER_NUMBER)
			die("must have number field!");
		return arg->value.val;

	case FILTER_ARG_EXP:
		return get_exp_value(event, arg, record);

	default:
		die("oops in filter");
	}
	return 0;
}

static int test_num(struct event_format *event,
		    struct filter_arg *arg, struct record *record)
{
	unsigned long long lval, rval;

	lval = get_arg_value(event, arg->num.left, record);
	rval = get_arg_value(event, arg->num.right, record);

	switch (arg->num.type) {
	case FILTER_CMP_EQ:
		return lval == rval;

	case FILTER_CMP_NE:
		return lval != rval;

	case FILTER_CMP_GT:
		return lval > rval;

	case FILTER_CMP_LT:
		return lval < rval;

	case FILTER_CMP_GE:
		return lval >= rval;

	case FILTER_CMP_LE:
		return lval <= rval;

	default:
		/* ?? */
		return 0;
	}
}

static int test_str(struct event_format *event,
		    struct filter_arg *arg, struct record *record)
{
	const char *val = record->data + arg->str.field->offset;
	const char *buffer;

	/*
	 * We need to copy the data since we can't be sure the field
	 * is null terminated.
	 */
	if (*(val + arg->str.field->size - 1)) {
		/* copy it */
		memcpy(arg->str.buffer, val, arg->str.field->size);
		/* the buffer is already NULL terminated */
		buffer = arg->str.buffer;
	} else
		/* OK, it's NULL terminated */
		buffer = val;

	switch (arg->str.type) {
	case FILTER_CMP_MATCH:
		return strcmp(buffer, arg->str.val) == 0;

	case FILTER_CMP_NOT_MATCH:
		return strcmp(buffer, arg->str.val) != 0;

	case FILTER_CMP_REGEX:
		/* Returns zero on match */
		return !regexec(&arg->str.reg, buffer, 0, NULL, 0);

	case FILTER_CMP_NOT_REGEX:
		return regexec(&arg->str.reg, buffer, 0, NULL, 0);

	default:
		/* ?? */
		return 0;
	}
}

static int test_op(struct event_format *event,
		   struct filter_arg *arg, struct record *record)
{
	switch (arg->op.type) {
	case FILTER_OP_AND:
		return test_filter(event, arg->op.left, record) &&
			test_filter(event, arg->op.right, record);

	case FILTER_OP_OR:
		return test_filter(event, arg->op.left, record) ||
			test_filter(event, arg->op.right, record);

	case FILTER_OP_NOT:
		return !test_filter(event, arg->op.right, record);

	default:
		/* ?? */
		return 0;
	}
}

static int test_filter(struct event_format *event,
		       struct filter_arg *arg, struct record *record)
{
	switch (arg->type) {
	case FILTER_ARG_BOOLEAN:
		/* easy case */
		return arg->bool.value;

	case FILTER_ARG_OP:
		return test_op(event, arg, record);

	case FILTER_ARG_NUM:
		return test_num(event, arg, record);

	case FILTER_ARG_STR:
		return test_str(event, arg, record);

	case FILTER_ARG_EXP:
	case FILTER_ARG_VALUE:
	case FILTER_ARG_FIELD:
		/*
		 * Expressions, fields and values evaluate
		 * to true if they return non zero
		 */
		return !!get_arg_value(event, arg, record);

	default:
		die("oops!");
		/* ?? */
		return 0;
	}
}

/**
 * pevent_event_filtered - return true if event has filter
 * @filter: filter struct with filter information
 * @event_id: event id to test if filter exists
 *
 * Returns 1 if filter found for @event_id
 *   otherwise 0;
 */
int pevent_event_filtered(struct event_filter *filter,
			  int event_id)
{
	struct filter_type *filter_type;

	if (!filter->filters)
		return 0;

	filter_type = find_filter_type(filter, event_id);

	return filter_type ? 1 : 0;
}

/**
 * pevent_filter_match - test if a record matches a filter
 * @filter: filter struct with filter information
 * @record: the record to test against the filter
 *
 * Returns:
 *  1 - filter found for event and @record matches
 *  0 - filter found for event and @record does not match
 * -1 - no filter found for @record's event
 * -2 - if no filters exist
 */
int pevent_filter_match(struct event_filter *filter,
			struct record *record)
{
	struct pevent *pevent = filter->pevent;
	struct filter_type *filter_type;
	int event_id;

	if (!filter->filters)
		return FILTER_NONE;

	event_id = pevent_data_type(pevent, record);

	filter_type = find_filter_type(filter, event_id);

	if (!filter_type)
		return FILTER_NOEXIST;

	return test_filter(filter_type->event, filter_type->filter, record) ?
		FILTER_MATCH : FILTER_MISS;
}

static char *op_to_str(struct event_filter *filter, struct filter_arg *arg)
{
	char *str = NULL;
	char *left = NULL;
	char *right = NULL;
	char *op = NULL;
	int left_val = -1;
	int right_val = -1;
	int val;
	int len;

	switch (arg->op.type) {
	case FILTER_OP_AND:
		op = "&&";
		/* fall through */
	case FILTER_OP_OR:
		if (!op)
			op = "||";

		left = arg_to_str(filter, arg->op.left);
		right = arg_to_str(filter, arg->op.right);
		if (!left || !right)
			break;

		/* Try to consolidate boolean values */
		if (strcmp(left, "TRUE") == 0)
			left_val = 1;
		else if (strcmp(left, "FALSE") == 0)
			left_val = 0;

		if (strcmp(right, "TRUE") == 0)
			right_val = 1;
		else if (strcmp(right, "FALSE") == 0)
			right_val = 0;

		if (left_val >= 0) {
			if ((arg->op.type == FILTER_OP_AND && !left_val) ||
			    (arg->op.type == FILTER_OP_OR && left_val)) {
				/* Just return left value */
				str = left;
				left = NULL;
				break;
			}
			if (right_val >= 0) {
				/* just evaluate this. */
				val = 0;
				switch (arg->op.type) {
				case FILTER_OP_AND:
					val = left_val && right_val;
					break;
				case FILTER_OP_OR:
					val = left_val || right_val;
					break;
				default:
					break;
				}
				str = malloc_or_die(6);
				if (val)
					strcpy(str, "TRUE");
				else
					strcpy(str, "FALSE");
				break;
			}
		}
		if (right_val >= 0) {
			if ((arg->op.type == FILTER_OP_AND && !right_val) ||
			    (arg->op.type == FILTER_OP_OR && right_val)) {
				/* Just return right value */
				str = right;
				right = NULL;
				break;
			}
			/* The right value is meaningless */
			str = left;
			left = NULL;
			break;
		}

		len = strlen(left) + strlen(right) + strlen(op) + 10;
		str = malloc_or_die(len);
		snprintf(str, len, "(%s) %s (%s)",
			 left, op, right);
		break;

	case FILTER_OP_NOT:
		op = "!";
		right = arg_to_str(filter, arg->op.right);
		if (!right)
			break;

		/* See if we can consolidate */
		if (strcmp(right, "TRUE") == 0)
			right_val = 1;
		else if (strcmp(right, "FALSE") == 0)
			right_val = 0;
		if (right_val >= 0) {
			/* just return the opposite */
			str = malloc_or_die(6);
			if (right_val)
				strcpy(str, "FALSE");
			else
				strcpy(str, "TRUE");
			break;
		}
		len = strlen(right) + strlen(op) + 3;
		str = malloc_or_die(len);
		snprintf(str, len, "%s(%s)", op, right);
		break;

	default:
		/* ?? */
		break;
	}
	free(left);
	free(right);
	return str;
}

static char *val_to_str(struct event_filter *filter, struct filter_arg *arg)
{
	char *str;

	str = malloc_or_die(30);

	snprintf(str, 30, "%lld", arg->value.val);

	return str;
}

static char *field_to_str(struct event_filter *filter, struct filter_arg *arg)
{
	return strdup(arg->field.field->name);
}

static char *exp_to_str(struct event_filter *filter, struct filter_arg *arg)
{
	char *lstr;
	char *rstr;
	char *op;
	char *str;
	int len;

	lstr = arg_to_str(filter, arg->op.left);
	rstr = arg_to_str(filter, arg->op.right);

	switch (arg->op.type) {
	case FILTER_EXP_ADD:
		op = "+";
		break;
	case FILTER_EXP_SUB:
		op = "-";
		break;
	case FILTER_EXP_MUL:
		op = "*";
		break;
	case FILTER_EXP_DIV:
		op = "/";
		break;
	case FILTER_EXP_MOD:
		op = "%";
		break;
	case FILTER_EXP_RSHIFT:
		op = ">>";
		break;
	case FILTER_EXP_LSHIFT:
		op = "<<";
		break;
	case FILTER_EXP_AND:
		op = "&";
		break;
	case FILTER_EXP_OR:
		op = "|";
		break;
	case FILTER_EXP_XOR:
		op = "^";
		break;
	default:
		die("oops in exp");
	}

	len = strlen(op) + strlen(lstr) + strlen(rstr) + 4;
	str = malloc_or_die(len);
	snprintf(str, len, "%s %s %s", lstr, op, rstr);
	free(lstr);
	free(rstr);

	return str;
}

static char *num_to_str(struct event_filter *filter, struct filter_arg *arg)
{
	char *lstr;
	char *rstr;
	char *str = NULL;
	char *op = NULL;
	int len;

	lstr = arg_to_str(filter, arg->num.left);
	rstr = arg_to_str(filter, arg->num.right);

	switch (arg->num.type) {
	case FILTER_CMP_EQ:
		op = "==";
		/* fall through */
	case FILTER_CMP_NE:
		if (!op)
			op = "!=";
		/* fall through */
	case FILTER_CMP_GT:
		if (!op)
			op = ">";
		/* fall through */
	case FILTER_CMP_LT:
		if (!op)
			op = "<";
		/* fall through */
	case FILTER_CMP_GE:
		if (!op)
			op = ">=";
		/* fall through */
	case FILTER_CMP_LE:
		if (!op)
			op = "<=";

		len = strlen(lstr) + strlen(op) + strlen(rstr) + 4;
		str = malloc_or_die(len);
		sprintf(str, "%s %s %s", lstr, op, rstr);

		break;

	default:
		/* ?? */
		break;
	}

	free(lstr);
	free(rstr);
	return str;
}

static char *str_to_str(struct event_filter *filter, struct filter_arg *arg)
{
	char *str = NULL;
	char *op = NULL;
	int len;

	switch (arg->str.type) {
	case FILTER_CMP_MATCH:
		op = "==";
		/* fall through */
	case FILTER_CMP_NOT_MATCH:
		if (!op)
			op = "!=";
		/* fall through */
	case FILTER_CMP_REGEX:
		if (!op)
			op = "=~";
		/* fall through */
	case FILTER_CMP_NOT_REGEX:
		if (!op)
			op = "!~";

		len = strlen(arg->str.field->name) + strlen(op) +
			strlen(arg->str.val) + 6;
		str = malloc_or_die(len);
		snprintf(str, len, "%s %s \"%s\"",
			 arg->str.field->name,
			 op, arg->str.val);
		break;

	default:
		/* ?? */
		break;
	}
	return str;
}

static char *arg_to_str(struct event_filter *filter, struct filter_arg *arg)
{
	char *str;

	switch (arg->type) {
	case FILTER_ARG_BOOLEAN:
		str = malloc_or_die(6);
		if (arg->bool.value)
			strcpy(str, "TRUE");
		else
			strcpy(str, "FALSE");
		return str;

	case FILTER_ARG_OP:
		return op_to_str(filter, arg);

	case FILTER_ARG_NUM:
		return num_to_str(filter, arg);

	case FILTER_ARG_STR:
		return str_to_str(filter, arg);

	case FILTER_ARG_VALUE:
		return val_to_str(filter, arg);

	case FILTER_ARG_FIELD:
		return field_to_str(filter, arg);

	case FILTER_ARG_EXP:
		return exp_to_str(filter, arg);

	default:
		/* ?? */
		return NULL;
	}

}

/**
 * pevent_filter_make_string - return a string showing the filter
 * @filter: filter struct with filter information
 * @event_id: the event id to return the filter string with
 *
 * Returns a string that displays the filter contents.
 *  This string must be freed with free(str).
 *  NULL is returned if no filter is found.
 */
char *
pevent_filter_make_string(struct event_filter *filter, int event_id)
{
	struct filter_type *filter_type;

	if (!filter->filters)
		return NULL;

	filter_type = find_filter_type(filter, event_id);

	if (!filter_type)
		return NULL;

	return arg_to_str(filter, filter_type->filter);
}

