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
#include <ctype.h>
#include <regex.h>
#include <errno.h>
#include <sys/types.h>

#include "parse-events.h"

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

static int process_valid_field(struct filter_arg *arg,
			       struct format_field *field,
			       enum filter_cmp_type op_type,
			       enum event_type type,
			       char *val,
			       char **error_str)
{
	switch (type) {

	case EVENT_SQUOTE:
		/* treat this as a character if string is of length 1? */
		if (strlen(val) == 1)
			goto as_int;
		/* fall through */

	case EVENT_DQUOTE:
		/* right now only allow match */
		switch (op_type) {
		case FILTER_CMP_EQ:
			op_type = FILTER_CMP_MATCH;
			break;
		case FILTER_CMP_NE:
			op_type = FILTER_CMP_NOT_MATCH;
			break;

		default:
			show_error(error_str,
				   "Op not allowed with string");
			return -1;
		}
		arg->type = FILTER_ARG_STR;
		arg->str.field = field;
		arg->str.type = op_type;
		arg->str.val = strdup(val);
		if (!arg->str.val)
			die("Can't allocate arg value");
		break;
	case EVENT_ITEM:
 as_int:
		arg->type = FILTER_ARG_NUM;
		arg->num.field = field;
		arg->num.type = op_type;
		arg->num.val = strtoll(val, NULL, 0);
		break;

	default:
		/* Can't happen */
		return -1;
	}

	return 0;
}

static enum event_type
process_filter(struct event_format *event, struct filter_arg **parg,
	       char **tok, char **error_str, int cont);

static enum event_type
process_paren(struct event_format *event, struct filter_arg **parg,
	      char **tok, char **error_str, int cont);

static enum event_type
process_not(struct event_format *event, struct filter_arg **parg,
	    char **tok, char **error_str, int cont);

static enum event_type
process_token(struct event_format *event, struct filter_arg **parg,
	      char **tok, char **error_str, int cont)
{
	enum event_type type;
	char *token;

	*tok = NULL;
	*parg = NULL;

	type = read_token(&token);

	if (type == EVENT_ITEM) {
		type = process_filter(event, parg, &token, error_str, cont);

	} else if (type == EVENT_DELIM && strcmp(token, "(") == 0) {
		free_token(token);
		type = process_paren(event, parg, &token, error_str, cont);

	} else if (type == EVENT_OP && strcmp(token, "!") == 0) {
		type = process_not(event, parg, &token, error_str, cont);
	}

	if (type == EVENT_ERROR) {
		free_token(token);
		free_arg(*parg);
		*parg = NULL;
		return EVENT_ERROR;
	}

	*tok = token;
	return type;
}

static enum event_type
process_op(struct event_format *event, struct filter_arg *larg,
	   struct filter_arg **parg, char **tok, char **error_str)
{
	enum event_type type;
	struct filter_arg *arg;

	arg = allocate_arg();
	arg->type = FILTER_ARG_OP;
	arg->op.left = larg;

	/* Can only be called with '&&' or '||' */
	arg->op.type = strcmp(*tok, "&&") == 0 ?
		FILTER_OP_AND : FILTER_OP_OR;

	free_token(*tok);

	type = process_token(event, &arg->op.right, tok, error_str, 1);
	if (type == EVENT_ERROR)
		free_arg(arg);

	*parg = arg;

	return type;
}

static enum event_type
process_filter(struct event_format *event, struct filter_arg **parg,
	       char **tok, char **error_str, int cont)
{
	struct format_field *field;
	enum filter_cmp_type etype;
	struct filter_arg *arg;
	enum event_type type;
	char *field_name;
	char *token;
	char *op;
	int ret;

	*parg = NULL;

	field_name = *tok;
	*tok = NULL;

	type = read_token(&token);
	if (type != EVENT_OP) {
		if (type == EVENT_NONE)
			show_error(error_str,
				   "Expected OP but found end of filter after %s",
				   field_name);
		else
			show_error(error_str,
				   "Expected OP but found %s after %s",
				   token, field_name);
		free_token(field_name);
		free_token(token);
		return EVENT_ERROR;
	}

	if (strcmp(token, "==") == 0) {
		etype = FILTER_CMP_EQ;
	} else if (strcmp(token, "!=") == 0) {
		etype = FILTER_CMP_NE;
	} else if (strcmp(token, "<") == 0) {
		etype = FILTER_CMP_LT;
	} else if (strcmp(token, ">") == 0) {
		etype = FILTER_CMP_GT;
	} else if (strcmp(token, "<=") == 0) {
		etype = FILTER_CMP_LE;
	} else if (strcmp(token, ">=") == 0) {
		etype = FILTER_CMP_GE;
	} else {
		show_error(error_str,
			   "Unknown op '%s' after '%s'",
			   token, field_name);
		free_token(field_name);
		free_token(token);
		return EVENT_ERROR;
	}
	op = token;

	type = read_token(&token);
	if (type != EVENT_ITEM && type != EVENT_SQUOTE && type != EVENT_DQUOTE) {
		show_error(error_str,
			   "Expected an item after '%s %s' instead of %s",
			   field_name, op, token);
		free_token(field_name);
		free_token(op);
		free_token(token);
		return EVENT_ERROR;
	}
	free_token(op);

	field = pevent_find_field(event, field_name);
	free_token(field_name);

	arg = allocate_arg();

	if (field) {
		ret = process_valid_field(arg, field, etype, type, token, error_str);
		if (ret < 0) {
			free_arg(arg);
			return EVENT_ERROR;
		}
	} else {
		/*
		 * When an event does not contain a field in the
		 * filter, just make it false.
		 */
		arg->type = FILTER_ARG_BOOLEAN;
		arg->bool.value = FILTER_FALSE;
	}

	free_token(token);

	type = read_token(tok);

	if (cont && type == EVENT_OP &&
	    (strcmp(*tok, "&&") == 0 || strcmp(*tok, "||") == 0)) {
		/* continue */;
		type = process_op(event, arg, parg, tok, error_str);
	} else
		*parg = arg;

	return type;
}

static enum event_type
process_paren(struct event_format *event, struct filter_arg **parg,
	      char **tok, char **error_str, int cont)
{
	struct filter_arg *arg;
	enum event_type type;

	*parg = NULL;

	type = process_token(event, &arg, tok, error_str, 1);
	if (type == EVENT_ERROR) {
		free_arg(arg);
		return type;
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

	type = read_token(tok);

	if (cont && type == EVENT_OP &&
	    (strcmp(*tok, "&&") == 0 || strcmp(*tok, "||") == 0)) {
		/* continue */;
		type = process_op(event, arg, parg, tok, error_str);
	} else
		*parg = arg;

	return type;
}

static enum event_type
process_not(struct event_format *event, struct filter_arg **parg,
	    char **tok, char **error_str, int cont)
{
	struct filter_arg *arg;
	enum event_type type;

	arg = allocate_arg();
	arg->type = FILTER_ARG_OP;
	arg->op.type = FILTER_OP_NOT;

	arg->op.left = NULL;
	type = process_token(event, &arg->op.right, tok, error_str, 0);
	if (type == EVENT_ERROR) {
		free_arg(arg);
		*parg = NULL;
		free_token(*tok);
		*tok = NULL;
		return EVENT_ERROR;
	}

	if (cont && type == EVENT_OP &&
	    (strcmp(*tok, "&&") == 0 || strcmp(*tok, "||") == 0)) {
		/* continue */;
		type = process_op(event, arg, parg, tok, error_str);
	} else
		*parg = arg;

	return type;
}

static int
process_event(struct event_format *event, const char *filter_str,
	      struct filter_arg **parg, char **error_str)
{
	enum event_type type;
	char *token;

	pevent_buffer_init(filter_str, strlen(filter_str));

	type = process_token(event, parg, &token, error_str, 1);

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
		ret = find_event(pevent, &events, sys_name, event_name);
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

void pevent_filter_free(struct event_filter *filter)
{
	int i;

	pevent_unref(filter->pevent);

	for (i = 0; i < filter->filters; i++)
		free_filter_type(&filter->event_filters[i]);

	free(filter->event_filters);
	free(filter);
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

static int test_num(struct event_format *event,
		    struct filter_arg *arg, struct record *record)
{
	unsigned long long val;

	val = get_value(arg->num.field, record);

	switch (arg->num.type) {
	case FILTER_CMP_EQ:
		return val == arg->num.val;

	case FILTER_CMP_NE:
		return val != arg->num.val;

	case FILTER_CMP_GT:
		return val > arg->num.val;

	case FILTER_CMP_LT:
		return val < arg->num.val;

	case FILTER_CMP_GE:
		return val >= arg->num.val;

	case FILTER_CMP_LE:
		return val <= arg->num.val;

	default:
		/* ?? */
		return 0;
	}
}

static int test_str(struct event_format *event,
		    struct filter_arg *arg, struct record *record)
{
	const char *val = record->data + arg->str.field->offset;

	switch (arg->str.type) {
	case FILTER_CMP_MATCH:
		return strncmp(val, arg->str.val, arg->str.field->size) == 0;

	case FILTER_CMP_NOT_MATCH:
		return strncmp(val, arg->str.val, arg->str.field->size) != 0;

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

	default:
		/* ?? */
		return 0;
	}
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

