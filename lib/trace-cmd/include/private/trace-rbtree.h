/* SPDX-License-Identifier: LGPL-2.1 */
/*
 * Copyright (C) 2023 Google, Steven Rostedt <rostedt@goodmis.org>
 *
 */
#ifndef _TRACE_RBTREE_H
#define _TRACE_RBTREE_H

struct trace_rbtree_node {
	struct trace_rbtree_node	*parent;
	struct trace_rbtree_node	*left;
	struct trace_rbtree_node	*right;
	int				color;
};

typedef int (*trace_rbtree_cmp_fn)(const struct trace_rbtree_node *A, const struct trace_rbtree_node *B);

typedef int (*trace_rbtree_search_fn)(const struct trace_rbtree_node *n, const void *data);

struct trace_rbtree {
	struct trace_rbtree_node	*node;
	trace_rbtree_search_fn		search;
	trace_rbtree_cmp_fn		cmp;
	size_t				nr_nodes;
};

void trace_rbtree_init(struct trace_rbtree *tree, trace_rbtree_cmp_fn cmp_fn,
		       trace_rbtree_search_fn search_fn);
struct trace_rbtree_node *trace_rbtree_find(struct trace_rbtree *tree, const void *data);
void trace_rbtree_delete(struct trace_rbtree *tree, struct trace_rbtree_node *node);
int trace_rbtree_insert(struct trace_rbtree *tree, struct trace_rbtree_node *node);
struct trace_rbtree_node *trace_rbtree_pop_nobalance(struct trace_rbtree *tree);

#endif /* _TRACE_RBTREE_H */
