// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2023 Google, Steven Rostedt <rostedt@goodmis.org>
 *
 */
#include <stdlib.h>
#include <stdbool.h>
#include "trace-local.h"
#include "trace-rbtree.h"

enum {
	RED,
	BLACK,
};

void __hidden trace_rbtree_init(struct trace_rbtree *tree, trace_rbtree_cmp_fn cmp_fn,
				trace_rbtree_search_fn search_fn)
{
	memset(tree, 0, sizeof(*tree));
	tree->search = search_fn;
	tree->cmp = cmp_fn;
}

static bool is_left(struct trace_rbtree_node *node)
{
	return node == node->parent->left;
}

static struct trace_rbtree_node **get_parent_ptr(struct trace_rbtree *tree,
						 struct trace_rbtree_node *node)
{
	if (!node->parent)
		return &tree->node;
	else if (is_left(node))
		return &node->parent->left;
	else
		return &node->parent->right;
}

static void rotate_left(struct trace_rbtree *tree,
			struct trace_rbtree_node *node)
{
	struct trace_rbtree_node **parent_ptr = get_parent_ptr(tree, node);
	struct trace_rbtree_node *parent = node->parent;
	struct trace_rbtree_node *old_right = node->right;

	*parent_ptr = old_right;
	node->right = old_right->left;
	old_right->left = node;

	if (node->right)
		node->right->parent = node;
	node->parent = old_right;
	old_right->parent = parent;
}

static void rotate_right(struct trace_rbtree *tree,
			 struct trace_rbtree_node *node)
{
	struct trace_rbtree_node **parent_ptr = get_parent_ptr(tree, node);
	struct trace_rbtree_node *parent = node->parent;
	struct trace_rbtree_node *old_left = node->left;

	*parent_ptr = old_left;
	node->left = old_left->right;
	old_left->right = node;

	if (node->left)
		node->left->parent = node;
	node->parent = old_left;
	old_left->parent = parent;
}

static void insert_tree(struct trace_rbtree *tree,
			struct trace_rbtree_node *node)
{
	struct trace_rbtree_node *next = tree->node;
	struct trace_rbtree_node *last_next = NULL;
	bool went_left = false;

	while (next) {
		last_next = next;
		if (tree->cmp(next, node) > 0) {
			next = next->right;
			went_left = false;
		} else {
			next = next->left;
			went_left = true;
		}
	}

	if (!last_next) {
		tree->node = node;
		return;
	}

	if (went_left)
		last_next->left = node;
	else
		last_next->right = node;

	node->parent = last_next;
}

#if 0
static int check_node(struct trace_rbtree *tree, struct trace_rbtree_node *node)
{
	if (!node->parent) {
		if (tree->node != node)
			goto fail;
	} else {
		if (!is_left(node)) {
			if (node->parent->right != node)
				goto fail;
		}
	}
	return 0;
fail:
	printf("FAILED ON NODE!");
	breakpoint();
	return -1;
}

static void check_tree(struct trace_rbtree *tree)
{
	struct trace_rbtree_node *node = tree->node;

	if (node) {
		if (check_node(tree, node))
			return;
		while (node->left) {
			node = node->left;
			if (check_node(tree, node))
				return;
		}
	}

	while (node) {
		if (check_node(tree, node))
			return;
		if (node->right) {
			node = node->right;
			if (check_node(tree, node))
				return;
			while (node->left) {
				node = node->left;
				if (check_node(tree, node))
				    return;
			}
			continue;
		}
		while (node->parent) {
			if (is_left(node))
				break;
			node = node->parent;
			if (check_node(tree, node))
				return;
		}
		node = node->parent;
	}
}
#else
static inline void check_tree(struct trace_rbtree *tree) { }
#endif

int __hidden trace_rbtree_insert(struct trace_rbtree *tree,
				 struct trace_rbtree_node *node)
{
	struct trace_rbtree_node *uncle;

	memset(node, 0, sizeof(*node));

	insert_tree(tree, node);
	node->color = RED;
	while (node && node->parent && node->parent->color == RED) {
		if (is_left(node->parent)) {
			uncle = node->parent->parent->right;
			if (uncle && uncle->color == RED) {
				node->parent->color = BLACK;
				uncle->color = BLACK;
				node->parent->parent->color = RED;
				node = node->parent->parent;
			} else {
				if (!is_left(node)) {
					node = node->parent;
					rotate_left(tree, node);
					check_tree(tree);
				}
				node->parent->color = BLACK;
				node->parent->parent->color = RED;
				rotate_right(tree, node->parent->parent);
				check_tree(tree);
			}
		} else {
			uncle = node->parent->parent->left;
			if (uncle && uncle->color == RED) {
				node->parent->color = BLACK;
				uncle->color = BLACK;
				node->parent->parent->color = RED;
				node = node->parent->parent;
			} else {
				if (is_left(node)) {
					node = node->parent;
					rotate_right(tree, node);
					check_tree(tree);
				}
				node->parent->color = BLACK;
				node->parent->parent->color = RED;
				rotate_left(tree, node->parent->parent);
				check_tree(tree);
			}
		}
	}
	check_tree(tree);
	tree->node->color = BLACK;
	tree->nr_nodes++;
	return 0;
}

struct trace_rbtree_node *trace_rbtree_find(struct trace_rbtree *tree, const void *data)
{
	struct trace_rbtree_node *node = tree->node;
	int ret;

	while (node) {
		ret = tree->search(node, data);
		if (!ret)
			return node;
		if (ret > 0)
			node = node->right;
		else
			node = node->left;
	}
	return NULL;
}

static struct trace_rbtree_node *next_node(struct trace_rbtree_node *node)
{
	if (node->right) {
		node = node->right;
		while (node->left)
			node = node->left;
		return node;
	}

	while (node->parent && !is_left(node))
		node = node->parent;

	return node->parent;
}

static void tree_fixup(struct trace_rbtree *tree, struct trace_rbtree_node *node)
{
	while (node->parent && node->color == BLACK) {
		if (is_left(node)) {
			struct trace_rbtree_node *old_right = node->parent->right;

			if (old_right->color == RED) {
				old_right->color = BLACK;
				node->parent->color = RED;
				rotate_left(tree, node->parent);
				old_right = node->parent->right;
			}
			if (old_right->left->color == BLACK &&
			    old_right->right->color == BLACK) {
				old_right->color = RED;
				node = node->parent;
			} else {
				if (old_right->right->color == BLACK) {
					old_right->left->color = BLACK;
					old_right->color = RED;
					rotate_right(tree, old_right);
					old_right = node->parent->right;
				}
				old_right->color = node->parent->color;
				node->parent->color = BLACK;
				old_right->right->color = BLACK;
				rotate_left(tree, node->parent);
				node = tree->node;
			}
		} else {
			struct trace_rbtree_node *old_left = node->parent->left;

			if (old_left->color == RED) {
				old_left->color = BLACK;
				node->parent->color = RED;
				rotate_right(tree, node->parent);
				old_left = node->parent->left;
			}
			if (old_left->right->color == BLACK &&
			    old_left->left->color == BLACK) {
				old_left->color = RED;
				node = node->parent;
			} else {
				if (old_left->left->color == BLACK) {
					old_left->right->color = BLACK;
					old_left->color = RED;
					rotate_left(tree, old_left);
					old_left = node->parent->left;
				}
				old_left->color = node->parent->color;
				node->parent->color = BLACK;
				old_left->left->color = BLACK;
				rotate_right(tree, node->parent);
				node = tree->node;
			}
		}
	}
	node->color = BLACK;
}

void trace_rbtree_delete(struct trace_rbtree *tree, struct trace_rbtree_node *node)
{
	struct trace_rbtree_node *x, *y;
	bool do_fixup = false;

	if (!node->left && !node->right && !node->parent) {
		tree->node = NULL;
		goto out;
	}

	if (!node->left || !node->right)
		y = node;
	else
		y = next_node(node);

	if (y->left)
		x = y->left;
	else
		x = y->right;

	if (x)
		x->parent = y->parent;

	if (!y->parent) {
		tree->node = x;
	} else {
		if (is_left(y))
			y->parent->left = x;
		else
			y->parent->right = x;
	}

	do_fixup = y->color == BLACK;

	if (y != node) {
		y->color = node->color;
		y->parent = node->parent;
		y->left = node->left;
		y->right = node->right;
		if (y->left)
			y->left->parent = y;
		if (y->right)
			y->right->parent = y;
		if (!y->parent) {
			tree->node = y;
		} else {
			if (is_left(node))
				y->parent->left = y;
			else
				y->parent->right = y;
		}
	}

	if (do_fixup)
		tree_fixup(tree, x);

 out:
	node->parent = node->left = node->right = NULL;
	tree->nr_nodes--;
	check_tree(tree);
}

__hidden struct trace_rbtree_node *trace_rbtree_next(struct trace_rbtree *tree,
						     struct trace_rbtree_node *node)
{
	check_tree(tree);
	/*
	 * When either starting or the previous iteration returned a
	 * node with a right branch, then go to the first node (if starting)
	 * or the right node, and then return the left most node.
	 */
	if (!node || node->right) {
		if (!node)
			node = tree->node;
		else
			node = node->right;
		while (node && node->left)
			node = node->left;
		return node;
	}

	/*
	 * If we are here, then the previous iteration returned the
	 * left most node of the tree or the right branch. If this
	 * is a left node, then simply return the parent. If this
	 * is a right node, then keep going up until its a left node,
	 * or we finished the iteration.
	 *
	 * If we are here and are the top node, then there is no right
	 * node, and this is finished (return NULL).
	 */
	if (!node->parent || is_left(node))
		return node->parent;

	do {
		node = node->parent;
	} while (node->parent && !is_left(node));

	return node->parent;
}

/*
 * Used for freeing a tree, just quickly pop off the children in
 * no particular order. This will corrupt the tree! That is,
 * do not do any inserting or deleting of this tree after calling
 * this function.
 */
struct trace_rbtree_node *trace_rbtree_pop_nobalance(struct trace_rbtree *tree)
{
	struct trace_rbtree_node *node = tree->node;

	if (!node)
		return NULL;

	while (node->left)
		node = node->left;

	while (node->right)
		node = node->right;

	if (node->parent) {
		if (is_left(node))
			node->parent->left = NULL;
		else
			node->parent->right = NULL;
	} else {
		tree->node = NULL;
	}

	return node;
}
