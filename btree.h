#ifndef _BTREE_H
#define _BTREE_H

#include <stdio.h>

typedef int (*cmp_func_t)(void *key1, void *key2);

struct btree_node {
	void *key;
	void *value;
};

struct btree_item {
	void *key, *value;
	struct btree_table *child;
};

struct btree_table {
	size_t size;
	struct btree_item items[];
};

struct btree {
	struct btree_table *top;
	cmp_func_t cmp;
	size_t num_keys;
};

void btree_init(struct btree *btree, cmp_func_t cmp, size_t num_keys);
void *btree_insert(struct btree *btree, void *key, void *value);
void *btree_get(struct btree *btree, void *key);
void *btree_delete(struct btree *btree, void *key);
size_t btree_depth(struct btree_table *table);

#endif
