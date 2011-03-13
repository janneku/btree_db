#include "btree.h"
#include <string.h>
#include <stdlib.h>

#if 0
void dump(struct btree_table *table, int level)
{
	if (table == NULL) return;
	size_t i, j;
	for (i = 0; i < table->size; ++i) {
		dump(table->items[i].child, level+1);
		for (j = 0; j < level; ++j)
			printf("   ");
		printf("%s", table->items[i].key);
	}
	dump(table->items[i].child, level+1);
}
#endif

static struct btree_table *alloc_table(struct btree *btree)
{
	size_t size = sizeof(struct btree_table) +
			sizeof(struct btree_item) * (btree->num_keys + 1);
	struct btree_table *table = malloc(size);
	if (table == NULL)
		return NULL;
	memset(table, 0, size);
	return table;
}

void btree_init(struct btree *btree, cmp_func_t cmp, size_t num_keys)
{
	btree->top = NULL;
	btree->num_keys = num_keys;
	btree->cmp = cmp;
}

static struct btree_table *split_table(struct btree *btree,
					struct btree_table *table,
					void **key, void **value)
{
	*key = table->items[btree->num_keys / 2].key;
	*value = table->items[btree->num_keys / 2].value;

	table->size = btree->num_keys / 2;

	struct btree_table *new_table = alloc_table(btree);
	new_table->size = btree->num_keys / 2 - 1;

	memcpy(new_table->items, &table->items[btree->num_keys / 2 + 1],
		btree->num_keys / 2 * sizeof(struct btree_item));

	return new_table;
}

static struct btree_table *collapse(struct btree_table *table)
{
	struct btree_table *child = table->items[0].child;
	free(table);
	return child;
}

static void remove_table(struct btree_table *table, size_t i,
			 void **key, void **value);

static void take_smallest(struct btree_table *table,
			 void **key, void **value)
{
	struct btree_table *child = table->items[0].child;
	if (child == NULL) {
		remove_table(table, 0, key, value);
		return;
	}
	take_smallest(child, key, value);
	if (child->size == 0)
		table->items[0].child = collapse(child);
}

static void take_largest(struct btree_table *table,
			 void **key, void **value)
{
	struct btree_table *child = table->items[table->size].child;
	if (child == NULL) {
		remove_table(table, table->size - 1, key, value);
		return;
	}
	take_largest(child, key, value);
	if (child->size == 0)
		table->items[table->size].child = collapse(child);
}

static void remove_table(struct btree_table *table, size_t i,
			 void **key, void **value)
{
	*key = table->items[i].key;
	*value = table->items[i].value;
	struct btree_table *left_child = table->items[i].child;
	struct btree_table *right_child = table->items[i + 1].child;

	if (left_child && right_child) {
		void *key, *value;
		if (left_child->size > right_child->size) {
			take_largest(left_child, &key, &value);
			if (left_child->size == 0)
				table->items[i].child = collapse(left_child);
		} else {
			take_smallest(right_child, &key, &value);
			if (right_child->size == 0)
				table->items[i + 1].child = collapse(right_child);
		}
		table->items[i].key = key;
		table->items[i].value = value;
		return;
	}

	memmove(&table->items[i], &table->items[i + 1],
		(table->size - i) * sizeof(struct btree_item));
	table->size--;

	if (left_child)
		table->items[i].child = left_child;
	else
		table->items[i].child = right_child;
}

static void *insert_table(struct btree *btree,
			  struct btree_table *table, void **key, void **value)
{
	size_t left = 0, right = table->size;
	while (left < right) {
		size_t i = (left + right) / 2;
		int cmp = btree->cmp(*key, table->items[i].key);
		if (cmp == 0) {
			/* already in the table */
			return table->items[i].value;
		}
		if (cmp < 0)
			right = i;
		else
			left = i + 1;
	}
	size_t i = left;

	void *ret = NULL;
	struct btree_table *child = table->items[i].child;
	struct btree_table *right_child = NULL;
	if (child) {
		/* recursion */
		ret = insert_table(btree, child, key, value);
		if (child->size < btree->num_keys)
			return ret;
		right_child = split_table(btree, child, key, value);
	} else
		ret = *value;

	table->size++;
	memmove(&table->items[i + 1], &table->items[i],
		(table->size - i) * sizeof(struct btree_item));
	table->items[i].key = *key;
	table->items[i].value = *value;
	table->items[i].child = child;
	table->items[i + 1].child = right_child;
	return ret;
}

static void *delete_table(struct btree *btree,
			  struct btree_table *table, void *key)
{
	size_t left = 0, right = table->size, i;
	while (left < right) {
		i = (left + right) / 2;
		int cmp = btree->cmp(key, table->items[i].key);
		if (cmp == 0)
			break;
		if (cmp < 0)
			right = i;
		else
			left = i + 1;
	}

	if (left == right) {
		/* not found - recursion */
		i = left;
		struct btree_table *child = table->items[i].child;
		if (child == NULL)
			return NULL;
		void *ret = delete_table(btree, child, key);
		if (child->size == 0)
			table->items[i].child = collapse(child);
		return ret;
	}

	void *ret = NULL;
	remove_table(table, i, &key, &ret);
	return ret;
}

void *btree_insert(struct btree *btree, void *key, void *value)
{
	void *ret = NULL;
	struct btree_table *right_child = NULL;
	if (btree->top) {
		ret = insert_table(btree, btree->top, &key, &value);
		if (btree->top->size < btree->num_keys)
			return ret;
		right_child = split_table(btree, btree->top, &key, &value);
	} else
		ret = value;

	struct btree_table *table = alloc_table(btree);
	table->size = 1;
	table->items[0].key = key;
	table->items[0].value = value;
	table->items[0].child = btree->top;
	table->items[1].child = right_child;

	btree->top = table;
	return ret;
}

void *btree_delete(struct btree *btree, void *key)
{
	void *ret = delete_table(btree, btree->top, key);
	if (btree->top->size == 0)
		btree->top = collapse(btree->top);
	return ret;
}

void *btree_get(struct btree *btree, void *key)
{
	struct btree_table *table = btree->top;
	while (table) {
		size_t left = 0, right = table->size;
		while (left < right) {
			size_t i = (left + right) / 2;
			int cmp = btree->cmp(key, table->items[i].key);
			if (cmp == 0)
				return table->items[i].value;
			if (cmp < 0)
				right = i;
			else
				left = i + 1;
		}
		table = table->items[left].child;
	}
	return NULL;
}

size_t btree_depth(struct btree_table *table)
{
	size_t i, max_depth = 0;
	for (i = 0; i <= table->size; ++i) {
		if (table->items[i].child) {
			size_t depth = btree_depth(table->items[i].child);
			if (depth > max_depth) max_depth = depth;
		}
	}
	return max_depth + 1;
}
