#include "btree.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h> /* htonl/ntohl */

static void read_table(struct btree *btree, struct btree_table *table,
			size_t offset)
{
	assert(offset != 0);
	fseek(btree->file, offset, SEEK_SET);
	if (fread(table, 1, sizeof(*table), btree->file) != sizeof(*table))
		assert(0);
}

static void write_table(struct btree *btree, struct btree_table *table,
			size_t offset)
{
	assert(offset != 0);
	fseek(btree->file, offset, SEEK_SET);
	if (fwrite(table, 1, sizeof(*table), btree->file) != sizeof(*table))
		assert(0);
}

int btree_open(struct btree *btree, const char *fname)
{
	btree->file = fopen(fname, "rb+");
	if (btree->file == NULL)
		return -1;

	struct btree_super super;
	if (fread(&super, 1, sizeof(super), btree->file) != sizeof(super))
		return -1;
	btree->top = ntohl(super.top);
	btree->free_top = ntohl(super.free_top);
	return 0;
}

static void write_super(struct btree *btree);

int btree_creat(struct btree *btree, const char *fname)
{
	memset(btree, 0, sizeof(*btree));
	btree->file = fopen(fname, "wb+");
	if (btree->file == NULL)
		return -1;
	write_super(btree);
	return 0;
}

void btree_close(struct btree *btree)
{
	fclose(btree->file);
}

static int in_allocator = 0;

static size_t delete_table(struct btree *btree, size_t table_offset,
			   const uint8_t *sha1);

static size_t collapse(struct btree *btree, size_t table_offset);

#define ALIGNMENT	15

static size_t alloc_chunk(struct btree *btree, size_t len)
{
	len = (len + ALIGNMENT) & ~ALIGNMENT;

	size_t offset = 0;
	if (!in_allocator) {
		/* find free chunk with the larger or the same size */
		uint8_t sha1[SHA1_LENGTH];
		memset(sha1, 0, sizeof(sha1));
		*(uint32_t *)sha1 = htonl(len);

		in_allocator = 1;
		offset = delete_table(btree, btree->free_top, sha1);
		if (offset)
			btree->free_top = collapse(btree, btree->free_top);
		in_allocator = 0;
	}
	if (offset == 0) {
		fseek(btree->file, 0, SEEK_END);
		offset = (ftell(btree->file) + ALIGNMENT) & ~ALIGNMENT;
	}
	return offset;
}

size_t insert_toplevel(struct btree *btree, size_t *table_offset,
		uint8_t *sha1, const void *data, size_t len);

struct chunk {
	size_t offset;
	size_t len;
};

#define FREE_QUEUE_LEN	256

static struct chunk free_queue[FREE_QUEUE_LEN];
static size_t free_queue_len = 0;

static void free_chunk(struct btree *btree, size_t offset, size_t len)
{
	assert(offset != 0);

	if (in_allocator) {
		if (free_queue_len >= FREE_QUEUE_LEN) return;
		struct chunk *chunk = &free_queue[free_queue_len++];
		chunk->offset = offset;
		chunk->len = len;
		return;
	}
	len = (len + ALIGNMENT) & ~ALIGNMENT;

	uint8_t sha1[SHA1_LENGTH];
	memset(sha1, 0, sizeof(sha1));
	*(uint32_t *)sha1 = htonl(len);
	((uint32_t *)sha1)[1] = rand();
	((uint32_t *)sha1)[2] = rand();

	in_allocator = 1;
	insert_toplevel(btree, &btree->free_top, sha1, NULL, offset);
	in_allocator = 0;
}

static void write_super(struct btree *btree)
{
	/* free queued chunks */
	size_t i;
	for (i = 0; i < free_queue_len; ++i) {
		struct chunk *chunk = &free_queue[i];
		free_chunk(btree, chunk->offset, chunk->len);
	}
	free_queue_len = 0;

	struct btree_super super;
	memset(&super, 0, sizeof super);
	super.top = htonl(btree->top);
	super.free_top = htonl(btree->free_top);

	fseek(btree->file, 0, SEEK_SET);
	if (fwrite(&super, 1, sizeof(super), btree->file) != sizeof(super))
		assert(0);
}

static size_t insert_data(struct btree *btree, const void *data, size_t len)
{
	if (data == NULL)
		return len;

	struct blob_info info;
	memset(&info, 0, sizeof info);
	info.len = htonl(len);

	size_t offset = alloc_chunk(btree, sizeof info + len);

	fseek(btree->file, offset, SEEK_SET);
	if (fwrite(&info, 1, sizeof info, btree->file) != sizeof info)
		assert(0);
	if (fwrite(data, 1, len, btree->file) != len)
		assert(0);

	return offset;
}

static size_t split_table(struct btree *btree, struct btree_table *table,
			  uint8_t *sha1, size_t *offset)
{
	memcpy(sha1, table->items[TABLE_SIZE / 2].sha1, SHA1_LENGTH);
	*offset = ntohl(table->items[TABLE_SIZE / 2].offset);

	struct btree_table new_table;
	memset(&new_table, 0, sizeof new_table);

	new_table.size = table->size - TABLE_SIZE / 2 - 1;

	table->size = TABLE_SIZE / 2;

	memcpy(new_table.items, &table->items[TABLE_SIZE / 2 + 1],
		(new_table.size + 1) * sizeof(struct btree_item));

	size_t new_table_offset = alloc_chunk(btree, sizeof new_table);
	write_table(btree, &new_table, new_table_offset);

	return new_table_offset;
}

static size_t collapse(struct btree *btree, size_t table_offset)
{
	struct btree_table table;
	read_table(btree, &table, table_offset);
	if (table.size == 0) {
		size_t ret = ntohl(table.items[0].child);
		free_chunk(btree, table_offset, sizeof table);
		return ret;
	}
	return table_offset;
}

static size_t remove_table(struct btree *btree, struct btree_table *table,
			   size_t i, uint8_t *sha1);

static size_t take_smallest(struct btree *btree, size_t table_offset,
			      uint8_t *sha1)
{
	struct btree_table table;
	read_table(btree, &table, table_offset);

	size_t offset = 0;
	size_t child = ntohl(table.items[0].child);
	if (child == 0) {
		offset = remove_table(btree, &table, 0, sha1);
	} else {
		offset = take_smallest(btree, child, sha1);
		table.items[0].child = htonl(collapse(btree, child));
	}
	write_table(btree, &table, table_offset);
	return offset;
}

static size_t take_largest(struct btree *btree, size_t table_offset,
			     uint8_t *sha1)
{
	struct btree_table table;
	read_table(btree, &table, table_offset);

	size_t offset = 0;
	size_t child = ntohl(table.items[table.size].child);
	if (child == 0) {
		offset = remove_table(btree, &table, table.size - 1, sha1);
	} else {
		offset = take_largest(btree, child, sha1);
		table.items[table.size].child = htonl(collapse(btree, child));
	}
	write_table(btree, &table, table_offset);
	return offset;
}

static size_t remove_table(struct btree *btree, struct btree_table *table,
			     size_t i, uint8_t *sha1)
{
	if (sha1)
		memcpy(sha1, table->items[i].sha1, SHA1_LENGTH);
	size_t offset = ntohl(table->items[i].offset);
	size_t left_child = ntohl(table->items[i].child);
	size_t right_child = ntohl(table->items[i + 1].child);

	if (left_child && right_child) {
		uint8_t new_sha1[SHA1_LENGTH];
		size_t new_offset;
		if (rand() & 1) {
			new_offset = take_largest(btree, left_child, new_sha1);
			table->items[i].child = htonl(collapse(btree, left_child));
		} else {
			new_offset = take_smallest(btree, right_child, new_sha1);
			table->items[i + 1].child = htonl(collapse(btree, right_child));
		}
		memcpy(table->items[i].sha1, new_sha1, SHA1_LENGTH);
		table->items[i].offset = htonl(new_offset);
	} else {
		memmove(&table->items[i], &table->items[i + 1],
			(table->size - i) * sizeof(struct btree_item));
		table->size--;

		if (left_child)
			table->items[i].child = htonl(left_child);
		else
			table->items[i].child = htonl(right_child);
	}
	return offset;
}

static size_t insert_table(struct btree *btree, size_t table_offset,
			 uint8_t *sha1, const void *data, size_t len)
{
	struct btree_table table;
	read_table(btree, &table, table_offset);

	size_t left = 0, right = table.size;
	while (left < right) {
		size_t i = (left + right) / 2;
		int cmp = memcmp(sha1, table.items[i].sha1, SHA1_LENGTH);
		if (cmp == 0) {
			/* already in the table */
			return ntohl(table.items[i].offset);
		}
		if (cmp < 0)
			right = i;
		else
			left = i + 1;
	}
	size_t i = left;

	size_t offset = 0;
	size_t child_offset = ntohl(table.items[i].child);
	size_t right_child = 0;
	size_t ret = 0;
	if (child_offset) {
		/* recursion */
		ret = insert_table(btree, child_offset, sha1, data, len);
		struct btree_table child;
		read_table(btree, &child, child_offset);
		if (child.size < TABLE_SIZE-1)
			return ret;
		right_child = split_table(btree, &child, sha1, &offset);
		write_table(btree, &child, child_offset);
	} else {
		ret = offset = insert_data(btree, data, len);
	}

	table.size++;
	memmove(&table.items[i + 1], &table.items[i],
		(table.size - i) * sizeof(struct btree_item));
	memcpy(table.items[i].sha1, sha1, SHA1_LENGTH);
	table.items[i].offset = htonl(offset);
	table.items[i].child = htonl(child_offset);
	table.items[i + 1].child = htonl(right_child);
	write_table(btree, &table, table_offset);
	return ret;
}

static void dump_sha1(const uint8_t *sha1)
{
	size_t i;
	for (i = 0; i < SHA1_LENGTH; i++)
		printf("%02x", sha1[i]);
}

static size_t delete_table(struct btree *btree, size_t table_offset,
			   const uint8_t *sha1)
{
	if (table_offset == 0)
		return 0;
	struct btree_table table;
	read_table(btree, &table, table_offset);

	size_t left = 0, right = table.size;
	while (left < right) {
		size_t i = (left + right) / 2;
		int cmp = memcmp(sha1, table.items[i].sha1, SHA1_LENGTH);
		if (cmp == 0) {
			/* found */
			size_t ret = remove_table(btree, &table, i, NULL);
			write_table(btree, &table, table_offset);
			return ret;
		}
		if (cmp < 0)
			right = i;
		else
			left = i + 1;
	}

	/* not found - recursion */
	size_t i = left;
	size_t ret = 0;
	size_t child = ntohl(table.items[i].child);
	ret = delete_table(btree, child, sha1);
	if (ret)
		table.items[i].child = htonl(collapse(btree, child));

	if (ret == 0 && in_allocator && i < table.size) {
		/* remove the next largest */
		ret = remove_table(btree, &table, i, NULL);
	}
	if (ret)
		write_table(btree, &table, table_offset);
	return ret;
}

size_t insert_toplevel(struct btree *btree, size_t *table_offset,
			uint8_t *sha1, const void *data, size_t len)
{
	size_t offset = 0;
	size_t ret = 0;
	size_t right_child = 0;
	if (*table_offset) {
		ret = insert_table(btree, *table_offset, sha1, data, len);
		struct btree_table table;
		read_table(btree, &table, *table_offset);
		if (table.size < TABLE_SIZE-1)
			return ret;
		right_child = split_table(btree, &table, sha1, &offset);
		write_table(btree, &table, *table_offset);
	} else {
		ret = offset = insert_data(btree, data, len);
	}

	struct btree_table new_table;
	memset(&new_table, 0, sizeof new_table);

	new_table.size = 1;
	memcpy(new_table.items[0].sha1, sha1, SHA1_LENGTH);
	new_table.items[0].offset = htonl(offset);
	new_table.items[0].child = htonl(*table_offset);
	new_table.items[1].child = htonl(right_child);

	size_t new_table_offset = alloc_chunk(btree, sizeof new_table);
	write_table(btree, &new_table, new_table_offset);

	*table_offset = new_table_offset;
	return ret;
}

void btree_insert(struct btree *btree, const uint8_t *c_sha1, const void *data,
		  size_t len)
{
	uint8_t sha1[SHA1_LENGTH];
	memcpy(sha1, c_sha1, sizeof sha1);
	insert_toplevel(btree, &btree->top, sha1, data, len);
	write_super(btree);
}

static size_t lookup(struct btree *btree, size_t table_offset,
		     const uint8_t *sha1)
{
	struct btree_table table;
	while (table_offset) {
		read_table(btree, &table, table_offset);
		size_t left = 0, right = table.size, i;
		while (left < right) {
			i = (left + right) / 2;
			int cmp = memcmp(sha1, table.items[i].sha1, SHA1_LENGTH);
			if (cmp == 0) {
				/* found */
				return ntohl(table.items[i].offset);
			}
			if (cmp < 0)
				right = i;
			else
				left = i + 1;
		}
		table_offset = ntohl(table.items[left].child);
	}
	return 0;
}

void *btree_get(struct btree *btree, const uint8_t *sha1, size_t *len)
{
	size_t offset = lookup(btree, btree->top, sha1);
	if (offset == 0)
		return NULL;

	fseek(btree->file, offset, SEEK_SET);
	struct blob_info info;
	if (fread(&info, 1, sizeof info, btree->file) != sizeof info)
		return NULL;
	*len = ntohl(info.len);

	void *data = malloc(*len);
	if (data == NULL)
		return NULL;
	if (fread(data, 1, *len, btree->file) != *len) {
		free(data);
		data = NULL;
	}
	return data;
}

int btree_delete(struct btree *btree, const uint8_t *sha1)
{
	size_t offset = delete_table(btree, btree->top, sha1);
	if (offset == 0)
		return -1;

	btree->top = collapse(btree, btree->top);
	write_super(btree);

	fseek(btree->file, offset, SEEK_SET);
	struct blob_info info;
	if (fread(&info, 1, sizeof info, btree->file) != sizeof info)
		return 0;

	free_chunk(btree, offset, sizeof info + ntohl(info.len));
	write_super(btree);
	return 0;
}
