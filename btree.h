#ifndef _BTREE_H
#define _BTREE_H

#include <stdio.h>
#include <stdint.h>

#define SHA1_LENGTH	20

struct btree_item {
	uint8_t sha1[SHA1_LENGTH];
	uint32_t offset;
	uint32_t child;
} __attribute__((packed));

#define TABLE_SIZE	((4096 - 4) / sizeof(struct btree_item))

struct btree_table {
	struct btree_item items[TABLE_SIZE];
	uint8_t size;
};

struct blob_info {
	uint32_t len;
};

struct btree_super {
	uint32_t top;
	uint32_t free_top;
};

struct btree {
	size_t top;
	size_t free_top;
	FILE *file;
};

int btree_open(struct btree *btree, const char *file);
int btree_creat(struct btree *btree, const char *file);
void btree_close(struct btree *btree);
void btree_insert(struct btree *btree, const uint8_t *sha1, const void *data,
		  size_t len);
void *btree_get(struct btree *btree, const uint8_t *sha1, size_t *len);
int btree_delete(struct btree *btree, const uint8_t *sha1);

#endif
