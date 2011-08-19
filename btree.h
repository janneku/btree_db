#ifndef _BTREE_H
#define _BTREE_H

#ifdef __CHECKER__
#define FORCE           __attribute__((force))
#else
#define FORCE
#endif

#ifdef __CHECKER__
#define BITWISE         __attribute__((bitwise))
#else
#define BITWISE
#endif

#include <stdio.h>
#include <stdint.h>

typedef uint16_t BITWISE __be16; /* big endian, 16 bits */
typedef uint32_t BITWISE __be32; /* big endian, 32 bits */

#define SHA1_LENGTH	20

#define CACHE_SLOTS	23 /* prime */

struct btree_item {
	uint8_t sha1[SHA1_LENGTH];
	__be32 offset;
	__be32 child;
} __attribute__((packed));

#define TABLE_SIZE	((4096 - 1) / sizeof(struct btree_item))

struct btree_table {
	struct btree_item items[TABLE_SIZE];
	uint8_t size;
} __attribute__((packed));

struct btree_cache {
	size_t offset;
	struct btree_table *table;
};

struct blob_info {
	__be32 len;
};

struct btree_super {
	__be32 top;
	__be32 free_top;
};

struct btree {
	size_t top;
	size_t free_top;
	size_t alloc;
	int fd;
	struct btree_cache cache[CACHE_SLOTS];
};

int btree_open(struct btree *btree);
int btree_creat(struct btree *btree);
void btree_close(struct btree *btree);
void btree_insert(struct btree *btree, const uint8_t *sha1, const void *data,size_t len);
void *btree_get(struct btree *btree, const uint8_t *sha1, size_t *len);
int btree_delete(struct btree *btree, const uint8_t *sha1);

#endif
