#include "btree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define warning(fmt...)	fprintf(stderr, "WARNING: " fmt)

static int file_exists(const char *path)
{
        struct stat st;
        return stat(path, &st) == 0;
}

static struct timespec start;

static void start_timer(void)
{
        clock_gettime(CLOCK_MONOTONIC, &start);
}

static double get_timer(void)
{
        struct timespec end;
        clock_gettime(CLOCK_MONOTONIC, &end);
        long seconds  = end.tv_sec  - start.tv_sec;
        long nseconds = end.tv_nsec - start.tv_nsec;
        return seconds + (double) nseconds / 1.0e9;
}

#define COUNT		3000000

int main(int argc, char **argv)
{

	const char *fname = "db.idx";

	if (argc < 2)
		return 0;

	srand(time(NULL));

	struct btree btree;
	uint8_t sha1[SHA1_LENGTH];
	char val[1024]="abddddddddddddddddddddddddddddddddddddddabdddddddddddddddddddddddddddddddddddddd";
	size_t i;

	if (file_exists(fname)) {
		if (btree_open(&btree)) {
			warning("Unable to open database\n");
			return 1;
		}
	} else {
		if (btree_creat(&btree)) {
			warning("Unable to create database\n");
			return 1;
		}
	}

	if (strcmp(argv[1], "insert") == 0) {
		memset(sha1, 0, sizeof sha1);

		start_timer();
		for (i = 0; i < COUNT; ++i) {
			sprintf((char *) sha1, "abcdefg%d", i);
			btree_insert(&btree, sha1, val, strlen(val));
			if((i%10000)==0)
			{
				fprintf(stderr,"finished %d ops%30s\r",i,"");
				fflush(stderr);
			}
		}
		printf("insert: %.6f\n", get_timer());
	}

	if (strcmp(argv[1], "get") == 0) {
		memset(sha1, 0, sizeof sha1);
		strcpy((char *) sha1, "foobar ");
		strcpy(val, "value ");

		start_timer();
		for (i = 1000; i < COUNT; ++i) {
			/* optimize a bit */
			sprintf(sha1, "abcdefg%d", (rand()%i));

			size_t len;
			void *data = btree_get(&btree, sha1, &len);
			free(data);

			 if((i%10000)==0)
			{
				fprintf(stderr,"finished %d ops%30s\r",i,"");
				fflush(stderr);
			}     
		}
		printf("get: %.6f\n", get_timer());

	} else if (strcmp(argv[1], "refill") == 0) {
		/* delete half of the data, then add it back */

		memset(sha1, 0, sizeof sha1);
		for (i = 0; i < COUNT/2; i++) {
			sprintf((char *) sha1, "foobar %zd", i);
			if (btree_delete(&btree, sha1))
				warning("not found: %zd\n", i);
		}

		memset(sha1, 0, sizeof sha1);
		for (i = 0; i < COUNT/2; i++) {
			sprintf((char *) sha1, "foobar %zd", i);
			sprintf(val, "value %zd", i*i);
			btree_insert(&btree, sha1, val, strlen(val));
		}

	} else if (strcmp(argv[1], "delete") == 0) {
		memset(sha1, 0, sizeof sha1);

		start_timer();
		for (i = 0; i < COUNT; i++) {
			sprintf((char *) sha1, "foobar %zd", i);
			if (btree_delete(&btree, sha1))
				warning("not found: %zd\n", i);
		}
		printf("delete: %.6f\n", get_timer());

	} else
		warning("unknown command\n");

	btree_close(&btree);

	return 0;
}
