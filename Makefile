CFLAGS = -O2 -W -Wall -g
OBJS = btree.o main.o

btree: $(OBJS)
	$(CC) -o $@ $(OBJS) -lcrypto -lrt
