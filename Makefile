CFLAGS = -O2 -W -Wall -g
OBJS = btree.o main.o

btree: $(OBJS)
	$(CC) -o $@ $(OBJS)  -lrt
clean:	
	rm -rf *.o *.db  *.idx btree
