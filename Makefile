CC=gcc
CFLAGS=-std=gnu11 -Wall -Wextra -O3
SRC=src/main.c
LIBS=-lcjson
OUT=pa

all:
	$(CC) $(SRC) $(CFLAGS) $(LIBS) -o $(OUT)
clean:
	@-rm $(OUT)