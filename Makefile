CC=gcc
CFLAGS=-std=gnu11 -Wall -Wextra -O3 -g
SRC=src/main.c
LIBS=-lcjson -lcrypt -lssl -lcrypto
OUT=pa

all:
	$(CC) $(SRC) $(CFLAGS) $(LIBS) -o $(OUT)
clean:
	@-rm $(OUT)
