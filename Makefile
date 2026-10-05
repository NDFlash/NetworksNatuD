CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c99
LDLIBS  = -lm

all: cgrab

cgrab: cgrab.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f cgrab *.o

.PHONY: all clean
