.POSIX:
CC      = cc
CFLAGS  = -Ofast -fopenmp -g -Wall -Wextra
LDFLAGS =
LDLIBS  = -lm

aidrivers: aidrivers.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ aidrivers.c $(LDLIBS)

clean:
	rm -f aidrivers
