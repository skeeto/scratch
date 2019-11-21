CC      = cc
CFLAGS  = -O3 -march=native -Wall -Wextra
LDFLAGS =
LDLIBS  =

primes: main.c primesieve.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ main.c $(LDLIBS)

clean:
	rm -f primes
