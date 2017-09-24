.POSIX:
CC     = cc -std=c99
CFLAGS = -Wall -Wextra -O3 -march=native -g3
all: tests speckcrypt
speckcrypt: speckcrypt.c speck.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ speckcrypt.c $(LDLIBS)
tests: tests.c speck.h
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ tests.c $(LDLIBS)
test: check
check: tests
	./tests
clean:
	rm -f tests speckcrypt
