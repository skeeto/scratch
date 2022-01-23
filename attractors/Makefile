.POSIX:
CC      = cc
CFLAGS  = -Wall -Wextra -Wdouble-promotion -Ofast
LDFLAGS = -s
LDLIBS  = -lm

bins = lorenz$(EXE) sprott$(EXE) aizawa$(EXE) halvorsen$(EXE) dadras$(EXE) \
       thomas$(EXE)

all: $(bins)

lorenz$(EXE): attractors.c
	$(CC) -DLORENZ $(CFLAGS) -o $@ attractors.c $(LDLIBS)

sprott$(EXE): attractors.c
	$(CC) -DSPROTT $(CFLAGS) -o $@ attractors.c $(LDLIBS)

aizawa$(EXE): attractors.c
	$(CC) -DAIZAWA $(CFLAGS) -o $@ attractors.c $(LDLIBS)

halvorsen$(EXE): attractors.c
	$(CC) -DHALVORSEN $(CFLAGS) -o $@ attractors.c $(LDLIBS)

dadras$(EXE): attractors.c
	$(CC) -DDADRAS $(CFLAGS) -o $@ attractors.c $(LDLIBS)

thomas$(EXE): attractors.c
	$(CC) -DTHOMAS $(CFLAGS) -o $@ attractors.c $(LDLIBS)

clean:
	rm -f $(bins)
