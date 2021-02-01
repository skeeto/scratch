.POSIX:
CC      = cc
CFLAGS  = -O3 -g -Wall -Wextra -D__USE_MINGW_ANSI_STDIO=0
LDFLAGS = -flto
LDLIBS  =

sources = monocrypt.c platform.c monocypher.c

monocrypt$(EXE): $(sources)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(sources) $(LDLIBS)

clean:
	rm -f monocrypt$(EXE)
