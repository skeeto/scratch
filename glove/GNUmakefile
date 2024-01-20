CC     = cc
CFLAGS = -g3 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
  -Wdouble-promotion -Wconversion -Wno-sign-conversion \
  -fsanitize=undefined -fsanitize-undefined-trap-on-error
LDFLAGS =
LDLIBS  =

all: glove-convert$(EXE) glove-lookup$(EXE)

glove-convert.exe: glove-convert_win32.c glove.c
	$(CC) -nostartfiles $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

glove-lookup.exe: glove-lookup_win32.c glove-lookup.c glove.c
	$(CC) -nostartfiles $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

glove-convert: glove-convert_posix.c glove.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

glove-lookup: glove-lookup_posix.c glove-lookup.c glove.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f glove-convert.exe glove-lookup.exe glove-convert glove-lookup
