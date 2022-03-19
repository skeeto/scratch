.POSIX:
CC      = cc -std=c11
CFLAGS  = -march=x86-64-v3 -O3 -Wall -Wextra
LDFLAGS = -s
LDLIBS  =
PREFIX  = /usr/local

csvquote$(EXE): csvquote.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ csvquote.c $(LDLIBS)

csvdump$(EXE): etc/csvdump.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ etc/csvdump.c $(LDLIBS)

install: csvquote$(EXE)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 755 csvquote$(EXE) $(DESTDIR)$(PREFIX)/bin
	gzip <csvquote.1 >$(DESTDIR)$(PREFIX)/share/man/man1/csvquote.1.gz

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/csvquote$(EXE)
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/csvquote.1.gz

bench: csvquote$(EXE) csvdump$(EXE)
	./csvdump | ./csvquote >/dev/null

clean:
	rm -f csvquote$(EXE) csvdump$(EXE)
