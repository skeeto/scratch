.POSIX:
CROSS   =
CC      = $(CROSS)gcc -std=c99
CFLAGS  = -DNDEBUG -Os -fno-asynchronous-unwind-tables
LDFLAGS = -s -nostdlib -Wl,--gc-sections
LDLIBS  = -lkernel32 -lshell32 -luser32 -lgdi32 -lshlwapi
WINDRES = $(CROSS)windres

pbmview.exe: pbmview.c icon.o
	$(CC) $(CFLAGS) -mwindows $(LDFLAGS) -o $@ pbmview.c icon.o $(LDLIBS)

icon.o: pbmview.ico
	echo '1 ICON "pbmview.ico"' | $(WINDRES) -o $@

clean:
	rm -f pbmview.exe icon.o
