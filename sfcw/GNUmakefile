CROSS   = i686-w64-mingw32-
CC      = $(CROSS)gcc -ansi -pedantic
WINDRES = $(CROSS)windres
CFLAGS  = -Os -march=i486 -mtune=generic -mno-stack-arg-probe \
 -fno-asynchronous-unwind-tables
LDFLAGS = -s -Wl,--gc-sections -mwindows -nostdlib
LDLIBS  = -lkernel32 -luser32 -lgdi32 -lcomctl32
sfcw.exe: sfcw.c resource.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ sfcw.c resource.o $(LDLIBS)
resource.o: resource.rc sfcw.ico sfcw.exe.manifest
	$(WINDRES) -o $@ resource.rc
clean:
	rm -f resource.o sfcw.exe
