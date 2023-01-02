CFLAGS  = /O2
sfw32.exe: sfw32.c resource.res
	$(CC) $(CFLAGS) sfw32.c resource.res
clean:
	if exist resource.res del resource.res
	if exist sfw32.exe    del sfw32.exe
	if exist sfw32.obj    del sfw32.obj
