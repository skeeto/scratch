CFLAGS  = /O2
sfcw.exe: sfcw.c resource.res
	$(CC) $(CFLAGS) sfcw.c resource.res
clean:
	if exist resource.res del resource.res
	if exist sfcw.exe     del sfcw.exe
	if exist sfcw.obj     del sfcw.obj
