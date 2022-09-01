CC      = cl /nologo
RC      = rc /nologo
CFLAGS  = /O2

pbmview.exe: pbmview.c icon.res
	$(CC) $(CFLAGS) pbmview.c icon.res

icon.rc:
	echo 1 ICON "pbmview.ico" >$@

clean:
	if exist icon.rc     del icon.rc
	if exist icon.res    del icon.res
	if exist pbmview.exe del pbmview.exe
	if exist pbmview.obj del pbmview.obj
