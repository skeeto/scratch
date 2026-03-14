CC 		= cc
CFLAGS 	= -Wall -Wconversion -g3 -fsanitize=undefined -fsanitize-trap

culprit.exe: main_windows.c culprit.c
	$(CC) -nostartfiles $(CFLAGS) -o $@ main_windows.c -lrstrtmgr -lntdll

test: main_test.c culprit.c
	$(CC) $(CFLAGS) -o $@ main_test.c

check: test
	./test
