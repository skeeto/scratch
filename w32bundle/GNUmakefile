CC       = cc
CPPFLAGS = -g3 -Wall -Wextra -Wconversion -fsanitize=undefined -fsanitize-trap

all: builder.exe builderw.exe

builder.exe: builder.cpp common.cpp loader.stub
	$(CC) -nostartfiles -DLOADER='u"loader.stub"' $(CPPFLAGS) -o $@ $<

builderw.exe: builder.cpp common.cpp loaderw.stub
	$(CC) -nostartfiles -DLOADER='u"loaderw.stub"' $(CPPFLAGS) -o $@ $<

loader.stub: loader.cpp common.cpp
	$(CC) -nostartfiles $(CPPFLAGS) -o $@ $<

loaderw.stub: loader.cpp common.cpp
	$(CC) -nostartfiles -mwindows -e mainCRTStartup $(CPPFLAGS) -o $@ $<

message.dll: message.c
	$(CC) -nostdlib -shared -s -e0 -o $@ $<

test.exe: test.c message.dll
	$(CC) -s -O -o $@ $^

wrap.exe: builder.exe loader.stub test.exe message.dll
	./builder test.exe message.dll >$@

clean:
	rm -f builder.exe loader.stub builderw.exe loaderw.stub \
	      message.dll test.exe wrap.exe
