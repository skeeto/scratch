CROSS    =
CPPFLAGS = -Wall -Wextra -g3 -fsanitize=undefined -fsanitize-trap
LDFLAGS  =

all: regex.dll main.exe

regex.dll: regex.cpp regex.def
	$(CROSS)g++ -std=c++17 -shared $(CPPFLAGS) $(LDFLAGS) -o $@ $^

regex.lib: regex.def
	$(CROSS)dlltool -d regex.def -l regex.lib

main.exe: main.c regex.lib regex.h
	$(CROSS)gcc $(CPPFLAGS) $(LDFLAGS) -o main.exe main.c regex.lib

clean:
	rm -f regex.dll regex.lib main.exe
