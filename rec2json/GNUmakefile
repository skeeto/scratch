# debug:   make
# release: make OPT=-O2

OPT      = -fsanitize=undefined -fsanitize-trap -D_GLIBCXX_DEBUG
CPPFLAGS = $(OPT) -g3 -Wall -Wconversion

all: rec2json-c$(EXE) rec2json-cpp$(EXE)

rec2json-c$(EXE): rec2json.c
	cc $(CPPFLAGS) -o $@ $^

rec2json-cpp$(EXE): rec2json.cpp
	c++ -std=c++20 $(CPPFLAGS) -o $@ $^

clean:
	rm -f rec2json-c$(EXE) rec2json-cpp$(EXE)
