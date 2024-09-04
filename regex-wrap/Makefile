CXX      = cl /nologo
CPPFLAGS = /W4 /Z7

all: regex.dll main.exe

regex.dll regex.lib: regex.cpp regex.def
	$(CXX) /LD /std:c++17 /EHsc $(CPPFLAGS) regex.cpp /link /def:regex.def

main.exe: main.c regex.lib regex.h
	$(CXX) $(CPPFLAGS) main.c regex.lib

clean:
	if exist regex.dll del regex.dll
	if exist regex.lib del regex.lib
	if exist regex.obj del regex.obj
	if exist regex.pdb del regex.pdb
	if exist regex.ilk del regex.ilk
	if exist regex.exp del regex.exp
	if exist main.exe  del main.exe
	if exist main.obj  del main.obj
	if exist main.pdb  del main.pdb
	if exist main.ilk  del main.ilk
