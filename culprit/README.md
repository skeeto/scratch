# culprint: list Windows processes holding open files

    $ culprit [PATHS...]

For each process holding open a file or directory at a given path, appiled
recursively for directories, list each apth with an associated process and
a tab-indented list of PIDs and process image paths touching that path:

    $ culprint path/to/project/
    path\to\project\src\
        [5232] C:\Users\skeeto\w64devkit\share\vim\gvim.exe
    path\to\project\
        [1934] C:\Users\skeeto\w64devkit\bin\gdb.exe
    path\to\project\build\
        [6236] C:\Users\skeeto\w64devkit\bin\main.exe
    path\to\project\build\main.exe
        [6236] C:\Users\skeeto\w64devkit\bin\main.exe
        [1934] C:\Users\skeeto\w64devkit\bin\gdb.exe

This program will not act upon these processes, but inform a user of what
processes they might be interested in manipulating or terminating.
