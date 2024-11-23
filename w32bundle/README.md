# Win32 Bundler

Bundles an application with its runtime and data into a single EXE. When
executed, the wrapper EXE dumps all the files in a unique directory in the
temporary directory, runs the first file, waits for it to exit, cleans up,
and passes through the original exit status.

Files are concatenated to the "loader" stub program with a file listing.
No linker or other build tools are needed when bundling an application.
The file bundle is a 4-byte-aligned block of data, beginning with a file
listing, one entry per file, plus a terminating zero entry:

```c
struct entry {
    i32 name_offset;
    i32 data_offset;
    i32 data_length;
};
```

Offsets are relative to the start of the block. Names are aligned,
null-terminated, [potentially ill-formed UTF-16][UTF-16] ready for use
with in any Win32 API. The block ends with an aligned 32-bit integer
giving its total size, including size integer. This integer is located at
the end of the wrapper EXE, from which the wrapper can find the beginning
of the bundle and so the file listing.

`builder.exe` creates a console subsystem wrapper, and `builderw.exe`
creates a windows subsystem wrapper (e.g. for GUI applications). This is
done using different stubs compiled for each subsystem. A smarter version
would flip the appropriate bit in the stub PE image so that only one stub
is necessary.

    $ builder main.exe util.dll data.bin >bundle.exe

The builder program only runs on Windows and has not been ported for
"cross-bundling" use. The makefile is designed for w64devkit, but the
application compiles with Clang and MSVC using the proper sequence of
commands. The `wrap.exe` target demos the console subsystem builder.

    $ make wrap.exe
    $ ./wrap

This program is mainly a proof of concept. The user interface is lacking,
and many error checks are omitted (see `TODO` in the sources). It would be
a lot more useful if it could bundle a whole directory hierarchy, e.g. it
could bundle up an entire "portable" application or even a game into a
single EXE. The offsets and sizes should probably be 64-bit, too. This
little project was inspired by [HexLoader][].


[HexLoader]: https://github.com/crepps/HexLoader
[UTF-16]: https://simonsapin.github.io/wtf-8/#potentially-ill-formed-utf-16
