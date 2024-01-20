# A binary GloVe database format

A library and tool to convert [GloVe-formatted data][glove] into a binary
format with built-in search index and to search that index.

Inspired by [glove.c](https://github.com/shubham0204/glove.c).

[glove]: https://nlp.stanford.edu/projects/glove/

## Library usage

The API is documented in `glove.h`, which presents a clean, C-like,
FFI-friendly interface to the functionality in `glove.c`. All allocation
and file I/O is handled by the caller. The implementation is freestanding
and does not require a libc (beyond compiler's standard requirements).

## Command line usage

The conversion tool converts standard input to standard output. The lookup
tool memory maps the database on standard input and looks up each command
line argument. In both cases, standard input must be a file, not a pipe.

    $ glove-convert <glove.840B.300d.txt >glove.840B.300d.db
    $ glove-lookup <glove.840B.300d.db hello world
    hello ...
    world ...

## Build

For command line tools, compile each `glove-*_PLATFORM.c` or use `make`:

    $ cc -O2 -o glove-convert glove-convert_PLATFORM.c
    $ cc -O2 -o glove-lookup  glove-lookup_PLATFORM.c

For the library on POSIX:

    $ cc -shared -O2 -o libglove.so glove.c

Library on Windows (w64devkit):

    $ cc -shared -O2 -o glove.dll glove.c

Library on Windows (MSVC):

    $ cl /LD /O2 glove.c /link /def:glove.def

## Database format

The database is laid out as a series of 32-bit words in native byte order,
except for the string table at the end. It is a full copy, independent of
the original text data.

    i32               : number of words (nwords)
    i32               : number of dimensions (ndims)
    i32               : mask-step-index exponent (exp)
    i32[nwords]       : array of string table offsets to word endings
    f32[ndims*nwords] : 2D array of all embedding data
    i32[1<<exp]       : mask-step-index hash table slots
    u8[]              : string table

It is intended to be memory-mapped and used in place. The index is an [MSI
hash table][msi] with an FNV hash on words as keys. For its keys, hash
table slots reference the offset array using 1-indexing, reserving zero
for empty slots, and the embeddings array for values for key matches.

String table offsets are one-past-the-end of the word, which allows length
and offset to be encoded simultaneously. To determine word length, compare
the offset to the preceeding word in the array. The first word lacks a
preceeding word, and so its offset is also its length.

[msi]: https://nullprogram.com/blog/2022/08/08/
