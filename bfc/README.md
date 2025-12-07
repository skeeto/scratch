# Compile brainfuck programs to Windows x64 COFF objects

Use w64devkit:

    $ cc -nostartfiles -O -o bfc.exe bfc.c
    $ cc -c -O runtime.c
    $ ./bfc hello.bf
    $ ld -o hello.exe hello.o runtime.o -lkernel32
    $ ./hello.exe
    Hello World!

Interfaces (see `runtime.c`):

```c
// Compiler defines this function
void bf_entry(unsigned char array[30'000], void *ctx);

// Needs to link these functions for I/O
void bf_putchar(unsigned char *, void *ctx);
void bf_getchar(unsigned char *, void *ctx);
```

Other linkers can link these objects as well. This is not an optimizing
compiler. I wrote it mainly to explore creating and linking COFF files.
