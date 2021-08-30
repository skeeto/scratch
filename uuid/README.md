# Fast, secure, embeddable UUID generator for C

Supports Linux, \*BSD, Windows, and macOS — and probably more by accident.

## Usage example

```c
char buf[37];
struct uuidgen g = UUIDGEN_INIT;

uuidgen(&g, buf);
buf[36] = 0;
puts(buf);
```

`etc/main.c` is a command line UUID generator, too.

## Other implementations

This repository also includes UUID generators for other languages.
