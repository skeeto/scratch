# prips: print IPv4 address ranges

A feature-complete clone and drop-in replacement for the [original
GPL-licensed `prips` command line tool][prips]. It passes the original's
test suite, and exceeds the original in important ways:

* 100% portable to any ANSI C implementation
* Validates inputs so it doesn't produce garbage
* Correctly handles the entire IPv4 range
* No buffer overflows for pathological inputs
* Thorough error checks
* Around 10x–100x faster, especially for large ranges and exclusions
* Dedicated to the public domain (better "license")

## Examples

Print a range of addresses:

    $ prips 127.0.0.0 127.0.0.255

Same, but with CIDR notation:

    $ prips 127.0.0.0/24

Exclude 127.0.0.0 and 127.0.0.255:

    $ prips -e ...0,255 127.0.0.0/24

All but 127.0.0.0/8:

    $ prips -e 127... 0.0.0.0/0

Scan a local network:

    $ prips -e ...255 192.168.1.0/24 |
          xargs -n1 -P16 host |
          grep -v NXDOMAIN

## Technical flaws in the original implementation

Older versions (<1.2.0) of the original cannot handle 255.255.255.255
since it's treated as a special error value. Newer versions (>=1.2.0)
treat all invalid IP addresses as 255.255.255.255, leading to confusing
error messages and silently incorrect results.

It's easy to trigger an assertion failure in the original. Regular users
should not see such failures, which are indented to indicate the presence
of a program defect. If assertions are disabled (`NDEBUG`), then this
failure becomes a buffer overflow.

    $ prips -e 1000
    prips: except.c:49: set_exceptions: Assertion `bufferind != 4` failed.

It's easy to trigger a buffer overflow in the original. Compile with ASan
(`-fsanitize=address`) or run with Valgrind to catch it:

    $ prips -e "...$(seq 257)"

Or just obliterate the stack in a regular build and observe a (probable)
segmentation fault:

    $ prips -e "...$(yes 1 | head -n1000)"

The original does not check for errors, so you won't know when it fails:

    $ prips 127.0.0.0/8 >/dev/full && echo success
    success

## Special, minimalist builds

This program is incredibly portable and requires no runtime, only needing
access to its command line arguments and a write system call. It can be
built for Linux (x86-64, Aarch64) and Windows (any) without linking
against libc or a CRT.

Linux (x86-64 and Aarch64):

    $ make CFLAGS="-Os -fno-pie -ffreestanding" \
           LDFLAGS="-s -no-pie -nostdlib -Wl,--omagic"

Note: GCC may emit a `memset` for Aarch64, which will need to be defined.
Also, `--omagic` binaries are much smaller but less compatible, so you may
want to exclude this option.

Mingw-w64:

    $ make CC=x86_64-w64-mingw32-gcc \
           CFLAGS="-Os -ffreestanding" \
           LDFLAGS="-s -nostdlib" \
           LDLIBS="-lkernel32 -lshell32" \
           EXE=.exe

MSVC:

    C:\>cl /Os /GS- prips.c


[prips]: https://devel.ringlet.net/sysutils/prips/
