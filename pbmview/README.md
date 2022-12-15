# Netpbm Viewer for Windows

Fast. Lightweight. Minimalistic. Supports [P2, P3, P5, and P6][pbm] at 255
maxdepth, [farbfeld][], and [QOI][]. Monitors for changes and
automatically refreshes. Drag-and-drop. Windows XP and later.

* <kbd>f</kbd>: toggle fullscreen
* <kbd>q</kbd> / <kbd>ESC</kbd>: exit the program
* <kbd>s</kbd>: toggle exact vs. smoothed filtering (default: auto)
* <kbd>z</kbd>: reset window to image size (or approximate)

If the input is unreadable for any reason, it does nothing — not even
reporting errors — until the image file is updated with useful image
contents. Only displays one image at a time and cannot navigate an image
gallery.

## Usage

Pass the image path as an argument, or supply no arguments and instead use
drag-and-drop. This interface works well as a file association for Netpbm
file extensions.

Automatic reload is particularly useful when writing programs that output
Netpbm images. For example, when developing a program that outputs Netpbm
on standard output, in GDB use `run` like so:

    gdb> run >output.ppm

Then open `output.ppm` in `pbmview` and leave it open. Each time you run
the program (`r`), the viewer will automatically display the new image.
The viewer will actively watch for the image file to be created if it does
not yet exist.

## Build

Grab [w64devkit][] and run `make`. With MSVC, run `nmake`. When cross
compiling, set `CROSS`.

    make CROSS=x86_64-w64-mingw32-

## Known issues

Uses `StretchDIBits` with `HALFTONE` scaling, a naive algorithm that is
not [gamma-aware][] and produces artifacts, especially in older versions
of Windows.


[farbfeld]: https://tools.suckless.org/farbfeld/
[gamma-aware]: https://web.archive.org/web/20190419162041/http://www.ericbrasseur.org/gamma.html
[pbm]: http://netpbm.sourceforge.net/doc/ppm.html
[QOI]: https://qoiformat.org/
[w64devkit]: https://github.com/skeeto/w64devkit
