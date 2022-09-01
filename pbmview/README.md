# Netpbm Viewer for Windows

Fast. Lightweight. Useful when writing programs that output Netpbm images.
Supports P2, P3, P5, and P6 at 255 maxdepth. Monitors for changes and
automatically refreshes. Works on Windows XP and later.

* <kbd>f</kbd>: toggle fullscreen
* <kbd>q</kbd> / <kbd>ESC</kbd>: exit the program
* <kbd>z</kbd>: reset window to image size (or approximate)

If the input is unreadable for any reason, it does nothing — not even
reporting errors — until the image file is updated with useful image
contents. Only displays one image at a time and cannot navigate an image
gallery.

## Build

Grab [w64devkit][] and run `make`. With MSVC, run `nmake`. When cross
compiling, set `CROSS`.

    make CROSS=x86_64-w64-mingw32-

## Known issues

Uses `StretchDIBits` with `HALFTONE` scaling, a naive algorithm that is
not [gamma-aware][] and produces artifacts, especially in older versions
of Windows.

Probably has some stateful issues when moving between fullscreen,
maximized, and normal.

Drag-and-drop is not yet implemented.


[gamma-aware]: http://www.ericbrasseur.org/gamma.html?i=1
[w64devkit]: https://github.com/skeeto/w64devkit
