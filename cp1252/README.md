# Various CP-1252 encode/decode functions

Various functions for efficiently encoding and decoding [code page
1252][wiki]. Includes "best fit" extensions so that all bytes of CP-1252
are mapped.

```c
// Decode one byte of CP-1252 to a Unicode code point.
//
// Undefined inputs are mapped to their "best fit" code point.
long cp1252_to_unicode(int c);

// Encode a Unicode code point into one byte of CP-1252.
//
// The five undefined CP-1252 bytes are mapped to their "best fit" code
// points. Otherwise unrepresentable input is converted to U+001A
// (SUBSTITUTE).
int unicode_to_cp1252(long r);

// Transcode one UTF-8 code point into one byte of CP-1252.
//
// The five undefined CP-1252 bytes are mapped to their "best fit" code
// points. Otherwise unrepresentable or invalid input is converted to U+001A
// (SUBSTITUTE). Always stores at exactly one byte to the output buffer.
// Returns the number of input bytes consumed (from 1 to 4).
int utf8_to_cp1252(void *cp1252, const void *utf8);

// Decode one byte of CP-1252 into bytes of UTF-8.
//
// Undefined bytes mapped to their "best bit" code points. Returns the
// number of bytes stored (from 1 to 3).
int cp1252_to_utf8(void *utf8, int c);
```


[wiki]: https://en.wikipedia.org/wiki/Windows-1252
