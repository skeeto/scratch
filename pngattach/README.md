# pngattach: attach files to a PNG image as metadata

The intended use is for attaching the source script(s) from which the
image was rendered. Attachments take the form of private "atCh" PNG
chunks, documented below, since none of the pre-defined chunks quite
captured what was needed.

PNG data is always transmitted on standard input and output. Example
usage:

    $ dot -Tpng graph.dot | pngattach graph.dot >graph.png

Which embeds the original source script into the PNG. It can be recovered
later with:

    $ pngattach -x <graph.png

Or using standard output:

    $ pngattach -xO <graph.png >graph.dot

## Dependencies

The tool only depends on zlib, used to compress and decompress
attachments. This dependency is optional if attachments are not
compressed.

## Usage

    usage: pngattach -c <PNG >PNG [FILE]...
           pngattach -d <PNG >PNG [FILE]...
           pngattach -t <PNG
           pngattach -x <PNG
      -c     create/update attachments (default)
      -d     delete attachments by name
      -h     print this usage message
      -O     write attachments to standard output
      -t     list attached files
      -u     do not compress attachments
      -v     print extracted file names (verbose)
      -x     extract all PNG attachments

## `atCh` chunk specification

An `atCh` PNG chunk has three parts:

* A null-terminated bytestring name representing a file name
* A 1-byte flag indicating if the attachment is compressed
* A blob of arbitrary data, optionally compressed with deflate

The name can be any length that fits in the chunk, and should be encoded
with UTF-8. It's up to each implementation to determine how to
appropriately interpret the bytestring for the local system. The name must
be at least one byte long, not counting the null terminator. It cannot
begin with a period (`0x2e`), nor contain control bytes (anything less
than `0x20`), nor slash (`0x2f`), nor backslash (`0x5c`), i.e. no
directory hierarchies.
