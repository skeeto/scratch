# 2022 r/place rendering and processing tools

The [official 2022 r/place data][dl] is in a bloated, inefficient, and
unfriendly format:

* The data isn't sorted, so every consumer must sort the entire, gigantic
  dataset for themselves before they can use it! It also makes compression
  less effective.

* User IDs are 88-byte, uncompressible hashes. With 10,381,125 distinct
  users, *at best* around 10% of the 12GB dataset is just these useless,
  random hashes. This also has knock-on effects that makes compression
  less efficient. A big waste.

* Timestamps are a variable-width, human-readable format that is tricky to
  parse. In the 2017 dataset it's just a unix epoch counter.

* The coordinate field embeds another CSV, and so must be parsed twice.

The compressed data is 12GB, uncompressing to 20GB — 160,353,104 placement
entries. Recompressing with `zstd` gets it down to 5.3GB, plus it's much
faster. With a little more thought, this can be further reduced to just
1.2GB compressed without information loss. The `convert` program does
this, changing the format to more closely match the 2017 dataset:

* The data is sorted, making it immediately useful.

* User IDs are converted to short numbers. The first hash listed in the
  original data is assigned user 0, the second hash is assigned user 1,
  etc.

* Timestamps are milliseconds after midnight UTC, April 1st. Easy to parse
  and fits in a 32-bit integer.

* Coordinates are split into their own fields.

* Colors are converted into a 32-element palette index (0-31).

The conversion process takes a couple of minutes on typical hardware.

## Sample output

The first few lines of the converted output:

    timestamp,user,color,x,y
    45850315,804018,14,42,42
    45862671,804019,3,999,999
    45866626,804020,7,44,42
    45871703,804021,21,2,2
    45884409,804022,7,23,23
    45890544,804023,6,420,420
    45917836,804024,10,110,37

## Rendering

The rendering program expects input in the smart format. The full pipeline
looks like so:

    $ gunzip <2022_place_canvas_history.csv.gzip |
          ./convert | ./render |
          ffmpeg -framerate 60 -i - -c:v libx264 -pix_fmt yuv420p place.mp4

As with conversion, the bottleneck is `gunzip`.


[dl]: https://old.reddit.com/r/place/comments/txvk2d/
