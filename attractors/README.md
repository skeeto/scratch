# Strange attractor animator

This program writes raw video to standard output animating of [various
strange attractors][st] (ODE systems). Pipe it into your favorite video
player or encoder that accepts video data from standard input.

    $ make
    $ ./lorenz | mpv --no-correct-pts --fps=60 --fs -
    $ ./lorenz | ppmtoy4m -F60:1 | vlc -
    $ ./lorenz | x264 --fps 60 --frames 3600 -o lorenz.mp4 /dev/stdin

Requires a C compiler supporting C99 or later.


[st]: https://www.dynamicmath.xyz/strange-attractors/
