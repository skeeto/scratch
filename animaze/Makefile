CC      = cc
CFLAGS  = -std=c11 -Wall -Wextra -O3 -march=native
LDFLAGS =
LDLIBS  =

animaze: animaze.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ animaze.c $(LDLIBS)

view: animaze
	./animaze | mpv --no-correct-pts --fps=60 --fs -

challenge.png: animaze
	./animaze -q -n100000 -w100 -h50 -s18 | gm convert ppm:- $@

maze.mp4: animaze
	./animaze -n1 | x264 --fps 60 -o $@ /dev/stdin

clean:
	rm -f animaze
