CFLAGS = -std=c99 -Wall
LDLIBS = -lm

bloom : bloom.o main.o

main.o : main.c bloom.h
bloom.o : bloom.c bloom.h

run : bloom
	./$^ -c < google_5000000.txt

clean :
	$(RM) bloom bloom.o main.o filter.bloom
