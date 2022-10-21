// Pink noise generator
//   $ cc -O -o pink pink.c
//   $ ./pink | mpv -
// This is free and unencumbered software released into the public domain.
#include <stdio.h>

static int u32le(unsigned long v)
{
    unsigned char b[] = {v, v>>8, v>>16, v>>24};
    return fwrite(b, 4, 1, stdout);
}

static int u16le(unsigned v)
{
    unsigned char b[] = {v, v>>8};
    return fwrite(b, 2, 1, stdout);
}

int main(void)
{
    #if _WIN32
    int _setmode(int, int);
    _setmode(1, 0x8000);
    #endif

    u32le(0x46464952); // "RIFF"
    u32le(0xffffffff); // file length
    u32le(0x45564157); // "WAVE"
    u32le(0x20746d66); // "fmt "
    u32le(16        ); // struct size
    u16le(1         ); // PCM
    u16le(2         ); // stereo
    u32le(44100     ); // sample rate
    u32le(44100*4   ); // byte rate
    u16le(2*2       ); // block size
    u16le(16        ); // bits per sample
    u32le(0x61746164); // "data"
    u32le(0xffffffff); // byte length

    unsigned long sum = 0;
    unsigned long long rng[16] = {0};
    for (unsigned c = 0; u16le((sum>>4) - 0x7fff); c++) {
        int i = __builtin_ffsl(c&0x7fff);
        sum -= rng[i]>>48 & 0xffff;
        rng[i] = rng[i]*0x3243f6a8885a308d + (i<<1) + 1;
        sum += rng[i]>>48 & 0xffff;
    }
}
