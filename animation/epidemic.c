/* Epidemic simulation
 * $ cc -Ofast -march=native epidemic.c -lm
 * $ ./a.out | mpv --no-correct-pts --fps=60 -
 * $ ./a.out | x264 -o simulation.mp4 --fps 60 --frames 2700 /dev/stdin
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SIZE               1080
#define SIZE               1080
#define NUM_ENTITY        1<<12
#define INIT_INFECTED        15
#define INFECT_CHANCE     0.80f
#define INFECT_DISTANCE   10.0f
#define INFECT_TIME         600
#define REPULSE            2.0f
#define INIT             1L<<10

static unsigned long long r32s;
static float r32(void)
{
    r32s = r32s*0xfc5434fdb4a9e74d + 1;
    return ldexpf(r32s>>40 & 0xffffff, -24);
}

struct v2 { float x, y; };

static float
v2_abs(struct v2 v)
{
    return sqrtf(v.x*v.x + v.y*v.y);
}

static struct v2
v2_sub(struct v2 a, struct v2 b)
{
    return (struct v2){a.x-b.x, a.y-b.y};
}

static struct v2
v2_scale(struct v2 v, float s)
{
    return (struct v2){v.x*s, v.y*s};
}

static struct v2
v2_add(struct v2 a, struct v2 b)
{
    return (struct v2){a.x+b.x, a.y+b.y};
}

static struct v2
v2_unit(struct v2 v)
{
    float d = v2_abs(v);
    return (struct v2){v.x/d, v.y/d};
}

static struct v2
v2_rand(float min, float max)
{
    float x = r32() * (max - min) + min;
    float y = r32() * (max - min) + min;
    return (struct v2){x, y};
}

static float
clamp(float x, float min, float max)
{
    return fminf(fmaxf(x, min), max);
}

static unsigned char buf[3L*SIZE*SIZE];

static void
buf_clear(void)
{
    memset(buf, 0, sizeof(buf));
}

static void
buf_set(int x, int y, long color)
{
    if (x >= 0 && x < SIZE && y >= 0 && y < SIZE) {
        buf[y*3L*SIZE + x*3L + 0] = color >> 16;
        buf[y*3L*SIZE + x*3L + 1] = color >>  8;
        buf[y*3L*SIZE + x*3L + 2] = color >>  0;
    }
}

static void
buf_write(void)
{
    printf("P6\n%d %d\n255\n", SIZE, SIZE);
    fwrite(buf, sizeof(buf), 1, stdout);
}

int
main(void)
{
    r32s = time(0);

    struct {
        struct v2 pos;
        struct v2 vel;
        enum {SIR_S, SIR_I, SIR_R} state;
        short time;
    } entity[NUM_ENTITY];

    for (int i = 0; i < NUM_ENTITY; i++) {
        entity[i].pos = v2_rand(0, SIZE);
        entity[i].vel = v2_unit(v2_rand(-1, 1));
        entity[i].state = SIR_S;
        entity[i].time = 0;
    }

    for (long n = 0; ; n++) {

        if (n == INIT) {
            for (int i = 0; i < INIT_INFECTED; i++) {
                entity[i].state = SIR_I;
            }
        }

        for (int i = 0; i < NUM_ENTITY; i++) {
            if (entity[i].state == SIR_I && ++entity[i].time > INFECT_TIME) {
                entity[i].state = SIR_R;
            }

            for (int j = i + 1; j < NUM_ENTITY; j++) {
                struct v2 d = v2_sub(entity[i].pos, entity[j].pos);
                float dist = v2_abs(d);
                struct v2 f = v2_scale(d, REPULSE/powf(dist, 3));
                if (entity[i].state != SIR_I || entity[j].state != SIR_I) {
                    entity[i].vel = v2_add(entity[i].vel, f);
                    entity[j].vel = v2_sub(entity[j].vel, f);
                }
                if (dist < INFECT_DISTANCE) {
                    if (entity[i].state == SIR_I && entity[j].state == SIR_S) {
                        if (r32() < INFECT_CHANCE)
                            entity[j].state = SIR_I;
                    }
                    if (entity[i].state == SIR_S && entity[j].state == SIR_I) {
                        if (r32() < INFECT_CHANCE)
                            entity[j].state = SIR_I;
                    }
                }
            }

            struct v2 target;
            static const struct v2 quarantine[] = {
                {SIZE * 0.1f, SIZE * 0.1f},
                {SIZE * 0.9f, SIZE * 0.1f},
                {SIZE * 0.1f, SIZE * 0.9f},
                {SIZE * 0.9f, SIZE * 0.9f},
            };
            switch (entity[i].state) {
            default: abort();
            case SIR_S:
            case SIR_R:
                target = (struct v2){SIZE / 2, SIZE / 2};
                break;
            case SIR_I:
                target = quarantine[0];
                float best = v2_abs(v2_sub(entity[i].pos, quarantine[0]));
                for (int q = 1; q < 4; q++) {
                    float d = v2_abs(v2_sub(entity[i].pos, quarantine[q]));
                    if (d < best) {
                        best = d;
                        target = quarantine[q];
                    }
                }
                break;
            }
            struct v2 vc = v2_sub(entity[i].pos, target);
            float attract = 0.00008f * REPULSE;
            entity[i].vel = v2_sub(entity[i].vel, v2_scale(vc, attract));
            entity[i].vel = v2_unit(entity[i].vel);
        }

        buf_clear();
        for (int i = 0; i < NUM_ENTITY; i++) {
            entity[i].pos.x += entity[i].vel.x;
            entity[i].pos.y += entity[i].vel.y;
            entity[i].pos.x = clamp(entity[i].pos.x, 0, SIZE - 1);
            entity[i].pos.y = clamp(entity[i].pos.y, 0, SIZE - 1);

            int x = entity[i].pos.x;
            int y = entity[i].pos.y;
            static long colors[] = {0xffffff, 0xff0000, 0x00ff00};
            buf_set(x-1, y, colors[entity[i].state]);
            buf_set(x+1, y, colors[entity[i].state]);
            buf_set(x, y, colors[entity[i].state]);
            buf_set(x, y-1, colors[entity[i].state]);
            buf_set(x, y+1, colors[entity[i].state]);
        }

        if (n > INIT) {
            buf_write();
        }
    }
}
