typedef unsigned char           u8;
typedef bool                    b8;
typedef int                     i32;
typedef unsigned                u32;
typedef long long               i64;
typedef unsigned long long      u64;
typedef typeof((u8*)0-(u8*)0)   iz;
typedef typeof(sizeof(0))       uz;

#define affirm(c)       while (!(c)) __builtin_trap()
#define lenof(a)        (iz)(sizeof(a) / sizeof(*(a)))
#define new(a, n, t)    (t *)alloc(a, n, sizeof(t), _Alignof(t))
#define S(s)            (Str){(u8 *)s, lenof(s)-1}

static i32 randn(u64 *r, i32 n)
{
    *r = *r*0x3243f6a8885a308d + 1;
    return (i32)(((*r>>32) * (u64)n)>>32);
}

static uz touz(iz n)
{
    affirm(n >= 0);
    return (uz)n;
}

typedef struct {
    u8 *beg;
    u8 *end;
} Arena;

static u8 *alloc(Arena *a, iz count, iz size, iz align)
{
    iz pad = (iz)-(uz)a->beg & (align - 1);
    affirm(count < (a->end - a->beg - pad)/size);
    u8 *r = a->beg + pad;
    a->beg += pad + count*size;
    return __builtin_memset(r, 0, touz(count*size));
}

typedef struct {
    u64 rng;
    i64 counter;
    i32 width;
    i64 keys[128];
} Gen;

typedef struct {
    i64 sets[64];
    u64 walls;
    u64 floors;
    u64 marks;
} Row;

static b8 has_wall(Row r, i32 i)
{
    return !(r.walls & ((u64)1<<i));
}

static b8 has_floor(Row r, i32 i)
{
    return !(r.floors & ((u64)1<<i));
}

static Row break_wall(Row r, i32 i)
{
    r.walls |= (u64)1<<i;
    return r;
}

static Row break_floor(Row r, i32 i)
{
    r.floors |= (u64)1<<i;
    return r;
}

static b8 marked(Row r, i32 i)
{
    return r.marks & ((u64)1<<i);
}

static Row mark(Row r, i32 i)
{
    r.marks |= (u64)1<<i;
    return r;
}

static Row unmark(Row r, i32 i)
{
    r.marks &= ~((u64)1<<i);
    return r;
}

static Row new_row(Gen *g, Row u)
{
    Row r = {};
    for (i32 i = 0; i < g->width; i++) {
        if (has_floor(u, i)) {
            r.sets[i] = ++g->counter;
        } else {
            r.sets[i] = u.sets[i];
        }
    }
    return r;
}

static void reset(Gen *g)
{
    for (i32 i = 0; i < lenof(g->keys); i++) {
        g->keys[i] = 0;
    }
}

typedef struct {
    i64  key;
    Gen *gen;
    u32  mask;
    u32  step;
    i32  idx;
} Iter;

static Iter next(Iter it)
{
    for (;;) {
        it.idx = (i32)(((u32)it.idx + it.step) & it.mask);
        if (!it.gen->keys[it.idx] || it.gen->keys[it.idx]==it.key) {
            return it;
        }
    }
}

static Iter iter(Gen *g, i64 key)
{
    Iter it = {};
    u64 hash = (u64)key * 1111111111111111111;
    it.key  = key;
    it.gen  = g;
    it.mask = lenof(g->keys) - 1;
    it.step = (u32)(hash >> (64 - 7)) | 1;
    it.idx  = (i32)hash;
    return next(it);
}

static Row join_walls(Gen *g, Row r)
{
    for (i32 i = 0; i < g->width-1; i++) {
        if (r.sets[i]!=r.sets[i+1] && !randn(&g->rng, 2)) {
            r = break_wall(r, i);
            i64 target = r.sets[i+1];
            // FIXME: quadratic, though does it matter with max width 64?
            for (i32 j = 0; j < g->width; j++) {
                if (r.sets[j] == target) {
                    r.sets[j] = r.sets[i];
                }
            }
        }
    }
    return r;
}

static Row generate(Gen *g, Row u)
{
    Row r = new_row(g, u);
    r = join_walls(g, r);

    reset(g);
    for (i32 i = 0; i < g->width; i++) {
        if (!randn(&g->rng, 4)) {
            r = break_floor(r, i);
            i32 idx = iter(g, r.sets[i]).idx;
            g->keys[idx] = r.sets[i];
        }
    }

    for (;;) {
        i32 count = 0;

        for (i32 i = 0; i < g->width; i++) {
            i32 idx = iter(g, r.sets[i]).idx;
            if (!g->keys[idx]) {
                if (!randn(&g->rng, 4)) {
                    r = break_floor(r, i);
                    g->keys[idx] = r.sets[i];
                } else {
                    count++;
                }
            }
        }

        if (!count) {
            return r;
        }
    }
}

typedef struct {
    i32 x;
    i64 y;
} V2;

static V2 dirs[] = {{+1, +0}, {+0, +1}, {-1, +0}, {+0, -1}};
typedef enum : i32 { Bearing_E, Bearing_S, Bearing_W, Bearing_N } Bearing;

static V2 apply(V2 v, i32 dir)
{
    v.x += dirs[dir].x;
    v.y += dirs[dir].y;
    return v;
}

static b8 equals(V2 a, V2 b)
{
    return a.x==b.x && a.y==b.y;
}

typedef struct {
    i64  top;
    Row *rows;
    i32  height;
    V2   position;
    V2   target;
} Maze;

static Maze new_maze(Arena *a, i32 height, Gen *g)
{
    Maze m = {};
    m.position.x = g->width / 2;
    m.height = height;
    m.rows = new(a, height, Row);
    for (i32 i = 0; i < height; i++) {
        m.rows[i] = generate(g, m.rows[(i+height-1)%height]);
    }
    return m;
}

static void advance(Maze *m, Gen *g)
{
    i32 next = (i32)(m->top++ % m->height);
    i32 prev = (next+m->height-1) % m->height;
    m->rows[next] = generate(g, m->rows[prev]);
}

static void clear_marks(Maze *m)
{
    for (i32 i = 0; i < m->height; i++) {
        m->rows[i].marks = 0;
    }
}

static Row *get_row(Maze *m, i64 y)
{
    return &m->rows[y % m->height];
}

typedef struct {
    V2 *data;
    iz  len;
} V2s;

static V2s solve(Maze *m, Gen *g, Arena *a)
{
    typedef struct Node Node;
    struct Node {
        Node *next;
        Node *parent;
        V2    v;
    };

    Node  *head = 0;
    Node **tail = &head;


    *tail = &(Node){.v=m->position};
    tail = &(*tail)->next;

    V2 end = m->target;

    clear_marks(m);
    while (head) {
        Node *node = head;
        V2 v = node->v;
        head = head->next;
        if (!head) tail = &head;

        if (v.x==end.x && v.y==end.y) {
            V2s r = {};
            for (Node *n = node; n; n = n->parent) {
                r.len++;
            }
            r.data = new(a, r.len, V2);

            iz i = r.len;
            clear_marks(m);
            for (Node *n = node; n; n = n->parent) {
                r.data[--i] = n->v;
                Row *r = get_row(m, n->v.y);
                *r = mark(*r, n->v.x);
            }
            return r;
        }

        for (i32 i = 0; i < 4; i++) {
            V2 t = apply(v, i);
            if (t.x<0 || t.x>=g->width || t.y<m->top || t.y>=m->top+m->height) {
                continue;
            } else if (marked(*get_row(m, t.y), t.x)) {
                continue;
            }
            switch (i) {
            case 0: if (has_wall(*get_row(m, v.y), v.x)) continue;
                    break;
            case 1: if (has_floor(*get_row(m, v.y), v.x)) continue;
                    break;
            case 2: if (has_wall(*get_row(m, t.y), t.x)) continue;
                    break;
            case 3: if (has_floor(*get_row(m, t.y), t.x)) continue;
                    break;
            }
            *tail = new(a, 1, Node);
            (*tail)->parent = node;
            (*tail)->v = t;
            tail = &(*tail)->next;
            Row *r = get_row(m, t.y);
            *r = mark(*r, t.x);
        }
    }

    return (V2s){};
}

static b8 set_target(Maze *m, Gen *g, Arena scratch)
{
    m->target = (V2){g->width-1, m->top+m->height-1};
    if (solve(m, g, &scratch).len) {
        return true;
    }

    for (i64 y = m->top+m->height-1; y > m->position.y; y--) {
        i32 beg  = 0;
        i32 end  = g->width;
        i32 step = +1;
        if (m->position.x < g->width/2) {
            beg  = g->width - 1;
            end  = -1;
            step = -1;
        }

        for (i32 x = beg; x != end; x += step) {
            if (marked(*get_row(m, y), x)) {
                m->target = (V2){x, y};
                return true;
            }
        }
    }

    return false;
}

typedef enum : i32 { Op_LEFT=-1, Op_MOVE, Op_RIGHT, Op_DIG } Op;

typedef struct {
    Op *data;
    iz  len;
} Program;

static Program compile(Bearing b, V2s solution, Arena *a)
{
    Program p = {};
    p.data = new(a, 3*solution.len, Op);
    for (iz i = 1; i < solution.len;) {
        V2 prev = solution.data[i-1];
        V2 next = solution.data[i+0];
        if (equals(apply(prev, b), next)) {
            p.data[p.len++] = Op_MOVE;
            i++;
        } else if (equals(apply(prev, (b+3)%4), next)) {
            p.data[p.len++] = Op_LEFT;
            b = (b + 3)%4;
        } else {
            p.data[p.len++] = Op_RIGHT;
            b = (b + 1)%4;
        }
    }
    return p;
}

typedef struct {
    Arena   save;
    Arena   active;
    Gen     gen;
    Maze    maze;
    Program program;
    iz      ip;
    Bearing bearing;
} Animation;

static Animation new_animation(Arena *a, i32 width, i32 height, u64 seed)
{
    Animation ani = {};
    ani.gen.rng   = seed;
    ani.gen.width = width;
    ani.maze = new_maze(a, height, &ani.gen);
    ani.save = *a;
    ani.active = *a;
    return ani;
}

static void step(Animation *ani)
{
    if (ani->ip == ani->program.len) {
        ani->ip = 0;
        ani->active = ani->save;
        if (set_target(&ani->maze, &ani->gen, ani->active)) {
            V2s solution = solve(&ani->maze, &ani->gen, &ani->active);
            ani->program = compile(ani->bearing, solution, &ani->active);
        } else {
            static Op dig[] = {Op_DIG};
            ani->program = (Program){dig, lenof(dig)};
        }
    }

    if (ani->ip < ani->program.len) {
        Row *r = 0;
        Op op = ani->program.data[ani->ip++];
        switch (op) {
        case Op_LEFT:
        case Op_RIGHT:
            ani->bearing = (ani->bearing + (i32)op + 4) % 4;
            break;
        case Op_MOVE:
            r = get_row(&ani->maze, ani->maze.position.y);
            *r = unmark(*r, ani->maze.position.x);
            ani->maze.position = apply(ani->maze.position, ani->bearing);
            break;
        case Op_DIG:
            r = get_row(&ani->maze, ani->maze.position.y);
            *r = break_floor(*r, ani->maze.position.x);
            break;
        }
        if (ani->maze.position.y>ani->maze.top+8 &&
            !get_row(&ani->maze, ani->maze.top)->marks) {
            advance(&ani->maze, &ani->gen);
        }
    }
}
