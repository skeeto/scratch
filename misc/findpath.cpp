// Find shortest path on CSV-formatted graph
// $ cc -std=c++23 -nostartfiles -o findpath.exe findpath.cpp
// $ ./findpath <graph.csv source destination
//
// $ ./findpath >random.csv
// $ ./findpath <random.csv A B
//
// Columns are source,destination,cost with non-negative costs. Sample:
//
//   A,B,3
//   A,C,2
//   B,D,2
//   C,D,1
//   C,E,4
//   D,E,2
//
// This is free and unencumbered software released into the public domain.

#define assert(c)   while (!(c)) [[assume(0)]]
#define countof(a)  (iz)(sizeof(a) / sizeof(*(a)))

typedef unsigned char      u8;
typedef   signed int       b32;
typedef   signed int       i32;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef          char16_t  c16;
typedef          char      byte;
typedef decltype(0z)       iz;
typedef decltype(0uz)      uz;

enum : i32 {
	i32MIN = (i32)0x80000000,
	i32MAX = (i32)0x7fffffff,
};

void *operator new(uz, void *p) { return p; }

struct arena {
	byte *beg;
	byte *end;
};

// Allocate an extendable allocation at the front of the arena.
template<typename T, typename ...A>
T *sow(iz count, arena *perm, A ...args)
{
	iz size = sizeof(T);
	iz pad  = -(uz)perm->beg & (alignof(T) - 1);
	assert(count < (perm->end - perm->beg - pad)/size);
	T *r = (T *)(perm->beg + pad);
	perm->beg += pad + size*count;
	for (iz i = 0; i < count; i++) {
		new (r+i) T(args...);
	}
	return r;
}

// Allocate a fixed allocation at the back of the arena.
template<typename T, typename ...A>
T *make(iz count, arena *perm, A ...args)
{
	iz size = sizeof(T);
	iz pad  = (uz)perm->end & (alignof(T) - 1);
	assert(count < (perm->end - perm->beg - pad)/size);
	perm->end -= size*count + pad;
	T *r = (T *)perm->end;
	for (iz i = 0; i < count; i++) {
		new (r+i) T(args...);
	}
	return r;
}

template<typename T, typename ...A>
T *make(arena *perm, A ...args)
{
	return make<T>(1, perm, args...);
}

template<typename T>
struct list {
	T *data = 0;
	iz len  = 0;
	iz cap  = 0;
	T &operator[](iz i) { return data[i]; }
};

template<typename T>
static list<T> push(arena *perm, list<T> vs, T v)
{
	if (vs.len == vs.cap) {
		if ((byte *)(vs.data+vs.cap) != perm->beg) {
			list<T> copy = vs;
			copy.data = sow<T>(copy.len, perm);
			for (iz i = 0; i < vs.len; i++) {
				copy[i] = vs[i];
			}
			vs = copy;
		}
		iz extend = vs.len ? vs.len : 4;
		sow<T>(extend, perm);
		vs.cap += extend;
	}
	vs.data[vs.len++] = v;
	return vs;
}

template<typename T>
static void swap(list<T> s, iz i, iz j)
{
	T t  = s[i];
	s[i] = s[j];
	s[j] = t;
}

struct s8 {
	u8 *data = 0;
	iz  len  = 0;

	s8() = default;
	s8(u8 *beg, u8 *end) : data{beg}, len{end-beg} {}

	template<iz N>
	s8(char const (&s)[N]) : data{(u8 *)s}, len{N-1} {}

	s8(s8 s, arena *a) : data{sow<u8>(s.len, a)}, len{s.len}
	{
		for (iz i = 0; i < s.len; i++) {
			data[i] = s[i];
		}
	}

	b32 operator==(s8 s)
	{
		if (len != s.len) return 0;
		for (iz i = 0; i < len; i++) {
			if (data[i] != s[i]) return 0;
		}
		return 1;
	}

	u8 &operator[](iz i) { return data[i]; }
};

static u64 hash(s8 s)
{
	u64 r = 0x100;
	for (iz i = 0; i < s.len; i++) {
		r ^= s[i];
		r *= 1111111111111111111u;
	}
	return r;
}

static s8 append(arena *perm, s8 head, s8 tail)
{
	if ((byte *)(head.data+head.len) != perm->beg) {
		head = s8{head, perm};
	}
	head.len += s8{tail, perm}.len;
	return head;
}

static s8 append(arena *perm, s8 head, i32 x)
{
	u8  buf[32];
	u8 *p = buf + countof(buf);
	i32 t = x<0 ? x : -x;
	do *--p = '0' - (u8)(t%10);
	while (t /= 10);
	if (x < 0) *--p = '-';
	return append(perm, head, s8{p, buf+countof(buf)});
}

struct s8pair {
	s8  head;
	s8  tail;
};

static s8pair cut(s8 s, u8 c)
{
	u8 *beg = s.data;
	u8 *end = s.data + s.len;
	u8 *cut = beg;
	for (; cut<end && *cut!=c; cut++) {}
	s8pair r = {};
	r.head = s8{beg, cut};
	if (cut < end) {
		r.tail = s8{cut+1, end};
	}
	return r;
}

struct i32result {
	i32 value;
	b32 ok;
};

static i32result parsei32(s8 s)
{
	i32result r = {};
	for (iz i = 0; i < s.len; i++) {
		i32 v = s[i] - '0';
		if ((u32)v > '9') return r;
		if (r.value > (i32MAX - v)/10) return r;
		r.value = r.value*10 + v;
	}
	r.ok = s.len > 0;
	return r;
}

struct vertex;

struct vertex {
	struct edge {
		vertex *dst;
		i32     cost;
	};
	vertex    *prev;
	vertex    *child[4];
	s8         name;
	list<edge> edges;
	i32        distance = i32MAX;
};

static vertex *find(vertex **m, s8 name, iz *count = 0, arena *perm = 0)
{
	for (u64 h = hash(name); *m; h <<= 2) {
		if (name == (*m)->name) {
			return *m;
		}
		m = &(*m)->child[h>>62];
	}
	if (!perm) return 0;
	(*count)++;
	*m = make<vertex>(perm);
	(*m)->name = name;
	return *m;
}

struct minheap {
	struct slot {
		vertex *vertex;
		i32     priority;
	};
	list<slot> slots;
};

static i32 get(minheap *q, iz i)
{
	return i<q->slots.len ? q->slots[i].priority : i32MAX;
}

static minheap::slot pop(minheap *q)
{
	minheap::slot r = q->slots[0];
	q->slots[0] = q->slots[--q->slots.len];
	for (iz i = 0;;) {
		iz left  = i*2 + 1;
		iz right = i*2 + 2;
		iz best  = i;
		best = get(q, left )<get(q, best) ? left  : best;
		best = get(q, right)<get(q, best) ? right : best;
		if (best == i) return r;
		swap(q->slots, i, best);
		i = best;
	}
}

static void push(minheap *q, vertex *v, i32 priority, arena *perm)
{
	q->slots = push(perm, q->slots, {v, priority});
	for (iz i = q->slots.len-1;;) {
		iz parent = (i - 1)/2;
		if (get(q, parent) <= get(q, i)) {
			break;
		}
		swap(q->slots, parent, i);
		i = parent;
	}
}

static s8 findpath(s8 csv, s8 beg, s8 end, arena *perm, arena scratch)
{
	iz nverts = 0;
	vertex *verts = 0;

	// Parse the CSV into a graph
	s8pair line = {};
	for (line.tail = csv; line.tail.len;) {
		line = cut(line.tail, '\n');
		if (line.head.len && line.head[line.head.len-1]=='\r') {
			line.head.len--;
		}

		s8pair field = cut(line.head, ',');
		if (!field.head.len) return {};
		vertex *src = find(&verts, field.head, &nverts, &scratch);

		field = cut(field.tail, ',');
		if (!field.head.len) return {};
		vertex *dst = find(&verts, field.head, &nverts, &scratch);

		field = cut(field.tail, ',');
		i32result parsed = parsei32(field.head);
		if (!parsed.ok) return {};
		i32 cost = parsed.value;

		src->edges = push(&scratch, src->edges, {dst, cost});
		dst->edges = push(&scratch, dst->edges, {src, cost});
	}

	vertex *start = find(&verts, beg);
	vertex *stop  = find(&verts, end);
	if (!start || !stop) return {};

	// Dijkstra's algorithm
	minheap queue = {};
	start->distance = 0;
	push(&queue, start, 0, &scratch);
	while (queue.slots.len) {
		auto [v, priority] = pop(&queue);
		if (v->distance != priority) continue;

		if (v == stop) {
			// Found: print the solution to a string
			s8 r = {};
			r = append(perm, r, v->distance);

			// Reverse the linked list
			vertex *last = 0;
			while (v) {
				vertex *next = v->prev;
				v->prev = last;
				last = v;
				v = next;
			}
			for (; last; last = last->prev) {
				r = append(perm, r, ",");
				r = append(perm, r, last->name);
			}
			r = append(perm, r, "\n");
			return r;
		}

		for (iz i = 0; i < v->edges.len; i++) {
			auto [dst, cost] = v->edges[i];
			i32 distance = v->distance + cost;
			if (distance < dst->distance) {
				dst->prev = v;
				dst->distance = distance;
				push(&queue, dst, distance, perm);
			}
		}
	}
	return {};
}

// Generate a random number in [lo, hi).
static i32 randi32(u64 *rng, i32 lo, i32 hi)
{
	*rng = *rng*0x3243f6a8885a308d + 1;
	return (i32)(((*rng>>32)*(hi - lo))>>32) + lo;
}

static s8 printname(arena *perm, s8 head, i32 v)
{
	u8  buf[16];
	u8 *beg = buf + countof(buf);
	do *--beg = (u8)(v%26) + 'A';
	while (v /= 26);
	return append(perm, head, s8{beg, buf+countof(buf)});
}

struct edges {
	edges *child[4];
	i32    src;
	i32    dst;
	edges(i32 src, i32 dst) : src{src}, dst{dst} {}
};

static b32 insert(edges **e, i32 src, i32 dst, arena *perm)
{
	if (src > dst) {
		i32 tmp = src;
		src = dst;
		dst = tmp;
	}
	for (u64 h = 1111111111111111111u*(-1-src)*(-1-dst); *e; h <<= 2) {
		if (src==(*e)->src && dst==(*e)->dst) {
			return 0;
		}
		e = &(*e)->child[h>>62];
	}
	*e = make<edges>(perm, src, dst);
	return 1;
}

static s8 gencsv(u64 seed, i32 nverts, i32 nedges, arena *perm, arena scratch)
{
	s8 r = {};
	edges *exists = 0;
	seed += 1111111111111111111u;
	for (i32 i = 0; i < nedges; i++) {
		for (;;) {
			i32 src = randi32(&seed, 0, nverts);
			i32 dst;
			do dst = randi32(&seed, 0, nverts);
			while (src == dst);
			if (insert(&exists, src, dst, &scratch)) {
				r = printname(perm, r, src);
				r = append(perm, r, ",");
				r = printname(perm, r, dst);
				r = append(perm, r, ",");
				i32 cost = randi32(&seed, 1, 51);
				r = append(perm, r, cost);
				r = append(perm, r, "\n");
				break;
			}
		}
	}
	return r;
}


#define W32(r) extern "C" __declspec(dllimport) r __stdcall
W32(c16 **) CommandLineToArgvW(c16 *, i32 *);
W32(void)   ExitProcess(i32);
W32(c16 *)  GetCommandLineW(void);
W32(uz)     GetStdHandle(i32);
W32(b32)    ReadFile(uz, u8 *, i32, i32 *, uz);
W32(byte *) VirtualAlloc(uz, uz, i32, i32);
W32(i32)    WideCharToMultiByte(i32, i32, c16 *, i32, u8 *, i32, uz, uz);
W32(b32)    WriteFile(uz, u8 *, i32, i32 *, uz);

static i32 trunc(iz n)
{
	return n>i32MAX ? i32MAX : (i32)n;
}

static b32 write(i32 fd, s8 s)
{
	uz h = GetStdHandle(-10 - fd);
	for (i32 off = 0; off < s.len;) {
		i32 len = trunc(s.len-off);
		b32 ok  = WriteFile(h, s.data, len, &len, 0);
		if (!ok) return 0;
		off += len;
	}
	return 1;
}

static s8 load(i32 fd, arena *perm)
{
	s8 r = {};
	r.data = (u8 *)perm->beg;
	iz avail = perm->end - perm->beg;
	uz stdin = GetStdHandle(-10 - fd);
	while (r.len < avail) {
		i32 len;
		ReadFile(stdin, r.data+r.len, trunc(avail-r.len), &len, 0);
		if (!len) break;
		r.len += len;
	}
	perm->beg += r.len;
	return r;
}

static b32 run(byte *mem, iz cap)
{
	arena perm[1] = {};
	perm->beg = mem;
	perm->end = mem + cap/2;
	arena scratch = {};
	scratch.beg = mem + cap/2;
	scratch.end = mem + cap;

	c16 *cmdline = GetCommandLineW();
	i32 argc;
	c16 **argv = CommandLineToArgvW(cmdline, &argc);
	s8 *args = make<s8>(argc, perm);
	for (i32 i = 0; i < argc; i++) {
		i32 len = WideCharToMultiByte(65001, 0, argv[i], -1, 0, 0, 0, 0);
		args[i].len = len - 1;
		args[i].data = make<u8>(len, perm);
		WideCharToMultiByte(65001, 0, argv[i], -1, args[i].data, len, 0, 0);
	}

	switch (argc) {
		default: {
			return 1;
		}
		case 1: {
			s8 csv = gencsv(0, 100000, 100000, perm, scratch);
			return !write(1, csv);
		}
		case 3: {
			s8 input = load(0, perm);
			s8 output = findpath(input, args[1], args[2], perm, scratch);
			return output.data ? !write(1, output) : 1;
		}
	}
}

extern "C" void mainCRTStartup()
{
	iz cap = 1z<<26;
	byte *mem = VirtualAlloc(0, cap, 0x3000, 4);
	b32 err = run(mem, cap);
	ExitProcess(!!err);
	assert(0);
}
