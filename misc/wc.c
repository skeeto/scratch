// wc for Windows
//
// Build (MSC): cl /O2 wc.c
// Build (GCC): cc -O3 -municode -o wc.exe wc.c
//
// See usage (-h) for a list of features.
//
// This was written using Visual Studio .NET 2003 (cl, nmake, debugger,
// docs) and Vim 7.4 on a fresh Windows XP install. I first built Vim from
// source using VS 2003, wrote a quick 6-line vimrc from memory, then wrote
// this tool. It was a fun exercise to debug in VS, edit in Vim, support
// Unicode paths, correctly print paths to the console, correctly print
// paths to files as UTF-8, and accomplish it all using a rather limited
// environment. My goal was to obtain experience with different tooling than
// usual, which might provide insight on improving w64devkit.
//
// MSVCRT stdio has always had poor Unicode support. Back in VS 2003 it's
// especially appalling, and so I had to write my own buffered output from
// scratch which would have proper Unicode support.
//
// Conclusions: VS 2003 is better than VS 2022 in some ways, particularly
// performance and UI speed, though it's certainly still bloated in its own
// way. If I was somehow thrown two decades into the past, I could still be
// quite productive with this period's configuration, though I'd probably
// write some tools for myself, such as hd, to fill in gaps. Over time I'd
// build up my own more reasonable and complete stdio alternative, too.
//
// My full _vimrc when editing this program:
//   filetype plugin indent on
//   syntax on
//   set nocp hid noswf bs=2 aw ar is nojs pa=** wmnu go=ac cpt-=i
//   set sw=4 ts=4 fo+=j cino=t0,l1,:0 cink-=0# lines=99 vb gcr=a:blinkon0
//   compiler! msvc
//   set efm=%f(%l)%*[:\ ]%m
//
// This is free and unencumbered software released into the public domain.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Buffered output wrapping a HANDLE. If the handle is a console then it
// writes Unicode, otherwise it writes UTF-8.
#define BUF_ERROR   (1 << 0)
#define BUF_CONSOLE (1 << 1)
struct buf {
	HANDLE h;
	int len, cap;
	int flags;
	union {
		unsigned char n[1<<12];
		wchar_t w[1<<11];
	} buf;
};

static void
buf_init(struct buf *b, HANDLE h)
{
	DWORD dummy;

	b->h = h;
	b->len = 0;
	if (GetConsoleMode(h,  &dummy)) {
		b->cap = sizeof(b->buf.w) / sizeof(b->buf.w[0]);
		b->flags = BUF_CONSOLE;
	} else {
		b->cap = sizeof(b->buf.n) / sizeof(b->buf.n[0]);
		b->flags = 0;
	}
}

static int
buf_error(struct buf *b)
{
	return b->flags & BUF_ERROR;
}

static void
buf_flush(struct buf *b)
{
	DWORD z;
	if (b->flags & BUF_ERROR || !b->len) {
		// do nothing
	} else if (b->flags & BUF_CONSOLE) {
		if (!WriteConsoleW(b->h, b->buf.w, b->len, &z, 0)) {
			b->flags |= BUF_ERROR;
		}
	} else {
		if (!WriteFile(b->h, b->buf.n, b->len, &z, 0)) {
			b->flags |= BUF_ERROR;
		}
	}
	b->len = 0;
}

static void
buf_byte(struct buf *b, int c)
{
	if (b->len == b->cap) {
		buf_flush(b);
	}
	if (b->flags & BUF_CONSOLE) {
		b->buf.w[b->len++] = (wchar_t)c;
	} else {
		b->buf.n[b->len++] = (unsigned char)c;
	}
}

static void
buf_rune(struct buf *b, wchar_t r)
{
	if (b->flags & BUF_CONSOLE) {
		buf_byte(b, r);
	} else {
		if (r < 0x80) {
			buf_byte(b, r);
		} else if (r < 0x800) {
			buf_byte(b, 0xc0 | (r >>  6));
			buf_byte(b, 0x80 | (r >>  0 & 63));
		} else {  // TODO: surrogates
			buf_byte(b, 0xe0 | (r >> 12));
			buf_byte(b, 0x80 | (r >>  6 & 63));
			buf_byte(b, 0x80 | (r >>  0 & 63));
		}
	}
}

static void
buf_str(struct buf *b, char *s)
{
	while (*s) buf_byte(b, *s++);
}

static void
buf_wstr(struct buf *b, wchar_t *s)
{
	while (*s) buf_rune(b, *s++);
}

static void
buf_i64(struct buf *b, long long x)
{
	char tmp[32];
	char *p = tmp+32;
	do {
		*--p = '0' + (char)(x%10);
		x /= 10;
	} while (x);
	while (p < tmp+32) {
		buf_byte(b, *p++);
	}
}

#define FLAG_LINES (1 << 0)
#define FLAG_WORDS (1 << 1)
#define FLAG_RUNES (1 << 2)
#define FLAG_BYTES (1 << 3)
#define FLAG_MLINE (1 << 4)
struct counts {
	long long n, w, r, c, m;
};

static void
add(struct counts *dst, struct counts *src)
{
	dst->n += src->n;
	dst->w += src->w;
	dst->r += src->r;
	dst->c += src->c;
	dst->m  = src->m > dst->m ? src-> m : dst->m;
}

static void
print(struct counts *c, wchar_t *name, int which, struct buf *b)
{
	int i, f;
	long long *p = &c->n;

	for (i = 0, f = 0; i < 5; i++) {
		if (which & (1<<i)) {
			if (f) buf_rune(b, '\t');
			buf_i64(b, p[i]);
			f = 1;
		}
	}

	if (name) {
		buf_rune(b, '\t');
		buf_wstr(b, name);
	}
	buf_rune(b, '\r');
	buf_rune(b, '\n');
}

static int
process(HANDLE h, struct counts *counts)
{
	static const unsigned char ws[256] = {
		0,0,0,0,0,0,0,0,0,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	static const unsigned char lf[256] = {
		0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	static const unsigned char len[256] = {
		0,1,1,1,1,1,1,1,1,8,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
	};
	static const unsigned char align[256] = {
		0,1,1,1,1,1,1,1,1,8,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
	};
	static const unsigned char utf8[256] = {
		0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	};
	static unsigned char buf[1<<14];

	int s = 0;
	long long n = 0, w = 0, r = 0, c = 0, m = 0, y = 0;

	for (;;) {
		int i;
		DWORD z;

		if (!ReadFile(h, buf, sizeof(buf), &z, 0)) {
			if (GetLastError() != ERROR_BROKEN_PIPE) {
				return 0;
			}
			return 1;
		}
		for (i = z; i < (int)sizeof(buf); i++) {
			buf[i] = 0;
		}

		c += z;
		for (i = 0; i < (int)sizeof(buf); i++) {
			// Branchless counters
			int b = buf[i];
			n += lf[b];
			w += ws[b] & s;  // TODO: Unicode whitespace
			s  = !ws[b];
			r += utf8[b];
			m  = y>m ? y : m;
			y += len[b];
			y &= ~(align[b] - 1);
		}

		if (z < sizeof(buf)) {
			break;
		}
	}

	counts->n = n;
	counts->w = w;
	counts->r = r;
	counts->c = c;
	counts->m = m;
	return 1;
}

struct wgetopt {
	wchar_t *optarg;
	int optind, optopt, optpos;
};

static int
wgetopt(struct wgetopt *x, int argc, wchar_t **argv, char *optstring)
{
	wchar_t *arg = argv[!x->optind ? (x->optind += !!argc) : x->optind];
	if (arg && arg[0] == '-' && arg[1] == '-' && !arg[2]) {
		x->optind++;
		return -1;
	} else if (!arg || arg[0] != '-' || ((arg[1] < '0' || arg[1] > '9') &&
	                                     (arg[1] < 'A' || arg[1] > 'Z') &&
	                                     (arg[1] < 'a' || arg[1] > 'z'))) {
		return -1;
	} else {
		while (*optstring && arg[x->optpos+1] != *optstring) {
			optstring++;
		}
		x->optopt = arg[x->optpos+1];
		if (!*optstring) {
			return '?';
		} else if (optstring[1] == ':') {
			if (arg[x->optpos+2]) {
				x->optarg = arg + x->optpos + 2;
				x->optind++;
				x->optpos = 0;
				return x->optopt;
			} else if (argv[x->optind+1]) {
				x->optarg = argv[x->optind+1];
				x->optind += 2;
				x->optpos = 0;
				return x->optopt;
			} else {
				return ':';
			}
		} else {
			if (!arg[++x->optpos+1]) {
				x->optind++;
				x->optpos = 0;
			}
			return x->optopt;
		}
	}
}

static int
usage(struct buf *b)
{
	static const char usage[] =
	"usage: wc [-Lchlmw] [FILE]...\r\n"
	"  -L     count longest line length\r\n"
	"  -c     count bytes\r\n"
	"  -h     print this usage message\r\n"
	"  -l     count newlines\r\n"
	"  -m     count runes\r\n"
	"  -w     count words\r\n";
	buf_str(b, (char *)usage);
	buf_flush(b);
	return buf_error(b);
}

static void
werror(wchar_t *name, struct buf *berr)
{
	wchar_t msg[256];
	FormatMessageW(0x1200, 0, GetLastError(), 0, msg, sizeof(msg), 0);
	buf_str(berr, "wc: ");
	buf_wstr(berr, name);
	buf_str(berr, ": ");
	buf_wstr(berr, msg);
	buf_flush(berr);
}

int
wmain(int argc, wchar_t **argv)
{
	HANDLE h;
	struct buf bout[1], berr[1];
	int i, nargs, opt, which = 0;
	struct wgetopt wgo = {0, 0, 0, 0};
	struct counts counts, total = {0};

	buf_init(bout, GetStdHandle(STD_OUTPUT_HANDLE));
	buf_init(berr, GetStdHandle(STD_ERROR_HANDLE));

	while ((opt = wgetopt(&wgo, argc, argv, "Lchlmw")) != -1) {
		switch (opt) {
		case 'L': which |= FLAG_MLINE; break;
		case 'c': which |= FLAG_BYTES; break;
		case 'h': return usage(bout);
		case 'l': which |= FLAG_LINES; break;
		case 'm': which |= FLAG_RUNES; break;
		case 'w': which |= FLAG_WORDS; break;
		case '?': buf_str(berr, "wc: invalid option: -");
		          buf_rune(berr, (wchar_t)wgo.optopt);
		          buf_rune(berr, '\n');
		          usage(berr);
		          return 1;
		}
	}
	nargs = argc - wgo.optind;
	which = which ? which : FLAG_LINES|FLAG_WORDS|FLAG_BYTES;

	if (nargs == 0) {
		h = GetStdHandle(STD_INPUT_HANDLE);
		if (!process(h, &counts)) {
			werror(L"<standard input>", berr);
			return 1;
		}
		print(&counts, 0, which, bout);

	} else {
		HANDLE h;
		for (i = wgo.optind; i < argc; i++) {
			h = CreateFileW(
				argv[i],
				GENERIC_READ,
				FILE_SHARE_READ|FILE_SHARE_DELETE,
				0,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				0
			);
			if (h == INVALID_HANDLE_VALUE) {
				werror(argv[i], berr);
				return 1;
			}
			process(h, &counts);
			CloseHandle(h);

			print(&counts, argv[i], which, bout);
			add(&total, &counts);
		}

		if (nargs > 1) {
			print(&total, L"total", which, bout);
		}
	}

	buf_flush(bout);
	if (buf_error(bout)) {
		werror(L"<standard output>", berr);
		return 1;
	}
	return 0;
}
