/* Unix "cal" for Windows
 *   $ cc -Os -fno-asynchronous-unwind-tables -mno-stack-arg-probe
 *        -s -nostdlib -Wl,--gc-sections -o cal.exe cal.c -lkernel32
 *   $ cl /Os /GS- cal.c
 *
 * Features:
 * - C89, CRT-free, no C standard library
 * - compiles to a few kB .exe linking only kernel32.dll
 * - supports at least back to Windows XP
 * - locale month and day-of-week names
 * - Unicode for console (wide API) and pipes/files (UTF-8)
 *
 * Assumptions about month and day locale strings:
 * - BMP only: no surrogates, no emoji
 * - no combining characters: one rune per glyph
 * - display width is 1 per rune (possibly wrong for CJK)
 *
 * Win32 calls are only made from functions prefixed "os_".
 *
 * This is free and unencumbered software released into the public domain.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#if defined(_MSC_VER)
#  pragma comment(linker, "/subsystem:console")
#  pragma comment(lib, "kernel32")
#endif

#define BUFMAX (1 << 11)  /* just beyond worst case */

struct locale {
    int year, month;
    wchar_t days[7][2];
    wchar_t months[12][15];
    int len[12];
};

struct arg {
    wchar_t *beg, *end;
};

/* Fetch the month names and day of the week abbreviations for the Win32
 * user locale. Months will be truncated to 15 runes. Days are exactly 2
 * runes in length, space-padded if necessary.
 */
static void
os_initlocale(struct locale *l)
{
    int i, j;
    SYSTEMTIME t;

    GetSystemTime(&t);
    l->year = t.wYear;
    l->month = t.wMonth;

    for (i = 0; i < 12; i++) {
        wchar_t tmp[80];
        int n = GetLocaleInfoW(0x400, 56+i, tmp, 80) - 1;
        l->len[i] = n = n>15 ? 15 : n;
        for (j = 0; j < n; j++) {
            l->months[i][j] = tmp[j];
        }
    }

    for (i = 0; i < 7; i++) {
        wchar_t tmp[9];
        int n = GetLocaleInfoW(0x400, 49+(i+6)%7, tmp, 9) - 1;
        l->days[i][0] = n>0 ? tmp[0] : ' ';
        l->days[i][1] = n>1 ? tmp[1] : ' ';
    }
}

/* Write a Unicode string to standard output (1) or error (2). */
static int
os_write(int fd, const wchar_t *buf, int len)
{
    int i;
    HANDLE h;
    DWORD tmp;
    int ulen = 0;
    char u8[BUFMAX*2];  /* well beyond worst case */

    h = GetStdHandle(fd==1 ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
    if (GetConsoleMode(h, &tmp)) {
        return WriteConsoleW(h, buf, len, &tmp, 0) && (int)tmp == len;
    }

    /* Convert to UTF-8 */
    for (i = 0; i < len; i++) {
        wchar_t r = buf[i];
        if (r < 0x80) {
            u8[ulen++] = r;
        } else if (r < 0x800) {
            u8[ulen++] = 0xc0 | (r >>  6     );
            u8[ulen++] = 0x80 | (r >>  0 & 63);
        } else {
            u8[ulen++] = 0xe0 | (r >> 12     );
            u8[ulen++] = 0x80 | (r >>  6 & 63);
            u8[ulen++] = 0x80 | (r >>  0 & 63);
        }
    }
    return WriteFile(h, u8, ulen, &tmp, 0) && (int)tmp == ulen;
}

/* Return the next command line argument given the previous argument.
 * Zero-initialize for the first call. The end is exclusive, and the
 * pointers will be null when no arguments remain.
 */
static struct arg
os_arg(struct arg a)
{
    if (!a.beg) {
        a.end = a.beg = GetCommandLineW();
    } else {
        if (*a.end == '"') {
            a.end++;
        }
        while (*a.end == '\t' || *a.end == ' ') {
            a.end++;
        }
        a.beg = a.end;
    }

    switch (*a.beg) {
    case   0: a.end = a.beg = 0;
              return a;
    case '"': for (a.end = ++a.beg;; a.end++) {
                  switch (*a.end) {
                  case   0:
                  case '"': return a;
                  }
              }
    default : for (;; a.end++) {
                  switch (*a.end) {
                  case    0:
                  case '\t':
                  case  ' ': return a;
                  }
              }
    }
}

/* Return the printed length of a year (1-4). */
static int
yearlen(int year)
{
    return 1 + (year>9) + (year>99) + (year>999);
}

/* Return true if the year is a leap year. */
static int
isleap(int year)
{
    return year<=1752 ? (year%4 == 0)  /* Julian */
        : year%4 == 0 && (year%100 != 0 || year%400 == 0);  /* Gregorian */
}

/* Return the number of days in the year and month (1-12). */
static int
monthdays(int year, int month)
{
    static const unsigned char t[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    return month==2 && isleap(year) ? 29 : t[month-1];
}

/* Return true if date the Gregorian era rather than the Julian era. */
static int
isgregorian(int year, int month, int day)
{
    return year>1752 || (year==1752 && month>9) ||
        (year==1752 && month==9 && day>2);
}

/* Return the day of the week (1-7, Sunday=1) for a year, month (1-12),
 * and day (1-31).
 */
static int
zeller(int year, int month, int day)
{
    int y, c, m, era;
    year -= (month + 21) / 12 % 2;
    y = year % 100;
    c = year / 100 % 100;
    m = 3 + (9+month)%12;
    era = isgregorian(year, month, day) ? c/4-2*c : 5-c;
    return (day + 13*(m+1)/5 + y + y/4 + era + 52*7 + 6)%7 + 1;
}

static wchar_t *
pushchar(wchar_t *buf, wchar_t c)
{
    buf[0] = c;
    return buf + 1;
}

static wchar_t *
pushnewline(wchar_t *buf)
{
    while (buf[-1] == ' ') {
        buf--;  /* trim trailing whitespace */
    }
    buf = pushchar(buf, '\r');
    buf = pushchar(buf, '\n');
    return buf;
}

static wchar_t *
pushspace(wchar_t *buf, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        buf[i] = ' ';
    }
    return buf + len;
}

static wchar_t *
pushstring(wchar_t *buf, wchar_t *s, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        buf[i] = s[i];
    }
    return buf + len;
}

static wchar_t *
pushyear(wchar_t *buf, int year)
{
    wchar_t *p = buf;
    switch (yearlen(year)) {
    case 4: p = pushchar(p, '0' + year / 1000     ); /* fallthrough */
    case 3: p = pushchar(p, '0' + year / 100  % 10); /* fallthrough */
    case 2: p = pushchar(p, '0' + year / 10   % 10); /* fallthrough */
    case 1: p = pushchar(p, '0' + year        % 10);
    }
    return p;
}

static wchar_t *
pushdayline(wchar_t *buf, struct locale *l)
{
    int i;
    for (i = 0; i < 7; i++) {
        buf[i*3+0] = l->days[i][0];
        buf[i*3+1] = l->days[i][1];
        buf[i*3+2] = ' ';
    }
    return buf + 20;
}

static wchar_t *
pushmonthrow(wchar_t *buf, int year, int month, int y)
{
    int x;
    int dow = zeller(year, month, 1) - 1;
    int ndays = monthdays(year, month);
    for (x = 0; x < 7; x++) {
        int i = y*7 + x;
        if (year==1752 && month==9 && i+1-dow>2) {
            i += 11;  /* changeover from Julian to Gregorian */
        }
        if (i < dow || i >= ndays+dow) {
            buf[x*3+0] = buf[x*3+1] = buf[x*3+2] = ' ';
        } else {
            int day = i - dow + 1;
            buf[x*3+0] = day/10 ? day/10+'0' : ' ';
            buf[x*3+1] = day%10 + '0';
            buf[x*3+2] = ' ';
        }
    }
    return buf + 20;
}

/* Render a single month. */
static wchar_t *
pushsingle(wchar_t *buf, int year, int month, struct locale *l)
{
    int y;
    wchar_t *p = buf;
    int ylen = yearlen(year);
    p = pushspace(p, (20 - l->len[month-1] - 1 - ylen) / 2);
    p = pushstring(p, l->months[month-1], l->len[month-1]);
    p = pushchar(p, ' ');
    p = pushyear(p, year);
    p = pushnewline(p);
    p = pushdayline(p, l);
    p = pushnewline(p);
    for (y = 0; y < 6; y++) {
        p = pushmonthrow(p, year, month, y);
        p = pushnewline(p);
    }
    return p;
}

/* Render a full year. */
static wchar_t *
pushmulti(wchar_t *buf, int year, struct locale *l)
{
    int y, my, mx;
    wchar_t *p = buf;

    p = pushspace(p, (64 - yearlen(year)) / 2);
    p = pushyear(p, year);

    for (my = 0; my < 4; my++) {
        p = pushnewline(p);

        for (mx = 0; mx < 3; mx++) {
            int m = my*3 + mx;
            int len = l->len[m];
            int pad = (20 - len) / 2;
            p = pushspace(p, mx?2:0);
            p = pushspace(p, pad);
            p = pushstring(p, l->months[m], len);
            p = pushspace(p, 20 - pad - len);
        }
        p = pushnewline(p);

        p = pushdayline(p, l);
        p = pushspace(p, 2);
        p = pushdayline(p, l);
        p = pushspace(p, 2);
        p = pushdayline(p, l);
        p = pushnewline(p);

        for (y = 0; y < 6; y++) {
            for (mx = 0; mx < 3; mx++) {
                p = pushspace(p, mx?2:0);
                p = pushmonthrow(p, year, 1+my*3+mx, y);
            }
            p = pushnewline(p);
        }
    }
    return p;
}

/* Parse up to a 4-digit integer. Returns -1 for invalid input, 10000
 * for out of range.
 */
static int
parse(struct arg a)
{
    long v = 0;
    if (a.beg == a.end) {
        return -1;
    }
    while (a.beg < a.end) {
        if (*a.beg < '0' || *a.beg > '9') {
            return -1;
        }
        v = v*10 + *a.beg++ - '0';
        if (v > 9999) {
            return 10000;
        }
    }
    return v;
}

static void
usage(void)
{
    static const wchar_t usage[] = L"usage: cal [[1..12] 1..9999]\n";
    os_write(2, usage, sizeof(usage)/2 - 1);
}

int mainCRTStartup(void)
{
    int argc = 0;
    int multi = 0;
    int year, month;
    struct locale l[1];
    struct arg argv[4], a = {0, 0};
    wchar_t *p, buf[BUFMAX];

    /* Split command line string into argc/argv */
    for (a = os_arg(a); a.beg; a = os_arg(a)) {
        if (argc < 4) {
            argv[argc++] = a;
        }
    }

    os_initlocale(l);
    switch (argc) {
    default: usage();
             return 1;
    case  0:
    case  1: year = l->year;
             month = l->month;
             break;
    case  2: multi = 1;
             year = parse(argv[1]);
             break;
    case  3: month = parse(argv[1]);
             year = parse(argv[2]);
    }
    if (year < 1 || year > 9999) {
        usage();
        return 1;
    }

    if (multi) {
        p = pushmulti(buf, year, l);
    } else {
        if (month < 1 || month > 12) {
            usage();
            return 1;
        }
        p = pushsingle(buf, year, month, l);
    }
    return !os_write(1, buf, p-buf);
}
