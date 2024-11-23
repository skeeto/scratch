enum { HEAPCAP = 1<<30 };
#include "common.cpp"

static s8 loadfile(c16 *path, Arena *a)
{
    i32 share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    uz h = CreateFileW(
        path, GENERIC_READ, share, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    );
    if (h == uz(-1)) {
        return {};
    }

    s8 r = {};
    r.data = a->beg;
    iz avail = a->end - a->beg;
    while (r.len < avail) {
        i32 len = trunc32(avail - r.len);
        if (!ReadFile(h, r.data+r.len, len, &len, 0)) {
            r = {};
            break;
        } else if (!len) {
            break;
        }
        r.len += len;
    }

    CloseHandle(h);
    a->beg += r.len;
    return r;
}

struct File {
    s16 name;
    s8  data;
    i32 nameoff;
    i32 dataoff;
};

struct Out {
    u8 *buf;
    i32 len = 0;
    i32 cap;
    b32 err = 0;
    i32 fd;

    Out() = default;
    Out(Arena *a, i32 fd, i32 cap) : buf{alloc<u8>(a, cap)}, cap{cap}, fd{fd} {}
};

static void flush(Out *b)
{
    if (!b->err && b->len) {
        uz h = GetStdHandle(-10 - b->fd);
        b->err = !WriteFile(h, b->buf, b->len, &b->len, 0);
        b->len = 0;
    }
}

static void write(Out *b, s8 s)
{
    for (iz off = 0; !b->err && off<s.len;) {
        i32 avail = b->cap - b->len;
        i32 count = avail<s.len-off ? avail : i32(s.len-off);
        u8 *dst = b->buf + b->len;
        u8 *src = s.data + off;
        for (iz i = 0; i < count; i++) {
            dst[i] = src[i];
        }
        off += count;
        b->len += count;
        if (b->len == b->cap) {
            flush(b);
        }
    }
}

static void write(Out *b, s16 s)
{
    for (iz i = 0; i < s.len; i++) {
        char const buf[] = {char(s[i]>>0), char(s[i]>>8), 0};
        write(b, s8{buf});
    }
}

static void write(Out *b, i32 x)
{
    char const buf[] = {
        char(x >>  0), char(x >>  8),
        char(x >> 16), char(x >> 24), 0,
    };
    write(b, s8{buf});
}

static i32 run(Arena a)
{
    Out out(&a, 1, 1<<14);
    Out err(&a, 2, 1<<8);

    c16  *cmd  = GetCommandLineW();
    i32   argc = 0;
    c16 **argv = CommandLineToArgvW(cmd, &argc);

    i32   nfiles = argc - 1;
    File *files  = alloc<File>(&a, nfiles);
    c16 **names  = argv + 1;
    for (i32 i = 0; i < nfiles; i++) {
        s16 name = names[i];
        files[i].name = basename(name);
        files[i].data = loadfile(names[i], &a);
        if (!files[i].data.data) {
            write(&err, "could not read file\n");  // TODO: include name
            flush(&err);
            return 1;
        } else if (files[i].data.len > 1<<30) {
            write(&err, "file too large\n");  // TODO: include name
            flush(&err);
            return 1;
        }
    }

    s8  zero = "\0\0\0\0\0\0\0\0\0\0\0\0";
    s16 exe  = LOADER u"\0";
    s16 dir  = dirname(getexepath(&a));
    s16 stub = concat(&a, dir, exe);
    s8  data = loadfile(stub.data, &a);  // TODO: error check
    if (!data.data) {
        write(&err, "could not find loader stub\n");
        flush(&err);
        return 1;
    }
    write(&out, data);
    write(&out, trunc(zero, -data.len&3));  // align

    i32 total = (nfiles + 1)*12;
    for (i32 i = 0; i < nfiles; i++) {
        files[i].nameoff = total;
        total += i32(files[i].name.len * 2);  // TODO: overflow check
    }

    for (i32 i = 0; i < nfiles; i++) {
        files[i].dataoff = total;
        total += i32(files[i].data.len);  // TODO: overflow check
    }

    for (i32 i = 0; i < nfiles; i++) {
        write(&out, files[i].nameoff);
        write(&out, files[i].dataoff);
        write(&out, i32(files[i].data.len));
    }
    write(&out, trunc(zero, 12));

    for (i32 i = 0; i < nfiles; i++) {
        write(&out, files[i].name);
    }
    for (i32 i = 0; i < nfiles; i++) {
        write(&out, files[i].data);
    }

    i32 pad = -total & 3;
    write(&out, trunc(zero, pad));  // align
    write(&out, total+pad+4);  // TODO: overflow check

    flush(&out);  // TODO: display error
    return out.err;
}
