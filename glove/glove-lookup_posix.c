#include "glove-lookup.c"
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static b32 fullwrite(u8 *buf, i32 len)
{
    for (i32 off = 0; off < len;) {
        i32 r = (i32)write(1, buf+off, len-off);
        if (r < 1) {
            return 0;
        }
        off += r;
    }
    return 1;
}

int main(int argc, char **argv)
{
    struct stat sb;
    if (fstat(0, &sb)) {
        return 1;
    }
    size len = sb.st_size;

    void *db = mmap(0, len, PROT_READ, MAP_PRIVATE, 0, 0);
    if (db == MAP_FAILED) {
        return 1;
    }

    size cap = 1<<20;
    arena scratch = {0};
    scratch.beg = mmap(0, cap, PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    scratch.end = scratch.beg + cap;

    s8 *args = new(&scratch, s8, argc);
    for (int i = 0; i < argc; i++) {
        args[i] = s8cstr(argv[i]);
    }
    return run(argc, args, db, scratch);
}
