#include "glove.c"
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    struct stat sb;
    if (fstat(0, &sb)) {
        return 1;
    }
    size len = sb.st_size;

    void *data = mmap(0, len, PROT_READ, MAP_PRIVATE, 0, 0);
    if (data == MAP_FAILED) {
        return 1;
    }

    glove_specs s;
    glove_examine(&s, data, len);

    byte *db = mmap(0, s.db_size, PROT_WRITE, MAP_PRIVATE|MAP_ANON, 1, 0);
    if (db == MAP_FAILED) {
        return 1;
    }
    glove_make_db(db, &s, data, len);

    for (size off = 0; off < s.db_size;) {
        size r = write(1, db+off, s.db_size-off);
        if (r < 1) {
            return 1;
        }
        off += r;
    }
    return 0;
}
