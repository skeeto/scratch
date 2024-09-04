#include <regex>
#include <stddef.h>
#include <stdint.h>

struct str {
    char     *data;
    ptrdiff_t len;
};

struct arena {
    char *beg;
    char *end;
};

struct strlist {
    str      *data;
    ptrdiff_t len;
};


// Allocation

static thread_local arena *perm;

void *operator new(size_t size, std::align_val_t align)
{
    arena    *a     = perm;
    ptrdiff_t ssize = size;
    ptrdiff_t pad   = (uintptr_t)a->end & ((int)align - 1);
    if (ssize < 0 || ssize > a->end - a->beg - pad) {
        throw std::bad_alloc{};
    }
    return a->end -= size + pad;
}

void *operator new(size_t size)
{
    return operator new(
        size,
        std::align_val_t(__STDCPP_DEFAULT_NEW_ALIGNMENT__)
    );
}

void operator delete(void *) noexcept {}
void operator delete(void *, std::align_val_t) noexcept {}

void operator delete(void *p, size_t size) noexcept
{
    arena *a = perm;
    if (a->end == (char *)p) {
        a->end += size;
    }
}


// Implementation

extern "C" std::regex *regex_new(str re, arena *a)
{
    perm = a;
    try {
        return new std::regex(re.data, re.data+re.len);
    } catch (...) {
        return {};
    }
}

extern "C" strlist regex_match(std::regex *re, str s, arena *a)
{
    perm = a;
    try {
        std::cregex_iterator it(s.data, s.data+s.len, *re);
        std::cregex_iterator end;

        strlist r = {};
        r.len  = std::distance(it, end);
        r.data = new str[r.len]();
        for (ptrdiff_t i = 0; it != end; it++, i++) {
            r.data[i].data = s.data + it->position();
            r.data[i].len  = it->length();
        }
        return r;

    } catch (...) {
        return {};
    }
}
