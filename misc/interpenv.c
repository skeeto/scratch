#include <string.h>

// Interpolate environment variables from the source string into the
// destination. Returns the length including null terinator, or zero if
// the destination is too short. Undefined variables are treated as
// empty, and $$ produces a single $. A variable is composed of the
// character set [0-9A-Z_a-z].
size_t interpenv(char *dst, size_t len, char *src, char **env)
{
    if (!len) {
        return 0;
    }

    char *c = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";
    char *d = dst;
    char *e = dst + len - 1;  // reserve byte for terminator
    while (*src) {
        if (*src == '$') {
            size_t varlen = strspn(++src, c);
            if (!varlen) {
                if (e == d) {
                    return 0;
                }
                src += *src == '$';  // "$$" => "$"
                *d++ = '$';
            } else {
                for (char **k = env; *k; k++) {
                    char *ke = strchr(*k, '=');
                    size_t kn = ke ? ke-*k : 0;
                    if (kn==varlen && !memcmp(*k, src, kn)) {
                        size_t vn = strlen(ke+1);
                        if (vn > (size_t)(e - d)) {
                            return 0;
                        }
                        memcpy(d, ke+1, vn);
                        d += vn;
                        break;
                    }
                }
                src += varlen;
            }
        }

        // Skip to text variable, or the end
        size_t clen = strcspn(src, "$");
        if (clen > (size_t)(e - d)) {
            return 0;
        }
        memcpy(d, src, clen);
        d += clen;
        src += clen;
    }
    *d++ = 0;
    return d - dst;
}


#if TEST
#include <stdio.h>

int main(int argc, char **argv, char **env)
{
    char buf[256];
    for (int i = 1; i < argc; i++) {
        size_t len = interpenv(buf, sizeof(buf), argv[i], env);
        if (len) {
            buf[len-1] = '\n';
            fwrite(buf, len, 1, stdout);
        }
    }
}
#endif
