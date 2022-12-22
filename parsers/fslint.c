// Minimalistic Python f-string linter
//
// Warns about plain strings containing f-string fields, and f-strings that
// do not contain replacement fields.
//
//   $ cc -O3 -o fslint fslint.c
//   $ ./fslint main.py example.py
//
// Heuristic: An f-string field is a bracket pair not containing brackets.
//
// Known bugs: Does not recognize situations where the format method is
// immediately invoked. Does not understand triple-quoted f-strings.
//
// This is free and unencumbered software released into the public domain.
#include <stdio.h>

static int
warning(char *name, long lineno, int fstring, int match)
{
    if (!fstring && match) {
        printf("%s:%ld: plain string has f-string field\n", name, lineno);
        return 1;
    } else if (fstring && !match) {
        printf("%s:%ld: f-string has no replacement fields\n", name, lineno);
        return 1;
    }
    return 0;
}

static long
process(FILE *f, char *name)
{
    int state = 0;
    long max = 0;
    long depth = 0;
    long lineno = 1;
    long issues = 0;

    for (;;) {
        int c = fgetc(f);
        if (c == EOF) {
            break;
        }
        lineno += c == '\n';
        //printf("%c %d\n",c>' '?c:' ',state);

        switch (state) {
        case  0: switch (c) {  // between tokens
                 case 'F' :
                 case 'f' : state =  1; break;
                 case '\'': state =  2; break;
                 case '"' : state =  3; break;
                 case '\t':
                 case '\n':
                 case '\r':
                 case ' ' :
                 case '%' :
                 case '&' :
                 case '(' :
                 case ')' :
                 case '*' :
                 case '+' :
                 case '-' :
                 case '/' :
                 case ':' :
                 case '<' :
                 case '=' :
                 case '>' :
                 case '[' :
                 case ']' :
                 case '^' :
                 case '~' : break;
                 case '#' : state = 11; break;
                 default  : state = 10;
                 } break;
        case  1: switch (c) {  // start f-string?
                 case '\'': state =  4; break;
                 case '"' : state =  5; break;
                 default  : state =  0;
                 } break;
        case  2:
        case  3:
        case  4:
        case  5: switch (c) {  // inside a string
                 case '{' : max = ++depth > max ? depth : max; break;
                 case '}' : depth = depth ? depth-1 : 0; break;
                 case '\\': state += 4; break;
                 case '\'': if (  state&1 ) continue;
                            state |= 1;  // fallthrough
                 case '"' : if (!(state&1)) continue;
                            int fstring = state >= 4;
                            int match = !depth && max == 1;
                            issues += warning(name, lineno, fstring, match);
                            state = max = depth = 0;
                 } break;
        case  6:
        case  7:
        case  8:
        case  9: state -= 4; break;  // string backslash
        case 10: switch (c) {  // inside a token
                 case '\'': state =  2; break;
                 case '"' : state =  3; break;
                 case '#' : state = 11; break;
                 case '\t':
                 case '\n':
                 case '\r':
                 case ' ' :
                 case '%' :
                 case '&' :
                 case '(' :
                 case ')' :
                 case '*' :
                 case '+' :
                 case '-' :
                 case '/' :
                 case ':' :
                 case '<' :
                 case '=' :
                 case '>' :
                 case '[' :
                 case ']' :
                 case '^' :
                 case '~' : state = 0;
        } break;
        case 11: state = c == '\n' ? 0 : state;  // comment
        }
    }

    return issues;
}

int
main(int argc, char **argv)
{
    long total = 0;

    for (int i = 1; i < argc; i++) {
        char *name = argv[i];

        FILE *f = fopen(name, "rb");
        if (!f) {
            fprintf(stderr, "fslint: could not open %s\n", name);
            return 1;
        }

        total += process(f, name);
        if (ferror(stdin)) {
            fprintf(stderr, "fslint: error reading %s\n", name);
            return 1;
        }
        fclose(f);
    }

    fflush(stdout);
    if (ferror(stdout)) {
        fprintf(stdout, "fslint: output error\n");
        return 1;
    }
    return !!total;
}
