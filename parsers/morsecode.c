/* Morse code decoder automaton
 * This is free and unencumbered software released into the public domain.
 */

/* Advance to the next state for an input, '.', '-'. or 0 (terminal).
 * The initial state is zero. Returns the next state, or the result:
 *   < 0 when more input is needed (i.e. next state)
 *   = 0 for invalid input
 *   > 0 the ASCII result
 */
int
morse_decode(int state, int c)
{
    //complete binary tree in level order
    //invalid nodes contain the NUL character
    static const unsigned char t[] =
        "\0"
        "ET"
        "IANM"
        "SURWDKGO"
        "HVF\0L\0PJBXCYZQ\0\0"
        //beware: "\03" is the same as "\3" (octal)!
        "54\0" "3\0\0\0" "2\0\0\0\0\0\0\0" "16\0\0\0\0\0\0\0" "7\0\0\08\090";
    switch (c) {
    case 0x00: return t[-state];
    case 0x2e:
    case 0x2d:
        //c - 0x2f == -1 when c==0x2e, -2 when c==0x2d
        return state*2 + c - 0x2f > -63 ? state*2 + c - 0x2f : 0;
    default: return 0;
    }
}


#ifdef TEST
#include <stdio.h>
#include <string.h>

#define CR(s) "\x1b[91;1m" s "\x1b[0m"
#define CG(s) "\x1b[92;1m" s "\x1b[0m"

int
main(void)
{
#ifdef _WIN32
    /* Best effort enable ANSI escape processing. */
    void *GetStdHandle(unsigned);
    int GetConsoleMode(void *, unsigned *);
    int SetConsoleMode(void *, unsigned);
    void *handle;
    unsigned mode;
    handle = GetStdHandle(-11); /* STD_OUTPUT_HANDLE */
    if (GetConsoleMode(handle, &mode)) {
        mode |= 0x0004; /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */
        SetConsoleMode(handle, mode); /* ignore errors */
    }
#endif

    static const struct {
        char input[6];
        char expect;
    } tests[] = {
        {"",       0 }, {".",     'E'}, {"-",     'T'}, {"..",    'I'},
        {".-",    'A'}, {"-.",    'N'}, {"--",    'M'}, {"...",   'S'},
        {"..-",   'U'}, {".-.",   'R'}, {".--",   'W'}, {"-..",   'D'},
        {"-.-",   'K'}, {"--.",   'G'}, {"---",   'O'}, {"....",  'H'},
        {"...-",  'V'}, {"..-.",  'F'}, {"..--",   0 }, {".-..",  'L'},
        {".-.-",   0 }, {".--.",  'P'}, {".---",  'J'}, {"-...",  'B'},
        {"-..-",  'X'}, {"-.-.",  'C'}, {"-.--",  'Y'}, {"--..",  'Z'},
        {"--.-",  'Q'}, {"---.",   0 }, {"----",   0 }, {".....", '5'},
        {"....-", '4'}, {"...-.",  0 }, {"...--", '3'}, {"..-..",  0 },
        {"..-.-",  0 }, {"..--.",  0 }, {"..---", '2'}, {".-...",  0 },
        {".-..-",  0 }, {".-.-.",  0 }, {".-.--",  0 }, {".--..",  0 },
        {".--.-",  0 }, {".---.",  0 }, {".----", '1'}, {"-....", '6'},
        {"-...-",  0 }, {"-..-.",  0 }, {"-..--",  0 }, {"-.-..",  0 },
        {"-.-.-",  0 }, {"-.--.",  0 }, {"-.---",  0 }, {"--...", '7'},
        {"--..-",  0 }, {"--.-.",  0 }, {"--.--",  0 }, {"---..", '8'},
        {"---.-",  0 }, {"----.", '9'}, {"-----", '0'},
        {"x", 0},
    };

    int fails = 0;
    int n, ntests = sizeof(tests) / sizeof(*tests);

    for (n = 0; n < ntests; n++) {
        const char *s = tests[n].input;
        int expect = tests[n].expect;
        int pass = 1;
        int state = 0;

        while (*s) {
            state = morse_decode(state, *s++);

            if (!state) {
                if (expect) {
                    printf(CR("FAIL") ": %s, want %c, got early error\n",
                           tests[n].input, expect);
                    pass = 0;
                }
                break;
            }

            if (state > 0) {
                printf(CR("FAIL") ": %s, want %c, got early 0x%02x\n",
                        tests[n].input, expect, state);
                pass = 0;
                break;
            }
        }

        if (state < 0) {
            state = morse_decode(state, 0);

            if (!state) {
                if (expect) {
                    printf(CR("FAIL") ": %s, want %c, got error\n",
                            tests[n].input, expect);
                    pass = 0;
                }
            } else if (state < 0) {
                printf(CR("FAIL") ": %s, want %c, got continuation\n",
                        tests[n].input, expect);
                pass = 0;
            } else if (state != expect) {
                if (expect) {
                    printf(CR("FAIL") ": %s, want %c, got 0x%02x\n",
                            tests[n].input, expect, state);
                } else {
                    printf(CR("FAIL") ": %s, want error, got 0x%02x (%c)\n",
                            tests[n].input, state, state);
                }
                pass = 0;
            }
        }

        if (pass) {
            if (expect) {
                printf(CG("PASS") ": %c %s\n", expect, tests[n].input);
            } else {
                printf(CG("PASS") ": ? %s\n", tests[n].input);
            }
        }

        fails += !pass;
    }

    // Test rejecting bad input "......"
    ntests++;
    for (int state = 0, count = 1;; count++) {
        state = morse_decode(state, '.');
        if (count<6 && state>=0) {
            printf(CR("FAIL") ": %.*s, got %d, want < 0\n",
                   count, "......", state);
            fails++;
            break;
        } else if (count==6 && !state) {
            printf(CG("PASS") ": ......\n");
            break;
        } else if (count==6 && state){
            printf(CR("FAIL") ": ......, got %d, want 0\n", state);
            fails++;
            break;
        }
    }

    // Test rejecting bad prefix ".-.-"
    ntests++;
    char *prefix=".-.-", *p=prefix;
    for (int state = 0, count = 0; *p; count++) {
        state = morse_decode(state, *p);
        p++;
        if (*p && state >= 0) {
            printf(CR("FAIL") ": %.*s, got %d, want < 0\n",
                   count, prefix, state);
            fails++;
            break;
        } else if (!*p && state == 0) {
            printf(CG("PASS") ": %s\n", prefix);
        } else if (!*p && state < 0) {
            printf(CR("FAIL") ": %s, got %d, want 0\n", prefix, state);
            fails++;
        }
    }

    if (!fails) {
        printf("All %d tests pass\n", ntests);
    }

    return !!fails;
}
#endif
