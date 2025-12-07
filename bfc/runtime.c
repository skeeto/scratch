#define W32 [[gnu::dllimport]]
W32 void  ExitProcess(int);
W32 void *GetStdHandle(int);
W32 int   ReadFile(void *, void *, int, int *, void *);
W32 int   WriteFile(void *, void *, int, int *, void *);

typedef struct {
    void *input;
    void *output;
    int   error;
} Context;

void bf_entry(unsigned char *, Context *ctx);

void bf_putchar(unsigned char *p, Context *ctx)
{
    ctx->error |= !WriteFile(ctx->output, p, 1, &(int){}, 0);
}

void bf_getchar(unsigned char *p, Context *ctx)
{
    *p = 0;  // zero on error/EOF
    ctx->error |= !ReadFile(ctx->input, p, 1, &(int){}, 0);
}

void mainCRTStartup()
{
    static unsigned char mem[30'000];
    Context ctx = {GetStdHandle(-10), GetStdHandle(-11), 0};
    bf_entry(mem, &ctx);
    ExitProcess(ctx.error);
}
