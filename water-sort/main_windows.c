#include "water-sort.c"

#if _MSC_VER  // make the command a littler simpler
#  pragma comment(linker, "/subsystem:windows")
#  pragma comment(lib, "gdi32.lib")
#  pragma comment(lib, "kernel32.lib")
#  pragma comment(lib, "libvcruntime.lib")
#  pragma comment(lib, "user32.lib")
#endif

#ifndef _WIN64
#  define GetWindowLongPtrA GetWindowLongA
#  define SetWindowLongPtrA SetWindowLongA
#endif

enum {
    CS_OWNDC            = 0x0020,
    GWLP_USERDATA       = -21,
    IDC_ARROW           = 0x7f00,
    MEM_COMMIT          = 0x1000,
    MEM_RESERVE         = 0x2000,
    PAGE_READWRITE      = 4,
    SRCCOPY             = 0xcc0020,
    VK_LEFT             = 0x25,
    VK_RIGHT            = 0x27,
    WAIT_TIMEOUT        = 258,
    WM_CLOSE            = 0x0010,
    WM_CREATE           = 0x0001,
    WM_KEYDOWN          = 0x0100,
    WM_LBUTTONDOWN      = 0x0201,
    WM_MBUTTONDOWN      = 0x0207,
    WM_MOUSEMOVE        = 0x0200,
    WM_PAINT            = 0x000f,
    WM_QUIT             = 0x0012,
    WM_RBUTTONDOWN      = 0x0204,
    WM_SIZE             = 0x0005,
    WS_MINIMIZEBOX      = 0x00020000,
    WS_SYSMENU          = 0x00080000,
    WS_THICKFRAME       = 0x00040000,
    WS_VISIBLE          = 0x10000000,
};

typedef struct {
    i32 style;
    uz  proc;
    i32 extra[2];
    uz  instance;
    uz  icon;
    uz  cursor;
    uz  background;
    u8 *menuname;
    u8 *classname;
} WndClass;

typedef struct {
    uz  hwnd;
    i32 msg;
    uz  wp;
    uz  lp;
    i32 time;
    i32 x, y;
} Msg;

typedef struct {
    uz hc;
    i32 erase;
    i32 x, y, w, h;
    b32 restore;
    b32 incupdate;
    u8  _[32];
} Paint;

#define W32(r) __declspec(dllimport) r __stdcall
W32(b32)    BitBlt(uz, i32, i32, i32, i32, uz, i32, i32, i32);
W32(b32)    DeleteDC(uz);
W32(b32)    DeleteObject(uz);
W32(b32)    EndPaint(uz, Paint *);
W32(b32)    GetClientRect(uz, i32 *);
W32(b32)    GetCursorPos(i32 *);
W32(b32)    GetMessageA(Msg *, uz, i32, i32);
W32(b32)    InvalidateRect(uz, i32 *, b32);
W32(b32)    QueryPerformanceCounter(i64 *);
W32(b32)    QueryPerformanceFrequency(i64 *);
W32(b32)    ScreenToClient(uz, i32 *);
W32(b32)    SetWindowTextA(uz, u8 *);
W32(b32)    TranslateMessage(Msg *);
W32(i16)    RegisterClassA(WndClass *);
W32(i32)    FillRect(uz, i32 *, uz);
W32(i32)    FrameRect(uz, i32 *, uz);
W32(i32)    GetSystemMetrics(i32);
W32(i32)    MsgWaitForMultipleObjects(i32, uz *, b32, i32, i32);
W32(uz)     BeginPaint(uz, Paint *);
W32(uz)     CreateCompatibleBitmap(uz, i32, i32);
W32(uz)     CreateCompatibleDC(uz);
W32(uz)     CreateSolidBrush(i32);
W32(uz)     CreateWindowExA(i32,u8*,u8*,i32,i32,i32,i32,i32,uz,uz,uz,void*);
W32(uz)     DefWindowProcA(uz, i32, uz, uz);
W32(uz)     DispatchMessageA(Msg *);
W32(uz)     LoadCursorA(uz, i32);
W32(uz)     SelectObject(uz, uz);
W32(uz)     SetWindowLongPtrA(uz, i32, void *);
W32(void *) GetWindowLongPtrA(uz, i32);
W32(void)   ExitProcess(i32);
W32(void)   PostQuitMessage(i32);
W32(void*)  VirtualAlloc(uz, iz, i32, i32);

static void paint(uz wnd, Game *game, Arena scratch)
{
    i32 rect[4];
    GetClientRect(wnd, rect);
    i32 w = game->ui.width  = rect[2] - rect[0];
    i32 h = game->ui.height = rect[3] - rect[1];
    DrawList *dl = renderui(top(game), game->nbottle, &game->ui, &scratch);

    Paint ps = {0};
    uz dc    = BeginPaint(wnd, &ps);
    uz mem   = CreateCompatibleDC(dc);
    uz bmp   = CreateCompatibleBitmap(dc, w, h);
    uz old   = SelectObject(mem, bmp);

    for (i32 i = 0; i < dl->len; i++) {
        i32 rect[] = {
            dl->ops[i].x,  dl->ops[i].y,
            dl->ops[i].x + dl->ops[i].w,
            dl->ops[i].y + dl->ops[i].h,
        };
        i32 color = dl->ops[i].color;
        u8 r = (u8)(color >> 16);
        u8 g = (u8)(color >>  8);
        u8 b = (u8)(color >>  0);
        uz brush = CreateSolidBrush(r|g<<8|b<<16);
        switch (dl->ops[i].mode) {
        case DRAW_FILL:
            FillRect(mem, rect, brush);
            break;
        case DRAW_BOX:
            FrameRect(mem, rect, brush);
            break;
        }
        DeleteObject(brush);
    }

    BitBlt(dc, 0, 0, w, h, mem, 0, 0, SRCCOPY);
    SelectObject(mem, old);
    DeleteDC(mem);
    DeleteObject(bmp);
    EndPaint(wnd, &ps);
}

typedef struct {
    i64   now;
    Game  game;
    Arena perm;
    i32   seed;
    b32   dirty;
} Win32Context;

static i32 seeds[] = {
    #include "seeds.txt"
};

static void init(uz wnd, Win32Context *ctx)
{
    i32 n = ctx->seed + 1;
    u8  title[32] = "Water Puzzle #";
    u8 *beg = title + 15 + (n>9) + (n>99) + (n>999) + (n>9999);
    do *--beg = '0' + (u8)(n%10);
    while (n /= 10);
    SetWindowTextA(wnd, title);

    ctx->game = (Game){0};
    ctx->game.nbottle   = MAXBOTTLE;
    ctx->game.ui.select = -1;
    ctx->game.puzzle    = genpuzzle(seeds[ctx->seed], ctx->game.nbottle);
    push(&ctx->game, ctx->game.puzzle);
}

static uz __stdcall wndproc(uz wnd, i32 msg, uz wp, uz lp)
{
    Win32Context *ctx = GetWindowLongPtrA(wnd, GWLP_USERDATA);
    switch (msg) {
        i32 pos[2];

    case WM_CREATE:
        ctx = *(Win32Context **)lp;
        SetWindowLongPtrA(wnd, GWLP_USERDATA, ctx);
        init(wnd, ctx);
        return 0;

    case WM_PAINT:
        paint(wnd, &ctx->game, ctx->perm);
        return 0;

    case WM_SIZE:
        InvalidateRect(wnd, 0, 0);
        return 0;

    case WM_CLOSE:
        PostQuitMessage(0);
        return 0;

    case WM_MOUSEMOVE:
        GetCursorPos(pos);
        ScreenToClient(wnd, pos);
        ctx->game.ui.mousex = pos[0];
        ctx->game.ui.mousey = pos[1];
        break;

    case WM_LBUTTONDOWN:
        GetCursorPos(pos);
        ScreenToClient(wnd, pos);
        ctx->game.ui.mousex = pos[0];
        ctx->game.ui.mousey = pos[1];
        ctx->game.input     = INPUT_CLICK;
        update(&ctx->game, ctx->now, ctx->perm);
        ctx->dirty = 1;
        break;

    case WM_MBUTTONDOWN:
        ctx->game.input = INPUT_HINT;
        update(&ctx->game, ctx->now, ctx->perm);
        ctx->dirty = 1;
        break;

    case WM_RBUTTONDOWN:
        ctx->game.input = INPUT_UNDO;
        update(&ctx->game, ctx->now, ctx->perm);
        ctx->dirty = 1;
        break;

    case WM_KEYDOWN:
        if (lp & 0x40000000) break;
        i32 nseeds = lenof(seeds);
        switch (wp) {
        case VK_LEFT:
            ctx->seed = (ctx->seed + nseeds - 1) % nseeds;
            init(wnd, ctx);
            break;
        case VK_RIGHT:
            ctx->seed = (ctx->seed +          1) % nseeds;
            init(wnd, ctx);
            break;
        case 'H':
            ctx->game.input = INPUT_HINT;
            update(&ctx->game, ctx->now, ctx->perm);
            break;
        case 'Q':
            PostQuitMessage(0);
            break;
        case 'R':
            ctx->game.input = INPUT_RESET;
            update(&ctx->game, ctx->now, ctx->perm);
            break;
        case 'U':
            ctx->game.input = INPUT_UNDO;
            update(&ctx->game, ctx->now, ctx->perm);
            break;
        }
        ctx->dirty = 1;
        break;
    }
    return DefWindowProcA(wnd, msg, wp, lp);
}

void __stdcall WinMainCRTStartup(void)
{
    i32   cap = SOLVE_MEM;
    char *mem = VirtualAlloc(0, cap, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    Arena tmp = {mem, mem+cap};

    Win32Context *ctx = new(&tmp, 1, Win32Context);
    ctx->perm = tmp;

    i32 width   = 800;
    i32 height  = 800;
    u8  class[] = "w";
    u8  title[] = "Water Sort";
    i32 x       = GetSystemMetrics(0)/2 - width/2;
    i32 y       = GetSystemMetrics(1)/2 - height/2;
    i32 style   = WS_MINIMIZEBOX | WS_THICKFRAME | WS_SYSMENU | WS_VISIBLE;

    WndClass wc  = {0};
    wc.style     = CS_OWNDC,
    wc.proc      = (uz)wndproc;
    wc.classname = class;
    wc.cursor    = LoadCursorA(0, IDC_ARROW);
    RegisterClassA(&wc);
    uz wnd = CreateWindowExA(
        0, class, title, style, x, y, width, height, 0, 0, 0, ctx
    );

    i64 freq;
    QueryPerformanceFrequency(&freq);
    freq /= 1000;

    for (i64 last = 0;;) {
        QueryPerformanceCounter(&ctx->now);
        ctx->now /= freq;
        ctx->dirty = ctx->now > last+30;

        if (MsgWaitForMultipleObjects(0, 0, 0, 30, -1) != WAIT_TIMEOUT) {
            Msg m;
            GetMessageA(&m, 0, 0, 0);
            switch (m.msg) {
            case WM_QUIT: {
                ExitProcess(0);
            } break;
            }
            TranslateMessage(&m);
            DispatchMessageA(&m);
        }

        if (ctx->dirty) {
            ctx->game.input = INPUT_NONE;
            update(&ctx->game, ctx->now, ctx->perm);
            InvalidateRect(wnd, 0, 0);
            last = ctx->now;
        }
    }
}
