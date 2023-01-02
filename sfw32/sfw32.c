/* Starflight Code Wheel
 * Like Pat Shearon's code wheel, but more portable and no .NET.
 * This is free and unencumbered software released into the public domain.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>

#ifdef _MSC_VER
  #pragma comment(lib, "kernel32.lib")
  #pragma comment(lib, "user32.lib")
  #pragma comment(lib, "gdi32.lib")
  #pragma comment(lib, "comctl32.lib")
  #pragma comment(linker, "/subsystem:windows")
#endif

static const char planets[] = "Arth\0" "Thoss/Eleran\0" "Harrison's Base\0"
"Sphexi\0" "Spewta\0" "Earth\0" "Mardan 2\0" "New Scotland\0" "Koann 3\0"
"Heaven\0" "Uhlek Brain World\0" "Gaal\0" "Akteron\0" "Nirvana\0"
"The Staff\0" "The Cross\0" "Pythagoras\0" "The 4 Seedlings\0" "The Axe\0"
"City of the Ancients\0" "Mars\0" "Crystal Planet\0" "Elan\0" "Votiputox";
static const unsigned char planets_lens[] = {
    5,13,16,7,7,6,9,13,8,7,18,5,8,8,10,10,11,16,8,21,5,15,5,10
};

static const char artifacts[] = "Dodecahedron\0" "Black Box\0"
"Mobius Device\0" "Crystal Orb\0" "Frightning Aparatus\0" "Rod Device\0"
"Red Cylinder\0" "Rubber Widget\0" "Throbbing Mass\0" "Suprising Utensil\0"
"Wee Green Blobbie\0" "Tesseract\0" "Whining Orb\0" "Bladed Toy\0"
"Nice Thing\0" "Ellipsoid\0" "Humming Gizzy\0" "Glowing Disk\0" "Black Egg\0"
"Amazing Artifact\0" "Shimmering Ball\0" "Flat Device\0" "Blue Bauble\0"
"Crystal Cone";
static unsigned char artifacts_lens[] = {
    13,10,14,12,20,11,13,14,15,18,18,10,12,11,11,10,14,13,10,17,16,12,12,13
};

static char const races[] = "Velox\0" "Thrynn\0" "Elowan\0" "Mechans\0"
"Spemin\0" "Gazurtoid\0" "Uhlek\0" "Minsterls\0" "Mysterion";
static unsigned char races_lens[] = {6, 7, 7, 8, 7, 10, 6, 10, 10};

static const long codes[] = {
    877443, 336818, 944682, 536992, 100139, 259789,
    298483, 556684, 600601, 334143, 532485, 153669,
    810980, 924289, 100022, 922505, 876180, 250241,
    975718, 776513, 100232, 153078, 444465, 157773,

    100119, 743593, 981215, 555412, 133909, 218651,
    726134, 100175, 347633, 307434, 632874, 404795,
    602834, 256564, 873662, 100052, 100084, 537286,
    313212, 100192, 228865, 137421, 382451, 850672,

    780433, 991615, 562162, 864256, 875009, 100151,
    100163, 701897, 877210, 483347, 210444, 100253,
    100277, 902494, 889321, 461700, 987316, 758635,
    124102, 298209, 462801, 834006, 800894, 270444,

    10174,  90610,  51932,  72507,  12957,  79279,
    33548,  10230,  10246,  64296,  96244,  15218,
    83396,  22943,  77617,  10721,  90880,  76792,
    10209,  69498,  86116,  76948,  17127,  69977,

    10180,  70354,  62683,  74048,  10200,  67312,
    84209,  97117,  48934,  69521,  84584,  35793,
    59456,  73911,  92052,  89933,  17820,  97060,
    18811,  10253,  87657,  88006,  10072,  71518,

    93385,  10190,  66682,  90020,  75292,  18200,
    76235,  40944,  10260,  60319,  42226,  62817,
    46570,  87734,  90218,  49417,  23968,  15713,
    16670,  65214,  31791,  10036,  10080,  22713,

    47038,  36602,  62394,  10210,  45830,  95267,
    10240,  93144,  19173,  21033,  90742,  22917,
    62237,  32177,  77027,  89337,  56213,  21556,
    90360,  84565,  76623,  10046,  71490,  26100,

    7754,   9291,   6532,   8073,   7160,   3793,
    5647,   7503,   2300,   4160,   1110,   3895,
    6375,   8550,   8885,   3082,   7412,   7139,
    2877,   3836,   9095,   5146,   5190,   1245,

    9303,   3165,   1941,   5324,   4104,   9026,
    9038,   6596,   5691,   2946,   9413,   1760,
    1170,   1810,   5522,   1868,   8347,   7767,
    8110,   1701,   3583,   6081,   6739,   3101,
};

static HWND planet, artifact, race, output;

static long lookup(void)
{
    int p, a, r;
    p = SendMessage(planet, CB_GETCURSEL, 0, 0);
    a = SendMessage(artifact, CB_GETCURSEL, 0, 0);
    r = SendMessage(race, CB_GETCURSEL, 0, 0);
    return codes[24*r+(24+p-a)%24];
}

static void populate(void)
{
    long x;
    char code[16], *p = code + sizeof(code);
    *--p = 0;
    for (x = lookup(); x; x /= 10) {
        *--p = '0' + x%10;
    }
    *--p = ':'; *--p = 'e'; *--p = 'd'; *--p = 'o'; *--p = 'C';
    SetWindowText(output, p);
    ShowWindow(output, SW_HIDE);
    ShowWindow(output, SW_SHOW);
}

static LRESULT CALLBACK proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg) {
    case WM_COMMAND:
        populate();
        return 0;

    case WM_CTLCOLORSTATIC:
        SetTextColor((HDC)wparam, (HWND)lparam==output?255:0);
        SetBkMode((HDC)wparam, TRANSPARENT);
        return (LRESULT)GetStockObject(NULL_BRUSH);

    case WM_CLOSE:
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wparam, lparam);
}

int WinMainCRTStartup(void)
{
    MSG msg;
    HWND hwnd;
    HFONT font;
    int i, off;
    WNDCLASSA wndclass = {0};

    InitCommonControls();

    wndclass.lpfnWndProc = proc;
    wndclass.lpszClassName = "sfcw";
    wndclass.hbrBackground = (HBRUSH)COLOR_WINDOW;
    wndclass.hIcon = LoadIcon(GetModuleHandle(0), MAKEINTRESOURCE(1));
    RegisterClassA(&wndclass);

    hwnd = CreateWindowA(
        "sfcw", "Starflight Code Wheel",
        WS_OVERLAPPED|WS_MINIMIZEBOX|WS_VISIBLE|WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 120, 0, 0, 0, 0
    );

    CreateWindow(
        "static", "Planet", WS_CHILD|WS_VISIBLE,
        7, 7, 150, 20, hwnd, 0, 0, 0
    );
    CreateWindow(
        "static", "Artifact", WS_CHILD|WS_VISIBLE,
        184, 7, 150, 20, hwnd, 0, 0, 0
    );
    CreateWindow(
        "static", "Race", WS_CHILD|WS_VISIBLE,
        361, 7, 100, 20, hwnd, 0, 0, 0
    );
    output = CreateWindow(
        "static", "Code:", WS_CHILD|WS_VISIBLE,
        7, 60, 400, 30, hwnd, 0, 0, 0
    );
    font = CreateFontA(
        20, 0, 0, 0, FW_BOLD, 0, 0, 0, ANSI_CHARSET,
        OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
        FF_DONTCARE, "Tahoma"
    );
    SendMessageA(output, WM_SETFONT, (WPARAM)font, 1);

    planet = CreateWindow(
        WC_COMBOBOX, "Planet",
        CBS_DROPDOWNLIST|CBS_HASSTRINGS|WS_TABSTOP|WS_CHILD|WS_VISIBLE,
        7, 25, 168, 1<<10, hwnd, 0, 0, 0
    );
    for (i=0, off=0; i < 24; off += planets_lens[i++]) {
        SendMessageA(planet, CB_ADDSTRING, 0, (LPARAM)(planets+off));
    }
    SendMessage(planet, CB_SETCURSEL, 0, 0);

    artifact = CreateWindow(
        WC_COMBOBOX, "Artifact",
        CBS_DROPDOWNLIST|CBS_HASSTRINGS|WS_TABSTOP|WS_CHILD|WS_VISIBLE,
        184, 25, 168, 1<<10, hwnd, 0, 0, 0
    );
    for (i=0, off=0; i < 24; off += artifacts_lens[i++]) {
        SendMessageA(artifact, CB_ADDSTRING, 0, (LPARAM)(artifacts+off));
    }
    SendMessage(artifact, CB_SETCURSEL, 0, 0);

    race = CreateWindow(
        WC_COMBOBOX, "Race",
        CBS_DROPDOWNLIST|CBS_HASSTRINGS|WS_TABSTOP|WS_CHILD|WS_VISIBLE,
        361, 25, 118, 1<<10, hwnd, 0, 0, 0
    );
    for (i=0, off=0; i < 9; off += races_lens[i++]) {
        SendMessageA(race, CB_ADDSTRING, 0, (LPARAM)(races+off));
    }
    SendMessage(race, CB_SETCURSEL, 0, 0);

    populate();

    while (GetMessageA(&msg, 0, 0, 0)) {
        if (msg.message == WM_QUIT) {
            break;
        }
        if (!IsDialogMessage(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
    return TerminateProcess(GetCurrentProcess(), 0);
    return 0;
}
