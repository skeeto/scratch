// Chip's Challenge gamepad-to-keyboard mapper
// The Steam version of the game does not support gamepads, so this
// program maps gamepads onto the default keyboard inputs. Mapping:
//   movement   : D-pad
//   ok/accept  : A
//   cycle      : B
//   drop       : X
//   switch     : Y
//   pause      : start
//   restart    : select
//   prev level : left shoulder
//   next level : right shoulder
//
// Build with w64devkit:
//   $ cc -Os -s -nostdlib -o ccpad ccpad.c -lkernel32 -luser32
// Build with MSVC:
//   C:\>cl /O2 ccpad.c
//
// This is free and unencumbered software released into the public domain.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <xinput.h>

#if defined(_MSC_VER)
#  pragma comment(lib, "kernel32")
#  pragma comment(lib, "user32")
#  pragma comment(linker, "/subsystem:console")
#endif

static const int gamepadmap[-VK_PAD_A+VK_PAD_RTHUMB_DOWNLEFT+1] = {
    [-VK_PAD_A + VK_PAD_A]          = VK_RETURN,
    [-VK_PAD_A + VK_PAD_B]          = 'E',    // cycle
    [-VK_PAD_A + VK_PAD_X]          = 'Q',    // drop
    [-VK_PAD_A + VK_PAD_Y]          = 'C',    // switch
    [-VK_PAD_A + VK_PAD_START]      = VK_F5,  // pause
    [-VK_PAD_A + VK_PAD_BACK]       = VK_F1,  // restart
    [-VK_PAD_A + VK_PAD_RSHOULDER]  = VK_F6,  // next level
    [-VK_PAD_A + VK_PAD_LSHOULDER]  = VK_F7,  // prev level
    [-VK_PAD_A + VK_PAD_DPAD_UP]    = 'W',
    [-VK_PAD_A + VK_PAD_DPAD_RIGHT] = 'D',
    [-VK_PAD_A + VK_PAD_DPAD_DOWN]  = 'S',
    [-VK_PAD_A + VK_PAD_DPAD_LEFT]  = 'A',
};

struct gamepad {
    int enabled;  // per-controller bit flags
    void  (*XInputEnable)(BOOL);
    DWORD (*XInputGetState)(DWORD, XINPUT_STATE *);
    DWORD (*XInputGetKeystroke)(DWORD, DWORD, PXINPUT_KEYSTROKE);
};

static struct gamepad loadgamepad(void)
{
    struct gamepad g = {0};
    HINSTANCE h = 0;
    h = h ? h : LoadLibraryA("xinput1_4.dll");
    h = h ? h : LoadLibraryA("xinput1_3.dll");
    h = h ? h : LoadLibraryA("xinput9_1_0.dll");
    if (h) {
        g.XInputEnable = (void *)GetProcAddress(h, "XInputEnable");
        g.XInputGetState = (void *)GetProcAddress(h, "XInputGetState");
        g.XInputGetKeystroke = (void *)GetProcAddress(h, "XInputGetKeystroke");
        if (g.XInputEnable) {
            g.XInputEnable(TRUE);
            for (int i = 0; i < 4; i++) {
                XINPUT_STATE state;
                if (!g.XInputGetState(i, &state)) {
                    g.enabled |= 1 << i;
                }
            }
        }
    }
    return g;
}

int mainCRTStartup(void)
{
    for (struct gamepad g = loadgamepad();; Sleep(15)) {
        for (int i = 0; i < 4; i++) {
            if (g.enabled & (1<<i)) {
                XINPUT_KEYSTROKE k;
                while (!g.XInputGetKeystroke(i, 0, &k)) {
                    INPUT in = {INPUT_KEYBOARD};
                    in.ki.wVk = gamepadmap[-VK_PAD_A+k.VirtualKey];
                    if (k.Flags & XINPUT_KEYSTROKE_KEYUP) {
                        in.ki.dwFlags |= KEYEVENTF_KEYUP;
                    }
                    SendInput(!!in.ki.wVk, &in, sizeof(in));
                }
            }
        }
    }
}
