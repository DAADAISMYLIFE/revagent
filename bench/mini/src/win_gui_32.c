#include <windows.h>
/* This bench exists for the runbook path: it is compiled as a 32-bit PE, and the sandbox image
   ships wine64 only (no 32-bit wine), so revagent/tools/run_binary.py answers
   "[cannot run here] 32-bit Windows PE ..." immediately (env_blocked) and run_gui sees no window.
   The flag is XOR-encoded (key 0x5A) as a byte array and decoded into a wide string at runtime,
   right before TextOutW, so `strings`/`strings -el` do not show it in the .exe. Statically
   decoding the XOR (e.g. reading this source, or emulating with unicorn) is also a legitimate
   solve, same as the runbook path. */
static const unsigned char FLAG_XOR[] = {
    0x1e, 0x12, 0x21, 0x2d, 0x6b, 0x34, 0x69, 0x68, 0x05, 0x28, 0x2f, 0x34, 0x38, 0x6a, 0x6a, 0x31, 0x27
};
#define FLAG_LEN (sizeof(FLAG_XOR) / sizeof(FLAG_XOR[0]))
static const unsigned char FLAG_KEY = 0x5A;

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_PAINT) {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps);
        HFONT f = CreateFontW(48, 0, 0, 0, FW_BOLD, 0, 0, 0, ANSI_CHARSET, 0, 0, ANTIALIASED_QUALITY, FF_DONTCARE, L"DejaVu Sans");
        SelectObject(dc, f);
        wchar_t flag[FLAG_LEN + 1];
        for (unsigned i = 0; i < FLAG_LEN; i++) flag[i] = (wchar_t)(FLAG_XOR[i] ^ FLAG_KEY);
        flag[FLAG_LEN] = L'\0';
        TextOutW(dc, 20, 40, flag, (int)FLAG_LEN);
        DeleteObject(f);
        EndPaint(h, &ps);
        return 0;
    }
    if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(h, m, w, l);
}
int WINAPI wWinMain(HINSTANCE hi, HINSTANCE hp, PWSTR cmd, int show) {
    WNDCLASSW wc = {0}; wc.lpfnWndProc = WndProc; wc.hInstance = hi; wc.lpszClassName = L"MiniGui32";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassW(&wc);
    HWND h = CreateWindowExW(0, L"MiniGui32", L"MiniGui32", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                             50, 50, 700, 200, NULL, NULL, hi, NULL);
    ShowWindow(h, SW_SHOW); UpdateWindow(h);
    MSG msg; while (GetMessageW(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return 0;
}
