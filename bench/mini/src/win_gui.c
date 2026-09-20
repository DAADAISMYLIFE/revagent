#include <windows.h>
static const wchar_t *FLAG = L"DH{gui_p41nt_0k}";
LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_PAINT) {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps);
        HFONT f = CreateFontW(48, 0, 0, 0, FW_BOLD, 0, 0, 0, ANSI_CHARSET, 0, 0, ANTIALIASED_QUALITY, FF_DONTCARE, L"DejaVu Sans");
        SelectObject(dc, f);
        TextOutW(dc, 20, 40, FLAG, (int)wcslen(FLAG));
        DeleteObject(f);
        EndPaint(h, &ps);
        return 0;
    }
    if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(h, m, w, l);
}
int WINAPI wWinMain(HINSTANCE hi, HINSTANCE hp, PWSTR cmd, int show) {
    WNDCLASSW wc = {0}; wc.lpfnWndProc = WndProc; wc.hInstance = hi; wc.lpszClassName = L"MiniGui";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassW(&wc);
    HWND h = CreateWindowExW(0, L"MiniGui", L"MiniGui", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                             50, 50, 700, 200, NULL, NULL, hi, NULL);
    ShowWindow(h, SW_SHOW); UpdateWindow(h);
    MSG msg; while (GetMessageW(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return 0;
}
