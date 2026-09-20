#include <windows.h>
/* Imports a DLL that does not exist, so the loader fails before WinMain: wine shows no window.
   Expected agent outcome: handoff_runbook (status "runbook"). The flag is never displayed here. */
__declspec(dllimport) int __stdcall NoSuchExport(int);
static const wchar_t *FLAG = L"DH{runb00k_p4th}";
int WINAPI wWinMain(HINSTANCE hi, HINSTANCE hp, PWSTR cmd, int show) {
    (void)FLAG;
    return NoSuchExport(1);
}
