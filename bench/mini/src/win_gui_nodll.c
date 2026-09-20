#include <windows.h>
/* Imports a DLL that does not exist, so the loader fails before WinMain: wine shows no window.
   Expected agent outcome: handoff_runbook (status "runbook"). The flag is never displayed here,
   and none is embedded in this binary either: the whole point of this bench is that the program
   cannot run, so a real flag string here would let an agent "solve" it with `strings` alone. */
__declspec(dllimport) int __stdcall NoSuchExport(int);
int WINAPI wWinMain(HINSTANCE hi, HINSTANCE hp, PWSTR cmd, int show) {
    return NoSuchExport(1);
}
