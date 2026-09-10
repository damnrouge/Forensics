// baseline_sleep.cpp
// Test-1: Suspicious beacon — checkin + discovery + Sleep()
// Compile: g++ baseline_sleep.cpp -o baseline_sleep.exe -lws2_32 -O2 -static

#include <windows.h>
#include <winsock2.h>
#include <tlhelp32.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define C2_HOST    "10.110.0.106"
#define C2_PORT    8080
#define SLEEP_MS   30000
#define ITERATIONS 20

void enum_processes() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        while (Process32Next(snap, &pe)) {}
    }
    CloseHandle(snap);
}

void query_registry() {
    HKEY hKey;
    char buf[256];
    DWORD sz = sizeof(buf);

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey);
    RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)buf, &sz);
    RegCloseKey(hKey);

    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hKey);
    RegCloseKey(hKey);
}

void enum_windows_check() {
    EnumWindows([](HWND, LPARAM) -> BOOL { return TRUE; }, 0);
    GetSystemMetrics(SM_CXSCREEN);
    GetSystemMetrics(SM_CYSCREEN);
}

void simulate_checkin(int iter) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {};
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(C2_PORT);
    sa.sin_addr.s_addr = inet_addr(C2_HOST);

    int result = connect(s, (struct sockaddr*)&sa, sizeof(sa));
    printf("  [checkin] iter=%d %s\n",
           iter, result == 0 ? "connected" : "no listener");

    closesocket(s);
    WSACleanup();
}

int main() {
    printf("[baseline-sleep] host=%s port=%d sleep=%dms iters=%d\n",
           C2_HOST, C2_PORT, SLEEP_MS, ITERATIONS);

    for (int i = 0; i < ITERATIONS; i++) {
        DWORD t = GetTickCount();

        simulate_checkin(i);
        enum_processes();
        query_registry();
        enum_windows_check();

        Sleep(SLEEP_MS);

        printf("  iter %d: %lu ms\n", i, GetTickCount() - t);
    }
    return 0;
}
