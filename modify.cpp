// baseline_sleep.cpp
// Test-1: Standard Sleep Pattern — purple team baseline
// Simulates beacon: outbound callback → Sleep() → repeat
// Compile: g++ baseline_sleep.cpp -o baseline_sleep.exe -lws2_32 -O2 -static

#include <windows.h>
#include <winsock2.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define C2_HOST    "192.168.x.x"   // ← your Kali IP
#define C2_PORT    8080
#define SLEEP_MS   60000
#define ITERATIONS 20

void simulate_checkin(int iter) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {};
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(C2_PORT);
    sa.sin_addr.s_addr = inet_addr(C2_HOST);

    int result = connect(s, (struct sockaddr*)&sa, sizeof(sa));
    printf("  [checkin] iter=%d result=%s\n",
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

        Sleep(SLEEP_MS);

        printf("  iter %d: %lu ms elapsed\n", i, GetTickCount() - t);
    }
    return 0;
}
