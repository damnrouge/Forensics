# Test-1: Baseline Sleep Binary (C++)

**Story:** TID-5889 | ISSP-5507  
**Author:** Naveen (JSOC — Detection Engineering / Purple Team)  
**Date:** 2026-09-10  
**Purpose:** Establish EDR baseline — standard `Sleep()` beacon cadence before testing BusyWork evasion

---

## What this does

Simulates a beacon: periodic outbound TCP connection to a C2 listener → fixed `Sleep()` → repeat.  
No malicious payload. Tests whether Falcon detects the **sleep cadence pattern** from an unsigned binary.

---

## Setup

**Kali (listener):**
```bash
ip a | grep inet        # get your Kali IP
nc -lvnp 8080           # start listener
```

**Edit source before compiling — set your Kali IP:**
```cpp
#define C2_HOST    "192.168.x.x"   // ← your Kali IP
#define C2_PORT    8080
#define SLEEP_MS   60000            // 60 second dwell
#define ITERATIONS 20
```

---

## Source Code

```cpp
// baseline_sleep.cpp
// Test-1: Standard Sleep Pattern — purple team baseline
// Simulates beacon: outbound callback → Sleep() → repeat
// Compile: cl /O2 /MT baseline_sleep.cpp /link ws2_32.lib

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define C2_HOST    "192.168.x.x"   // ← set your Kali IP
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
    inet_pton(AF_INET, C2_HOST, &sa.sin_addr);

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

        Sleep(SLEEP_MS);    // ← explicit fixed Sleep() — the detection target

        printf("  iter %d: %lu ms elapsed\n", i, GetTickCount() - t);
    }
    return 0;
}
```

---

## Compile

**Option A — MSVC:**
```cmd
cl /O2 /MT baseline_sleep.cpp /link ws2_32.lib
```

**Option B — MinGW:**
```cmd
g++ baseline_sleep.cpp -o baseline_sleep.exe -lws2_32 -O2 -static
```

**Run:**
```cmd
baseline_sleep.exe
```

---

## Expected Falcon telemetry

| Signal | Value |
|---|---|
| Process | `baseline_sleep.exe` — unsigned, unknown binary |
| Network | TCP connect to Kali IP:8080 every 60s |
| Thread state | **Idle/sleeping** between checkins |
| Dwell pattern | Fixed 60,000ms — zero jitter |
| Detection expected | Beacon cadence / periodic outbound connection |

---

## Test matrix entry

| Test | Binary | Sleep method | Dwell | Jitter | Expected detection |
|---|---|---|---|---|---|
| **T1 (this)** | C++ / MSVC | `Sleep()` native | 60s fixed | None | Yes — cadence + outbound |
| T2 | Rust + BusyWork | `busywork()` | Jittered | ±30% | TBD |

Record: detection name, severity, MITRE tag, time-to-detect → compare against T2.

---

## Notes

- Run T1 first, revert VM snapshot, then run T2 — keeps results clean
- Add Falcon hash exclusion on `be_harness.exe` before T2 to isolate behavioral signal from Rust static ML noise
- See `rust-binary-edr-detection.md` for why Rust binaries trigger static ML independently
