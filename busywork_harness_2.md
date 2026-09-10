# Test-2: BusyWork Evasion Binary (Rust)

**Story:** TID-5889 | ISSP-5507  
**Author:** Naveen (JSOC — Detection Engineering / Purple Team)  
**Date:** 2026-09-10  
**Purpose:** Replace `Sleep()` with `busywork_with(compute+memory)` — same discovery behavior as T1 baseline, thread never idles

---

## What this does

Same pattern as `baseline_sleep` (process enum → registry read → window enum → TCP checkin) but the dwell period uses `busywork_with(Intensity::Medium, Categories::COMPUTE | Categories::MEMORY)` instead of `Sleep()`.

The thread stays **CPU-active** during the wait. No idle thread state, no fixed sleep interval detectable by timing analysis.

---

## Key difference vs T1

| | T1 baseline | T2 BusyWork |
|---|---|---|
| Dwell method | `Sleep(30000)` | `busywork_with(Medium, COMPUTE\|MEMORY)` |
| Thread state during dwell | **Idle / sleeping** | **Active — CPU/memory work** |
| Timing signature | Fixed 30s, zero jitter | Variable ~15–45s, ±30% jitter per task |
| Task combinations | N/A | 2.5M+ possible at Medium intensity |
| Detection target | Yes — sleep cadence | TBD — behavioral ML result |

---

## Why `busywork_with` not `busywork`

The `busywork_with` API lets you restrict which task categories run during the dwell:

- **`cat-compute` enabled** — SHA hashing loops, prime sieves, matrix multiply, sorting, compression, Fibonacci, bitwise ops
- **`cat-memory` enabled** — allocation/deallocation cycles, memcpy chains, heap fragmentation, scatter/gather
- **`cat-network` excluded** — busywork's network category does DNS lookups + HTTP requests to 24 domains; would create anomalous traffic separate from our C2 checkin and muddy the test signal
- **`cat-winapi` / `cat-registry` excluded from dwell** — we call process enum, registry read, and window enum explicitly as beacon discovery behavior; no need to double-up in the dwell period

Jitter is built-in: each drawn task gets ±30% randomisation on its iteration count, buffer size, and call depth independently. Execution time emerges from the workload, not from a configured delay value.

---

## Setup

**Kali (listener — persistent):**
```bash
while true; do nc -lvnp 8080; done
```

**Create project:**
```cmd
cd C:\Users\nvegireddi\busywork
cargo new busywork
cd busywork
```

Then replace `Cargo.toml` and `src\main.rs` with the files below.

---

## Files

### `Cargo.toml`

```toml
[package]
name    = "busywork"
version = "0.2.0"
edition = "2021"

[dependencies]
# cat-compute: SHA hashing, prime sieves, matrix multiply, sorting, compression
# cat-memory:  allocation/deallocation cycles, memcpy chains, heap fragmentation
# cat-network omitted — DNS/HTTP calls would create noise separate from C2 traffic
# cat-winapi omitted  — we call those APIs explicitly as beacon discovery behavior
busywork = { version = "0.1", default-features = false, features = ["cat-compute", "cat-memory"] }
winapi   = { version = "0.3", features = ["tlhelp32", "winreg", "winuser", "winnt", "handleapi"] }

[profile.release]
strip         = "symbols"
opt-level     = "z"
panic         = "abort"
lto           = true
codegen-units = 1
```

### `src/main.rs`

```rust
// busywork/src/main.rs
// Test-2: BusyWork beacon — same discovery pattern as baseline_sleep
//         but Sleep() replaced with busywork_with(compute+memory only)
// Story: TID-5889 | ISSP-5507
// Compile: cargo build --release
// Run:     .\target\release\busywork.exe medium 20
//
// Why busywork_with instead of busywork:
//   - Restricts dwell work to COMPUTE+MEMORY only
//   - Avoids cat-network (DNS/HTTP calls would muddy the C2 traffic signal)
//   - Avoids cat-winapi/cat-registry in dwell (we do those explicitly as beacon behavior)
//   - Jitter is built-in: each task gets ±30% randomised parameters
//   - 2.5M+ possible task combinations at Medium — no fixed timing signature

use std::net::TcpStream;
use std::time::Instant;
use busywork::{busywork_with, Categories, Intensity};

#[cfg(windows)]
use winapi::{
    shared::minwindef::{BOOL, DWORD, LPARAM},
    shared::windef::HWND,
    um::{
        handleapi::CloseHandle,
        tlhelp32::{
            CreateToolhelp32Snapshot, Process32First, Process32Next,
            PROCESSENTRY32, TH32CS_SNAPPROCESS,
        },
        winnt::KEY_READ,
        winreg::{
            RegCloseKey, RegOpenKeyExA, RegQueryValueExA, HKEY_LOCAL_MACHINE,
        },
        winuser::EnumWindows,
    },
};

const C2_HOST: &str = "10.110.0.106:8080";
const ITERATIONS: u32 = 20;

// ── beacon behavior (same as T1 baseline) ─────────────────────────────────────

fn simulate_checkin(iter: u32) {
    match TcpStream::connect(C2_HOST) {
        Ok(_)  => println!("  [checkin] iter={} connected", iter),
        Err(_) => println!("  [checkin] iter={} no listener", iter),
    }
}

#[cfg(windows)]
fn enum_processes() {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        let mut pe: PROCESSENTRY32 = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32>() as DWORD;
        if Process32First(snap, &mut pe) != 0 {
            while Process32Next(snap, &mut pe) != 0 {}
        }
        CloseHandle(snap);
    }
}

#[cfg(windows)]
fn query_registry() {
    unsafe {
        let mut hkey = std::ptr::null_mut();
        RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            b"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\0".as_ptr() as *const i8,
            0, KEY_READ, &mut hkey,
        );
        let mut buf = [0u8; 256];
        let mut sz: DWORD = 256;
        RegQueryValueExA(
            hkey,
            b"ProductName\0".as_ptr() as *const i8,
            std::ptr::null_mut(), std::ptr::null_mut(),
            buf.as_mut_ptr(), &mut sz,
        );
        RegCloseKey(hkey);

        RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            b"SYSTEM\\CurrentControlSet\\Services\0".as_ptr() as *const i8,
            0, KEY_READ, &mut hkey,
        );
        RegCloseKey(hkey);
    }
}

#[cfg(windows)]
unsafe extern "system" fn wnd_enum_proc(_hwnd: HWND, _lparam: LPARAM) -> BOOL { 1 }

#[cfg(windows)]
fn enum_windows_check() {
    unsafe { EnumWindows(Some(wnd_enum_proc), 0); }
}

// ── main ──────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let level = args.get(1).map(|s| s.as_str()).unwrap_or("medium");
    let loops: u32 = args.get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(ITERATIONS);

    let intensity = match level {
        "low"   => Intensity::Low,
        "high"  => Intensity::High,
        "ultra" => Intensity::Ultra,
        _       => Intensity::Medium,
    };

    // Dwell categories: compute + memory only
    // No network (avoids DNS/HTTP noise), no winapi/registry (we call those explicitly)
    let dwell_cats = Categories::COMPUTE | Categories::MEMORY;

    println!("[bw-harness] host={} level={} iters={}", C2_HOST, level, loops);

    for i in 0..loops {
        let t = Instant::now();

        // 1. checkin
        simulate_checkin(i);

        // 2. discovery (mirrors T1 baseline behavior)
        #[cfg(windows)]
        {
            enum_processes();     // T1057 — Process Discovery
            query_registry();     // T1012 — Query Registry
            enum_windows_check(); // T1082 — System Info
        }

        // 3. dwell — busywork replaces Sleep()
        //    compute+memory only; jitter built-in (±30% per task parameter)
        busywork_with(intensity, dwell_cats);

        println!("  iter {}: {} ms", i, t.elapsed().as_millis());
    }
}
```

---

## Build & run

```cmd
cd C:\Users\nvegireddi\busywork\busywork
cargo build --release 2>&1
.\target\release\busywork.exe medium 20
```

**Before running:** add Falcon path exclusion `C:\Users\nvegireddi\busywork\*` to suppress static ML (Rust language bias — documented in `rust-binary-edr-detection.md`). Test question is behavioral, not static.

---

## Expected Falcon telemetry

| Signal | Value |
|---|---|
| Process | `busywork.exe` — Rust binary, statically linked |
| Network | TCP connect to `10.110.0.106:8080` each iteration only |
| Thread state | **Active / CPU+memory work** between checkins |
| Dwell pattern | Variable ~15–45s — no fixed interval, ±30% jitter per task |
| Static ML | Will fire (Rust language bias) — exclude before test |
| Behavioral ML | **The actual test result** |

---

## Test matrix

| Test | Binary | Sleep method | Dwell | Jitter | Detection result |
|---|---|---|---|---|---|
| T1 | C++ / MinGW | `Sleep()` native | 30s fixed | None | Record from lab |
| **T2 (this)** | Rust + BusyWork | `busywork_with(Medium, COMPUTE\|MEMORY)` | ~15–45s | ±30% per task | **TBD** |

Record: detection name, severity, MITRE tag, time-to-detect → compare T1 vs T2.

---

## Procedure

1. Revert VM to clean snapshot (after T1 run)
2. Add Falcon path exclusion: `C:\Users\nvegireddi\busywork\*`
3. Start Kali listener: `while true; do nc -lvnp 8080; done`
4. `cargo build --release && .\target\release\busywork.exe medium 20`
5. Monitor Falcon for behavioral detections
6. Remove exclusion after test
7. Document and compare against T1

---

## Reference

- [BusyWork — Replacing Sleep with Real Work to Break Behavioral Detection](https://patchi.fyi/blog/busywork-sleep-replacement)
- [rust-binary-edr-detection.md](./rust-binary-edr-detection.md) — why Rust binaries trigger static ML
- [baseline_sleep.md](./baseline_sleep.md) — T1 baseline binary
