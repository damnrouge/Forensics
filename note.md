C++ (baseline_sleep.exe) — T1

A fake beacon. Every 30 seconds it wakes up, looks around (lists processes, reads registry, checks windows), connects to Kali, then goes back to sleep. This is exactly how real malware beacons behave. The Sleep(30000) is the detection target — Falcon sees a process that periodically wakes, does recon, calls out, sleeps. Fixed interval, zero jitter. Easy to fingerprint.

Rust (busywork.exe) — T2

Same fake beacon — same recon, same Kali checkin. But instead of Sleep(), it stays busy doing real CPU and memory work (hashing, sorting, memory allocations) between checkins. The thread never idles. There's no fixed sleep interval — the pause is however long the work takes, with random variation built in. Falcon's behavioral detection looks for the sleep→wakeup→callout pattern. If the thread never sleeps, that pattern doesn't exist.
