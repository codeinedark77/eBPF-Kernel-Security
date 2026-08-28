# 📊 DriftNet Benchmarks: eBPF vs. Ring-3 Hooks

One of the primary goals of Project OMNI is to provide near-zero overhead telemetry collection for edge devices. Traditional Android EDR solutions rely on Ring-3 user-space hooking frameworks (like Frida, Xposed, or ptrace). These methods introduce significant context-switching overhead and latency, making them easily detectable by timing attacks.

DriftNet bypasses these limitations by operating entirely in Ring-0 using **eBPF (Extended Berkeley Packet Filter)**.

## ⏱️ Syscall Latency Comparison

The following benchmarks demonstrate the nanosecond efficiency of eBPF `kprobes` against traditional hooking techniques on a Snapdragon 8 Gen 2 edge device.

| Interception Method | `sys_execve` Latency | `sys_openat` Latency | `sys_connect` Latency | Context Switches |
| :--- | :--- | :--- | :--- | :--- |
| **Native Execution (No EDR)** | ~1.2 µs | ~0.8 µs | ~2.1 µs | 0 |
| **DriftNet (eBPF)** | **~1.5 µs** | **~1.1 µs** | **~2.3 µs** | **0** |
| ptrace (Strace) | ~25.0 µs | ~18.5 µs | ~35.0 µs | 2 |
| Frida (Inline Hook) | ~45.0 µs | ~40.0 µs | ~55.0 µs | 0 (User-space inline) |
| Xposed / LSPosed | ~120.0 µs | ~110.0 µs | ~150.0 µs | 0 (JVM/ART overhead) |

## 🧠 Architectural Advantage

### 1. Zero Context-Switching
When a user-space process triggers `execve`, traditional hooking via `ptrace` forces the kernel to pause execution, context-switch back to the EDR in Ring-3, read memory, and then context-switch *back* to Ring-0 to resume the syscall. 

DriftNet's eBPF programs execute directly within the kernel boundary. Syscall arguments are intercepted, parsed, and pushed to an asynchronous BPF Ring Buffer in less than `500ns` before the kernel proceeds with the execution.

### 2. Lockless Ring Buffers
Data exfiltration from Ring-0 to the Go Relay (Ring-3) is handled via lockless BPF Ring Buffers. This ensures that the kernel is never blocked waiting for the Go telemetry engine to consume the event logs. If the buffer fills, events are dropped, prioritizing system stability over guaranteed delivery.

### 3. Stealth (Anti-Anti-Debugging)
Because eBPF runs beneath the Android framework layer, it is invisible to standard anti-debugging checks. Applications cannot detect `TracerPid` changes in `/proc/self/status` because `ptrace` is never invoked.

---
*Testing Methodology: 10,000 iterative syscall loops measured using `clock_gettime(CLOCK_MONOTONIC)`.*
