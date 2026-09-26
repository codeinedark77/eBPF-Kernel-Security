# 📊 DriftNet Benchmarks: eBPF vs. Ring-3 Hooks

One of the primary goals of Project OMNI is to provide near-zero overhead telemetry collection for edge devices. Traditional Android EDR solutions rely on Ring-3 user-space hooking frameworks (like Frida, Xposed, or ptrace). These methods introduce significant context-switching overhead and latency, making them easily detectable by timing attacks.

DriftNet bypasses these limitations by operating entirely in Ring-0 using **eBPF (Extended Berkeley Packet Filter)**.

## ⏱️ eBPF Probe Overhead Comparison

The following benchmarks demonstrate the nanosecond efficiency of eBPF `kprobes` against traditional hooking techniques on a **Snapdragon 870 (OnePlus 9R)** edge device. These metrics represent the *interception overhead* added to the syscall, not the total execution time of the syscall itself. *(Measured across 10,000 iterations).*

| Interception Method | `sys_execve` Overhead | `sys_openat` Overhead | `sys_connect` Overhead | Context Switches |
| :--- | :--- | :--- | :--- | :--- |
| **Native Execution (No EDR)** | 0 ns | 0 ns | 0 ns | 0 |
| **DriftNet (eBPF)** | **~350 ns (±45 ns)** | **~280 ns (±30 ns)** | **~310 ns (±35 ns)** | **0** |
| ptrace (Strace) | ~25,000 ns (±2k ns)| ~18,500 ns (±1.5k ns)| ~35,000 ns (±3k ns)| 2 |
| Frida (Inline Hook) | ~45,000 ns | ~40,000 ns | ~55,000 ns | 0 (User-space inline) |
| Xposed / LSPosed | ~120,000 ns | ~110,000 ns | ~150,000 ns | 0 (JVM/ART overhead) |

## 🧠 Architectural Advantage & Known Limitations

### 1. Zero Context-Switching
When a user-space process triggers `execve`, traditional hooking via `ptrace` forces the kernel to pause execution, context-switch back to the EDR in Ring-3, read memory, and then context-switch *back* to Ring-0 to resume the syscall. 

DriftNet's eBPF programs execute directly within the kernel boundary. Syscall arguments are intercepted, parsed, and pushed to an asynchronous BPF Ring Buffer in less than `500ns` before the kernel proceeds with the execution.

### 2. Lockless Ring Buffers
Data exfiltration from Ring-0 to the Go Relay (Ring-3) is handled via lockless BPF Ring Buffers. This ensures that the kernel is never blocked waiting for the Go telemetry engine to consume the event logs. If the buffer fills, events are dropped, prioritizing system stability over guaranteed delivery.

### 3. Stealth (Anti-Anti-Debugging)
Because eBPF runs beneath the Android framework layer, it is invisible to standard anti-debugging checks. Applications cannot detect `TracerPid` changes in `/proc/self/status` because `ptrace` is never invoked.

### 4. ⚠️ KNOWN LIMITATION: The Local AI Triage Bottleneck
While the eBPF hooks operate in nanoseconds, the **Local AI Triage (Llama 3.1 8B)** stage is a massive computational bottleneck. An LLM call per flagged event takes milliseconds-to-seconds, completely dwarfing the microsecond kernel numbers highlighted above. Currently, there is no advanced batching or sampling logic implemented, meaning sustained syscall volume *will* overwhelm the AI processing queue.

---
*Testing Methodology: Measured using `bpftool prog profile` for eBPF latency overhead.*
