# Project Omni (DriftNet): The Future Scope

Project Omni was designed as an absolute proof-of-concept for **Autonomous AI Security**. By injecting an eBPF sensor into the kernel and pairing it with a local Llama 3.1 engine, we bypassed the fundamental limitations of Android user-space sandboxing. 

But this is only Phase 1.

Here is the technical roadmap for the future scope of this project:

## Phase 2: Ring-0 Active Response & Memory Introspection
Currently, the AI issues a `BLOCK` verdict by sending a kill signal to the process from the `driftnetd` user-space relay.
- **eBPF Deep Integration:** Push the active response logic directly into the eBPF kernel space. Instead of waiting for the Go relay to issue `kill()`, the eBPF hook will instantly `bpf_send_signal(SIGKILL)` to the process the microsecond the AI marks the signature as malicious.
- **Process Memory Scanning:** Hook `sys_ptrace` and `sys_mmap`. When a process triggers a 1.0 Novelty Anomaly, the eBPF probe will dump the first 4KB of the process's memory headers and pipe it to the local AI. The AI will scan the raw memory for known malware signatures (e.g., packed Dalvik executables or Metasploit payloads) in real-time.

## Phase 3: The Distributed Swarm
A single laptop running Llama 3.1 8B is a powerful local sentinel. But scaling this requires a swarm.
- **Federated Threat Intel:** Multiple Android devices running the `ebpf_sensor` will stream their telemetry into a centralized Kubernetes cluster.
- **vLLM Swarm Intelligence:** Instead of a single Ollama instance, the telemetry will be routed through a Kafka queue into a swarm of massive Llama 3.1 70B models running on A100 GPUs via vLLM. 
- **Zero-Day Auto-Patching:** When the Swarm detects a zero-day exploit on Device A, it instantly generates a new baseline rule and pushes an over-the-air update to the Go Relays on Devices B, C, and D, immunizing the entire network in seconds.

## Phase 4: Extreme Anti-Tampering
Malware developers will eventually try to kill the `driftnetd` relay or the eBPF loader to blind the AI.
- **Kernel-Level Cloaking:** We will write additional eBPF hooks to intercept `sys_kill` and `sys_ptrace`. If *any* process (even rooted ones) attempts to read or kill `driftnetd`, the kernel will spoof a success response while silently ignoring the kill request. The security daemon will become mathematically un-killable and invisible to the Android userspace.

---
### Conclusion
Project Omni has successfully proven that LLMs can operate as deterministic, real-time security analysts at the kernel level. The foundation is built. The future is an un-killable, self-updating neural immune system for Android.
