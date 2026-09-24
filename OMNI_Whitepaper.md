# Project OMNI: Autonomous Mobile Cyber-Warfare Node
## Architecture and Technical Whitepaper

**Author:** Yash Kandhare  
**Date:** August 2026  
**Repository:** Project OMNI  

---

### Abstract
Project OMNI represents a paradigm shift in mobile Endpoint Detection and Response (EDR). Unlike traditional mobile security products that rely on cloud telemetry, virtualization, or accessibility services, OMNI operates entirely bare-metal on an Android edge node (OnePlus 9R). By fusing eBPF kernel engineering, heterogeneous GPU compute, and a Lazy AI orchestrator, OMNI provides highly resilient zero-day threat detection with minimal battery overhead.

---

### 1. The Kernel Sensor: eBPF Ring 0 Telemetry
At the lowest level, traditional Android antivirus software relies on polling `/proc` or using Android APIs, which sophisticated malware easily bypasses. OMNI intercepts execution at the Linux kernel level (Ring 0) using extended Berkeley Packet Filter (eBPF).

- **Implementation:** A custom C program compiled via LLVM/Clang for the `aarch64` target.
- **Hooks:** We attach kprobes to `__arm64_sys_openat` and `__arm64_sys_connect` tracepoints.
- **UID Filtering:** To eliminate performance overhead, the eBPF probe implements native UID filtering (`if (data.uid < 10000) return 0;`), completely ignoring Android OS framework noise and exclusively tracking untrusted third-party applications.
- **Network Exfiltration:** By reading the `sockaddr_in` struct natively in memory during `sys_connect`, the kernel probe records every remote IP address and port that applications attempt to contact, before encryption can take place.

---

### 2. The Edge Node: Bare-Metal Ubuntu Chroot
OMNI avoids the extreme performance penalty of virtualization (e.g., QEMU or Termux PRoot) by deploying a full Ubuntu 22.04 `aarch64` rootfs directly onto the Android `/data/local` partition.
- Uses `chroot` and kernel namespace binding to share the host's networking stack, CPU, and GPU completely natively.
- Hosts our Go-lang WebSocket relay, the Next.js Analytics dashboard, and a headless XFCE4 VNC server.

---

### 3. DriftNet: Mathematical Anomaly Detection (NCD)
Instead of relying on signature databases, OMNI uses mathematics to detect zero-day malware behavior.
- **Normalized Compression Distance (NCD):** We use a Go-based backend (DriftNet) that ingests the eBPF ring buffer stream via WebSockets. The system builds a behavioral baseline of normal application syscalls.
- When an app executes, its syscall trace is compressed against the baseline. If the resulting NCD score crosses the `0.5` threshold, the behavior is statistically flagged as a novel deviation (an anomaly).

---

### 4. Lazy AI: Heterogeneous GPU Thermal Orchestration
Running a 600MB Large Language Model (LLM) continuously on a Snapdragon 870 GPU causes severe thermal throttling and battery drain. 
- **The AI Engine:** We cross-compiled `llama.cpp` using the Android NDK to run native inference on the mobile Adreno GPU.
- **The Orchestrator:** We engineered a native "Lazy AI" watchdog. The LLM is kept completely dormant (0% battery drain) during normal operation. 
- When DriftNet's math flags an anomaly, it writes to a state file (`/root/llm_state`). The native Magisk watchdog detects this, dynamically wakes up the GPU, loads the LLM into VRAM, triages the anomaly, and instantly `SIGKILL`s the process.

---

### 5. Native Persistence: Magisk Auto-Boot Daemon
The entire system operates autonomously. Packaged as a standard Magisk module, a late-start script (`service.sh`) orchestrates the entire pipeline upon Android boot.
- Silently mounts the Ubuntu Edge Node.
- Attaches the eBPF kernel hooks.
- Spools up the DriftNet Next.js dashboard (exposed on `0.0.0.0:8787` - *Note: Requires reverse proxy authentication for production deployments*).
- Deploys the VNC server (`127.0.0.1:5901`).

---

### Conclusion
Project OMNI proves that enterprise-grade, kernel-level EDR is viable on consumer mobile edge nodes without sacrificing battery life or performance. By pushing telemetry to the kernel and triage to the edge, OMNI represents the future of autonomous cyber-warfare nodes.
