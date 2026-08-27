# Project OMNI: Autonomous Mobile Cyber-Warfare Node 👑

Project OMNI is a massive, multi-architecture cyber-warfare and Endpoint Detection & Response (EDR) suite designed to operate entirely offline on a bare-metal Android edge device (OnePlus 9R). 

It combines low-level Linux Kernel engineering (eBPF), heterogeneous GPU compute, native Android systems programming, and local Large Language Models (LLMs) to create an autonomous, un-bypassable threat detection platform.

---

## 🚀 Key Capabilities (The "God Mode" Upgrades)

We transformed this project from a heavy proof-of-concept into a **stealthy, battery-efficient, production-grade root daemon**. 

### 1. Zero-Overhead Kernel Telemetry (eBPF Ring 0)
- **What it does:** A custom C program compiled via LLVM/Clang to eBPF is injected directly into the Android Linux kernel. It intercepts `sys_openat` and `sys_execve` syscalls directly at the OS level.
- **The Upgrade:** We implemented native C-level UID filtering within the kernel probe to completely ignore Android framework processes (UIDs < 10000). By filtering out system noise at Ring 0, the eBPF probe now exclusively tracks untrusted third-party apps with near-zero overhead.

### 2. Thermal & Battery Orchestration (Lazy AI)
- **What it does:** A C++ LLaMA AI engine cross-compiled via the Android NDK runs natively on the Snapdragon 870 hardware to triage zero-day anomalies.
- **The Upgrade:** Running a 600MB LLM continuously on a mobile GPU causes severe thermal throttling. We engineered an event-driven **Lazy AI Orchestrator**. The AI is kept completely dormant, consuming 0% battery. When DriftNet's mathematical backend detects an anomaly, the orchestrator dynamically wakes up the GPU, loads the LLM weights, triages the threat, and instantly kills the AI process to preserve battery.

### 3. Native Magisk Module Daemon (Auto-Boot)
- **What it does:** Project OMNI is packaged as a standard Magisk Module.
- **The Upgrade:** You no longer need ADB, a laptop, or a terminal to start the EDR. When the phone boots, Magisk's `service.sh` silently mounts the Ubuntu Edge Node, attaches the eBPF kernel hooks, starts the DriftNet Next.js dashboard, and deploys the AI Watchdog entirely in the background.

### 4. Full Ubuntu Linux GUI Integration
- **What it does:** Alongside the EDR, Project OMNI hosts a headless XFCE4 Ubuntu Desktop Environment running inside a `chroot` on the `/data` partition, without the massive performance overhead of virtualization.
- **The Upgrade:** The Magisk daemon automatically spins up a VNC server (`127.0.0.1:5901`). You can access a full Linux Desktop environment directly on your Android screen using any local VNC Viewer app.

---

## 🏛️ Module Architecture Breakdown

### 📡 Module 1: Native Network & Binder IPC Subsystem (`modules/net_ipc/`)
- **Native Raw Socket Sniffer:** High-efficiency `aarch64` raw socket daemon performing IP packet parsing without third-party dependencies.
- **BoringSSL Plaintext Interceptor:** Dynamic Frida instrumentation targeting `libssl.so` to extract plaintext payloads before TLS encryption.

### 🛡️ Module 2: Native AppSec & Anti-Analysis Suite (`modules/appsec/`)
- **Native Security Core:** C++ security testbed implementing multi-stage anti-tampering (`PTRACE_TRACEME`, `TracerPid`).
- **Dynamic Bypass Engine:** Frida harness intercepting low-level `libc` calls to dynamically spoof clean environment states.

### ⚡ Module 3: Heterogeneous GPU Compute Engine (`modules/compute/`)
- **Adreno GPU Compute Shader:** GLSL 4.5 compute shader executing parallel math on Qualcomm Adreno 650 GPUs.
- **Vulkan Acceleration Benchmark:** Native C++ compute harness evaluating zero-copy memory allocation (`dmabuf` / `ion`).

### 🧠 Module 4: DriftNet Local Intelligence (`modules/driftnet/`)
- **DriftNet Backend:** Go-based backend modified to route triage requests to the local Lazy AI orchestrator.
- **DriftNet Dashboard:** Next.js React frontend to visualize real-time process execution and compression-math scoring from the eBPF kernel pipeline.

### 🔌 Module 5: eBPF Kernel Probes (`modules/ebpf_kernel/`)
- **Ring-0 Hooks:** Raw C probes compiled for the `bpf` target with UID filtering.
- **Go WebSocket Relay:** High-performance Go binary that pipes kernel telemetry directly into DriftNet's WebSocket ingestion engine.

---

## 🛠️ Installation & Usage

This system is completely autonomous and deployed natively via Magisk.

1. Install the `project_omni` Magisk module zip via the Magisk Manager app on your rooted device.
2. Reboot the phone.
3. **Access the EDR Dashboard:** Open your mobile browser (or a laptop on the same WiFi network) and navigate to `http://127.0.0.1:8787`.
4. **Access the Ubuntu Linux GUI:** Open any VNC Viewer app on your phone and connect to `127.0.0.1:5901` (Password: `ubuntu`).

---
*Architected and engineered from the kernel up.*
