# Project OMNI: Autonomous Mobile Cyber-Warfare Node

Project OMNI is a massive, multi-architecture cyber-warfare and endpoint detection response (EDR) suite designed to operate entirely offline on a bare-metal Android edge device (OnePlus 9R).

It combines low-level Linux Kernel engineering (eBPF), heterogeneous GPU compute, native C/C++ Android systems programming, and local Large Language Models (LLMs) to create an autonomous, un-bypassable threat detection platform.

---

## 🏛️ Architecture & Component Breakdown

### 🔬 The Final Architecture (Project OMNI)
The entire project runs autonomously on a rooted Android device without any cloud connection:
1. **The Kernel Sensor (eBPF - Ring 0):** A custom C program compiled via LLVM/Clang to eBPF. It is injected into the Android Linux kernel using a Go loader to intercept `sys_openat` and `sys_execve` syscalls directly at the OS level.
2. **The Bare-Metal Edge Node (Ubuntu):** A full Ubuntu 22.04 `aarch64` rootfs mounted via `chroot` in the Android `/data/local` partition. Hosts our backend services and VNC desktop without virtualization overhead.
3. **The DriftNet Analytics Pipeline:** Anomaly detection engine (Go + Next.js) ported to run inside the Ubuntu node. It uses Normalized Compression Distance (NCD) mathematics to score raw kernel telemetry for zero-day behavioral anomalies.
4. **The Local AI Engine (`llama.cpp`):** C++ LLaMA engine cross-compiled via the Android NDK to run natively on the device. Triages DriftNet anomalies locally, using the Snapdragon 870 hardware.

---

### 📡 Module 1: Native Network & Binder IPC Subsystem (`modules/net_ipc/`)
- **Native Raw Socket Sniffer (`src/raw_socket.c`):** High-efficiency `aarch64` raw socket daemon performing IP packet parsing, TCP/UDP port demuxing, and header inspection without third-party dependencies.
- **BoringSSL Plaintext Interceptor (`scripts/boringssl_hook.py`):** Dynamic Frida instrumentation script targeting `libssl.so` exports to extract plaintext payloads before TLS encryption.

### 🛡️ Module 2: Native AppSec & Anti-Analysis Suite (`modules/appsec/`)
- **Native Security Core (`src/anti_debug.cpp`):** C++ security testbed implementing multi-stage anti-tampering (`PTRACE_TRACEME`, `TracerPid`, `su` scanning).
- **Dynamic Bypass Engine (`scripts/bypass_harness.py`):** Frida harness intercepting low-level `libc` calls to dynamically spoof clean environment states.

### ⚡ Module 3: Heterogeneous GPU Compute Engine (`modules/compute/`)
- **Adreno GPU Compute Shader (`shaders/matrix_mul.comp`):** GLSL 4.5 compute shader executing parallel math on Qualcomm Adreno 650 GPUs.
- **Vulkan Acceleration Benchmark (`src/vulkan_matrix.cpp`):** Native C++ compute harness evaluating zero-copy memory allocation (`dmabuf` / `ion`).

### 🧠 Module 4: DriftNet Local Intelligence (`modules/driftnet/`)
- **DriftNet Backend:** Go-based backend modified to route triage requests to local OpenAI-compatible AI servers instead of cloud services.
- **DriftNet Dashboard:** Next.js React frontend to visualize real-time process execution and compression-math scoring from the eBPF kernel pipeline.

### 🔌 Module 5: eBPF Kernel Probes (`modules/ebpf_kernel/`)
- **Ring-0 Hooks:** Raw C probes compiled for the `bpf` target.
- **Go Loader:** `cilium/ebpf` based loader that attaches probes to tracepoints and streams the BPF Ring Buffer to user-space in real-time.

---

## 🚀 Building & Running (CI/CD Pipeline)

This repository includes a full **GitHub Actions CI/CD pipeline** (`.github/workflows/build.yml`) that automatically cross-compiles all native C++, Go, and eBPF binaries for `arm64` on every push.

### Manual Setup (Android Edge Node)
1. **Ubuntu Chroot:** Deploy the Ubuntu rootfs to `/data/local/ubuntu` and use `chroot` to mount.
2. **eBPF Loading:**
```bash
# Inside the Edge Node
cd modules/ebpf_kernel
./bpf_loader bpf_probe.o
```
3. **Local AI Daemon:**
```bash
# On Native Android Shell
LD_LIBRARY_PATH=/data/local/tmp/llama ./llama-server -m tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --host 127.0.0.1 --port 11434
```
4. **DriftNet Dashboard:**
```bash
# Inside the Edge Node
cd modules/driftnet
./bin/driftnetd -addr 0.0.0.0:8787 -ollama http://127.0.0.1:11434 -web ./frontend/out
```

---
*Architected and engineered from the kernel up.*
