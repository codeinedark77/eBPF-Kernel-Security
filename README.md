# 🛡️ DriftNet (Project OMNI)

<div align="center">
  <img src="https://img.shields.io/badge/Status-Production-success?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Kernel-eBPF-black?style=for-the-badge&logo=linux" />
  <img src="https://img.shields.io/badge/Backend-Go-00ADD8?style=for-the-badge&logo=go" />
  <img src="https://img.shields.io/badge/Frontend-Next.js-black?style=for-the-badge&logo=next.js" />
  <img src="https://img.shields.io/badge/Agentic_-Phase_2-000000?style=for-the-badge&logo=github" />
</div>

<br />

**DriftNet** is a Ring-0 cybersecurity daemon designed for Android edge devices. It utilizes eBPF (Extended Berkeley Packet Filter) kernel probes to passively intercept and stream execution, network, and file-system syscalls with near-zero overhead. 

Unlike traditional Ring-3 EDRs or user-space hooks (Frida/Xposed) which are easily detected and bypassed by modern malware, DriftNet operates entirely in kernel-space, making it invisible to userspace applications.

---

## 🔬 Core Architecture

DriftNet is split into three primary layers:
1. **The Kernel Probes (C/eBPF):** Intercepts ARM64 syscalls (`sys_openat`, `sys_connect`, `sys_execve`).
2. **The Telemetry Relay (Go):** A high-throughput WebSocket server that reads the eBPF BPF map ring buffers.
3. **The Tactical Dashboard (Next.js):** A real-time UI mapping the telemetry against behavioral baseline signatures.

```mermaid
graph TD
    subgraph "Ring-0 (Kernel Space)"
        K[Linux Kernel]
        P1[kprobe/__arm64_sys_execve]
        P2[kprobe/__arm64_sys_openat]
        P3[kprobe/__arm64_sys_connect]
        RB[(BPF Ring Buffer)]
        
        K --> P1
        K --> P2
        K --> P3
        P1 --> RB
        P2 --> RB
        P3 --> RB
    end

    subgraph "Ring-3 (User Space)"
        GL[Go BPF Loader (CGO)]
        GR[Go WebSocket Relay]
        UI[Next.js Dashboard]
        
        RB -->|Read Maps| GL
        GL --> GR
        GR -->|ws://events| UI
    end
    
    style K fill:#2c3e50,stroke:#fff,stroke-width:2px,color:#fff
    style RB fill:#e74c3c,stroke:#fff,stroke-width:2px,color:#fff
    style GR fill:#00ADD8,stroke:#fff,stroke-width:2px,color:#fff
    style UI fill:#000,stroke:#fff,stroke-width:2px,color:#fff
```

---

## ⚡ Deployment & Infrastructure

### Cloud C2 Deployment (Docker & Terraform)
DriftNet's Next.js dashboard is fully containerized and can be deployed as a Command & Control (C2) server on AWS using Terraform.

1. **Local Orchestration (Docker Compose)**
   ```bash
   cd deploy/
   docker-compose up -d --build
   ```
2. **Cloud Provisioning (Terraform)**
   ```bash
   cd deploy/terraform/
   terraform init
   terraform apply -auto-approve
   ```

### Edge Node Installation (Android)
- A rooted Android device (Magisk).
- Kernel version `>= 5.10` with `CONFIG_BPF_SYSCALL=y`.
- Ubuntu Chroot environment configured in `/data/local/ubuntu`.

**1. Flash the Magisk Module**
```bash
cd magisk_module/
zip -r OMNI_Magisk_Release.zip .
adb push OMNI_Magisk_Release.zip /sdcard/Download/
```
*Install via Magisk Manager and reboot.*

**2. Start the Telemetry Relay**
The Go relay compiles down to a statically linked ARM64 binary.
```bash
cd modules/ebpf_kernel
GOOS=linux GOARCH=arm64 go build -o driftnetd bpf_loader.go bpf_relay.go
adb push driftnetd /data/local/tmp/
adb shell "su -c 'chmod +x /data/local/tmp/driftnetd && /data/local/tmp/driftnetd'"
```

---

## 🛡️ Telemetry & Benchmarks

- **Process Spawning (`sys_execve`):** Detects hidden shell executions and payload staging.
- **Network Exfiltration (`sys_connect`):** Maps outbound socket connections to malicious IPs before DNS resolution.
- **File System Tampering (`sys_openat`):** Monitors access to sensitive credentials, `AndroidManifest.xml`, and shared preferences.

**Performance:** DriftNet's eBPF probes induce less than `2µs` of latency per syscall, making them entirely invisible to standard Ring-3 timing attacks. *See [BENCHMARKS.md](BENCHMARKS.md) for full performance telemetry against Frida and Xposed.*

<div align="center">
  <i>Built for performance. Built for the edge.</i>
</div>
