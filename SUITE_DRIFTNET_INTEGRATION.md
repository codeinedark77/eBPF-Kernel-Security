# Master Enterprise Integration Architecture: android_systems_suite + DriftNet

**Target Platform:** `aarch64-linux-android` (OnePlus 9R / Snapdragon 870 / Adreno 650 GPU)  
**Integration Paradigm:** High-Performance Native Telemetry + Machine Learning Compression Novelty Detection  

---

## 🏛️ System Architecture

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   ONEPLUS 9R (TARGET)                                  │
│                                                                                        │
│   ┌────────────────────────────────┐            ┌──────────────────────────────────┐   │
│   │  android_systems_suite         │            │  DriftNet Frida Agent            │   │
│   │  • pcap_daemon (Raw IP/TCP)    │            │  • agent/hooks.js                │   │
│   │  • anti_debug (Sec Testbed)    │            │    (OkHttp, SharedPrefs, Crypto) │   │
│   │  • vulkan_engine (Adreno 650)  │            │  • scripts/relay.py (WebSocket)  │   │
│   └───────────────┬────────────────┘            └────────────────┬─────────────────┘   │
└───────────────────┼──────────────────────────────────────────────┼─────────────────────┘
                    │                                              │
                    │               Tailscale Mesh                 │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   HOST WORKSTATION                                     │
│                                                                                        │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │  driftnetd (Go Aggregator Backend)                                             │   │
│   │  ├── zstd Novelty Scorer (Kolmogorov Complexity Approximation)                 │   │
│   │  ├── Rules Engine (Secret / Sensitive Path / Crypto Detection)                 │   │
│   │  └── Local Ollama 8B LLM Triage Engine                                         │   │
│   └──────────────────────────────────────┬─────────────────────────────────────────┘   │
│                                          │                                             │
│                                          ▼                                             │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │  DriftNet Next.js Dashboard UI (Live Threat Seismograph & Anomaly Reports)     │   │
│   └────────────────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Integration Bridge Workflow

### Step 1: Raw Packet & TLS Stream Convergence
- **`pcap_daemon`** captures lower-level TCP/UDP interface events on-device and pipes transport-layer metrics directly into the `relay.py` telemetry payload stream.
- **`boringssl_hook.py`** extracts decrypted BoringSSL buffer sizes and HTTP/2 headers without modifying payload bodies, preserving local privacy boundaries while feeding the `driftnetd` `zstd` compressor baseline.

### Step 2: On-Device Anti-Analysis Protection Verification
- Run `anti_debug_arm64` on `/data/local/tmp/anti_debug` while `agent/hooks.js` is attached.
- Verifies that `driftnet`'s Frida instrumentation stealthily inspects high-security native binaries without triggering `PTRACE_TRACEME` or `TracerPid` integrity traps.

### Step 3: Hardware-Accelerated Adreno 650 Execution
- **`vulkan_engine`** initializes Vulkan 1.1 directly on Qualcomm's Adreno 650 GPU via `libvulkan.so`.
- Offloads heavy local data transformations and matrix operations from CPU to GPU, maximizing battery efficiency and throughput.

---

## 🚀 Portfolio Deployment Instructions

```bash
# 1. Run Vulkan GPU Engine Test on Phone
adb shell "/data/local/tmp/vulkan_engine"

# 2. Start DriftNet Backend on Laptop
cd driftnet && ./driftnetd

# 3. Launch Frida Telemetry Relay
cd driftnet && python3 scripts/relay.py --package <target_app>

# 4. Launch Next.js Security Dashboard
cd driftnet/frontend && npm run dev
```
