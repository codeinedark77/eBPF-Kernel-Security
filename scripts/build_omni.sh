#!/bin/bash
set -e

# Move to the root of the android_systems_suite repository
cd "$(dirname "$0")/.."

echo "=========================================="
echo "    🛡️ DriftNet (Project OMNI) Builder   "
echo "=========================================="

if [ -z "$NDK_HOME" ]; then
    echo "[-] Error: NDK_HOME environment variable is not set."
    echo "    Please set it to your Android NDK path."
    echo "    Example: export NDK_HOME=/home/codeinedark/Android/Sdk/ndk/25.1.8937393"
    exit 1
fi

CLANG="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"

if [ ! -f "$CLANG" ]; then
    echo "[-] Error: Clang compiler not found at $CLANG"
    exit 1
fi

echo "[*] Compiling eBPF Kernel Probes (Ring-0)..."
cd modules/ebpf_kernel
$CLANG -O2 -target bpf -D__TARGET_ARCH_arm64 \
    -isystem $NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include \
    -isystem $NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/aarch64-linux-android \
    -c bpf_probe.c -o bpf_probe.o

echo "[*] Compiling Go Relays (bpf_loader & bpf_relay)..."
# Compile the BPF Loader
GOOS=linux GOARCH=arm64 go build -o bpf_loader bpf_loader.go
# Compile the BPF Relay
GOOS=linux GOARCH=arm64 go build -o bpf_relay bpf_relay.go
cd ../../

echo "[*] Compiling DriftNet Backend (driftnetd)..."
cd driftnet
GOOS=linux GOARCH=arm64 go build -o bin/driftnetd cmd/driftnetd/main.go
cd ../

echo "[*] Assembling Magisk Module Chroot structure..."
# Prepare the root layout required by service.sh
mkdir -p magisk_module/root/loader
mkdir -p magisk_module/root/driftnet/bin

cp modules/ebpf_kernel/bpf_probe.o magisk_module/root/loader/
cp modules/ebpf_kernel/bpf_loader magisk_module/root/loader/
cp modules/ebpf_kernel/bpf_relay magisk_module/root/loader/
cp driftnet/bin/driftnetd magisk_module/root/driftnet/bin/

echo "[*] Packaging OMNI_Magisk_Release.zip..."
cd magisk_module
# Remove any old zip to ensure a clean package
rm -f OMNI_Magisk_Release.zip
zip -r OMNI_Magisk_Release.zip ./* -x "OMNI_Magisk_Release.zip"
cd ../

echo "=========================================="
echo "[+] SUCCESS: Build complete!"
echo "[+] Magisk Module ready: magisk_module/OMNI_Magisk_Release.zip"
echo "=========================================="
