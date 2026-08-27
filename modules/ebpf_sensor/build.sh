#!/bin/bash
set -e

NDK_HOME="/home/codeinedark/Downloads/android-ndk-r26b"
CLANG="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"

mkdir -p build

echo "[*] Compiling eBPF sensor..."
$CLANG -O2 -target bpf -c src/sensor.c -o build/sensor.o

echo "[+] Compilation successful!"
