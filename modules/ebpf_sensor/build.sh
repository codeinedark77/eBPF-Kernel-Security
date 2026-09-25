#!/bin/bash
set -e

NDK_HOME="$NDK_HOME"
CLANG="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"

mkdir -p build

echo "[*] Compiling eBPF sensor..."
$CLANG -O2 -target bpf -c src/sensor.c -o build/sensor.o

echo "[+] Compilation successful!"
