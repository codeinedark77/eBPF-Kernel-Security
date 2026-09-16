#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
export TZ=Etc/UTC

echo "Testing Go Build..."
cd /workspace/modules/driftnet
apt-get update >/dev/null 2>&1
apt-get install -y golang >/dev/null 2>&1
go mod tidy
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -v -o driftnetd ./cmd/driftnetd 2> go_error.log || cat go_error.log

echo "Testing eBPF Build..."
apt-get install -y clang llvm libbpf-dev linux-headers-generic gcc-aarch64-linux-gnu libc6-dev-arm64-cross >/dev/null 2>&1
cd /workspace/modules/ebpf_kernel
clang -O2 -target bpf -g -D__TARGET_ARCH_arm64 -c bpf_probe.c -o bpf_probe.o 2> ebpf_error.log || cat ebpf_error.log

echo "Done."
