#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export TZ=Etc/UTC

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

apt-get update >/dev/null 2>&1
apt-get install -y \
  golang \
  clang \
  llvm \
  libbpf-dev \
  linux-headers-generic \
  gcc-aarch64-linux-gnu \
  libc6-dev-arm64-cross >/dev/null 2>&1

echo "Testing Go Build..."
cd "$repo_root/modules/driftnet"
go mod tidy
env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -v -o driftnetd ./cmd/driftnetd 2>go_error.log

if [[ -s go_error.log ]]; then
  cat go_error.log >&2
  exit 1
fi

echo "Testing eBPF Build..."
cd "$repo_root/modules/ebpf_kernel"
clang -O2 -target bpf -g -D__TARGET_ARCH_arm64 \
  -c bpf_probe.c -o bpf_probe.o 2>ebpf_error.log

if [[ -s ebpf_error.log ]]; then
  cat ebpf_error.log >&2
  exit 1
fi

echo "Done."
