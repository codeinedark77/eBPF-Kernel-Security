#!/bin/bash
cd /root/loader
pkill -f bpf_loader
pkill -f bpf_relay
./bpf_loader bpf_probe.o | ./bpf_relay > nohup.out 2>&1 &
