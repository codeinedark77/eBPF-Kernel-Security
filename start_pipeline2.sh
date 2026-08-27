killall bpf_loader
cd /root/loader
nohup sh -c './bpf_loader bpf_probe.o | ./bpf_relay' > /root/loader/nohup.out 2>&1 &
