killall bpf_loader
cd /root/loader
nohup sh -c './bpf_loader bpf_probe.o | python3 bpf_relay.py' > /root/loader/nohup.out 2>&1 &
