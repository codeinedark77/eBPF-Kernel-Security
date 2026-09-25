#!/system/bin/sh
# Run as root on the phone -- `adb shell` then `su`, a root shell app, or Shizuku's
# `rish`. Everything here is read-only, changes nothing. I can't test this against
# your actual chroot setup (busybox vs toybox vs full coreutils in there is unknown
# to me), so treat this as a strong starting point, not a guaranteed one-shot script
# -- if a command isn't found, that's your environment telling you something, not a
# failure to panic about.
#
# Uses the same "chroot into /data/local/ubuntu as root" pattern your own
# magisk_module/service.sh already relies on, so these checks run in the same
# namespace driftnetd actually lives in rather than the bare Android side.

RUN() { chroot /data/local/ubuntu /bin/su - root -c "$1" 2>&1; }

echo "===== 1) What is driftnetd ACTUALLY bound to right now? ====="
echo "Before applying the patch, expect 0.0.0.0:8787. After (and a restart), expect 127.0.0.1:8787."
RUN "ss -tlnp 2>/dev/null | grep 8787 || netstat -tlnp 2>/dev/null | grep 8787 || echo 'ss/netstat not in the chroot -- try: cat /proc/net/tcp and look for port 8787 in hex (0x1E43), then check which socket owns it'"

echo
echo "===== 2) What -model flag is the RUNNING process actually using? ====="
echo "Ground truth for TinyLlama vs Llama-3.1-8B, independent of what any doc or flag default claims."
ps -ef 2>/dev/null | grep driftnetd | grep -v grep
RUN "ps aux 2>/dev/null | grep driftnetd | grep -v grep"

echo
echo "===== 3) Which kprobes are actually attached in the running kernel? ====="
echo "Confirms only security_socket_connect + do_execve_file are live, nothing for openat."
echo "DO NOT try to re-enable the commented-out openat probe to 'test' this properly --"
echo "its own comment says that caused kernel panics on CRDroid. If you ever do want to"
echo "poke at it, do that on a secondary device or with a recovery-restorable backup,"
echo "not your daily phone -- a boot-persistent Magisk module that panics on every boot"
echo "is a genuinely annoying thing to have to recover from."
cat /sys/kernel/debug/tracing/kprobe_events 2>/dev/null
RUN "bpftool prog list 2>/dev/null"

echo
echo "===== 4) Is Ollama actually serving the model you expect? ====="
RUN "curl -s http://127.0.0.1:11434/api/tags"

echo
echo "===== 5) Cross-device exposure check ====="
echo "Get this phone's tailnet address first:"
RUN "tailscale ip -4 2>/dev/null" || echo "  (run 'tailscale ip -4' wherever Tailscale is actually installed in your setup)"
echo "Then, from a DIFFERENT device on the same tailnet, run:"
echo "  curl -s http://<that-ip>:8787/healthz"
echo "  curl -s http://<that-ip>:8787/api/events/recent"
echo "Before the patch: expect a real answer, from any device that can reach that IP, with no login."
echo "After the patch + restart: expect a timeout / connection refused from anything off-device."
