#!/bin/bash
echo "[*] Killing old instances..."
adb shell 'su -c "pkill -9 -f llama; pkill -9 -f driftnetd"'
sleep 2

echo "[*] Skipping Local AI on phone to prevent thermal shutdown..."
# Local AI runs on the laptop via Ollama
sleep 1

echo "[*] Starting DriftNet (Dashboard + eBPF Analytics) on port 8787..."
# -addr changed from 0.0.0.0:8787 to 127.0.0.1:8787: no endpoint here has auth, and
# CheckOrigin accepts any origin, so 0.0.0.0 meant anything that could reach the
# phone's IP could read every finding and open the raw ingest socket. adb already
# reaches loopback via `adb forward`/`adb reverse`, so this doesn't need a wide bind.
adb shell 'su -c "chroot /data/local/ubuntu /bin/su - root -c \"nohup /root/driftnet/bin/driftnetd -addr 127.0.0.1:8787 -data /root/driftnet/data -ollama http://127.0.0.1:11434 -model llama3.1:8b -web /root/driftnet/frontend/out > /root/driftnet/nohup.out 2>&1 &\""'
sleep 5

echo "[*] Establishing Network Bridges..."
adb forward tcp:8787 tcp:8787
adb reverse tcp:11434 tcp:11434
echo "[+] Forwarded 8787 (Dashboard) to Laptop and Reversed 11434 (Local AI) to Phone"

echo "[*] System Ready. Testing Endpoints..."
curl -s -I http://127.0.0.1:8787/ | head -n 1
curl -s -X POST http://127.0.0.1:11434/v1/chat/completions -H "Content-Type: application/json" -d '{"model": "llama3.1:8b", "messages": [{"role": "user", "content": "Hello"}], "max_tokens": 10}' | grep -o '"content":"[^"]*"'

