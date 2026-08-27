#!/bin/bash
echo "[*] Killing old instances..."
adb shell 'su -c "pkill -9 -f llama; pkill -9 -f driftnetd"'
sleep 2

echo "[*] Starting Local AI (llama.cpp) on port 11434..."
adb shell 'su -c "nohup env LD_LIBRARY_PATH=/data/local/tmp/llama /data/local/tmp/llama/llama-server -m /data/local/tmp/llama/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --host 127.0.0.1 --port 11434 -c 2048 > /data/local/tmp/llama/nohup.out 2>&1 &"'
sleep 5

echo "[*] Starting DriftNet (Dashboard + eBPF Analytics) on port 8787..."
adb shell 'su -c "chroot /data/local/ubuntu /bin/su - root -c \"nohup /root/driftnet/bin/driftnetd -addr 0.0.0.0:8787 -data /root/driftnet/data -ollama http://127.0.0.1:11434 -model tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf -web /root/driftnet/frontend/out > /root/driftnet/nohup.out 2>&1 &\""'
sleep 5

echo "[*] Forwarding Ports to Laptop..."
adb forward tcp:8787 tcp:8787
adb forward tcp:11434 tcp:11434
echo "[+] Forwarded 8787 (Dashboard) and 11434 (Local AI)"

echo "[*] System Ready. Testing Endpoints..."
curl -s -I http://127.0.0.1:8787/ | head -n 1
curl -s -X POST http://127.0.0.1:11434/v1/chat/completions -H "Content-Type: application/json" -d '{"model": "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf", "messages": [{"role": "user", "content": "Hello"}], "max_tokens": 10}' | grep -o '"content":"[^"]*"'

