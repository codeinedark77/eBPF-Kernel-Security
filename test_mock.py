import websocket
import json
import time
import random

ws = websocket.create_connection("ws://127.0.0.1:8787/ws/ingest")

apps = ["com.android.chrome", "com.whatsapp", "com.evil.malware", "com.termux"]
files = ["/etc/hosts", "/data/data/com.whatsapp/databases/msgstore.db", "IP:192.168.1.100:4444", "/sys/fs/selinux/enforce"]

for _ in range(15):
    app = random.choice(apps)
    fname = random.choice(files)
    kind = "sys_openat"
    if "IP:" in fname:
        kind = "sys_connect"
        fname = "192.168.1.100:4444"
        
    ev = {
        "device": "SM-G998B",
        "app": app,
        "kind": kind,
        "detail": {"pid": random.randint(1000, 9000), "uid": 1000, "fname": fname},
        "app_version": "1.0"
    }
    ws.send(json.dumps(ev))
    print("Sent mock event:", ev)
    time.sleep(0.5)

ws.close()
