#!/usr/bin/env python3
"""
driftnet relay: attaches Frida to a target app on the phone (over USB or
adb-over-Tailscale), receives batched hook events via Frida's message
channel, and forwards each event to driftnetd's WebSocket ingestion
endpoint on the laptop.

This two-process design (Frida agent in JS + this relay in Python) exists
because Frida's JS runtime doesn't ship a WebSocket client, but Frida's
send()/message channel to the host process is rock solid — so the host
process (this script) does the network fan-out instead.

Usage:
    pip install frida frida-tools websocket-client
    python3 relay.py --package com.example.targetapp --driftnet-url ws://100.x.y.z:8787/ws/ingest

Requires: frida-server running on the phone (matching frida version),
reachable via `frida -U` (USB) or `frida -H <tailscale-ip>:27042` (network).
"""

import argparse
import json
import sys
import threading
import time

try:
    import frida
except ImportError:
    print("Missing dependency: pip install frida frida-tools", file=sys.stderr)
    sys.exit(1)

try:
    import websocket  # websocket-client
except ImportError:
    print("Missing dependency: pip install websocket-client", file=sys.stderr)
    sys.exit(1)


class DriftnetRelay:
    def __init__(self, driftnet_url: str, agent_script_path: str):
        self.driftnet_url = driftnet_url
        self.agent_script_path = agent_script_path
        self.ws = None
        self.ws_lock = threading.Lock()
        self._connect()

    def _connect(self):
        with self.ws_lock:
            try:
                self.ws = websocket.create_connection(self.driftnet_url, timeout=5)
                print(f"[relay] connected to driftnetd at {self.driftnet_url}")
            except Exception as e:
                print(f"[relay] failed to connect to driftnetd: {e}", file=sys.stderr)
                self.ws = None

    def _send_event(self, event: dict):
        payload = json.dumps(
            {
                "device": event.get("device", "unknown"),
                "app": event.get("app", "unknown"),
                "kind": event.get("kind", "custom"),
                "detail": event.get("detail", {}),
                "app_version": event.get("app_version", ""),
            }
        )
        with self.ws_lock:
            if self.ws is None:
                self._connect()
            if self.ws is None:
                return
            try:
                self.ws.send(payload)
            except Exception as e:
                print(f"[relay] send failed, reconnecting: {e}", file=sys.stderr)
                self.ws = None

    def on_message(self, message, data):
        if message["type"] == "send":
            payload = message["payload"]
            if payload.get("type") == "driftnet_batch":
                events = payload.get("events", [])
                for ev in events:
                    self._send_event(ev)
                if events:
                    print(f"[relay] forwarded {len(events)} events")
        elif message["type"] == "error":
            print(f"[relay] agent error: {message.get('stack', message)}", file=sys.stderr)

    def run(self, target_package: str, use_usb: bool, host: str | None):
        if host:
            device = frida.get_device_manager().add_remote_device(host)
        elif use_usb:
            device = frida.get_usb_device(timeout=10)
        else:
            device = frida.get_local_device()

        print(f"[relay] attaching to {target_package} on {device.name}")
        session = device.attach(target_package)

        with open(self.agent_script_path, "r") as f:
            script_src = f.read()

        script = session.create_script(script_src)
        script.on("message", self.on_message)
        script.load()

        print(f"[relay] attached to {target_package}, streaming events (Ctrl+C to stop)")

        def ws_listener():
            while True:
                try:
                    if self.ws:
                        msg = self.ws.recv()
                        if msg:
                            data = json.loads(msg)
                            if data.get("type") == "action":
                                print(f"[relay] received action from driftnetd: {data.get('action')}")
                                script.post(data)
                    else:
                        time.sleep(1)
                except Exception as e:
                    time.sleep(1)

        t = threading.Thread(target=ws_listener, daemon=True)
        t.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[relay] shutting down")
            session.detach()


def main():
    ap = argparse.ArgumentParser(description="driftnet Frida-to-WebSocket relay")
    ap.add_argument("--package", required=True, help="target app package name")
    ap.add_argument(
        "--driftnet-url",
        default="ws://127.0.0.1:8787/ws/ingest",
        help="driftnetd WebSocket ingest URL (use its Tailscale address)",
    )
    ap.add_argument(
        "--agent",
        default="agent/hooks.js",
        help="path to the Frida agent script",
    )
    ap.add_argument("--usb", action="store_true", default=True, help="use USB-attached device (default)")
    ap.add_argument("--host", default=None, help="connect to frida-server over network instead, e.g. 100.x.y.z:27042")
    args = ap.parse_args()

    relay = DriftnetRelay(args.driftnet_url, args.agent)
    relay.run(args.package, use_usb=args.usb and not args.host, host=args.host)


if __name__ == "__main__":
    main()
