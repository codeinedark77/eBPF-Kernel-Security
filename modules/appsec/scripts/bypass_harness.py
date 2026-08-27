#!/usr/bin/env python3
import frida
import sys

JS_CODE = """
console.log("[*] AppSec Dynamic Bypass Harness Loaded.");

// Hook access() to bypass root file detection
var access_ptr = Module.findExportByName(null, "access");
if (access_ptr) {
    Interceptor.attach(access_ptr, {
        onEnter: function (args) {
            var path = Memory.readUtf8String(args[0]);
            if (path.indexOf("su") !== -1 || path.indexOf("Superuser") !== -1) {
                console.log("[+] Intercepted su path check: " + path + " -> Spoofing F_OK (Not Found)");
                this.is_su = true;
            }
        },
        onLeave: function (retval) {
            if (this.is_su) {
                retval.replace(-1); // Return -1 (ENOENT file not found)
            }
        }
    });
    console.log("[+] Hooked libc!access for root bypass.");
}

// Hook ptrace() to bypass PTRACE_TRACEME checks
var ptrace_ptr = Module.findExportByName(null, "ptrace");
if (ptrace_ptr) {
    Interceptor.attach(ptrace_ptr, {
        onEnter: function (args) {
            var request = args[0].toInt32();
            if (request === 0) { // PTRACE_TRACEME = 0
                console.log("[+] Intercepted ptrace(PTRACE_TRACEME) -> Spoofing Success");
                this.is_traceme = true;
            }
        },
        onLeave: function (retval) {
            if (this.is_traceme) {
                retval.replace(0); // Return 0 (Success)
            }
        }
    });
    console.log("[+] Hooked libc!ptrace for anti-debug bypass.");
}

// Hook fopen() to spoof /proc/self/status TracerPid
var fopen_ptr = Module.findExportByName(null, "fopen");
if (fopen_ptr) {
    Interceptor.attach(fopen_ptr, {
        onEnter: function (args) {
            var filename = Memory.readUtf8String(args[0]);
            if (filename && filename.indexOf("/proc/self/status") !== -1) {
                console.log("[+] Intercepted fopen(" + filename + ")");
            }
        }
    });
}
"""

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 bypass_harness.py <process_name_or_pid>")
        sys.exit(1)
        
    target = sys.argv[1]
    print(f"[*] Attaching Frida Bypass Harness to: {target}")
    
    try:
        device = frida.get_usb_device()
        session = device.attach(int(target) if target.isdigit() else target)
        script = session.create_script(JS_CODE)
        script.load()
        print("[*] Bypass harness active. Press Ctrl+C to detach.")
        sys.stdin.read()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()
