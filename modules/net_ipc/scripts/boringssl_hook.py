#!/usr/bin/env python3
import frida
import sys
import time

JS_CODE = """
if (Process.arch === 'arm64') {
    console.log("[*] Frida attaching to ARM64 target process: " + Process.id);
    
    var ssl_read_ptr = Module.findExportByName("libssl.so", "SSL_read");
    var ssl_write_ptr = Module.findExportByName("libssl.so", "SSL_write");
    
    if (ssl_read_ptr) {
        Interceptor.attach(ssl_read_ptr, {
            onEnter: function (args) {
                this.ssl = args[0];
                this.buf = args[1];
                this.num = args[2].toInt32();
            },
            onLeave: function (retval) {
                var bytes_read = retval.toInt32();
                if (bytes_read > 0) {
                    var payload = Memory.readByteArray(this.buf, bytes_read);
                    console.log("\\n[<<< SSL_read Plaintext Received (" + bytes_read + " bytes)]");
                    console.log(hexdump(payload, { offset: 0, length: Math.min(bytes_read, 256), header: true, ansi: true }));
                }
            }
        });
        console.log("[+] Hooked libssl.so!SSL_read at " + ssl_read_ptr);
    } else {
        console.log("[-] Export SSL_read not found in libssl.so");
    }

    if (ssl_write_ptr) {
        Interceptor.attach(ssl_write_ptr, {
            onEnter: function (args) {
                this.ssl = args[0];
                this.buf = args[1];
                this.num = args[2].toInt32();
                if (this.num > 0) {
                    var payload = Memory.readByteArray(this.buf, this.num);
                    console.log("\\n[>>> SSL_write Plaintext Sent (" + this.num + " bytes)]");
                    console.log(hexdump(payload, { offset: 0, length: Math.min(this.num, 256), header: true, ansi: true }));
                }
            },
            onLeave: function (retval) {}
        });
        console.log("[+] Hooked libssl.so!SSL_write at " + ssl_write_ptr);
    } else {
        console.log("[-] Export SSL_write not found in libssl.so");
    }
} else {
    console.log("[-] Non-arm64 process detected.");
}
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[+] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[-] {message['stack']}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 boringssl_hook.py <process_name_or_pid>")
        sys.exit(1)
        
    target = sys.argv[1]
    print(f"[*] Attaching Frida to: {target}")
    
    try:
        device = frida.get_usb_device()
        if target.isdigit():
            session = device.attach(int(target))
        else:
            session = device.attach(target)
            
        script = session.create_script(JS_CODE)
        script.on('message', on_message)
        script.load()
        print("[*] Script loaded successfully. Press Ctrl+C to detach.")
        sys.stdin.read()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()
