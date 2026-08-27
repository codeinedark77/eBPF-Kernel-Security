# ARM64 Low-Level Disassembly & Reverse Engineering Guide

**Target Architecture:** `aarch64` (ARM 64-bit v8-A / Snapdragon 870)  
**Binary Analyzed:** `modules/appsec/anti_debug_arm64`  
**Tooling:** Frida v16, NDK Clang Disassembler (`llvm-objdump`), Ghidra  

---

## 🔬 ARM64 Architecture Fundamentals

When analyzing native Android binaries (`.so` libraries or executables compiled for `aarch64`), understanding ARM64 register architecture and calling conventions is essential:

* **`x0` - `x7` (64-bit) / `w0` - `w7` (32-bit):** Parameter passing and return value registers.
  * Function arguments `arg0` through `arg7` are passed in `x0`-`x7`.
  * Return values are stored in `x0` (or `w0` for 32-bit integers).
* **`x8` (Indirect Result / Syscall Number):** Used to hold the Linux system call number during raw `SVC #0` invocations.
* **`x29` (Frame Pointer - FP):** Points to the current stack frame.
* **`x30` (Link Register - LR):** Holds the return address for function calls executed via `BL` (Branch with Link).
* **`SP` (Stack Pointer):** Points to the top of the current stack.

---

## 🎯 Disassembly Analysis: `check_ptrace()`

Below is the annotated ARM64 assembly disassembly of the compiled `check_ptrace()` function from `anti_debug.cpp`:

```assembly
; ============================================================================
; Function: check_ptrace() -> int
; Purpose: Execute PTRACE_TRACEME to detect active debuggers
; ============================================================================

check_ptrace:
    SUB         SP, SP, #0x20           ; Allocate 32 bytes of stack frame
    STP         X29, X30, [SP, #0x10]   ; Store Frame Pointer and Link Register on stack
    ADD         X29, SP, #0x10          ; Set Frame Pointer to stack base

    ; Prepare ptrace(PTRACE_TRACEME, 0, 1, 0) call
    MOV         W0, #0x0                ; W0 = PTRACE_TRACEME (enum value 0)
    MOV         W1, #0x0                ; W1 = PID 0
    MOV         W2, #0x1                ; W2 = addr 1
    MOV         W3, #0x0                ; W3 = data 0
    BL          ptrace                  ; Branch to libc!ptrace export

    ; Check Return Value in W0
    CMP         W0, #0x0                ; Compare return value with 0 (Success)
    B.GE        .L_PTRACE_SUCCESS       ; Branch to SUCCESS if return >= 0

.L_PTRACE_FAILED:
    ; PTRACE_TRACEME returned -1 (Debugger Detected!)
    ADRP        X0, .LC_ALERT_MSG       ; Load page address of alert string
    ADD         X0, X0, #:lo12:.LC_ALERT_MSG
    BL          printf                  ; Print Security Alert
    MOV         W0, #0x1                ; Return 1 (Failure / Tampered)
    B           .L_EPILOGUE

.L_PTRACE_SUCCESS:
    ; PTRACE_TRACEME returned 0 (Clean)
    ADRP        X0, .LC_PASS_MSG        ; Load page address of pass string
    ADD         X0, X0, #:lo12:.LC_PASS_MSG
    BL          printf                  ; Print Pass Message
    MOV         W0, #0x0                ; Return 0 (Success / Clean)

.L_EPILOGUE:
    LDP         X29, X30, [SP, #0x10]   ; Restore Frame Pointer and Link Register
    ADD         SP, SP, #0x20           ; Deallocate stack frame
    RET                                 ; Return to caller (address in X30)
```

---

## ⚡ Frida Dynamic Register Patching Strategy

Understanding the assembly above reveals exactly how Frida bypasses the anti-debugging security check:

1. **Option A (Export Interception):** Attach to `libc!ptrace` and force the `retval` to `0`:
   ```javascript
   Interceptor.attach(Module.findExportByName(null, "ptrace"), {
       onLeave: function (retval) {
           retval.replace(0); // Overwrite W0 register with 0 (Success)
       }
   });
   ```

2. **Option B (Direct ARM64 Instruction Patching):** If `ptrace` is invoked via inline assembly (`SVC #0`), locate the `CMP W0, #0` or conditional branch `B.GE` instruction in memory and overwrite the instruction opcode with `NOP` (`0x1F2003D5` in ARM64 hex):
   ```javascript
   // Overwrite conditional branch with NOP (No Operation)
   Memory.writeByteArray(target_address, [0xd5, 0x03, 0x20, 0x1f]);
   ```

---

## 🏁 Summary
By combining static disassembly analysis (understanding stack frames, `X0`/`W0` return registers, and `BL` branch instructions) with dynamic Frida instrumentation, security analysts can inspect and defeat complex native anti-tampering defenses on modern Android `aarch64` platforms.
