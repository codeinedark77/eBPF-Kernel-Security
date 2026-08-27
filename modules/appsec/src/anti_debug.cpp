#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// 1. Anti-Debugging Check via PTRACE_TRACEME
int check_ptrace() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        printf("[!] SECURITY ALERT: Debugger detected via ptrace! (PTRACE_TRACEME failed)\n");
        return 1;
    }
    printf("[+] PTRACE check passed: No debugger attached.\n");
    return 0;
}

// 2. Anti-Debugging Check via /proc/self/status (TracerPid)
int check_tracer_pid() {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return 0;
    
    char line[256];
    int tracer_pid = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer_pid = atoi(&line[10]);
            break;
        }
    }
    fclose(fp);
    
    if (tracer_pid != 0) {
        printf("[!] SECURITY ALERT: Debugger/Frida detected! (TracerPid = %d)\n", tracer_pid);
        return 1;
    }
    printf("[+] TracerPid check passed: TracerPid is 0.\n");
    return 0;
}

// 3. Root Detection via Binary & Mount Checks
int check_root() {
    const char *su_paths[] = {
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/data/local/su",
        "/su/bin/su"
    };
    
    for (int i = 0; i < 9; i++) {
        if (access(su_paths[i], F_OK) == 0) {
            printf("[!] SECURITY ALERT: Root binary found at: %s\n", su_paths[i]);
            return 1;
        }
    }
    printf("[+] Root binary scan passed: Standard su paths clean.\n");
    return 0;
}

int main() {
    printf("========================================================\n");
    printf("  Android AppSec Challenge: Anti-Analysis Core\n");
    printf("  Target Architecture: ARM64 (aarch64-linux-android)\n");
    printf("========================================================\n\n");

    int status = 0;
    status |= check_ptrace();
    status |= check_tracer_pid();
    status |= check_root();

    if (status != 0) {
        printf("\n[x] SECURITY INTEGRITY CHECKS FAILED: Tampering Detected!\n");
        return 99;
    }

    printf("\n[SUCCESS] ALL INTEGRITY CHECKS PASSED: Environment Secure.\n");
    return 0;
}
