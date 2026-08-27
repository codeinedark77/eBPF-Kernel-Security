/*
 * AetherMobile / android_systems_suite: Zero-Copy Packet Capture Daemon
 * Architecture: Linux AF_PACKET + PACKET_MMAP (RX_RING)
 * Target: aarch64-linux-android (Snapdragon 870 / Linux 5.4 Kernel)
 *
 * Technical Rationale:
 * Standard raw sockets require the Linux kernel to copy packet buffers from 
 * kernel memory space into user-space buffers via recvfrom() / read() syscalls.
 * 
 * PACKET_MMAP creates a shared ring-buffer in memory mapped between kernel space 
 * and user space using mmap(). The kernel writes incoming frames directly into 
 * the mapped ring buffer, eliminating context switches and copy overhead.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define CONF_RING_FRAMES 128
#define CONF_FRAME_SIZE 2048
#define CONF_BLOCK_SIZE 4096
#define CONF_BLOCK_NR (CONF_RING_FRAMES * CONF_FRAME_SIZE / CONF_BLOCK_SIZE)

struct ring_frame_header {
    struct tpacket_hdr tp_h;
    struct sockaddr_ll tp_l;
};

int main(int argc, char *argv[]) {
    printf("========================================================\n");
    printf("  AetherMobile: High-Performance Zero-Copy RX_RING Engine\n");
    printf("  Architecture: Linux AF_PACKET + PACKET_MMAP (aarch64)\n");
    printf("========================================================\n\n");

    // 1. Create Raw Packet Socket
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (fd < 0) {
        perror("[-] Socket creation failed (Requires Root / CAP_NET_RAW)");
        return 1;
    }
    printf("[+] AF_PACKET raw socket created.\n");

    // 2. Configure PACKET_MMAP RX_RING parameters
    struct tpacket_req req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = CONF_BLOCK_SIZE;
    req.tp_frame_size = CONF_FRAME_SIZE;
    req.tp_block_nr   = CONF_BLOCK_NR;
    req.tp_frame_nr   = CONF_RING_FRAMES;

    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, (void *)&req, sizeof(req)) < 0) {
        perror("[-] setsockopt(PACKET_RX_RING) failed");
        close(fd);
        return 1;
    }
    printf("[+] PACKET_RX_RING configured (%u frames, %u bytes/block).\n", req.tp_frame_nr, req.tp_block_size);

    // 3. Map shared memory ring buffer between Kernel & User space
    size_t ring_size = req.tp_block_nr * req.tp_block_size;
    uint8_t *mapped_ring = (uint8_t *)mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    
    if (mapped_ring == MAP_FAILED) {
        perror("[-] mmap() shared ring-buffer allocation failed");
        close(fd);
        return 1;
    }
    printf("[+] Zero-Copy shared memory ring buffer mapped at %p (%zu KB).\n", mapped_ring, ring_size / 1024);

    // 4. Bind socket to default network interface (wlan0 / eth0)
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex  = if_nametoindex("wlan0");
    if (sll.sll_ifindex == 0) {
        sll.sll_ifindex = 1; // Fallback to loopback or primary index
    }
    
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("[-] Socket bind to interface failed");
        munmap(mapped_ring, ring_size);
        close(fd);
        return 1;
    }
    printf("[+] Socket bound to interface index: %d\n", sll.sll_ifindex);
    printf("\n[*] Engine ready. Listening for Zero-Copy ring buffer frames...\n\n");

    // 5. Poll frames directly from mapped memory ring
    int captured = 0;
    unsigned int frame_index = 0;

    while (captured < 10) {
        struct tpacket_hdr *header = (struct tpacket_hdr *)(mapped_ring + (frame_index * CONF_FRAME_SIZE));
        
        // Check if Kernel handed frame status to TP_STATUS_USER
        if (header->tp_status & TP_STATUS_USER) {
            struct iphdr *iph = (struct iphdr *)((uint8_t *)header + header->tp_net);
            
            struct sockaddr_in src, dst;
            src.sin_addr.s_addr = iph->saddr;
            dst.sin_addr.s_addr = iph->daddr;
            
            printf("[Frame %02d] [Zero-Copy Ring] %s -> %s | Len: %u bytes | Status: TP_STATUS_USER\n",
                   captured + 1,
                   inet_ntoa(src.sin_addr),
                   inet_ntoa(dst.sin_addr),
                   header->tp_len);
                   
            // Release frame back to Kernel (TP_STATUS_KERNEL)
            header->tp_status = TP_STATUS_KERNEL;
            frame_index = (frame_index + 1) % CONF_RING_FRAMES;
            captured++;
        } else {
            usleep(10000); // 10ms polling sleep
        }
    }

    printf("\n[*] Captured 10 frames via Zero-Copy mmap ring buffer.\n");
    munmap(mapped_ring, ring_size);
    close(fd);
    printf("[+] Shared ring unmapped cleanly. Zero-Copy RX engine terminated.\n");
    return 0;
}
