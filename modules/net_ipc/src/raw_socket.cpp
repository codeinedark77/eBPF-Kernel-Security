#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <iomanip>

#define PACKET_BUF_SIZE 65536

void process_packet(unsigned char* buffer, int size) {
    struct iphdr *iph = (struct iphdr*)buffer;
    
    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    
    std::cout << "[IP Packet] "
              << inet_ntoa(source.sin_addr) << " -> "
              << inet_ntoa(dest.sin_addr)
              << " | Protocol: ";
              
    if (iph->protocol == IPPROTO_TCP) {
        unsigned short iph_len = iph->ihl * 4;
        struct tcphdr *tcph = (struct tcphdr*)(buffer + iph_len);
        std::cout << "TCP (" << ntohs(tcph->source) << " -> " << ntohs(tcph->dest) << ")"
                  << " | Len: " << size << std::endl;
    } else if (iph->protocol == IPPROTO_UDP) {
        unsigned short iph_len = iph->ihl * 4;
        struct udphdr *udph = (struct udphdr*)(buffer + iph_len);
        std::cout << "UDP (" << ntohs(udph->source) << " -> " << ntohs(udph->dest) << ")"
                  << " | Len: " << size << std::endl;
    } else {
        std::cout << (int)iph->protocol << " | Len: " << size << std::endl;
    }
}

int main(int argc, char *argv[]) {
    std::cout << "========================================================\n";
    std::cout << "  Android Systems Suite: Native Raw Socket Sniffer\n";
    std::cout << "  Target Architecture: ARM64 (aarch64-linux-android)\n";
    std::cout << "========================================================\n\n";

    int sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        perror("Socket Creation Error (Requires Root / CAP_NET_RAW)");
        return 1;
    }

    unsigned char *buffer = (unsigned char *)malloc(PACKET_BUF_SIZE);
    if (!buffer) {
        std::cerr << "Failed to allocate packet memory buffer.\n";
        close(sock_raw);
        return 1;
    }

    std::cout << "[*] Raw socket initialized successfully. Listening for TCP packets...\n\n";

    int packet_count = 0;
    while (packet_count < 30) {
        struct sockaddr saddr;
        socklen_t saddr_len = sizeof(saddr);
        
        int data_size = recvfrom(sock_raw, buffer, PACKET_BUF_SIZE, 0, &saddr, &saddr_len);
        if (data_size < 0) {
            perror("Recvfrom error");
            break;
        }
        
        process_packet(buffer, data_size);
        packet_count++;
    }

    std::cout << "\n[*] Captured 30 packets. Shutting down raw socket listener.\n";
    free(buffer);
    close(sock_raw);
    return 0;
}
