#include <stdio.h>
#include <netdb.h> // gethostbyname
#include <strings.h> // bzero
#include <arpa/inet.h> // inet_ntoa
#include <unistd.h> // close
#include <sys/time.h>

#include "icmp.h"

#define BUF_SIZE 4096

//#define DEBUG

void decoder_plain(struct icmp_packet* icmp) {
    struct timeval* t = (struct timeval*)icmp->payload;
    uint16_t data = t->tv_usec & 0xFFFF;
    printf("%c%c", data >> 8, data & 0xFF);
    fflush(stdout);
}

struct timeval decoder_offset_tv = {0};
void decoder_offset(struct icmp_packet* icmp) {
    struct timeval* t = (struct timeval*)icmp->payload;
    if(decoder_offset_tv.tv_sec == 0 || decoder_offset_tv.tv_sec + 10 < t->tv_sec) {
        decoder_offset_tv = *t;
    } else {
        uint8_t data = (t->tv_sec - decoder_offset_tv.tv_sec - 1) * 1000 + t->tv_usec / 1000 - decoder_offset_tv.tv_usec / 1000;
        printf("%c", data);
        fflush(stdout);
        decoder_offset_tv = *t;
    }
}

int main(int argc, char* argv[]) {
    struct sockaddr_in cliaddr;
    socklen_t cliaddrlen = sizeof(struct sockaddr_in);

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(fd < 0) {
        perror("socket");
        return 1;
    }

    char buf[BUF_SIZE];

    while (1) {
        ssize_t n = recvfrom(fd, buf, BUF_SIZE, 0, (struct sockaddr*)&cliaddr, &cliaddrlen);

        struct iphdr* ip_header = (struct iphdr*)buf;
        struct icmp_packet* icmp = (struct icmp_packet*)(buf + (4 * ip_header->ihl));
        uint16_t packet_size = (ntohs(ip_header->tot_len)) - (4*ip_header->ihl);

#ifdef DEBUG
        printf("Packet from %s (size: %li %u)\n", inet_ntoa(cliaddr.sin_addr), n, packet_size);
        printf("HEX:\n");
        for(int i = 0; i < n; i++) {
            printf("%02x ", buf[i] & 0xFF);
        }
        printf("\n");
        printf("raw! %u %u %u/%u\n", icmp->type, icmp->code, icmp->seq, icmp->id);
#endif // DEBUG

        if(packet_size == sizeof(struct icmp_packet) && icmp_check(icmp)) {
            if(icmp->type != 8) {
                continue;
            }
            if(icmp->seq == 0) {
                printf("%s: ", inet_ntoa(cliaddr.sin_addr));
            }

//            decoder_plain(icmp);
            decoder_offset(icmp);
        }
    }

    close(fd);
    return 0;
}