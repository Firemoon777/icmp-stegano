#include <stdio.h>
#include <netdb.h> // gethostbyname
#include <strings.h> // bzero
#include <arpa/inet.h> // inet_ntoa
#include <unistd.h> // close
#include <sys/time.h>
#include <malloc.h>

#include "icmp.h"

#define TIME_OFFSET_MS 1000000

char* message;
size_t message_len = 0;

uint64_t encoder_plain() {
    uint16_t data = 0;
    switch (message_len) {
        case 0:
            return 0;
        case 1:
            data = message[0] << 8;
            message_len = 0;
            break;
        default:
            data = (message[0] << 8) + message[1];
            message_len -= 2;
            message += 2;
    }
    printf("Current message: %c%c\n", data >> 8, data & 0xFF);
    struct timeval* t = (struct timeval*)icmp_packet.payload;
    t->tv_usec = (t->tv_usec - t->tv_usec & 0xFFFF) + data;
    return TIME_OFFSET_MS;
}

int encoder_offset_started = 0;
struct timeval encoder_offset_tv = {0};

int encoder_offset() {
    if(message_len == 0) return 0;

    struct timeval* t = (struct timeval*)icmp_packet.payload;

    if(encoder_offset_tv.tv_sec == 0) {
        printf("Init\n");
        encoder_offset_tv = *t;
    } else {
        *t = encoder_offset_tv;
    }

    printf("Current letter: %c (%u)\n", message[0], (uint8_t)message[0]);

    encoder_offset_tv.tv_usec += ((uint8_t)message[0]) * 1000;
    encoder_offset_tv.tv_sec += 1 + encoder_offset_tv.tv_usec / 1000000;
    encoder_offset_tv.tv_usec = encoder_offset_tv.tv_usec % 1000000;

    printf("\t%lu:%lu -> %lu:%lu\n", t->tv_sec, t->tv_usec, encoder_offset_tv.tv_sec, encoder_offset_tv.tv_usec);

    message++;
    message_len--;

    return TIME_OFFSET_MS + (uint8_t)message[0] * 1000;
}

int main(int argc, char* argv[]) {
    printf("size header = %lu\n", sizeof(struct icmp));
    printf("size = %lu\n", sizeof(struct icmp_packet));
    if(argc != 3) {
        printf("%s: hostname message\n", argv[0]);
        return 1;
    }
    char* hostname = argv[1];
    printf("Host: %s\n", argv[1]);

    struct sockaddr_in dstaddr;
    socklen_t dstaddrlen = sizeof(struct sockaddr_in);
    bzero(&dstaddr, dstaddrlen);
    dstaddr.sin_family = AF_INET;

    struct hostent* host = gethostbyname(hostname);
    dstaddr.sin_addr = *((struct in_addr*)host->h_addr_list[0]);
    printf("IP: %s\n", inet_ntoa(dstaddr.sin_addr));

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(fd < 0) {
        perror("socket");
        return 1;
    }

    message = argv[2];
    message_len = strlen(message) + 1;
    printf("Message: %s (%lu)\n", message, message_len);

    uint16_t seq = 0;

    while(1) {
        icmp_create_echo(seq++, 0);
        struct timeval* t = (struct timeval*)icmp_packet.payload;
        gettimeofday(t, NULL);
        for(int j = sizeof(struct timeval); j < ICMP_PAYLOAD_SIZE; j++) {
            icmp_packet.payload[j] = j;
        }
//        uint64_t result = encoder_plain();
        uint64_t result = encoder_offset();
        if(!result) {
            break;
        }

        icmp_packet.checksum = icmp_calculate_checksum((char*)&icmp_packet, sizeof(struct icmp_packet));

        if(sendto(fd, (void*)&icmp_packet, sizeof(struct icmp_packet), 0, (struct sockaddr*)&dstaddr, dstaddrlen) < 0) {
            perror("sendto");
            break;
        }
        usleep(result);
    }

    close(fd);
    return 0;
}