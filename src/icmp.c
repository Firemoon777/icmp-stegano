#include <stdio.h>
#include "icmp.h"

struct icmp_packet icmp_packet;

uint16_t icmp_calculate_checksum(char* buf, uint16_t buflen) {
    uint16_t* buf16 = (uint16_t*)buf;
    uint16_t buf16len = buflen / sizeof(uint16_t);

    uint32_t sum = 0;
    for(int i = 0; i < buf16len; i++) {
        sum += *(buf16 + i);
    }

    if(buflen % 2 != 0) {
        sum += (uint16_t)(buf[buf16len * 2 + 1]) * 0x100;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~(uint16_t)(sum & 0xFFFF);
}

int icmp_check(struct icmp_packet* packet) {
    return icmp_calculate_checksum((char*)packet, sizeof(struct icmp_packet)) == 0;
}

void icmp_create_echo(uint16_t seq, uint16_t id) {
    bzero(&icmp_packet, 8);
    icmp_packet.type = ICMP_ECHO;
    icmp_packet.code = 0;
    icmp_packet.seq = seq;
    icmp_packet.id = id;
    icmp_packet.checksum = 0;
}

