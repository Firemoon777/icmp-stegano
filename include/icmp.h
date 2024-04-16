#pragma once

#include <stdint.h>
#include <string.h>
#include <netinet/ip_icmp.h>

#define ICMP_PAYLOAD_SIZE 56

#pragma pack(push, 1)
struct icmp_packet {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
    char payload[ICMP_PAYLOAD_SIZE];
};
#pragma pack(pop)

extern struct icmp_packet icmp_packet;

void icmp_create_echo(uint16_t seq, uint16_t id);
uint16_t icmp_calculate_checksum(char* buf, uint16_t buflen);
int icmp_check(struct icmp_packet* packet);
