#pragma once
#include <arpa/inet.h>
#include <ctime>
#include <iostream>

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;

uint16_t checksum(const uint8_t* buf, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len; i += 2) {
        uint16_t word = (buf[i] << 8) | (i + 1 < len ? buf[i + 1] : 0);
        sum += word;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~static_cast<uint16_t>(sum);
}

uint16_t swap16(uint16_t val) {
    return (val >> 8) | (val << 8);
}

uint32_t swap32(uint32_t val) {
    return ((val >> 24) & 0xff) | ((val >> 8) & 0xff00) |
           ((val << 8) & 0xff0000) | ((val << 24) & 0xff000000);
}