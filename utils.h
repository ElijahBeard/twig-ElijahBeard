#pragma once
#include <arpa/inet.h>
#include <ctime>
#include <iostream>

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;
int debug = 0;
bool file_is_big_endian = false;

uint16_t checksum(uint16_t* buf, int len) {
    uint32_t sum = 0;
    for (; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(uint8_t*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

uint16_t swap16(uint16_t val) {
    return (val >> 8) | (val << 8);
}

uint32_t swap32(uint32_t val) {
    return ((val >> 24) & 0xff) |
           ((val >> 8) & 0xff00) |
           ((val << 8) & 0xff0000) |
           ((val << 24) & 0xff000000);
}

void print_timestamp(uint32_t ts_secs, uint32_t ts_usecs) {
    time_t raw_time = static_cast<time_t>(ts_secs);
    struct tm* t = localtime(&raw_time);
    if (t == nullptr) {
        printf("Invalid time\n");
        return;
    }
    printf("%04d-%02d-%02d %02d:%02d:%02d.%06u\n",
            t->tm_year + 1900,
            t->tm_mon + 1,
            t->tm_mday,
            t->tm_hour,
            t->tm_min,
            t->tm_sec,
            ts_usecs);
}
