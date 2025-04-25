#pragma once
#include <arpa/inet.h>
#include <ctime>
#include <iostream>
#include <unordered_map>

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;

void construct_path(const char* ip_str, const char* mask_str, char** paths) {
    unsigned int octets[4];
    sscanf(ip_str, "%u.%u.%u.%u", &octets[0], &octets[1], &octets[2], &octets[3]);

    // masklength
    int masklength = atoi(mask_str);

    // get network address
    int host_bits = 32 - masklength;
    uint32_t ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    uint32_t mask = ~((1U << host_bits) - 1);
    uint32_t network = ip & mask;
    octets[0] = (network >> 24) & 0xFF;
    octets[1] = (network >> 16) & 0xFF;
    octets[2] = (network >> 8) & 0xFF;
    octets[3] = network & 0xFF;

    // filename
    char filename[64];
    snprintf(filename, sizeof(filename), "%u.%u.%u.%u_%s.dmp",
                octets[0], octets[1], octets[2], octets[3], mask_str);

    paths[0] = (char*)malloc(strlen(filename) + 3);
        paths[1] = (char*)malloc(strlen(filename) + 14);
        if (!paths[0] || !paths[1]) {
            perror("malloc");
            free(paths[0]);
            free(paths[1]);
        }
        strcpy(paths[0], "./");
        strcat(paths[0], filename);
        strcpy(paths[1], "../Twig_tools/");
        strcat(paths[1], filename);
}

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
