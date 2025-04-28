#pragma once
#include <arpa/inet.h>
#include <ctime>
#include <iostream>
#include <unordered_map>

#include "pheaders.h"

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

uint16_t checksum(const void* data, size_t len) {
    const uint16_t* buf = (const uint16_t*)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len) sum += *(uint8_t*)buf;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

inline uint16_t udp_checksum(const ipv4_hdr& ip, const udp_hdr& udp, const uint8_t* payload, size_t payload_len) {
    struct pseudo_header {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_length;
    } __attribute__((packed));

    pseudo_header ph;
    ph.src_addr = ip.src;
    ph.dst_addr = ip.dest;
    ph.zero = 0;
    ph.protocol = 17;
    ph.udp_length = udp.len;

    std::vector<uint8_t> data;

    data.insert(data.end(), (uint8_t*)&ph, (uint8_t*)&ph + sizeof(ph));
    data.insert(data.end(), (uint8_t*)&udp, (uint8_t*)&udp + sizeof(udp_hdr));
    data.insert(data.end(), payload, payload + payload_len);

    return checksum(data.data(), data.size());
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

uint32_t str_to_ip(const char* str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, str, &addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", str);
        exit(1);
    }
    return addr.s_addr; // Network byte order
}

std::string ip_to_str(uint32_t ip) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, buf, INET_ADDRSTRLEN);
    return std::string(buf);
}

uint32_t calc_network(uint32_t ip, uint32_t mask_length) {
    uint32_t mask = htonl(0xffffffff << (32 - mask_length)) & 0xffffffff;
    return ip & mask;
}

void ip_to_mac(uint32_t ip, uint8_t mac[6]) {
    mac[0] = 0x5e;
    mac[1] = 0xfe;
    uint32_t ip_host = ntohl(ip);
    memcpy(&mac[2], &ip_host, 4);
}