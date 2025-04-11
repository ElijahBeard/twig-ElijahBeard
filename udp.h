#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <iostream>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "pheaders.h"
#include "utils.h"

struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t checksum;
} __attribute__ ((packed));

void udp_respond(int fd_w, pcap_pkthdr &packet_header, char* packet_data){
    char response_data[65536];
    size_t packet_length = packet_header.caplen;
    memcpy(response_data, packet_data, packet_length);

    // create structures
    pcap_pkthdr reply_packet_header;
    eth_hdr* eth_response = reinterpret_cast<eth_hdr*>(response_data);
    ipv4_hdr* ip_response = reinterpret_cast<ipv4_hdr*>(response_data + 14);
    uint8_t ip_header_len = (ip_response->version_ihl & 0b1111) * 4;
    udp_hdr* udp_response = reinterpret_cast<udp_hdr*>(response_data + 14 + ip_header_len);

    // build packet header
    struct timeval now;
    gettimeofday(&now,NULL);
    reply_packet_header.caplen = packet_header.caplen;
    reply_packet_header.len = packet_header.len;
    reply_packet_header.ts_secs = now.tv_sec;
    reply_packet_header.ts_usecs = now.tv_usec;

    // swap ethernet mac
    {
        eth_response->type = htons(0x0800);
        uint8_t tmp_mac[6];
        memcpy(tmp_mac, eth_response->dst, 6);
        memcpy(eth_response->dst, eth_response->src, 6);
        memcpy(eth_response->src, tmp_mac, 6);
    }
    
    // swap ip
    {
        uint32_t tmp = ip_response->dest;
        ip_response->dest = ip_response->src;
        ip_response->src = tmp;
        ip_response->checksum = 0;
    }

    // calculate ip checksum
    {
        uint16_t check = checksum(reinterpret_cast<uint8_t *>(ip_response), ip_header_len);
        ip_response->checksum = check;
        // is checksum == ffff?
        //printf("ip-checksum:%u",check);
    }

    // swap / modify udp
    {
        uint16_t orig_sport = udp_response->sport; // Already in network order
        uint16_t orig_dport = udp_response->dport; // Already in network order
        udp_response->sport = orig_dport;          // Reply from dst port (e.g., 7)
        udp_response->dport = orig_sport;          // To src port (e.g., 36022)
        udp_response->len = htons(packet_length - 14 - ip_header_len);
        udp_response->checksum = 0;    
    }

    // udp checksum

    // swap endianess
    pcap_pkthdr write_header = reply_packet_header;
    if (file_is_big_endian) {
        write_header.ts_secs = swap32(write_header.ts_secs);
        write_header.ts_usecs = swap32(write_header.ts_usecs);
        write_header.caplen = swap32(write_header.caplen);
        write_header.len = swap32(write_header.len);
    }

    //write 
    struct iovec iov[2];
    iov[0].iov_base = &reply_packet_header;
    iov[0].iov_len = sizeof(reply_packet_header);
    iov[1].iov_base = &response_data;
    iov[1].iov_len = packet_length;
    ssize_t bytes_written = writev(fd_w, iov, 2);

    // check validity
    if (debug) {
        printf("IP Header Bytes:\n");
        for (int i = 0; i < ip_header_len; i++) {
            printf("%02x ", (unsigned char)*((char*)ip_response + i));
        }
        printf("\n");
    }
    ssize_t expected_bytes = sizeof(reply_packet_header) + packet_length;
    if (bytes_written != expected_bytes) {
        fprintf(stderr, "Warning: expected to write %zd bytes, but wrote %zd\n", expected_bytes, bytes_written);
    }
    if (bytes_written == 0) {
        if(debug)
            printf("Wrote ICMP echo reply, %zd bytes\n", bytes_written);
    } else if (bytes_written < 0) {
        perror("readv");
        exit (-1);
    }

    if (fsync(fd_w) == -1) {
        perror("fsync");
        close(fd_w);
    }
}