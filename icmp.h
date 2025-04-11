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

struct icmp_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t id;
	uint16_t sequence;
} __attribute__((packed));

void icmp_respond(int fd_w, pcap_pkthdr &packet_header, char *packet_data){
    char response_data[65536];
    size_t packet_length = packet_header.caplen;
    memcpy(response_data, packet_data, packet_length);

    // create structures
    pcap_pkthdr reply_packet_header;
    eth_hdr* eth_response = reinterpret_cast<eth_hdr*>(response_data);
    ipv4_hdr* ip_response = reinterpret_cast<ipv4_hdr*>(response_data + 14);
    uint8_t ip_header_len = (ip_response->version_ihl & 0b1111) * 4;
    icmp_hdr* icmp_response = reinterpret_cast<icmp_hdr*>(
    reinterpret_cast<char*>(ip_response) + ip_header_len);
    
    // build packet header
    struct timeval now;
    gettimeofday(&now,NULL);
    reply_packet_header.caplen = packet_header.caplen;
    reply_packet_header.len = packet_header.len;
    reply_packet_header.ts_secs = now.tv_sec;
    reply_packet_header.ts_usecs = now.tv_usec;
    
    // swap ethernet mac
    eth_response->type = htons(0x0800);
    uint8_t tmp_mac[6];
    memcpy(tmp_mac, eth_response->dst, 6);
    memcpy(eth_response->dst, eth_response->src, 6);
    memcpy(eth_response->src, tmp_mac, 6);
    
    // swap ip
    uint32_t tmp = ip_response->dest;
    ip_response->dest = ip_response->src;
    ip_response->src = tmp;
    ip_response->checksum = 0;

    // calculate ip checksum
    {
        uint16_t check = checksum(reinterpret_cast<uint8_t *>(ip_response), ip_header_len);
        ip_response->checksum = check;
        // is checksum == ffff
        //printf("ip-checksum:%u",check);
    }
    
    // modify icmp
    icmp_response->type = 0;
    icmp_response->code = 0;
    icmp_response->checksum = 0;
    size_t icmp_length = packet_length - 14 - ip_header_len;
    {
        uint16_t check = checksum(reinterpret_cast<uint8_t *>(icmp_response), icmp_length);
        icmp_response->checksum = check;
        printf("icmp-checksum:%u",check);
    }

    // flip to big endian

    // write
    struct iovec iov[2];
    iov[0].iov_base = &reply_packet_header;
    iov[0].iov_len = sizeof(reply_packet_header);
    iov[1].iov_base = &response_data;
    iov[1].iov_len = packet_length;
    ssize_t bytes_written = writev(fd_w, iov, 2);
    // check ip
    if (debug) {
        printf("IP Header Bytes:\n");
        for (int i = 0; i < ip_header_len; i++) {
            printf("%02x ", (unsigned char)*((char*)ip_response + i));
        }
        printf("\n");
    }
    // check validity
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


    // temp debug area:
    if(debug){
        //printf("Sending reply to IP: %s\n", inet_ntoa(*(in_addr*)&ip_response->dest));
        printf("          MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth_response->dst[0], eth_response->dst[1], eth_response->dst[2],
        eth_response->dst[3], eth_response->dst[4], eth_response->dst[5]);
        printf("Request caplen=%u len=%u\n", packet_header.caplen, packet_header.len);
        printf("Reply caplen=%u len=%u\n", reply_packet_header.caplen, reply_packet_header.len);
        printf("Will write back %zd total bytes (caplen: %u)\n", sizeof(reply_packet_header) + packet_length, reply_packet_header.caplen);
    }

    if (fsync(fd_w) == -1) {
        perror("fsync");
        close(fd_w);
    }    
}
