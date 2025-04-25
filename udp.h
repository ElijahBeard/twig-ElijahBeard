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
#include "shrub.h"

uint16_t udp_checksum(pcap_pkthdr packet_header, ipv4_hdr *ip_response, udp_hdr *udp_response) {
    udp_pseudo p_udp;
    p_udp.src = ip_response->src;
    p_udp.dst = ip_response->dest;
    p_udp.zeros = 0;
    p_udp.protocol = 17;
    p_udp.udp_len = udp_response->len;

    size_t packet_length = packet_header.caplen;
    uint8_t ip_header_len = (ip_response->version_ihl & 0b1111) * 4;
    size_t udp_data_len = packet_length - 14 - ip_header_len - sizeof(udp_hdr);
    size_t total_len = sizeof(p_udp) + sizeof(udp_hdr) + udp_data_len;
    uint8_t* checksum_buf = new uint8_t[total_len];
    memcpy(checksum_buf, &p_udp, sizeof(p_udp));
    memcpy(checksum_buf + sizeof(p_udp), udp_response, sizeof(udp_hdr) + udp_data_len);

    uint16_t udp_check = checksum(reinterpret_cast<uint16_t*>(checksum_buf), total_len);    return udp_check;
    delete[] checksum_buf;
    return udp_check;
}

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

    // check if double value
    static int last_seq = -1;
    int seq = ntohs(*((uint16_t*)(response_data + 14 + ip_header_len + sizeof(udp_hdr))));
    if (seq == last_seq) {
        if (debug) printf("Duplicate seq %d, skipping\n", seq);
        return;
    }
    last_seq = seq;

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
        uint16_t check = checksum(reinterpret_cast<uint16_t *>(ip_response), ip_header_len);
        ip_response->checksum = check;
        // is checksum == ffff?
        //printf("ip-checksum:%u",check);
    }

    // swap / modify udp
    {
        uint16_t orig_sport = udp_response->sport;
        uint16_t orig_dport = udp_response->dport;
        udp_response->sport = orig_dport;
        udp_response->dport = orig_sport;
        udp_response->len = htons(packet_length - 14 - ip_header_len);
        udp_response->checksum = 0;
    }

    // udp checksum
    uint16_t udp_check = udp_checksum(packet_header,ip_response,udp_response);
    udp_response->checksum = udp_check;

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
            printf("Wrote ECHO reply, %zd bytes\n", bytes_written);
    } else if (bytes_written < 0) {
        perror("readv");
        exit (-1);
    }

    if (fsync(fd_w) == -1) {
        perror("fsync");
        close(fd_w);
    }
}

void udp_time(int fd_w, pcap_pkthdr &packet_header, char* packet_data){
    const uint32_t epoch_offset = 2208988800U;
    struct timeval now;
    gettimeofday(&now, NULL);
    uint32_t time_protocol = htonl(static_cast<uint32_t>(now.tv_sec) + epoch_offset);

    char response_data[65536];
    size_t packet_length = 14 + 20 + 8 + 4;
    memcpy(response_data, packet_data, packet_header.caplen);
    eth_hdr* eth_response = reinterpret_cast<eth_hdr*>(response_data);
    ipv4_hdr* ip_response = reinterpret_cast<ipv4_hdr*>(response_data + 14);
    uint8_t ip_header_len = (ip_response->version_ihl & 0b1111) * 4;
    udp_hdr* udp_response = reinterpret_cast<udp_hdr*>((char*)ip_response + ip_header_len);

    pcap_pkthdr reply_packet_header;
    reply_packet_header.ts_secs = now.tv_sec;
    reply_packet_header.ts_usecs = now.tv_usec;
    reply_packet_header.caplen = packet_length;
    reply_packet_header.len = packet_length;

    uint8_t tmp_mac[6];
    memcpy(tmp_mac, eth_response->dst, 6);
    memcpy(eth_response->dst, eth_response->src, 6);
    memcpy(eth_response->src, tmp_mac, 6);
    eth_response->type = htons(0x0800);

    uint32_t tmp = ip_response->dest;
    ip_response->dest = ip_response->src;
    ip_response->src = tmp;
    ip_response->total_length = htons(20 + 8 + 4);
    ip_response->ttl = 64; // idk
    ip_response->checksum = 0;
    uint16_t ip_check = checksum(reinterpret_cast<uint16_t*>(ip_response), ip_header_len);
    ip_response->checksum = htons(ip_check);

    uint16_t client_port = udp_response->sport;
    udp_response->sport = htons(37);
    udp_response->dport = client_port;
    udp_response->len = htons(8 + 4);
    udp_response->checksum = 0;

    memcpy(response_data + 14 + ip_header_len + 8, &time_protocol, 4);

    pcap_pkthdr write_header = reply_packet_header;
    if (file_is_big_endian) {
        write_header.ts_secs = swap32(write_header.ts_secs);
        write_header.ts_usecs = swap32(write_header.ts_usecs);
        write_header.caplen = swap32(write_header.caplen);
        write_header.len = swap32(write_header.len);
    }

    struct iovec iov[2];
    iov[0].iov_base = &write_header;
    iov[0].iov_len = sizeof(write_header);
    iov[1].iov_base = response_data;
    iov[1].iov_len = packet_length;
    ssize_t bytes_written = writev(fd_w, iov, 2);

    if (debug) {
        printf("TIME: timestamp=0x%08x\n", ntohl(time_protocol));
        printf("UDP reply, %zd bytes\n", bytes_written);
    }

    if (fsync(fd_w) == -1) {
        perror("fsync");
    }
};