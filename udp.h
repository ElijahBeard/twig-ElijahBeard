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

#include "shrub.h" // for globals

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

    uint16_t udp_check = checksum(reinterpret_cast<uint16_t*>(checksum_buf), total_len);
    delete[] checksum_buf;
    return udp_check;
}

void udp_respond(int interface_idx, const struct pcap_pkthdr* pph, const char* packet){
    const struct eth_hdr* i_eth = (const struct eth_hdr*)packet;
    const struct ipv4_hdr* i_ip = (const struct ipv4_hdr*)(packet + sizeof(struct eth_hdr));
    const struct udp_hdr* i_udp = (const struct udp_hdr*)(packet+sizeof(struct eth_hdr) + (i_ip->version_ihl & 0x0f) * 4);
    size_t udp_payload_len = pph->caplen - sizeof(struct eth_hdr) - (i_ip->version_ihl & 0x0f)*4 - sizeof(struct udp_hdr);

    // response packet
    std::vector<uint8_t> buffer;
    
    // swap eth
    struct eth_hdr eth;
    memcpy(eth.dst,i_eth->src,6);
    memcpy(eth.src,interfaces[interface_idx].mac_addr,6);
    eth.type = htons(0x0800);
    buffer.insert(buffer.end(),(uint8_t*)&eth,(uint8_t*)&eth + sizeof(eth));
    
    // swap ip
    struct ipv4_hdr ip = *i_ip;
    ip.src = interfaces[interface_idx].ipv4_addr;
    ip.dest = i_ip->src;
    ip.ttl = 255;
    ip.checksum = 0;
    ip.checksum = checksum(&ip,(ip.version_ihl & 0x0f) * 4);
    ip.total_length = htons(sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) + udp_payload_len);
    buffer.insert(buffer.end(),(uint8_t*)&ip,(uint8_t*)&ip + sizeof(ip));

    // udp swap
    struct udp_hdr udp = *i_udp;
    uint16_t tmp = udp.sport;
    udp.sport = udp.dport;
    udp.dport = tmp;
    udp.checksum = 0;
    //udp.checksum = udp_checksum(*pph,&ip,&udp); // if doesnt work try i_ variants
    // insert udp to buffer
    udp.len = htons(sizeof(struct udp_hdr) + udp_payload_len);
    buffer.insert(buffer.end(), packet + sizeof(struct eth_hdr) + (i_ip->version_ihl & 0x0f) * 4 + sizeof(struct udp_hdr),
                  packet + sizeof(struct eth_hdr) + (i_ip->version_ihl & 0x0f) * 4 + sizeof(struct udp_hdr) + udp_payload_len);

    write_packet(interface_idx, buffer.data(), buffer.size());
}

void udp_time(int interface_idx, const struct pcap_pkthdr* pph, const char* packet){
    printf("This is a UDP time moment\n");
    const struct eth_hdr* i_eth = (const struct eth_hdr*)packet;
    const struct ipv4_hdr* i_ip = (const struct ipv4_hdr*)(packet + sizeof(struct eth_hdr));
    const struct udp_hdr* i_udp = (const struct udp_hdr*)(packet+sizeof(struct eth_hdr) + (i_ip->version_ihl & 0x0f) * 4);
    size_t udp_payload_len = pph->caplen - sizeof(struct eth_hdr) - (i_ip->version_ihl & 0x0f)*4 - sizeof(struct udp_hdr);

    // response packet
    printf("Init buffer\n");
    std::vector<uint8_t> buffer;

    struct eth_hdr eth;
    memcpy(eth.dst, i_eth->src, 6);
    memcpy(eth.src, interfaces[interface_idx].mac_addr, 6);
    eth.type = htons(0x0800);
    printf("Insert eth buffer\n");
    buffer.insert(buffer.end(), (uint8_t*)&eth, (uint8_t*)&eth + sizeof(eth));

    // ip protocol
    struct ipv4_hdr ip;
    ip.version_ihl = 0x45;
    ip.tos = 0;
    ip.total_length = htons(sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) + 4);
    ip.ident = 0;
    ip.flags_offset = 0;
    ip.ttl = 255;
    ip.protocol = 17; // UDP
    ip.checksum = 0;
    ip.src = interfaces[interface_idx].ipv4_addr;
    ip.dest = i_ip->src;
    ip.checksum = checksum(&ip,(ip.version_ihl & 0x0f) * 4);
    printf("Insert ip buffer\n");
    buffer.insert(buffer.end(), (uint8_t*)&ip, (uint8_t*)&ip + sizeof(ip));

    // udp hdr
    struct udp_hdr udp;
    udp.sport = htons(37);
    udp.dport = i_udp->sport;
    udp.len = htons(sizeof(struct udp_hdr) + udp_payload_len);
    udp.checksum = 0;
    printf("Insert udp buffer\n");
    buffer.insert(buffer.end(), (uint8_t*)&udp, (uint8_t*)&udp + sizeof(udp));

    const uint32_t epoch_offset = 2208988800U;
    struct timeval now;
    gettimeofday(&now, NULL);
    uint32_t time_protocol = htonl(static_cast<uint32_t>(now.tv_sec) + epoch_offset);
    printf("Insert time buffer\n");
    buffer.insert(buffer.end(), (uint8_t*)&time_protocol, (uint8_t*)&time_protocol + 4);
    
    write_packet(interface_idx, buffer.data(), buffer.size());
};