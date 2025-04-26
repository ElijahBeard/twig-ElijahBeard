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

void arp_respond(int interface_idx, const pcap_pkthdr& pph, const char* packet) {
    const struct eth_hdr* i_eth = (const struct eth_hdr*)packet;
    const struct arp_hdr* i_arp = (const struct arp_hdr*)(packet + sizeof(struct eth_hdr));

    if (ntohs(i_arp->op) != 1 || i_arp->target_ip != interfaces[interface_idx].ipv4_addr) return;

    if (debug) printf("Received ARP request for %s / %d\n", ip_to_str(i_arp->target_ip).c_str(), interface_idx);

    std::vector<uint8_t> buffer;
    struct eth_hdr eth;
    memcpy(eth.dst, i_eth->src, 6);
    memcpy(eth.src, interfaces[interface_idx].mac_addr, 6);
    eth.type = htons(0x0806);
    buffer.insert(buffer.end(), (uint8_t*)&eth, (uint8_t*)&eth + sizeof(eth));

    struct arp_hdr arp;
    arp.hardware_type = htons(1);
    arp.protocol_type = htons(0x0800);
    arp.hardware_len = 6;
    arp.protocol_len = 4;
    arp.op = htons(2);
    memcpy(arp.sender_mac, interfaces[interface_idx].mac_addr, 6);
    arp.sender_ip = interfaces[interface_idx].ipv4_addr;
    memcpy(arp.target_mac, i_arp->sender_mac, 6);
    arp.target_ip = i_arp->sender_ip;
    buffer.insert(buffer.end(), (uint8_t*)&arp, (uint8_t*)&arp + sizeof(arp));

    write_packet(interface_idx, buffer.data(), buffer.size());

    uint16_t cache_key = ntohs(i_arp->sender_ip & 0xFFFF); // maybe try uint32_t cache_key = i_arp->sender_ip;
    memcpy(arp_cache[cache_key], i_arp->sender_mac, 6);

    if (debug) printf("Sent ARP reply to %s, cached MAC for key %u\n", ip_to_str(i_arp->sender_ip).c_str(), cache_key);
}

void arp_request(int interface_idx, uint32_t target_ip) {
    std::vector<uint8_t> buffer;

    struct eth_hdr eth;
    memset(eth.dst, 0xFF, 6);
    memcpy(eth.src, interfaces[interface_idx].mac_addr, 6);
    eth.type = htons(0x0806);
    buffer.insert(buffer.end(), (uint8_t*)&eth, (uint8_t*)&eth + sizeof(eth));

    struct arp_hdr arp;
    arp.hardware_type = htons(1);
    arp.protocol_type = htons(0x0800);
    arp.hardware_len = 6;
    arp.protocol_len = 4;
    arp.op = htons(1);
    memcpy(arp.sender_mac, interfaces[interface_idx].mac_addr, 6);
    arp.sender_ip = interfaces[interface_idx].ipv4_addr;
    memset(arp.target_mac, 0, 6); // UNKNOWN GET THIS FIXED
    arp.target_ip = target_ip;
    buffer.insert(buffer.end(), (uint8_t*)&arp, (uint8_t*)&arp + sizeof(arp));

    write_packet(interface_idx, buffer.data(), buffer.size());
    if (debug) printf("Sent ARP request for %s on iface %d\n", ip_to_str(target_ip).c_str(), interface_idx);
}

// void cache_arp(arp_hdr *arp){
//     if (ntohs(arp->hardware_type) == 1 && ntohs(arp->protocol_type) == 0x0800 &&
//         arp->hardware_len == 6 && arp->protocol_len == 4) 
//     {
//         uint16_t op = ntohs(arp->op);
//         if (op == 1 || op == 2) {
//             uint8_t mac[6];
//             memcpy(mac, arp->sender_mac, 6);
//             memcpy(arp_cache[arp->sender_ip], mac, 6);
//         }
//     }
//     if (debug){
//         if (arp_cache.empty()) {
//             return;
//         }
//         for (const auto& entry : arp_cache) {
//             uint32_t ip = entry.first;
//             const uint8_t* mac = entry.second;
//             printf("%3u.%3u.%3u.%3u -> %02x:%02x:%02x:%02x:%02x:%02x\n",
//                    (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
//                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
//         }
//     }
// }