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

void print_arp_cache() {
    printf("ARP Cache:\n");
    for (const auto& entry : arp_cache) {
        uint32_t ip = entry.first;
        const uint8_t* mac = entry.second.data();
        printf("  IP: %s -> MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               ip_to_str(ip).c_str(),
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

void arp_respond(int interface_idx, const arp_hdr* req_arp) {
    std::vector<uint8_t> buffer;

    //eth
    eth_hdr eth;
    memcpy(eth.dst,req_arp->sender_mac,6);
    memcpy(eth.src,interfaces[interface_idx].mac_addr,6);
    eth.type = htons(0x0806);
    buffer.insert(buffer.end(),(uint8_t*)&eth,(uint8_t*)&eth + sizeof(eth));

    //arp
    arp_hdr arp;
    arp.hardware_type = htons(1);
    arp.protocol_type = htons(0x0800);
    arp.hardware_len = 6;
    arp.protocol_len = 4;
    arp.op = htons(2); // for reply
    memcpy(arp.sender_mac,interfaces[interface_idx].mac_addr,6);
    arp.sender_ip = interfaces[interface_idx].ipv4_addr;
    memcpy(arp.target_mac,req_arp->sender_mac,6);
    arp.target_ip = req_arp->sender_ip;
    buffer.insert(buffer.end(),(uint8_t*)&arp,(uint8_t*)&arp + sizeof(arp));

    write_packet(interface_idx,buffer.data(),buffer.size());
}

void process_arp(int interface_idx, const pcap_pkthdr& pph, const char *packet) {
    if(pph.caplen < sizeof(eth_hdr) + sizeof(arp_hdr)) {
        if (debug) printf("Arp short\n");
        return;
    }

    const arp_hdr* arp = (const arp_hdr*)(packet + sizeof(eth_hdr));

    uint32_t sender_ip = arp->sender_ip;
    uint32_t target_ip = arp->target_ip;

    arp_cache[sender_ip] = {};
    memcpy(arp_cache[sender_ip].data(),arp->sender_mac,6);

    // case request
    if (ntohs(arp->op) == 1) {
        for (int i = 0; i < num_interfaces; i++) {
            if (target_ip == interfaces[i].ipv4_addr) {
                arp_respond(interface_idx,arp);
                break;
            }
        }
    }
    // case reply
    else if (ntohs(arp->op == 2)) {
        if (debug) printf("arp recieved reply ip %s\n",ip_to_str(target_ip).c_str());
        if (debug) print_arp_cache();
    }
}

void arp_request(int interface_idx, uint32_t target_ip) {
    std::vector<uint8_t> buffer;

    eth_hdr eth;
    memset(eth.dst,0xFF,6);
    memcpy(eth.src,interfaces[interface_idx].mac_addr,6);
    eth.type = htons(0x0806);
    buffer.insert(buffer.end(),(uint8_t*)&eth,(uint8_t*)&eth + sizeof(eth));

    //arp
    arp_hdr arp;
    arp.hardware_type = htons(1);
    arp.protocol_type = htons(0x0800);
    arp.hardware_len = 6;
    arp.protocol_len = 4;
    arp.op = htons(1); // for request
    memcpy(arp.sender_mac,interfaces[interface_idx].mac_addr,6);
    arp.sender_ip = interfaces[interface_idx].ipv4_addr;
    memset(arp.target_mac,0,6);
    arp.target_ip = target_ip;
    buffer.insert(buffer.end(),(uint8_t*)&arp,(uint8_t*)&arp + sizeof(arp));

    write_packet(interface_idx,buffer.data(),buffer.size());
}

int get_arp_mac(uint32_t ip, uint8_t* mac) {
    if (arp_cache.count(ip)) {
        memcpy(mac, arp_cache[ip].data(),6);
        return 1;
    }
    return 0;
}
