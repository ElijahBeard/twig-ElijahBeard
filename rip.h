#include <cstdlib>
#include <ctime>
#include <vector>

#include "pheaders.h"
#include "shrub.h"
#include "utils.h"

void send_rip_response(int interface_idx, uint32_t dest) {
    std::vector<uint8_t> buffer;

    eth_hdr eth;
    if (dest == rip_multicast_addr) {
        memset(eth.dst,0xFF,6);
    } else {
        // implement resolve via ARP
        memset(eth.dst,0xFF,6);
    }
    memcpy(eth.src,interfaces[interface_idx].mac_addr,6);
    eth.type = htons(0x0800);
    buffer.insert(buffer.end(), (uint8_t*)&eth, (uint8_t*)&eth + sizeof(eth));

    ipv4_hdr ip;
    ip.version_ihl = 0x45;
    ip.tos = 0;
    ip.total_length = htons(sizeof(ip) + sizeof(udp_hdr) + sizeof(rip_hdr) + routing_table.size()*sizeof(rip_entry));
    ip.ident = htons(0x2222);
    ip.flags_offset = 0;
    ip.ttl = 48; // local network
    ip.protocol = 17; // UDP
    ip.checksum = 0;
    ip.src = interfaces[interface_idx].ipv4_addr;
    ip.dest = dest;
    ip.checksum = checksum(&ip, sizeof(ip));
    buffer.insert(buffer.end(), (uint8_t*)&ip, (uint8_t*)&ip + sizeof(ip));

    udp_hdr udp;
    udp.sport = htons(rip_port);
    udp.dport = htons(rip_port);
    udp.len = htons(sizeof(udp) + sizeof(rip_hdr) + routing_table.size()*sizeof(rip_entry));
    udp.checksum = 0;
    buffer.insert(buffer.end(), (uint8_t*)&udp, (uint8_t*)&udp + sizeof(udp));

    rip_hdr rip;
    rip.command = 2;
    rip.version = 2;
    rip.zero = 0;
    buffer.insert(buffer.end(), (uint8_t*)&rip, (uint8_t*)&rip + sizeof(rip));

    for (const auto& route : routing_table) {
        if (route.interface_idx == interface_idx && route.next_hop == dest) continue;
        rip_entry entry;
        entry.family = htons(2);
        entry.tag = 0;
        entry.ip = route.dest_ip;
        entry.subnet = route.mask;
        entry.next_hop = route.next_hop;
        entry.metric = htonl(route.next_hop == dest ? rip_cost_infinity : route.metric);
        buffer.insert(buffer.end(), (uint8_t*)&entry, (uint8_t*)&entry + sizeof(entry));
    }

    write_packet(interface_idx,buffer.data(),buffer.size());
}

void process_rip(int interface_idx, ipv4_hdr* ip, udp_hdr* udp, const char* data, size_t len) {
    if (len < sizeof(rip_hdr)) return;
    rip_hdr* rip = (rip_hdr*)data;
    if(rip->version != 2 || rip->zero != 0 ) return;

    if(rip->command == 1) {
        size_t num_entries = (len - sizeof(rip_hdr)) / sizeof(rip_entry);
        rip_entry* entries = (rip_entry*)(data + sizeof(rip_hdr));
        bool full_table = (num_entries == 1 && entries[0].ip == 0);

        if(full_table) {
            send_rip_response(interface_idx,ip->src);
        } else {
            // possible expansion routes requests.
            send_rip_response(interface_idx,ip->src);
        }
    } else if (rip->command == 2) {
        size_t num_entries = (len - sizeof(rip_hdr)) / sizeof(rip_entry);
        rip_entry* entries = (rip_entry*)(data + sizeof(rip_hdr));
        
        for (size_t i = 0; i < num_entries; i++) {
            uint32_t dest = entries[i].ip;
            uint32_t mask = entries[i].subnet;
            uint32_t metric = ntohl(entries[i].metric);
            uint32_t next_hop = entries[i].next_hop ? entries[i].next_hop : ip->src;

            if (dest == interfaces[interface_idx].ipv4_addr || metric + 1 > rip_cost_infinity) continue;

            bool update = false;
            for (auto& route : routing_table) {
                if (route.dest_ip == dest && route.mask == mask) {
                    if (metric + 1 < route.metric) {
                        route.metric = metric + 1;
                        route.next_hop = next_hop;
                        route.interface_idx = interface_idx;
                        route.last_update = time(nullptr);
                    }
                    update = true;
                    break;
                }
            }
            if (!update && metric < rip_cost_infinity - 1) {
                routing_table.push_back({dest,mask,next_hop,metric + 1,interface_idx,time(nullptr)});
            }
            if (debug) print_routing_table();
        }
    }
}