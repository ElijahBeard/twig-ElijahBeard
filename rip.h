#include <cstdlib>
#include <ctime>
#include <vector>

#include "pheaders.h"
#include "shrub.h"
#include "utils.h"

void send_rip_announcement() {
    for(int i = 0; i < num_interfaces; i++) {
        std::vector<uint8_t> buffer;

        eth_hdr eth;
        memset(eth.dst, 0, 6);
        eth.dst[0] = 0x01; eth.dst[1] = 0x00; eth.dst[2] = 0x5e;
        eth.dst[3] = 0x00; eth.dst[4] = 0x00; eth.dst[5] = 0x09;
        memcpy(eth.src, interfaces[i].mac_addr, 6);
        eth.type = htons(0x0800);
        buffer.insert(buffer.end(), (uint8_t*)&eth, (uint8_t*)&eth + sizeof(eth));

        ipv4_hdr ip;
        ip.version_ihl = 0x45;
        ip.tos = 0;
        ip.total_length = htons(sizeof(ip) + sizeof(udp_hdr) + sizeof(rip_hdr) + routing_table.size()*sizeof(rip_entry));
        ip.ident = 0;
        ip.flags_offset = 0;
        ip.ttl = 64; // local network
        ip.protocol = 17; // UDP
        ip.checksum = 0;
        ip.src = interfaces[i].ipv4_addr;
        ip.dest = htonl(0xE0000009);
        ip.checksum = checksum(&ip, sizeof(ip));
        buffer.insert(buffer.end(), (uint8_t*)&ip, (uint8_t*)&ip + sizeof(ip));

        udp_hdr udp;
        udp.sport = htons(520);
        udp.dport = htons(520);
        udp.len = htons(sizeof(udp) + sizeof(rip_hdr) + routing_table.size()*sizeof(rip_entry));
        udp.checksum = 0;
        buffer.insert(buffer.end(), (uint8_t*)&udp, (uint8_t*)&udp + sizeof(udp));

        rip_hdr rip;
        rip.command = 2;
        rip.version = 2;
        rip.zero = 0;
        buffer.insert(buffer.end(), (uint8_t*)&rip, (uint8_t*)&rip + sizeof(rip));

        for (const auto& route : routing_table) {
            rip_entry entry;
            entry.family = htons(2);
            entry.tag = 0;
            entry.ip = route.dest_ip;
            entry.subnet = route.mask;
            entry.next_hop = 0; // sender
            entry.metric = htonl(route.metric + 1);
            buffer.insert(buffer.end(), (uint8_t*)&entry, (uint8_t*)&entry + sizeof(entry));
        }

        write_packet(i, buffer.data(), buffer.size());
    }
}

void process_rip(int interface_idx, ipv4_hdr* ip, udp_hdr* udp, const char* data, size_t len) {
    if (len < sizeof(rip_hdr)) return;

    rip_hdr* rip = (rip_hdr*)data;
    if (rip->command != 2 || rip->version != 2) return;

    size_t num_entries = (len - sizeof(rip_hdr)) / sizeof(rip_entry);
    rip_entry* entries = (rip_entry*)(data + sizeof(rip_hdr));
    
    
    for (size_t i = 0; i < num_entries; i++) {
        uint32_t dest_ip = entries[i].ip;
        uint32_t mask = entries[i].subnet;
        uint32_t metric = ntohl(entries[i].metric);
        uint32_t next_hop = entries[i].next_hop ? entries[i].next_hop : ip->src;

        if (dest_ip == interfaces[interface_idx].ipv4_addr) continue;
    
        if (metric + 1 > 16) continue;

        // update existing route or add new
        bool updated = false;
        for (auto& route : routing_table) {
            if (route.dest_ip == dest_ip && route.mask == mask) {
                if (metric + 1 < route.metric) {
                    route.metric = metric + 1;
                    route.next_hop = next_hop;
                    route.interface_idx = interface_idx;
                    route.last_update = time(NULL);
                }
                updated = true;
                break;
            }
        }
        if (!updated && metric < 16) {
            routing_table.push_back({
                dest_ip,
                mask,
                next_hop,
                metric + 1,
                interface_idx,
                time(nullptr)
            });
        }        
    print_routing_table();
    }
}