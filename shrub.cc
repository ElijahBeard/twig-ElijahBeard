#include <cstdlib>

#include "shrub.h"
#include "pheaders.h"
#include "icmp.h"
#include "udp.h"
#include "arp.h"
#include "rip.h"

void process_packet(int interface_idx) {
    pcap_pkthdr pph;
    char packet[65536];
    int ret = read(interfaces[interface_idx].fd_r,&pph,sizeof(pph));
    if (ret <= 0 ) return;
    if (ret < (int)sizeof(pph)) return;

    ret = read(interfaces[interface_idx].fd_r,packet,pph.caplen);
    if (ret < (int)pph.caplen) return;

    if (pph.caplen > sizeof(packet)) {
        if (debug) printf("Dropping oversized packet: %u > %zu\n", pph.caplen, sizeof(packet));
        return;
    }
    
    eth_hdr* eth = (eth_hdr*)packet;
    //if (memcmp(eth->src, interfaces[interface_idx].mac_addr, 6) == 0) return;
        
    ipv4_hdr* ip = (ipv4_hdr*)(packet + sizeof(eth_hdr));
    bool local = false;
    for (int i = 0; i < num_interfaces; i++) {
        if (ip->dest == interfaces[i].ipv4_addr) {
            local = true;
            break;
        }
    }

    // case dst is current index
    if (local) {
        // ICMP
        if (ip->protocol == 1) {
            icmp_hdr* icmp = (icmp_hdr*)(packet + sizeof(eth_hdr) + (ip->version_ihl & 0x0f) * 4);
            if(icmp->type == 8) {
                icmp_respond(interface_idx,pph,packet);
            }
        }

        // UDP
        else if (ip->protocol == 17) {
            udp_hdr* udp = (udp_hdr*)(packet + sizeof(eth_hdr) + (ip->version_ihl & 0x0f) * 4);
            if (ntohs(udp->dport) == 7) {
                udp_respond(interface_idx,&pph,packet);
            } 
            else if (ntohs(udp->dport) == 37) {
                udp_time(interface_idx,&pph,packet);
            }
            else {
                process_rip(interface_idx, ip, udp, (char*)udp + sizeof(udp_hdr), 
                pph.caplen - sizeof(eth_hdr) - (ip->version_ihl & 0x0f)*4 - sizeof(udp_hdr));
            }
        }
    } 
    // case forwarding
    else if (num_interfaces > 1) {
        ip->ttl--;
        if (ip->ttl == 0) {
            if (debug) printf("TTL expired for packet to %s\n", ip_to_str(ip->dest).c_str());
            return;
        }

        int best_idx = -1;
        uint32_t best_mask = 0;
        for (size_t i = 0; i < routing_table.size(); i++) {
            if ((ip->dest & routing_table[i].mask) == routing_table[i].dest_ip &&
                routing_table[i].mask >= best_mask) {
                best_idx = i;
                best_mask = routing_table[i].mask;
            }
        }

        if (best_idx == -1) {
            if (debug) printf("No route to %s\n", ip_to_str(ip->dest).c_str());
            return;
        }

        int out_iface = routing_table[best_idx].interface_idx;
        uint32_t next_hop = routing_table[best_idx].next_hop ? routing_table[best_idx].next_hop : ip->dest;
        uint32_t cache_key = next_hop;

        if (arp_cache.count(cache_key)) {
            memcpy(eth->dst, arp_cache[cache_key], 6);
            memcpy(eth->src, interfaces[out_iface].mac_addr, 6);
            ip->checksum = 0;
            ip->checksum = checksum(ip, ((ip->version_ihl & 0x0f) * 4));
            write_packet(out_iface, packet, pph.caplen);
            if (debug) printf("Forwarded packet to %s via iface %d\n", ip_to_str(ip->dest).c_str(), out_iface);
        } else {
            // Send ARP request and drop packet (rely on retransmission)
            arp_request(out_iface, next_hop);
            if (debug) printf("No MAC for %s, sent ARP request, dropping packet\n", ip_to_str(next_hop).c_str());
            return;
        }
    }
}

int main(int argc, char* argv[]) {
    std::vector<std::string> interfaces_ = parse_interfaces(argc,argv);
    num_interfaces = interfaces_.size();
    for (int i = 0; i < num_interfaces; i++) {
        setup_interface(interfaces_[i].c_str(), i);
    }

    init_routing_table();

    time_t last_rip = 0;
    while(1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        int max_fd = 0;
        for(int i = 0; i < num_interfaces; i++) {
            FD_SET(interfaces[i].fd_r,&readfds);
            if (interfaces[i].fd_r > max_fd) max_fd = interfaces[i].fd_r;
        }
        struct timeval tv = {1,0}; // 1 sec timeout
        int ret = select(max_fd + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0){
            if (errno == EINTR) continue;
            perror("select");
            exit(1);
        } else if (ret == 0) {
            if (num_interfaces > 1) {
                time_t now = time(NULL);
                if(now - last_rip >= rip_interval) {
                    printf("im sending an epic rip announcement\n");
                    send_rip_announcement();
                    last_rip = now;
                }
            }
        } else {
            for (int i = 0; i < num_interfaces; i++) {
                if (FD_ISSET(interfaces[i].fd_r, &readfds)) {
                    //if (debug) printf("im processing a damn packet yo\n");
                    process_packet(i);
                }
            }
        }
    }
    return 0;
}