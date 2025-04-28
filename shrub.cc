#include <cstdlib>

#include "shrub.h"
#include "pheaders.h"
#include "icmp.h"
#include "udp.h"
#include "arp.h"
#include "rip.h"

void send_rip_announcement() {
    for(int i = 0; i < num_interfaces; i++) {
        send_rip_response(i, rip_multicast_addr);
    }
}

void process_packet(int interface_idx) {
    pcap_pkthdr pph;
    char packet[65536];
    int ret = read(interfaces[interface_idx].fd_r,&pph,sizeof(pph));
    if (ret <= 0 ) return;
    if (ret < (int)sizeof(pph)) return;
    if (pph.caplen > sizeof(packet)) {if(debug) printf("packets' too damn big\n");}
    //if(debug) printf("just read %d bytes out of pph. true psize: %d processing...\n",ret,(int)sizeof(pph));

    if (file_is_big_endian) {
        pph.ts_secs = swap32(pph.ts_secs);
        pph.ts_usecs = swap32(pph.ts_usecs);
        pph.caplen = swap32(pph.caplen);
        pph.len = swap32(pph.len);
    }

    if (pph.caplen > 65535 || pph.caplen < 14) {
        printf("Invalid caplen: %u\n", pph.caplen);
        exit(999);
    }

    ret = read(interfaces[interface_idx].fd_r,packet,pph.caplen);
    if (ret < (int)pph.caplen) return;
    //if (debug) printf("just read %d bytes out of packet. true psize: %d\n",ret,(int)pph.caplen);
    if (pph.caplen < sizeof(eth_hdr)) {if(debug) printf("packets' too damn small for ether\n");}

    
    eth_hdr* eth = (eth_hdr*)packet;
    if (!eth) {if(debug) printf("Null eth_hdr on iface %d\n",interface_idx);}

    // NOT DOING ARP FOR NOW

    // if(ntohs(eth->type) == 0x0806) {
    //     process_arp(interface_idx,pph,packet);
    //     return;
    // }
    //if (memcmp(eth->src, interfaces[interface_idx].mac_addr, 6) == 0) return;
        
    ipv4_hdr* ip = (ipv4_hdr*)(packet + sizeof(eth_hdr));

    bool local = false;
    for (int i = 0; i < num_interfaces; i++) {
        if (ip->dest == interfaces[i].ipv4_addr) {
            local = true;
            break;
        }
        uint32_t network = calc_network(interfaces[i].ipv4_addr, interfaces[i].mask_length);
        uint32_t broadcast = network | (~((0xffffffff) << (32 - interfaces[i].mask_length)));
        if (ip->dest == broadcast) {
            local = true;
            break;
        }
    }

    if (ip->dest == rip_multicast_addr) {
        local = true;
    }
    
    if(debug){if(!local) printf("Im not local ho\n");}

    // case dst is current index
    if (local) {
        // ICMP
        if (ip->protocol == 1) {
            if(debug) printf("im ICMP!\n");
            icmp_hdr* icmp = (icmp_hdr*)(packet + sizeof(eth_hdr) + (ip->version_ihl & 0x0f) * 4);
            if(icmp->type == 8) {
                icmp_respond(interface_idx,pph,packet);
            }
        }

        // UDP
        else if (ip->protocol == 17) {
            if(debug) printf("im UDP!\n");
            udp_hdr* udp = (udp_hdr*)(packet + sizeof(eth_hdr) + (ip->version_ihl & 0x0f) * 4);
            uint16_t dport = ntohs(udp->dport);
            if (dport == 7) {
                if(debug) printf("im UDP RESPOND!\n");
                udp_respond(interface_idx,&pph,packet);
            } 
            else if (dport == 37) {
                if(debug) printf("im UDP TIME!\n");
                udp_time(interface_idx,&pph,packet);
            }
            else if (dport == 520){
                if(debug) printf("im RIP! :D\n");
                process_rip(interface_idx, ip, udp, (char*)udp + sizeof(udp_hdr), 
                pph.caplen - sizeof(eth_hdr) - (ip->version_ihl & 0x0f)*4 - sizeof(udp_hdr));
            }
        }
    } 
    // case forwarding
    else {
        ip->ttl--;
        if (ip->ttl == 0) {
            // TODO ICMP TIME EXCEEDED
            if (debug) printf("TTL expired for packet to %s\n", ip_to_str(ip->dest).c_str());
            return;
        }
        // all over the place
        ip->checksum = 0;
        ip->checksum = checksum(ip, (ip->version_ihl & 0x0f) * 4);

        int best_idx = -1;
        uint32_t best_mask = 0;
        for (size_t i = 0; i < routing_table.size(); i++) {
            if ((ip->dest & routing_table[i].mask) == routing_table[i].dest_ip) {
                if (routing_table[i].mask > best_mask) {
                    best_idx = i;
                    best_mask = routing_table[i].mask;
                }
            }
        }

        if (best_idx == -1) {
            if (debug) printf("No route to host: %s\n", ip_to_str(ip->dest).c_str());
            send_destintation_unreachable(interface_idx,eth,ip);
            return;
        }

        int out_iface = routing_table[best_idx].interface_idx;
        uint32_t next_hop = routing_table[best_idx].next_hop;
        if (next_hop == 0) next_hop = ip->dest;
        uint16_t cache_key = ntohs(next_hop & 0xFFFF);
        
        if (arp_cache.count(cache_key)) {
            memcpy(eth->dst,arp_cache[cache_key].data(),6);
            memcpy(eth->src,interfaces[out_iface].mac_addr,6);
            write_packet(out_iface,packet,pph.caplen);
            if (debug) printf("Forwarded packet to %s via iface %d, dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                ip_to_str(ip->dest).c_str(), out_iface,
                eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3], eth->dst[4], eth->dst[5]);
        } else {
            arp_request(out_iface,next_hop);
            if (debug) printf("No MAC for %s, sent ARP request on iface %d, dropping packet\n",
                ip_to_str(next_hop).c_str(), out_iface);
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

    time_t last_rip = time(nullptr) + 1;
    while(1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        int max_fd = 0;
        for(int i = 0; i < num_interfaces; i++) {
            FD_SET(interfaces[i].fd_r,&readfds);
            if (interfaces[i].fd_r > max_fd) max_fd = interfaces[i].fd_r;
        }
        struct timeval tv = {1,0};
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
                    usleep(10000);
                    process_packet(i);
                }
            }
        }
    }
    return 0;
}