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
#include "icmp.h"
#include "udp.h"
#include "arp.h"

#include "shrub.h" // for globals

void write_packet(int interface_idx, const void* data, size_t len) {
    struct pcap_pkthdr pph;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    pph.ts_secs = tv.tv_sec;
    pph.ts_usecs = tv.tv_usec;
    pph.caplen = len;
    pph.len = len;

    struct iovec iov[2];
    iov[0].iov_base = &pph;
    iov[0].iov_len = sizeof(pph);
    iov[1].iov_base = const_cast<void*>(data);
    iov[1].iov_len = len;

    if (writev(interfaces[interface_idx].fd_w,iov,2) != sizeof(pph) + len) {
        perror("writev");
    }
}

void process_packet(int interface_idx) {
    pcap_pkthdr pph;
    char packet[65536];
    int ret = read(interfaces[interface_idx].fd_r,&pph,sizeof(pph));
    if (ret <= 0 ) return;
    if (ret < (int)sizeof(pph)) return;

    ret = read(interfaces[interface_idx].fd_r,packet,pph.caplen);
    if (ret < (int)pph.caplen) return;

    // splitting into structures
    eth_hdr* eth = (eth_hdr*)packet;
    if (memcmp(eth->src, interfaces[interface_idx].mac_addr, 6) == 0) return;
        
    if (ntohs(eth->type) != 0x0800) return; // not ipv4
    ipv4_hdr* ip = (ipv4_hdr*)(packet + sizeof(eth_hdr));
    uint8_t ip_hl = (ip->version_ihl & 0x0f) * 4;
    uint16_t total_len = ntohs(ip->total_length);

    // if dest is current interface
    bool local = false;
    for (int i = 0; i< num_interfaces; i++) {
        if (ip->dest == interfaces[i].ipv4_addr) {
            local = true;
            break;
        }
    }

    // case dst is current index
    if (local) {
        // ICMP
        if (ip->protocol == 1) {
            icmp_hdr* icmp = (icmp_hdr*)((char*)ip + ip_hl);
            if(icmp->type == 8) {
                icmp_respond(interfaces[interface_idx].fd_w,pph,packet);
            }
        }

        // UDP
        else if (ip->protocol == 17) {
            udp_hdr* udp = (udp_hdr*)((char*)ip + ip_hl);
            if (ntohs(udp->dport) == 37) {
                udp_time(interfaces[interface_idx].fd_w,pph,packet);
            }
            else if (ntohs(udp->dport) == 7) {
                udp_respond(interfaces[interface_idx].fd_w,pph,packet);
            } 
            // else {
            //     // process_rip(interfaces_idx,ip,udp,(char*)udp + sizeof(udp_hdr)
            //     //             , total_len - ip_hl - sizeof(udp_hdr));
            // }
        }
    } 
    // case forwarding
    else if (num_interfaces > 1) { 
        ip->ttl--;
        
        if (ip->ttl == 0) {
            if (debug) printf("UR DONE X_X\n");
            return;
        }
        
        int best_idx = -1;
        uint32_t best_mask = 0;
        for (int i = 0; i < routing_table.size(); i++) {
            if ((ip->dest & routing_table[i].mask) == routing_table[i].dest_ip
                && routing_table[i].mask >= best_mask) 
            {
                    best_idx = i;
                    best_mask = routing_table[i].mask;
            }
                
        }

        if (best_idx == -1) {
            if(debug) printf("No route to %s\n",ip_to_str(ip->dest).c_str());
            return;
        }

        uint32_t next_hop = routing_table[best_idx].next_hop;
        int out_iface = routing_table[best_idx].interface_idx;
        memcpy(eth->src, interfaces[out_iface].mac_addr, 6);
        uint8_t dst_mac[6];
        ip_to_mac(next_hop ? next_hop : ip->dest, dst_mac);
        memcpy(eth->dst, dst_mac, 6);
        write_packet(out_iface,packet,pph.caplen);
    }

}