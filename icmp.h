#include <cstdlib>
#include <vector>

#include "pheaders.h"
#include "utils.h"

#include "shrub.h" // for globals

void icmp_respond(int interface_idx, const pcap_pkthdr& pph, const char* packet){ // make sure you change implremenetion of icmp_respond in process packet
    const struct eth_hdr* i_eth = (const struct eth_hdr*)packet;
    const struct ipv4_hdr* i_ip = (const struct ipv4_hdr*)(packet + sizeof(struct eth_hdr));
    const struct icmp_hdr* i_icmp = (const struct icmp_hdr*)(packet+sizeof(struct eth_hdr) + (i_ip->version_ihl & 0x0f) * 4);

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
    ip.checksum = checksum(&ip, (ip.version_ihl & 0x0f) * 4);
    buffer.insert(buffer.end(), (uint8_t*)&ip, (uint8_t*)&ip + sizeof(ip));

    // icmp code change
    struct icmp_hdr icmp = *i_icmp;
    icmp.type = 0;
    icmp.code = 0;
    icmp.checksum = 0;
    buffer.insert(buffer.end(), (uint8_t*)&icmp, (uint8_t*)&icmp + sizeof(icmp));

    buffer.insert(buffer.end(), packet + sizeof(struct eth_hdr) + (i_ip->version_ihl & 0x0f) * 4 + sizeof(struct icmp_hdr),
                  packet + pph.caplen);

    // icmp checksum
    icmp.checksum = checksum(buffer.data() + sizeof(struct eth_hdr) + sizeof(struct ipv4_hdr),
                             buffer.size() - sizeof(struct eth_hdr) - sizeof(struct ipv4_hdr));
    memcpy(buffer.data() + sizeof(struct eth_hdr) + sizeof(struct ipv4_hdr), &icmp, sizeof(icmp));

    write_packet(interface_idx, buffer.data(), buffer.size());
    if (debug) {
        printf("Sent ICMP echo reply to %s\n", ip_to_str(i_ip->src).c_str());
    }
}

void send_destintation_unreachable(int interface_idx, eth_hdr* eth, ipv4_hdr* ip) {
    if (debug) printf("Sending ICMP Destination Unreachable to %s\n", ip_to_str(ip->src).c_str());

    char buffer[1500];
    memset(buffer, 0, sizeof(buffer));

    eth_hdr* eth_out = (eth_hdr*)buffer;
    ipv4_hdr* ip_out = (ipv4_hdr*)(buffer + sizeof(eth_hdr));
    icmp_hdr* icmp = (icmp_hdr*)(buffer + sizeof(eth_hdr) + sizeof(ipv4_hdr));

    memcpy(eth_out->dst, eth->src, 6);
    memcpy(eth_out->src, interfaces[interface_idx].mac_addr, 6);
    eth_out->type = htons(0x0800);

    ip_out->version_ihl = 0x45;
    ip_out->tos = 0;
    ip_out->total_length = htons(sizeof(ipv4_hdr) + sizeof(icmp_hdr) + 64);
    ip_out->ident = 0;
    ip_out->flags_offset = 0;
    ip_out->ttl = 64;
    ip_out->protocol = 1;
    ip_out->checksum = 0;
    ip_out->src = interfaces[interface_idx].ipv4_addr;
    ip_out->dest = ip->src;
    ip_out->checksum = checksum(ip_out, sizeof(ipv4_hdr));

    icmp->type = 3;
    icmp->code = 1;
    icmp->checksum = 0;
    memcpy((char*)icmp + sizeof(icmp_hdr), ip, 64);

    icmp->checksum = checksum(icmp, sizeof(icmp_hdr) + 64);

    write_packet(interface_idx, buffer, sizeof(eth_hdr) + sizeof(ipv4_hdr) + sizeof(icmp_hdr) + 64);
}