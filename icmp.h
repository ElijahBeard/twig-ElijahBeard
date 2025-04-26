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
    ip.checksum = checksum(&ip,(ip.version_ihl & 0x0f) * 4);
    buffer.insert(buffer.end(),(uint8_t*)&ip,(uint8_t*)&ip + sizeof(ip));

    // icmp code change
    struct icmp_hdr icmp = *i_icmp;
    icmp.type = 0;
    icmp.code = 0;
    icmp.checksum = 0;
    buffer.insert(buffer.end(), (uint8_t*)&icmp, (uint8_t*)&icmp + sizeof(icmp));

    size_t icmp_payload_len = pph.caplen - (sizeof(struct eth_hdr) + (i_ip->version_ihl & 0x0f) * 4 + sizeof(struct icmp_hdr));
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
