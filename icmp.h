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

void icmp_respond(int interface_idx, const pcap_pkthdr& pph, const char* packet){ // make sure you change implremenetion of icmp_respond in process packet
    const eth_hdr* in_eth = (const eth_hdr*)packet;
    const ipv4_hdr* in_ip = (const ipv4_hdr*)(packet + sizeof(eth_hdr));
    const icmp_hdr* in_icmp = (const icmp_hdr*)((char*)in_ip + (in_ip->version_ihl & 0x0f) * 4);

    std::vector<char> buffer;
    eth_hdr eth = {in_eth->src, interfaces[interface_idx].mac_addr, htons(0x0800)}; // this error is from mac address indifference
    buffer.insert(buffer.end(), (char*)&eth, (char*)&eth + sizeof(eth));

    ipv4_hdr ip = *in_ip;
    ip.src = interfaces[interface_idx].ipv4_addr;
    ip.dest = in_ip->src;
    ip.checksum = 0;
    ip.checksum = checksum(&ip, sizeof(ip)); // args or mac address thing 
    buffer.insert(buffer.end(), (char*)&ip, (char*)&ip + sizeof(ip));

    icmp_hdr icmp = *in_icmp;
    icmp.type = 0; // Echo reply
    icmp.checksum = 0;
    buffer.insert(buffer.end(), (char*)&icmp, (char*)&icmp + sizeof(icmp));

    buffer.insert(buffer.end(), packet + sizeof(eth_hdr) + (in_ip->version_ihl & 0x0f) * 4 + sizeof(icmp_hdr),
                  packet + pph.caplen);

    icmp.checksum = checksum(buffer.data() + sizeof(eth_hdr) + sizeof(ipv4_hdr), // i think this one is also checksum args and mac address indifference
                             buffer.size() - sizeof(eth_hdr) - sizeof(ipv4_hdr));
    memcpy(buffer.data() + sizeof(eth_hdr) + sizeof(ipv4_hdr), &icmp, sizeof(icmp));

    write_packet(interface_idx, buffer.data(), buffer.size());
    if (debug) printf("Sent ICMP echo reply to %s\n", ip_to_str(in_ip->src).c_str());
}
