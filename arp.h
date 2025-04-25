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