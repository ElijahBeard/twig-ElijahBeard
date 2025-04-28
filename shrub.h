#pragma once

#include <cstdlib>
#include <string>
#include <iostream>
#include <set>
#include <vector>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <array>
#include <sys/wait.h>

#include "utils.h"
#include "pheaders.h"

struct interface {
    uint32_t ipv4_addr;
    uint32_t mask_length;
    uint8_t mac_addr[6];
    int fd_r;
    int fd_w;
};

struct route {
    uint32_t dest_ip;
    uint32_t mask;
    uint32_t next_hop;
    uint32_t metric;
    int interface_idx;
    time_t last_update;
};

int debug = 0;

std::unordered_map<uint32_t, std::array<uint8_t,6> > arp_cache;
struct interface interfaces[10];
int num_interfaces = 0;
std::vector<route> routing_table;
int rip_interval = 30;
std::string default_route;
bool file_is_big_endian = false;
#define PCAP_MAGIC 0xa1b2c3d4

const uint32_t rip_multicast_addr = 0xE0000009;
const uint16_t rip_port = 520;
const uint32_t rip_cost_infinity = 16;

// prints help lol
void print_help(){
    printf("Usage: ./shrub [options]\n");
    printf("Options:\n");
    printf("  -i IPv4addr_masklength  Add interface (e.g., -i 172.31.10.254_24)\n");
    printf("  --default-route NEXT_HOP_IP  Set default route\n");
    printf("  -d Enable debugging\n");
    printf("  -r SECONDS RIP update interval\n");
    printf("  -h Print this help\n");
    exit(0);
}

int write_pcap_file_header(const char* filename) {
    pid_t pid = fork();
    if(pid == 0) {
        if (debug) printf("Writing pcap file header for %s",filename);
        execl("./make_pcap.sh","make_pcap.sh",filename,(char*)nullptr);
        perror("excel");
        _exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        return WEXITSTATUS(status);
    } else {
        perror("fork");
        return -1;
    }
}

// handles -i input converts to structs for interfaces vector
std::vector<std::string> parse_interfaces(int argc, char* argv[]){
    std::vector<std::string> interfaces_;
    for (int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "-i") == 0) {
            i++;
            if (i >= argc) print_help();
            interfaces_.push_back(argv[i]);
        }
        if(strcmp(argv[i], "--default-route") == 0) {
            i++;
            if (i >= argc) print_help();
            default_route = argv[i];
        }
        if(strcmp(argv[i], "-d") == 0) {
            debug++;
            //printf("im debugging ^^\n");
        }
        if(strcmp(argv[i], "-r") == 0) {
            i++;
            if (i >= argc) print_help();
            rip_interval = atoi(argv[i]);
            if (rip_interval <= 0) print_help();
        }
        if(strcmp(argv[i], "-h") == 0) {
            print_help();
            exit(0);
        }
    }
    if (debug) {
        printf("default route:%s\n",default_route.c_str());
        printf("rip interval:%d\n",rip_interval);
    }
    if (interfaces_.empty()) print_help();
    return interfaces_;
}

// opens file for interface and fills interface struct
void setup_interface(const char* interface_, int interface_idx) {
    std::string arg(interface_);
    size_t pos = arg.find('_');
    if (pos == std::string::npos) {
        fprintf(stderr, "Invalid interface spec: %s\n", interface_);
        exit(1);
    }
    std::string ip_str = arg.substr(0, pos);
    std::string mask_str = arg.substr(pos + 1);
    uint32_t ip = str_to_ip(ip_str.c_str());
    uint32_t mask_length = atoi(mask_str.c_str());
    uint32_t network = calc_network(ip,mask_length);

    char filename[64];
    snprintf(filename,sizeof(filename),"%s_%u.dmp",ip_to_str(network).c_str(), mask_length);
    if(debug) printf("%s_%u.dmp\n",ip_to_str(network).c_str(),mask_length);

    struct stat st;
    if(stat(filename,&st) == 0) {
        if (access(filename, R_OK | W_OK) != 0) {
            fprintf(stderr, "File %s exists but is not accessible: %s\n", filename, strerror(errno));
            exit(1);
        }
    } else {
        int fd = open(filename,O_CREAT | O_WRONLY, 0644);
        if (fd < 0) {
            perror("open\n");
            exit(1);
        }
        close(fd);
        if (write_pcap_file_header(filename) != 0) {
            printf("write fail pcap header for %s\n",filename);
            exit(1);
        }
    }

    if (debug) {
        //printf("\nfilename: %s\n", filename);
        printf("ip: %s\n", ip_str.c_str());
        //printf("mask: %s\n\n", mask_str.c_str());
    }


    int fd_r = open(filename,O_RDONLY);
    int fd_w = open(filename, O_WRONLY | O_APPEND);
    if (fd_r < 0 || fd_w < 0) {
        perror("open");
        exit(1);
    } 

    pcap_file_header pfh;
    if (read(fd_r,&pfh,sizeof(pfh)) != sizeof(pfh)) {
        perror("read pcap header\n");
        exit(1);
    }

    if(debug) printf("setup_interface: swapping endianess!\n");

    if (pfh.magic == PCAP_MAGIC) {  // 0xa1b2c3d4 
        file_is_big_endian = false;
    } else if (pfh.magic == swap32(PCAP_MAGIC)) {  
        file_is_big_endian = true;
        pfh.version_major = swap16(pfh.version_major);
        pfh.version_minor = swap16(pfh.version_minor);
        pfh.thiszone = swap32(pfh.thiszone);
        pfh.sigfigs = swap32(pfh.sigfigs);
        pfh.snaplen = swap32(pfh.snaplen);
        pfh.linktype = swap32(pfh.linktype);
    } else {
        fprintf(stderr, "invalid magic number: 0x%08x\n", pfh.magic);
        exit(1);
    }

    interfaces[interface_idx].ipv4_addr = ip;
    interfaces[interface_idx].mask_length = mask_length;
    ip_to_mac(ip, interfaces[interface_idx].mac_addr);
    interfaces[interface_idx].fd_r = fd_r;
    interfaces[interface_idx].fd_w = fd_w;

    uint8_t* mac = interfaces[interface_idx].mac_addr;
    mac[0] = 0x5E;
    mac[1] = 0xFE;
    memcpy(mac + 2, &ip,4);
}

// prints routing table lol
void print_routing_table() {
    if (!debug) return;
    printf("Routing Table:\n");
    for (const auto& entry : routing_table) {
        printf("Dest: %s/%d, Next Hop: %s, Metric: %d, Iface: %d\n",
               ip_to_str(entry.dest_ip).c_str(),
               32 - __builtin_clz(entry.mask),
               entry.next_hop ? ip_to_str(entry.next_hop).c_str() : "Direct",
               entry.metric, entry.interface_idx);
    }
    printf("\n");
}

void init_routing_table() {
    for (int i = 0; i < num_interfaces; i++) {
        uint32_t mask = (0xffffffff << (32 - interfaces[i].mask_length)) & 0xffffffff;
        uint32_t network = calc_network(interfaces[i].ipv4_addr, interfaces[i].mask_length);
        routing_table.push_back({network, mask, 0, 0, i});
        if (debug) {
            printf("Added route for iface %d: %s/%d\n", i,
                   ip_to_str(network).c_str(), interfaces[i].mask_length);
        }
    }
    if (!default_route.empty()) {
        if (num_interfaces == 1) {
            fprintf(stderr, "--default-route only for routers\n");
            exit(1);
        }

        std::string clean_default_route = default_route;
        size_t pos = clean_default_route.find('_');
        if (pos != std::string::npos) {
            clean_default_route = clean_default_route.substr(0, pos);
        }

        uint32_t next_hop = str_to_ip(clean_default_route.c_str());
        int iface_idx = -1;
        for (int i = 0; i < num_interfaces; i++) {
            uint32_t mask = (0xffffffff << (32 - interfaces[i].mask_length)) & 0xffffffff;
            uint32_t network = calc_network(interfaces[i].ipv4_addr, interfaces[i].mask_length);
            if ((next_hop & mask) == network) {
                iface_idx = i;
                break;
            }
        }
        if (iface_idx == -1) {
            fprintf(stderr, "Default route next hop not on any network\n");
            exit(1);
        }
        routing_table.push_back({0, 0, next_hop, 1, iface_idx});
        if (debug) {
            printf("Added default route via %s on iface %d\n",
                   ip_to_str(next_hop).c_str(), iface_idx);
        }
    }
    print_routing_table();
}

void write_packet(int interface_idx, const void* data, size_t len) {
    printf("Writing!\n");
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

    ssize_t expected = static_cast<ssize_t>(sizeof(pph) + len);
    if (writev(interfaces[interface_idx].fd_w, iov, 2) != expected) {
        perror("writev");
    }
}