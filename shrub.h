#pragma once

#include <cstdlib>
#include <string>
#include <iostream>
#include <set>

#include "utils.h"

struct interface {
    uint32_t ipv4_addr;
    uint32_t mask_length;
    uint64_t mac_addr;
    int fd_r;
    int fd_w;
};

struct route {
    uint32_t dest_ip;
    uint32_t mask;
    uint32_t next_hop;       // Next hop IP (0 for directly connected)
    int metric;              // Hop count (0-16)
    int interface_idx;
};

int debug = 0;
struct interface interfaces[10];
int num_interfaces = 0;
std::vector<route> routing_table;
int rip_interval = 30;
std::string default_route;
bool file_is_big_endian = false;

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

void setup_interface(const char* interface_, int interface_idx) {
    // interface parsing
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

    uint32_t network = calc_network(ip, mask_length);
    std::string filename = "../Twig_tools/" + ip_to_str(network) + "_" + mask_str + ".dmp";

    if (debug) {
        printf("\nfilename: %s\n", filename.c_str());
        printf("ip: %s\n", ip_str.c_str());
        printf("mask: %s\n\n", mask_str.c_str());
    }

    // wait for file to exist
    struct stat buffer;
    while (access(filename.c_str(),F_OK) != 0) {
        printf("Waiting for network %s to exist...\n",filename.c_str());
        sleep(2);
    }

    int fd_r = open(filename.c_str(),O_RDONLY);
    int fd_w = open(filename.c_str(), O_WRONLY | O_APPEND);
    if (fd_r < 0 || fd_w < 0) {
        perror("open");
        exit(1);
    } 

    pcap_file_header pfh;
    if (read(fd_r,&pfh,sizeof(pfh)) != sizeof(pfh)) {
        perror("read pcap header\n");
        exit(1);
    }
    if (pfh.magic != PCAP_MAGIC && pfh.magic != swap32(PCAP_MAGIC)) {
        perror("invalid pcap magic\n");
        exit(2);
    }
    file_is_big_endian = (pfh.magic == swap32(PCAP_MAGIC));

    interfaces[interface_idx] = {
        .ipv4_addr = ip,
        .mask_length = mask_length,
        .mac_addr = ip_to_mac(ip),
        .fd_r = fd_r,
        .fd_w = fd_w
    };
}