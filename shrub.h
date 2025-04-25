#include <cstdlib>
#include <string>
#include <iostream>
#include <set>

struct interface {
    uint32_t ipv4_addr;
    uint32_t mask_length;
    uint32_t network;           // Network address (IP & mask)
    std::string pcap_file;
    int fd_read;
    int fd_write;
    off_t read_offset;
    std::set<off_t> write_offsets; // Offsets of packets written by this instance
    uint64_t mac_addr;
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
        for(int i = 0; i < num_interfaces; i++){
            printf("%s\n",interfaces_[i].c_str());
        }
        printf("default route:%s\n",default_route.c_str());
        printf("rip interval:%d\n",rip_interval);
    }
    if (interfaces_.empty()) print_help();
    return interfaces_;
}