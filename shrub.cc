#include <cstdlib>

#include "twig.h"
#include "shrub.h"

int main(int argc, char* argv[]) {
    std::vector<std::string> interfaces_ = parse_interfaces(argc,argv);
    num_interfaces = interfaces_.size();
    for (int i = 0; i < num_interfaces; i++) {
        setup_interface(interfaces_[i].c_str(), i);
    }

    init_routing_table();

    // time_t last_rip = 0;
    // while(1) {
    //     fd_set readfds;
    //     FD_ZERO(&readfds);
    //     for(int i = 0; i < num_interfaces i++) {
    //         FD_SET(interfaces[i].pcap_f_read,&readfds);
    //         if (interfaces_[i].pcap_fd_read > max_fd) max_fd = interfaces_[i].pcap_fd_read;
    //     }
    //     struct timeval tv = {1,0}; // 1 sec timeout
    //     int ret = select(max_fd + 1, &readfds, NULL, NULL, &tv);
    //     if (ret < 0){
    //         if (errno == EINTR) continue;
    //         perror("select");
    //         exit(1);
    //     } else if (ret == 0) {
    //         if (num_interfaces > 1) {
    //             time_t now = time(NULL);
    //             if(now - last_rip >= rip_interval) {
    //                 send_rip_announcement();
    //                 last_rip = now;
    //             }
    //         }
    //     } else {
    //         for (int i = 0; i < num_interfaces; i++) {
    //             if (FD_ISSET(interfaces[i].pcap_fd_read, &readfds)) {
    //                 process_packet(i);
    //             }
    //         }
    //     }
    // }
}