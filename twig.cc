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

int mask = 0;
int help = 0;
char *dot_dmp;

int read_pcap_header(int fd_w, pcap_file_header file_header){
    struct iovec iov[1];
    iov[0].iov_base = &file_header;
    iov[0].iov_len = sizeof(file_header);
    ssize_t bytes_read = readv(fd_w, iov, 1);
    if (bytes_read == 0) {
        return 0;
    }
    if (bytes_read == -1) {
        perror("readv");
        return -1;
    }

    if (file_header.magic == PCAP_MAGIC) {  // 0xa1b2c3d4 
        file_is_big_endian = false;
    } else if (file_header.magic == swap32(PCAP_MAGIC)) {  
        file_is_big_endian = true;
        file_header.version_major = swap16(file_header.version_major);
        file_header.version_minor = swap16(file_header.version_minor);
        file_header.thiszone = swap32(file_header.thiszone);
        file_header.sigfigs = swap32(file_header.sigfigs);
        file_header.snaplen = swap32(file_header.snaplen);
        file_header.linktype = swap32(file_header.linktype);
    } else {
        fprintf(stderr, "invalid magic number: 0x%08x\n", file_header.magic);
        return -1;
    }

    printf("magic:0x%x\nvers:%u.%u\nzone:%u\nsigfigs:%u\nsnaplen:%u\nlinktype:%u\n",
        file_header.magic ,file_header.version_major, 
        file_header.version_minor, file_header.thiszone,
        file_header.sigfigs, file_header.snaplen, file_header.linktype);
    return 0;

}

int read_packet(int fd_r, int fd_w, pcap_file_header file_header){
    pcap_pkthdr packet_header;
    char packet_data[65536];
    memset(&packet_data, 0, 65536);

    struct iovec iov[2];
    iov[0].iov_base = &packet_header;
    iov[0].iov_len = sizeof(packet_header);
    iov[1].iov_base = &packet_data;
    iov[1].iov_len = 65535;
    ssize_t bytes_read = readv(fd_r, iov, 2);
    if (bytes_read == 0) {
        //printf("waiting for next packet...\n");
        usleep(1000);
        return 0;
    } else if (bytes_read < 0) {
        perror("readv");
        return -1;
    }

    if (file_is_big_endian) {
        packet_header.ts_secs = swap32(packet_header.ts_secs);
        packet_header.ts_usecs = swap32(packet_header.ts_usecs);
        packet_header.caplen = swap32(packet_header.caplen);
        packet_header.len = swap32(packet_header.len);
    }

    if (packet_header.caplen > 65535 || packet_header.caplen < 14) {
        printf("Invalid caplen: %u\n", packet_header.caplen);
        return 0;
    }

    if (packet_header.caplen < sizeof(eth_hdr)) {
        std::cerr << "Packet too short for Ethernet\n";
        return 0;
    }

    print_timestamp(packet_header.ts_secs,packet_header.ts_usecs);

    eth_hdr* eth = (eth_hdr*)packet_data;
    uint16_t eth_type = ntohs(eth->type);

    if (eth_type == 0x0800) {
        if(debug)
            printf("Ethernet Type: 0x%04x IPV4\n", eth_type);
        if (debug) printf("Ethernet Type: 0x%04x IPv4\n", eth_type);
        ipv4_hdr* ip = reinterpret_cast<ipv4_hdr*>(packet_data + 14);
        uint8_t ip_header_len = (ip->version_ihl & 0b1111) * 4;        
        // ICMP
        if (ip->protocol == 1) {
            icmp_hdr* icmp = reinterpret_cast<icmp_hdr*>((char*)ip + ip_header_len);
            if(debug)
                printf("ICMP type: %d code: %d\n", icmp->type, icmp->code);
            if (icmp->type == 8) {
                if(debug)
                    printf("ICMP echo request received, sending reply...\n");
                icmp_respond(fd_w,packet_header,packet_data); // icmp.h
            }
        }
        // UDP
        else if (ip->protocol == 17) {
            udp_hdr* udp = reinterpret_cast<udp_hdr*>(packet_data + 14 + ip_header_len);
            if(debug)
                printf("UDP len: %d\n", udp->len);
            udp_respond(fd_w,packet_header,packet_data); // udp.h
        }
    } else {
        if(debug)
            printf("detected NOTHING IM USELESS\n");
    }

    if(debug)
        printf("Packet len: %u\n",packet_header.caplen);
    
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage%s <packet_file.dmp>\n",argv[0]);
        return 1; 
    }
    if (argc == 2) { dot_dmp = argv[1]; }
    if (strcmp(argv[1],"-d") == 0)  { debug = 1; dot_dmp = argv[2];}
    if (strcmp(argv[1], "-i") == 0) { mask = 1; dot_dmp = argv[2]; }
    if (strcmp(argv[1], "-h") == 0) { help = 1; dot_dmp = argv[2]; }

    struct stat buffer;
    while (stat(dot_dmp, &buffer) != 0) {
        //printf("Waiting for network %s to exist...\n",dot_dmp);
        //sleep(2);
    }
    int fd_w = open(dot_dmp, O_WRONLY | O_APPEND);
    if (fd_w < 0) {
        perror("open");
        exit(1);
    }
    int fd_r = open(dot_dmp,O_RDONLY);
    if (fd_r < 0) {
        perror("open");
        exit(1);
    }
    struct pcap_file_header file_header;
    read_pcap_header(fd_r, file_header);
    while(1){
        int status = read_packet(fd_r, fd_w, file_header);
        if (status == -1) {
            printf("error reading packet: -1\n");
            break;
        }
    }
    close(fd_r);
    close(fd_w);
    return 0;
}