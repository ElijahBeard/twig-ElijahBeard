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


int debug = 0;
int mask = 0;
int help = 0;
char *dot_dmp;

void print_timestamp(uint32_t ts_secs, uint32_t ts_usecs) {
    time_t raw_time = static_cast<time_t>(ts_secs);
    struct tm* t = localtime(&raw_time);
    if (t == nullptr) {
        printf("Invalid time\n");
        return;
    }
    printf("%04d-%02d-%02d %02d:%02d:%02d.%06u\n",
            t->tm_year + 1900,
            t->tm_mon + 1,
            t->tm_mday,
            t->tm_hour,
            t->tm_min,
            t->tm_sec,
            ts_usecs);
}

int read_pcap_header(int fd, pcap_file_header file_header){
    struct iovec iov[1];
    iov[0].iov_base = &file_header;
    iov[0].iov_len = sizeof(file_header);
    ssize_t bytes_read = readv(fd, iov, 1);
    if (bytes_read == 0) {
        return 0;
    }
    if (bytes_read == -1) {
        perror("readv");
        return -1;
    }

    bool file_is_big_endian = false;
    if (file_header.magic == PCAP_MAGIC) {
        file_is_big_endian = false;
    } else if (file_header.magic == swap32(PCAP_MAGIC)) {
        file_is_big_endian = true;
    } else {
        fprintf(stderr, "invalid magic number: 0x%08x\n", file_header.magic);
        exit(1);
    }

    if (file_is_big_endian) {
        file_header.magic         = swap32(file_header.magic);
        file_header.version_major = swap16(file_header.version_major);
        file_header.version_minor = swap16(file_header.version_minor);
        file_header.thiszone      = swap32(file_header.thiszone);
        file_header.sigfigs       = swap32(file_header.sigfigs);
        file_header.snaplen       = swap32(file_header.snaplen);
        file_header.linktype      = swap32(file_header.linktype);
    }

    printf("magic:0x%x\nvers:%u.%u\nzone:%u\nsigfigs:%u\nsnaplen:%u\nlinktype:%u\n",
        file_header.magic ,file_header.version_major, 
        file_header.version_minor, file_header.thiszone,
        file_header.sigfigs, file_header.snaplen, file_header.linktype);
    return 0;

}

void icmp_respond(pcap_pkthdr &packet_header, char *packet_data){
    int fd_2 = open(dot_dmp, O_WRONLY | O_APPEND);
    if (fd_2 < 0) {
        perror("open");
        exit(1);
    }

    char response_data[65536];
    size_t packet_length = packet_header.caplen;
    memcpy(response_data, packet_data, packet_length);

    pcap_pkthdr reply_packet_header;
    eth_hdr* eth_response = reinterpret_cast<eth_hdr*>(response_data);
    ipv4_hdr* ip_response = reinterpret_cast<ipv4_hdr*>(response_data + 14);
    uint8_t ip_header_len = (ip_response->version_ihl & 0b1111) * 4;
    icmp_hdr* icmp_response = reinterpret_cast<icmp_hdr*>(
    reinterpret_cast<char*>(ip_response) + ip_header_len);
    
    // create packet header
    struct timeval now;
    gettimeofday(&now,NULL);
    reply_packet_header.caplen = packet_header.caplen;
    reply_packet_header.len = packet_header.len;
    reply_packet_header.ts_secs = now.tv_sec;
    reply_packet_header.ts_usecs = now.tv_usec;
    
    // swap ethernet mac
    eth_response->type = htons(0x0800);
    uint8_t tmp_mac[6];
    memcpy(tmp_mac, eth_response->dst, 6);
    memcpy(eth_response->dst, eth_response->src, 6);
    memcpy(eth_response->src, tmp_mac, 6);
            
    // swap ip
    uint32_t tmp = ip_response->dest;
    ip_response->dest = ip_response->src;
    ip_response->src = tmp;
    ip_response->checksum = 0;
    ip_response->checksum = checksum(reinterpret_cast<unsigned short*>(ip_response), ip_header_len);

    // modify icmp
    icmp_response->type = 0;
    icmp_response->code = 0;
    icmp_response->checksum = 0;
    size_t icmp_length = packet_length - 14 - ip_header_len;
    icmp_response->checksum = checksum(reinterpret_cast<unsigned short*>(icmp_response), icmp_length);

    // write
    struct iovec iov[2];
    iov[0].iov_base = &reply_packet_header;
    iov[0].iov_len = sizeof(reply_packet_header);
    iov[1].iov_base = &response_data;
    iov[1].iov_len = packet_length;
    ssize_t bytes_written = writev(fd_2, iov, 2);
    // check ip
    if (debug) {
        printf("IP Header Bytes:\n");
        for (int i = 0; i < ip_header_len; i++) {
            printf("%02x ", (unsigned char)*((char*)ip_response + i));
        }
        printf("\n");
    }
    // check validity
    ssize_t expected_bytes = sizeof(reply_packet_header) + packet_length;
    if (bytes_written != expected_bytes) {
        fprintf(stderr, "Warning: expected to write %zd bytes, but wrote %zd\n", expected_bytes, bytes_written);
    }
    if (bytes_written == 0) {
        if(debug)
            printf("Wrote ICMP echo reply, %zd bytes\n", bytes_written);
    } else if (bytes_written < 0) {
        perror("readv");
        exit (-1);
    }

    close(fd_2);
}

int read_packet(int fd, pcap_file_header file_header){
    pcap_pkthdr packet_header;
    char packet_data[65536];
    memset(&packet_data, 0, 65536);

    struct iovec iov[2];
    iov[0].iov_base = &packet_header;
    iov[0].iov_len = sizeof(packet_header);
    iov[1].iov_base = &packet_data;
    iov[1].iov_len = 65535;
    ssize_t bytes_read = readv(fd, iov, 2);
    if (bytes_read == 0) {
        //printf("waiting for next packet...\n");
        //sleep(2);
        return 0;
    } else if (bytes_read < 0) {
        perror("readv");
        return -1;
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

        ipv4_hdr *ip = (ipv4_hdr*)(packet_data + 14);
        
        // ICMP ...
        if (ip->protocol == 1) {
            icmp_hdr* icmp = (icmp_hdr*)((char*)ip + (ip->version_ihl & 0b1111) * 4);
            if(debug)
                printf("ICMP type: %d code: %d\n", icmp->type, icmp->code);
            if (icmp->type == 8) {
                if(debug)
                    printf("ICMP echo request received, sending reply...\n");
                icmp_respond(packet_header,packet_data);
            }
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

    int fd = open(dot_dmp,O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(1);
    }
    struct pcap_file_header file_header;
    read_pcap_header(fd, file_header);
    while(1){
        int status = read_packet(fd, file_header);
        if (status == -1) {
            printf("error reading packet: -1\n");
            break;
        }
    }
    close(fd);
    return 0;
}