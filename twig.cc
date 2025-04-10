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
bool file_is_big_endian = false;

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
        file_is_big_endian = true;
        file_header.version_major = swap16(file_header.version_major);
        file_header.version_minor = swap16(file_header.version_minor);
        file_header.thiszone = swap32(file_header.thiszone);
        file_header.sigfigs = swap32(file_header.sigfigs);
        file_header.snaplen = swap32(file_header.snaplen);
        file_header.linktype = swap32(file_header.linktype);
    } else if (file_header.magic == swap32(PCAP_MAGIC)) {  // 0xd4c3b2a1
        file_is_big_endian = false;
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

void icmp_respond(int fd_w, pcap_pkthdr &packet_header, char *packet_data){
    char response_data[65536];
    size_t packet_length = packet_header.caplen;
    memcpy(response_data, packet_data, packet_length);

    // create structures
    pcap_pkthdr reply_packet_header;
    eth_hdr* eth_response = reinterpret_cast<eth_hdr*>(response_data);
    ipv4_hdr* ip_response = reinterpret_cast<ipv4_hdr*>(response_data + 14);
    uint8_t ip_header_len = (ip_response->version_ihl & 0b1111) * 4;
    icmp_hdr* icmp_response = reinterpret_cast<icmp_hdr*>(
    reinterpret_cast<char*>(ip_response) + ip_header_len);
    
    // build packet header
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

    // calculate ip checksum
    {
        uint16_t check = checksum(reinterpret_cast<const uint8_t *>(ip_response), ip_header_len);
        ip_response->checksum = check;
        // is checksum == ffff
        printf("ip-checksum:%u",check);
    }
    
    
    // modify icmp
    icmp_response->type = 0;
    icmp_response->code = 0;
    icmp_response->checksum = 0;
    size_t icmp_length = packet_length - 14 - ip_header_len;
    {
        uint16_t check = checksum(reinterpret_cast<const uint8_t *>(icmp_response), icmp_length);
        icmp_response->checksum = check;
        printf("icmp-checksum:%u",check);
    }

    // flip to big endian

    // write
    struct iovec iov[2];
    iov[0].iov_base = &reply_packet_header;
    iov[0].iov_len = sizeof(reply_packet_header);
    iov[1].iov_base = &response_data;
    iov[1].iov_len = packet_length;
    ssize_t bytes_written = writev(fd_w, iov, 2);
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


    // temp debug area:
    if(debug){
        //printf("Sending reply to IP: %s\n", inet_ntoa(*(in_addr*)&ip_response->dest));
        printf("          MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth_response->dst[0], eth_response->dst[1], eth_response->dst[2],
        eth_response->dst[3], eth_response->dst[4], eth_response->dst[5]);
        printf("Request caplen=%u len=%u\n", packet_header.caplen, packet_header.len);
        printf("Reply caplen=%u len=%u\n", reply_packet_header.caplen, reply_packet_header.len);
        printf("Will write back %zd total bytes (caplen: %u)\n", sizeof(reply_packet_header) + packet_length, reply_packet_header.caplen);
    }

    if (fsync(fd_w) == -1) {
        perror("fsync");
        close(fd_w);
    }    
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

        ipv4_hdr *ip = (ipv4_hdr*)(packet_data + 14);
        
        // ICMP ...
        if (ip->protocol == 1) {
            icmp_hdr* icmp = (icmp_hdr*)((char*)ip + (ip->version_ihl & 0b1111) * 4);
            if(debug)
                printf("ICMP type: %d code: %d\n", icmp->type, icmp->code);
            if (icmp->type == 8) {
                if(debug)
                    printf("ICMP echo request received, sending reply...\n");
                icmp_respond(fd_w,packet_header,packet_data);
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