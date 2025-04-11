#pragma once
#include <cstring>
#include <arpa/inet.h>

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;

#define PCAP_MAGIC         0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

struct pcap_file_header {
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;	/* gmt to local correction; this is always 0 */
	bpf_u_int32 sigfigs;	/* accuracy of timestamps; this is always 0 */
	bpf_u_int32 snaplen;	/* max length saved portion of each pkt */
	bpf_u_int32 linktype;	/* data link type (LINKTYPE_*) */
} __attribute__((packed));

struct pcap_pkthdr {
	bpf_u_int32 ts_secs;		/* time stamp */
	bpf_u_int32 ts_usecs;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length of this packet (off wire) */
} __attribute__((packed));


struct eth_hdr {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
};

struct ipv4_hdr {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t ident;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dest;
};

struct arp_hdr {
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_len;
	uint8_t protocol_len;
	uint16_t op;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
};