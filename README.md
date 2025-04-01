# twig-ElijahBeard
- [ ]  Review README / PDF
- [ ]  Experiment with Shim
- [ ]  Set up Project
- [ ]  Add CLI parsing for -i -d -h
- [ ]  **File IO for packet interfaces →**
    - [ ]  Create module for reading from and writing to packet files
        - [ ]  Opening file
        - [ ]  Wait for it to exist
        - [ ]  Read Header Information
- [ ]  **Network Protocol Implementations →**
    - [ ]  ICMP
    - [ ]  ARP Cache
    - [ ]  UDP Demux
    - [ ]  Checksum

## Network Protocol Implementations

1. **ICMP:** respond to ping
2. **ARP:** maintain ARP cache, populate it from incoming packets
3. **UDP:** demultiplex UDP traffic and implement:
    1. UDP echo server (RFC 862)
    2. UDP time server (RFC 868, similar to socket_time.c)
4. **Checksums:** calculate IP, ICMP, and UDP checksums correctly for the purpose of communicating with external programs
5. **NAT Functionality:**
    1. Adjust IP addresses and ports when packets leave the private network
    2. Reverse the process when packets return
    3. Forbid outside packets from targeting private addresses
6. **Routing and Performance:**
    1. Ensure routers send RIP updates on schedule and that routing tables converge
    2. Optimize packet routing for best possible path across the network
7. **Additional Functional Requirements:**
    1. **-i** option specifies interface IP and mask (determines file eg 192.168.1.10/24 → 192.168.1.0_24.dmp)
    2. **-d** option enables debug
    3. **-h** print help summary