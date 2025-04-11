# For Silas
My twig looks for dmp files in ../Twig_tools/ since thats what my directory looks like. I don't know what your's is. In case your dmp files populate in . go to twig.cc and make SILAS_SWITCH 1 xd

Also I haven't done:

# twig-ElijahBeard TODO
- [ ]  Add CLI parsing
    - [ ] -i
    - [🩹] -d
    - [ ] -h
- [🩹]  **File IO for packet interfaces →**
    - [🩹]  Create module for reading from and writing to packet files
        - [🩹]  Opening file
        - [🩹]  Wait for it to exist
        - [🩹]  Read Header Information
- [ ]  **Network Protocol Implementations →**
    - [🩹] Ip Checksum
    - [🩹] ICMP
    - [💔] UDP Demux
    - [ ] UDP Checksum (EXTRA CREDIT)
    - [ ] ARP Cache