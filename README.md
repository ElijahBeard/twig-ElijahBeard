# SILAS,
My twig looks for dmp files in `../Twig_tools/` since thats what my directory looks like. 
In case your dmp files populate in `./` go to twig.cc and make THE_SILAS_SWITCH = 1

# twig-ElijahBeard TODO
- 🩹  **Add CLI parsing →**
    - [🩹] -i
    - [✅] -d
    - [✅] -h
- ✅  **File IO for packet interfaces →**
    - [✅]  Opening file
    - [✅]  Wait for it to exist
    - [✅]  Read Header Information
- 🩹  **Network Protocol Implementations →**
    - [✅] Ip Checksum
    - [✅] ICMP
    - [✅] UDP Demux
    - [🩹] UDP Checksum (EXTRA CREDIT)
    - [ ] ARP Cache
