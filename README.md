# SHRUB

## For Silas or Grader
```
This version of shrub is one that I started on a new machine, due to having lost my laptop. Ostermann has granted me time to turn this in on saturday.

The commits here are copied over from an old repo of shrub, but I decided to combine them because it felt nice.
```

Structure
```
/shrub-ElijahBeard
  |_ shrub.cc (main, process packet)
  |_ shrub.h (contains globals, input parsing, write packets, other logic)
  |_ rip.h (process rip, send rip announcements)
  |_ utils.h (swap_16, swap_32, ip_to_mac, ip_to_string, string_to_ip, calc_network, etc)
  |_ arp.h 
  |_ icmp.h (icmp replies)
  |_ udp.h (udp echo replies, udp time, udp checksum)
  |_ pheaders.h (contains all packet headers)
```

# TODO 
- [x] parse_input(int argc, char* argv[])
- [x] interfaces init
- [x] interfaces loop
- [x] correctly read packet
- [x] correctly write packet
- [x] routing tables init
- [/] utilize routing tables
- [x] icmp
- [x] udp "open issue"
- [x] udp time "open issue"
- [x] udp ping "open issue"
- [x] rip
- [x] arp
- [_] CHAIN working
- [_] BOWTIE working