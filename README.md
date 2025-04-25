# SHRUB
Structure
```
/shrub-ElijahBeard
  |_ shrub.cc (parse input, parse interface, setup interface, loop through interfaces, uses twig.h read_packet / process_packet)
  |_ shrub.h (contains globals, input parsing, function definition)
  |_ route.h (contains routing tables, init_routing, add_route)
  |_ twig.h (read packet header, read packet)
  |_ utils.h (swap_16, swap_32, ip_to_mac, ip_to_string, string_to_ip, calc_network)
  |_ arp.h
  |_ icmp.h
  |_ udp.h
  |_ pheaders.h (all packet headers)
  ~maybe~
  |_ ipv4.h
  |_ pcap_headers.h
  |_ ethernet.h
```

# TODO 
- [x] parse_input(int argc, char* argv[])
- [x] interfaces init
- [x] interfaces loop
- [x] correctly read packet
- [x] correctly write packet
- [x] RIPv2