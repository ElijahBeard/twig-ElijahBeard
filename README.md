# SHRUB

## For Silas or Grader
```
This version of shrub is one that I started on a new machine, due to having lost my laptop. Ostermann has granted me time to turn this in on saturday.

The commits here are copied over from an old repo of shrub, but I decided to combine them because it felt nice.
```

Structure
```
/shrub-ElijahBeard
  |_ shrub.cc (parse input, parse interface, setup interface, loop through interfaces, uses twig.h read_packet / process_packet)
  |_ shrub.h (contains globals, input parsing, function definition)
  |_ rip.h (contains routing tables, init_routing, add_route)
  |_ utils.h (swap_16, swap_32, ip_to_mac, ip_to_string, string_to_ip, calc_network)
  |_ arp.h
  |_ icmp.h
  |_ udp.h
  |_ pheaders.h (all packet headers)
```

# TODO 
- [x] parse_input(int argc, char* argv[])
- [x] interfaces init
- [_] interfaces loop
- [_] correctly read packet
- [_] correctly write packet
- [x] routing tables init
- [_] utilize routing tables
- [/] icmp
- [_] udp
- [_] udp time
- [_] udp ping
- [_] rip