# trafficmonitor

A traffic monitor that shows what hosts are talking to each other, on what protocol, and how many bytes transferred. Metrics are exported via Prometheus.

Metrics for how much total data transfered to and from internet are also exported, where traffic between networks defined with the `localNetworks` are left out of the summary.

NB: If flag `-promisc=true` is set setting `-iface="any"` are not allowed. Only specific named interfaces can be used if running in promiscuous mode.

## Overview

To build: Clone the repository, and run `go build -o trafficmonitor` from within the repository main folder, and start the program with `sudo ./trafficmonitor <choose flags here>`

To build it with the c libraries statically linked into the binary

```bash
LDFLAGS='-l/usr/lib/libpcap.a' CGO_ENABLED=1 \
    go build -ldflags '-linkmode external -extldflags -static' -o trafficmonitor
```

Flags that are currently supported are:

```flags
Usage of ./trafficmonitor:
  -filter string
    filter to use, same as nmap filters
  -iface string
    the name of the interface to listen on
  -localIPs value
    comma separated list of local host adresses
  -localNetworks value
    The local networks of this host in comma separated CIDR notation. If values are given then defaults will be overridden, so make sure to include the defaults if you add extras and also want what was there by default. Defaults are "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
  -promHTTP string
    set ip and port for prometheus to listen. Ex. localhost:8888 (default ":8888")
  -promRefresh int
    the refresh rate in seconds that prometheus should refresh the metrics (default 5)
  -promisc
    set to true for promiscuous mode
  -snaplen int
    the snaplen. Values from 0-65535 (default 1500)
```

The metrics produced will look like this

```prometheus
# HELP hosts_src_dst Number of bytes transfered between hosts
# TYPE hosts_src_dst gauge
hosts_src_dst{addr="10.0.0.124->216.58.211.138, proto: udp",dstPort="udp/443(https)",firstSeen="2021 03 17 13:31:58",port="udp/443(https)"} 5602
hosts_src_dst{addr="10.0.0.124->239.255.255.250, proto: udp",dstPort="udp/1900(ssdp)",firstSeen="2021 03 17 13:31:55",port="udp/1900(ssdp)"} 696
hosts_src_dst{addr="10.0.0.124->51.120.77.187, proto: tcp",dstPort="tcp/80(http)",firstSeen="2021 03 17 13:32:04",port="tcp/80(http)"} 178
hosts_src_dst{addr="10.0.0.124->64.233.162.189, proto: udp",dstPort="udp/443(https)",firstSeen="2021 03 17 13:32:01",port="udp/443(https)"} 580
hosts_src_dst{addr="216.58.211.138->10.0.0.124, proto: udp",dstPort="reply_udp/443(https)",firstSeen="2021 03 17 13:31:58",port="reply_udp/443(https)"} 6229
hosts_src_dst{addr="51.120.77.187->10.0.0.124, proto: tcp",dstPort="reply_tcp/80(http)",firstSeen="2021 03 17 13:32:04",port="reply_tcp/80(http)"} 2.724882e+06
hosts_src_dst{addr="64.233.162.189->10.0.0.124, proto: udp",dstPort="reply_udp/443(https)",firstSeen="2021 03 17 13:32:01",port="reply_udp/443(https)"} 472
...
...
# HELP total_incoming total incoming bytes from internet
# TYPE total_incoming gauge
total_incoming 1.313759453e+09
# HELP total_outgoing total outgoing bytes from internet
# TYPE total_outgoing gauge
total_outgoing 1.06581345e+08
```
