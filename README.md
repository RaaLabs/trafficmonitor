# trafficmonitor

A traffic monitor that shows what hosts are talking to each other, on what protocol, and how many bytes transferred. Metrics are exported via Prometheus.

## Overview

To build: Clone the repository, and run `go build` from within the repository main folder, and start the program with `sudo ./trafficmonitor <choose flags here>`

Flags that are currently supported are:

```text
  -filter string
    filter to use, same as nmap filters
  -printConsole
    set to true if you also want to print the output of the gathered metrics to console
  -promHTTP string
    set ip and port for prometheus to listen. Ex. localhost:8888 (default ":8888")
  -promRefresh int
    the refresh rate in seconds that prometheus should refresh the metrics (default 5)
```

The metrics produced will look like this

```prometheus
# HELP hosts_src_dst Number of bytes transfered between hosts
# TYPE hosts_src_dst gauge
hosts_src_dst{addr="1.1.1.1->10.0.0.124, proto: udp",dstPort="50508",firstSeen="2021-03-15 16:11:30.353535 +0100 CET m=+88.549728083",port="udp/50508",srcPort="53(domain)"} 119
hosts_src_dst{addr="1.1.1.1->10.0.0.124, proto: udp",dstPort="50961",firstSeen="2021-03-15 16:11:09.803995 +0100 CET m=+68.000553441",port="udp/50961",srcPort="53(domain)"} 160
```
