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
