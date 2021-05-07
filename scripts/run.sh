#!/bin/bash

sleep 10
/bin/bash -c 'LOCALIP=$(nmcli conn show WAN 2>&1|grep IP4.ADDRESS|awk "{print \$2}") && CAPTURENIC=$(nmcli conn |grep "WAN"|awk "{print \$4}")  && /usr/local/trafficmonitor/trafficmonitor -filter= -iface=${CAPTURENIC} -localIPs=${LOCALIP} -promRefresh=10 -promHTTP=127.0.0.1:8888'