package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var mu sync.Mutex

const ()

// Information about the packet
type data struct {
	firstSeen   string
	udpOrTcp    string
	srcIP       string
	srcPort     string
	dstIP       string
	dstPort     string
	totalAmount int
}

func main() {
	{
		tst := flagStringSlice{
			values: []string{"192.168.0.1/24", "10.10.10.10/22"},
		}

		ifsInfo, err := getLocalIPsInfo(tst)
		if err != nil {
			log.Printf("error: getIfacesInfo: %v\n", err)
		}

		fmt.Printf("broadcasts: %v\n", ifsInfo)
	}

	f := newFlags()

	if f.iface == "" {
		log.Printf("error: you have to specify an interface to listen on\n")
		os.Exit(1)
	}

	if !f.localIPs.ok {
		log.Printf("error: no local host ip's specified\n")
		os.Exit(1)
	}

	localIPMap := map[string]struct{}{}
	for _, v := range f.localIPs.values {
		localIPMap[v] = struct{}{}
	}

	metrics := newMetrics(f.localNetworks)
	go metrics.startPrometheus(f.promHTTP)

	IPMap := map[string]map[string]data{}
	go metrics.do(IPMap, f.promRefresh)

	// Get a BPF filter handle that we can set the filter on.
	handle, err := pcap.OpenLive(f.iface, int32(f.snaplen), f.promisc, pcap.BlockForever)
	if err != nil {
		log.Printf("error: pcap.OpenLive failed: %v\n", err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(f.filter)
	if err != nil {
		log.Printf("error: handle.SetBPFFilter failed: %v\n", err)
	}

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP
	var udp layers.UDP
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &udp, &payload)
	decoded := make([]gopacket.LayerType, 0, 10)

	for {
		packetData, ci, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			log.Printf("error getting packet: %v %v", err, ci)
			continue
		}

		err = parser.DecodeLayers(packetData, &decoded)
		if err != nil {
			// log.Printf("error decoding packet: %v", err)
			continue
		}

		d := data{}

		for _, typ := range decoded {
			switch typ {
			case layers.LayerTypeEthernet:
			case layers.LayerTypeIPv4:
				d.firstSeen = time.Now().Format("2006 01 2 15:04:05")
				d.srcIP = ip4.SrcIP.String()
				d.dstIP = ip4.DstIP.String()
			case layers.LayerTypeTCP:
				d.udpOrTcp = "tcp"
				d.srcPort = d.udpOrTcp + "/" + tcp.SrcPort.String()
				d.dstPort = d.udpOrTcp + "/" + tcp.DstPort.String()
			case layers.LayerTypeUDP:
				d.udpOrTcp = "udp"
				d.srcPort = d.udpOrTcp + "/" + udp.SrcPort.String()
				d.dstPort = d.udpOrTcp + "/" + udp.DstPort.String()
			case gopacket.LayerTypePayload:
				d.totalAmount = len(payload.LayerContents())
			}
		}

		if d.totalAmount == 0 {
			continue
		}

		key1srcDst := d.srcIP + "->" + d.dstIP + ", proto: " + d.udpOrTcp

		key1srcDstRev := d.dstIP + "->" + d.srcIP + ", proto: " + d.udpOrTcp
		// Check if this is the return traffic for udp
		if _, ok := IPMap[key1srcDstRev][d.srcPort]; ok {

			// Check if the ip where defined as a local ip at startup
			_, ok2 := localIPMap[d.dstIP]

			if ok2 || d.dstIP == "127.0.0.1" {
				d.dstPort = "reply_" + d.srcPort
			}
		}

		// If already present, copy totalLength and time from previous.
		if v, ok := IPMap[key1srcDst][d.dstPort]; ok {
			d.totalAmount = v.totalAmount + d.totalAmount
			d.firstSeen = v.firstSeen
		} else if v, ok := IPMap[key1srcDst]["reply_"+d.dstPort]; ok {
			d.totalAmount = v.totalAmount + d.totalAmount
			d.firstSeen = v.firstSeen
		}

		// Declare the inner port map, and then store it in the outer hosts map.
		protoMap := map[string]data{}
		protoMap[d.dstPort] = d
		mu.Lock()
		IPMap[key1srcDst] = protoMap
		mu.Unlock()

	}
}
