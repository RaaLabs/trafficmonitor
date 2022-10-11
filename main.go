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
	srcMac      string
	dstMac      string
	totalAmount int
}

func main() {
	f := newFlags()

	if f.iface == "" {
		log.Printf("error: you have to specify an interface to listen on\n")
		os.Exit(1)
	}

	if !f.localIPs.ok {
		log.Printf("error: no local host ip's specified\n")
		os.Exit(1)
	}

	ifsInfo, err := getLocalIPsInfo(f.localIPs)
	if err != nil {
		log.Printf("error: getIfacesInfo: %v\n", err)
		os.Exit(1)
	}

	broadcastMap := map[string]struct{}{}

	for _, v := range ifsInfo {
		broadcastMap[v.broadcast] = struct{}{}
	}

	fmt.Printf("broadcasts: %v\n", ifsInfo)

	localIPMap := map[string]localIPInfo{}
	for _, v := range ifsInfo {
		localIPMap[v.address] = v
	}

	metrics := newMetrics(f.localNetworks)
	go metrics.startPrometheus(f.promHTTP)

	IPMap := map[string]map[string]map[string]data{}
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
				d.srcMac = eth.SrcMAC.String()
				d.dstMac = eth.DstMAC.String()
			case layers.LayerTypeIPv4:
				// d.firstSeen = time.Now().Format("2006 01 2 15:04:05")
				d.firstSeen = time.Now().Format(time.RFC3339)
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

		// Check if this is the return traffic for udp by checking if there had
		// been an outbound sessions using the same two ip adresses reversed present
		// in the map.
		if _, ok := IPMap[d.dstIP][d.srcIP][d.srcPort]; ok {

			// Check if the ip where defined as a local ip at startup
			_, localIPAddrOK := localIPMap[d.dstIP]

			// If dstIP where a defined interface or the loopback interface it
			// means that this is the return traffic. To be able to group these
			// since the source port of the return traffic for UDP will differ
			// we rather prefix the source port with reply_, since it is the same
			// as the dstport port when the outbound sessions was initiated, and
			// we will then group all the reply/return trafic by the original
			// outbound dst port prefixed with reply_. This is ok since we don't
			// care about the source port of the inbound udp trafic.
			// HERE:
			if ok || localIPAddrOK || d.dstIP == "127.0.0.1" {
				d.dstPort = "reply_" + d.srcPort
			}
		}

		// // ---
		// {
		// 	_, broadcastOK := broadcastMap[d.dstIP]
		// 	if broadcastOK {
		// 		fmt.Printf("broadcast 1: %#v\n", d)
		// 	}
		// }
		// // ---

		// // Check if the ip is the broadcast address for any of the local
		// // networks, and if it is prefix the dstport with _broadcast so
		// // we are able to group them.
		// _, broadcastOK := broadcastMap[d.dstIP]
		// if broadcastOK {
		// 	d.dstPort = "broadcast_" + d.dstPort
		// }

		// If already present, copy totalLength and time from previous.
		if v, ok := IPMap[d.srcIP][d.dstIP][d.dstPort]; ok {
			d.totalAmount = v.totalAmount + d.totalAmount
			d.firstSeen = v.firstSeen
		} else if v, ok := IPMap[d.srcIP][d.dstIP]["reply_"+d.dstPort]; ok {
			d.totalAmount = v.totalAmount + d.totalAmount
			d.firstSeen = v.firstSeen
		}
		// else if v, ok := IPMap[key1srcDst]["broadcast_"+d.dstPort]; ok {
		// 	d.totalAmount = v.totalAmount + d.totalAmount
		// 	d.firstSeen = v.firstSeen
		// }

		// ---
		// {
		// 	_, broadcastOK := broadcastMap[d.dstIP]
		// 	if broadcastOK {
		// 		fmt.Printf("broadcast 2: %#v\n", d)
		// 	}
		// }
		// ---

		mu.Lock()
		var ok bool

		// Check if map key's exist, and of not create them as needed.
		_, ok = IPMap[d.srcIP]
		if !ok {
			IPMap[d.srcIP] = map[string]map[string]data{}
		}
		_, ok = IPMap[d.srcIP][d.dstIP]
		if !ok {
			IPMap[d.srcIP][d.dstIP] = map[string]data{}
		}

		// Store the values parsed from the packed in
		IPMap[d.srcIP][d.dstIP][d.dstPort] = d
		mu.Unlock()

		// fmt.Println("----------------------")
		// for ksip, vsip := range IPMap {
		// 	for kdip, vdip := range vsip {
		// 		for kdport, vdport := range vdip {
		// 			fmt.Printf("ksip: %v, kdip: %v, kdport: %v, vdport: %v\n", ksip, kdip, kdport, vdport)
		// 		}
		// 	}
		// }
	}
}
