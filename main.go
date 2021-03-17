package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var mu sync.Mutex

const (
	iface   = "any"
	snapLen = int32(1500)
	promisc = false
	timeout = pcap.BlockForever
)

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

// Take the provided information about an IP packet, and store the
// wanted values in a map structure.
func createMapValue(ipLayer gopacket.Layer, packet gopacket.Packet, IPMap map[string]map[string]data) {
	ip, _ := ipLayer.(*layers.IPv4)
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {

		d := data{}

		// Check
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			d.udpOrTcp = "tcp"
			tcp, _ := tcpLayer.(*layers.TCP)
			d.srcPort = d.udpOrTcp + "/" + tcp.SrcPort.String()
			d.dstPort = d.udpOrTcp + "/" + tcp.DstPort.String()
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			d.udpOrTcp = "udp"
			udp, _ := udpLayer.(*layers.UDP)
			d.srcPort = d.udpOrTcp + "/" + udp.SrcPort.String()
			d.dstPort = d.udpOrTcp + "/" + udp.DstPort.String()
		} else {
			return
		}

		d.firstSeen = time.Now().Format("2006 01 2 15:04:05")
		d.srcIP = ip.SrcIP.String()
		d.dstIP = ip.DstIP.String()

		key1srcDst := d.srcIP + "->" + d.dstIP + ", proto: " + d.udpOrTcp

		if key1srcDst == "10.0.0.124->51.120.77.187, proto: tcp" {
			fmt.Printf("len: %s", appLayer.Payload())
		}
		d.totalAmount = packet.Metadata().Length

		// key1srcDstRev := d.dstIP + "->" + d.srcIP + ", proto: " + d.udpOrTcp
		// // Check if this is the return traffic for udp
		// if _, ok := IPMap[key1srcDstRev][d.srcPort]; ok {
		// 	if d.dstIP == "10.0.0.124" || d.dstIP == "127.0.0.1" {
		// 		d.dstPort = "reply_" + d.srcPort
		// 	}
		// }

		// If already present, copy totalLength and time from previous.
		if v, ok := IPMap[key1srcDst][d.dstPort]; ok {
			//fmt.Printf("**************************** PRESENT ****************************\n")
			d.totalAmount = v.totalAmount + d.totalAmount
			d.firstSeen = v.firstSeen
		} else {
			//fmt.Printf("**************************** NOT PRESENT ****************************\n")
		}

		// Declare the inner map, and then store it in the outer map.
		protoMap := map[string]data{}
		protoMap[d.dstPort] = d
		mu.Lock()
		IPMap[key1srcDst] = protoMap
		mu.Unlock()

		//fmt.Printf("--------------------Start-----------------------\n")

		//mu.Lock()
		//for k1, v1 := range IPMap {
		//	for k2, v2 := range v1 {
		//		fmt.Printf("k1: %v, k2: %v, v2: %#v\n", k1, k2, v2)
		//	}
		//}
		//mu.Unlock()
	}
}

// Start prometheus listener.
func startPrometheus(port string) {
	n, err := net.Listen("tcp", port)
	if err != nil {
		log.Printf("error: failed to open prometheus listen port: %v\n", err)
		os.Exit(1)
	}
	m := http.NewServeMux()
	m.Handle("/metrics", promhttp.Handler())
	http.Serve(n, m)
}

// doMetrics will register all the metrics for IPMap
func doMetrics(IPMap map[string]map[string]data, refresh int) {
	hosts := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "hosts_src_dst",
			Help: "Number of bytes transfered between hosts",
		},
		// []string{"addr", "port", "firstSeen", "srcPort", "dstPort"},
		[]string{"addr", "port", "firstSeen", "dstPort"},
	)

	// Metrics have to be registered to be exposed:
	prometheus.MustRegister(hosts)

	for {
		mu.Lock()
		for k1, v1 := range IPMap {
			// fmt.Printf("addr: %v", k1)
			for k2, v2 := range v1 {
				// hosts.With(prometheus.Labels{"addr": k1, "port": k2, "firstSeen": v2.firstSeen.String(), "srcPort": v2.srcPort, "dstPort": v2.dstPort}).Set(float64(v2.totalAmount))
				hosts.With(prometheus.Labels{"addr": k1, "port": k2, "firstSeen": v2.firstSeen, "dstPort": v2.dstPort}).Set(float64(v2.totalAmount))
			}
		}
		mu.Unlock()

		time.Sleep(time.Second * time.Duration(refresh))
	}
}

func main() {
	filter := flag.String("filter", "", "filter to use, same as nmap filters")
	promHTTP := flag.String("promHTTP", ":8888", "set ip and port for prometheus to listen. Ex. localhost:8888")
	promRefresh := flag.Int("promRefresh", 5, "the refresh rate in seconds that prometheus should refresh the metrics")
	var localNetworks flagStringSlice
	flag.Var(&localNetworks, "startCLISubscriber", "enter value")
	flag.Parse()

	go startPrometheus(*promHTTP)

	// Check if the interface exists, or is set to "any"
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		log.Println("error: pcap.FindAllDevs: ", err)
	}

	var devFound = false

	for _, dev := range ifs {
		if dev.Name == iface {
			devFound = true
		}
	}

	if !devFound && iface != "any" {
		log.Printf("error: did not find the interface %v\n", iface)
		return
	}

	// Get a BPF filter handle that we can set the filter on.
	handle, err := pcap.OpenLive("en0", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Printf("error: pcap.OpenLive failed: %v\n", err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(*filter)
	if err != nil {
		log.Printf("error: handle.SetBPFFilter failed: %v\n", err)
	}

	IPMap := map[string]map[string]data{}

	go doMetrics(IPMap, *promRefresh)

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

		if err := parser.DecodeLayers(packetData, &decoded); err != nil {
			fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
		}

		d := data{}

		for _, typ := range decoded {
			fmt.Println("  Successfully decoded layer type", typ)
			switch typ {
			case layers.LayerTypeEthernet:
				fmt.Println("    Eth ", eth.SrcMAC, eth.DstMAC)
			case layers.LayerTypeIPv4:
				fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)
				d.firstSeen = time.Now().Format("2006 01 2 15:04:05")
				d.srcIP = ip4.SrcIP.String()
				d.dstIP = ip4.DstIP.String()
			case layers.LayerTypeTCP:
				// fmt.Println("    TCP ", tcp.SrcPort, tcp.DstPort)
				d.udpOrTcp = "tcp"
				d.srcPort = d.udpOrTcp + "/" + tcp.SrcPort.String()
				d.dstPort = d.udpOrTcp + "/" + tcp.DstPort.String()
			case layers.LayerTypeUDP:
				// fmt.Println("    UDP ", udp.SrcPort, udp.DstPort)
				d.udpOrTcp = "udp"
				d.srcPort = d.udpOrTcp + "/" + udp.SrcPort.String()
				d.dstPort = d.udpOrTcp + "/" + udp.DstPort.String()
			case gopacket.LayerTypePayload:
				// fmt.Printf("    Payload %v\n", payload)
				d.totalAmount = len(payload.LayerContents())
			}
		}

		key1srcDst := d.srcIP + "->" + d.dstIP + ", proto: " + d.udpOrTcp

		key1srcDstRev := d.dstIP + "->" + d.srcIP + ", proto: " + d.udpOrTcp
		// Check if this is the return traffic for udp
		if _, ok := IPMap[key1srcDstRev][d.srcPort]; ok {
			if d.dstIP == "10.0.0.124" || d.dstIP == "127.0.0.1" {
				d.dstPort = "reply_" + d.srcPort
			}
		}

		// If already present, copy totalLength and time from previous.
		if v, ok := IPMap[key1srcDst][d.dstPort]; ok {
			//fmt.Printf("**************************** PRESENT ****************************\n")
			d.totalAmount = v.totalAmount + d.totalAmount
			d.firstSeen = v.firstSeen
		} else {
			//fmt.Printf("**************************** NOT PRESENT ****************************\n")
		}

		// Declare the inner map, and then store it in the outer map.
		protoMap := map[string]data{}
		protoMap[d.dstPort] = d
		mu.Lock()
		IPMap[key1srcDst] = protoMap
		mu.Unlock()

	}
}
