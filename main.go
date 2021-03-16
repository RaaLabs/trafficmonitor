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
	snapLen = int32(65535)
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

// Will print out the content of the map to STDOUT.
func printMap(IPMap map[string]map[string]data, timeStart time.Time) {
	fmt.Printf("--------------------Start: %v-----------------------\n", timeStart)

	mu.Lock()
	for k1, v1 := range IPMap {
		for k2, v2 := range v1 {
			fmt.Printf("k1: %v, k2: %v, v2: %#v\n", k1, k2, v2)
		}
	}
	mu.Unlock()
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

// Convert a uint16 to host byte order (big endian)
func Htons(v uint16) int {
	return int((v << 8) | (v >> 8))
}

func main() {
	filter := flag.String("filter", "", "filter to use, same as nmap filters")
	promHTTP := flag.String("promHTTP", ":8888", "set ip and port for prometheus to listen. Ex. localhost:8888")
	promRefresh := flag.Int("promRefresh", 5, "the refresh rate in seconds that prometheus should refresh the metrics")
	printConsole := flag.Bool("printConsole", false, "set to true if you also want to print the output of the gathered metrics to console")
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
	handle, err := pcap.OpenLive(iface, snapLen, promisc, timeout)
	if err != nil {
		log.Printf("error: pcap.OpenLive failed: %v\n", err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(*filter)
	if err != nil {
		log.Printf("error: handle.SetBPFFilter failed: %v\n", err)
	}

	// ---------

	// ---------

	IPMap := map[string]map[string]data{}

	go doMetrics(IPMap, *promRefresh)

	timeStart := time.Now()

	// gopacket.NetPacketSource will return a channel that we range over
	src := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		packet, err := src.NextPacket()
		if err != nil {
			log.Printf("error: NextPacket: %v\n", err)
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		// If it is a real packet, check the content of the packet, and
		// update the map with the new values.
		if ipLayer != nil {
			createMapValue(ipLayer, packet, IPMap)
		} else {
			continue
		}

		if *printConsole {
			printMap(IPMap, timeStart)
		}
	}
}
