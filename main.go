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
	snapLen = int32(1600)
	promisc = false
	timeout = pcap.BlockForever
)

// Information about the packet
type data struct {
	firstSeen   time.Time
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

		d := data{firstSeen: time.Now()}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			d.srcPort = tcp.SrcPort.String()
			d.dstPort = tcp.DstPort.String()
			d.udpOrTcp = "tcp"
		}

		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			d.srcPort = udp.SrcPort.String()
			d.dstPort = udp.DstPort.String()
			d.udpOrTcp = "udp"
		}

		d.srcIP = ip.SrcIP.String()
		d.dstIP = ip.DstIP.String()
		key1srcDst := d.srcIP + "->" + d.dstIP + ", proto: " + d.udpOrTcp
		key2portInfo := d.udpOrTcp + "/" + d.dstPort

		d.totalAmount = packet.Metadata().Length

		// If already present, copy totalLength and time from previous.
		if v, ok := IPMap[key1srcDst]; ok && IPMap[key1srcDst][key2portInfo].udpOrTcp == d.udpOrTcp {
			d.totalAmount = v[key2portInfo].totalAmount + d.totalAmount
			d.firstSeen = v[key2portInfo].firstSeen
		}

		// Declare the inner map, and then store it in the outer map.
		protoMap := map[string]data{}
		protoMap[key2portInfo] = d
		mu.Lock()
		IPMap[key1srcDst] = protoMap
		mu.Unlock()
	}
}

// Will print out the content of the map to STDOUT.
func printMap(IPMap map[string]map[string]data, timeStart time.Time) {
	fmt.Printf("--------------------Start: %v-----------------------\n", timeStart)

	mu.Lock()
	for k, v := range IPMap {
		fmt.Printf("addr: %v", k)
		for k, v := range v {
			fmt.Printf(", port: %v", k)
			fmt.Printf(", size: %v, firstSeen: %v, srcPort: %v, dstPort: %v", v.totalAmount, v.firstSeen, v.srcPort, v.dstPort)
		}
		fmt.Println()
	}
	mu.Unlock()
	fmt.Printf("--------------------------------------------\n")
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
		[]string{"addr", "port", "firstSeen", "srcPort", "dstPort"},
	)

	// Metrics have to be registered to be exposed:
	prometheus.MustRegister(hosts)

	for {
		mu.Lock()
		for k1, v1 := range IPMap {
			// fmt.Printf("addr: %v", k1)
			for k2, v2 := range v1 {
				hosts.With(prometheus.Labels{"addr": k1, "port": k2, "firstSeen": v2.firstSeen.String(), "srcPort": v2.srcPort, "dstPort": v2.dstPort}).Set(float64(v2.totalAmount))
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

	IPMap := map[string]map[string]data{}

	go doMetrics(IPMap, *promRefresh)

	timeStart := time.Now()

	// gopacket.NetPacketSource will return a channel that we range over
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range src.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		// If it is a real packet, check the content of the packet, and
		// update the map with the new values.
		if ipLayer != nil {
			createMapValue(ipLayer, packet, IPMap)
		}

		if *printConsole {
			printMap(IPMap, timeStart)
		}
	}
}
