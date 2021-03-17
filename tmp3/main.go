package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	var eth layers.Ethernet
	var ip layers.IPv4
	var tcp layers.TCP
	var payload gopacket.Payload

	log.Print("probe collection started")

	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}
	if err = handle.SetBPFFilter("port 80"); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &ip, &tcp, &payload)
	decoded := make([]gopacket.LayerType, 0, 4)

	for {
		data, ci, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			log.Printf("error getting packet: %v %v", err, ci)
			continue
		}
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			// log.Printf("error decoding packet: %v", err)
			continue
		}

		fmt.Printf(" ********************* ip: %s\n", ip.BaseLayer.Payload)
		fmt.Println(" ********************* payload: ", payload.String())

		//flow := NewTcpIpFlowFromLayers(ip, tcp)
		//log.Printf("packet flow %s\n", flow)
		//log.Printf("IP TTL %d\n", ip.TTL)
	}
}
