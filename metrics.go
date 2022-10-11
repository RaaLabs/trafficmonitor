package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metrics struct {
	localNetworks flagStringSlice
}

func newMetrics(localNetworks flagStringSlice) *metrics {
	m := metrics{localNetworks: localNetworks}
	return &m
}

// Start prometheus listener.
func (m *metrics) startPrometheus(port string) {
	n, err := net.Listen("tcp", port)
	if err != nil {
		log.Printf("error: failed to open prometheus listen port: %v\n", err)
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	http.Serve(n, mux)
}

// doMetrics will register all the metrics for IPMap
func (m *metrics) do(IPMap map[string]map[string]map[string]data, refresh int) {
	hosts := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "hosts_src_dst",
			Help: "Number of bytes transfered between hosts",
		},
		// []string{"addr", "port", "firstSeen", "srcPort", "dstPort"},
		[]string{"a_srcAddr", "b_dstAddr", "c_dstPort", "d_firstSeen", "e_srcMac", "f_dstMac"},
	)

	totalInOpts := prometheus.GaugeOpts{
		Name: "total_incoming",
		Help: "total incoming bytes from internet",
	}
	totalInGauge := promauto.NewGauge(totalInOpts)

	totalOutOpts := prometheus.GaugeOpts{
		Name: "total_outgoing",
		Help: "total outgoing bytes from internet",
	}
	totalOutGauge := promauto.NewGauge(totalOutOpts)

	// Metrics have to be registered to be exposed:
	prometheus.MustRegister(hosts)

	for {
		mu.Lock()
		var totalIn int
		var totalOut int

		for ksip, vsip := range IPMap {
			for kdip, vdip := range vsip {
				for kdport, vdport := range vdip {
					hosts.With(prometheus.Labels{"a_srcAddr": ksip, "b_dstAddr": kdip, "c_dstPort": kdport, "d_firstSeen": vdport.firstSeen, "e_srcMac": vdport.srcMac, "f_dstMac": vdport.dstMac}).Set(float64(vdport.totalAmount))

					for _, v3 := range m.localNetworks.values {
						cidr := strings.Split(v3, "/")
						if len(cidr) < 2 {
							log.Printf("error: local networks: wrong format of addr/maskbits\n")
							os.Exit(1)
						}
						maskb, err := strconv.Atoi(cidr[1])
						if err != nil {
							log.Printf("error: failed to convert maskbits to int: %v\n", err)
						}

						// Check if the source address is a local address.
						ok1, err := checkAddrInPrefix(vdport.srcIP, cidr[0], maskb)
						if err != nil {
							log.Printf("error: checkAddrInPrefix failed: %v\n", err)
						}

						// Check if the destination address is a local address.
						ok2, err := checkAddrInPrefix(vdport.dstIP, cidr[0], maskb)
						if err != nil {
							log.Printf("error: checkAddrInPrefix failed: %v\n", err)
						}

						// If source is local, and destination is not local.
						if ok1 && !ok2 {
							totalOut += vdport.totalAmount
							// fmt.Println("totalOut += v2.totalAmount: ", totalOut)
						}

						// If source is not local, and destination is local.
						if !ok1 && ok2 {
							totalIn += vdport.totalAmount
							// fmt.Println("totalIn += v2.totalAmount: ", totalIn)
						}
					}
				}
			}
		}

		totalInGauge.Set(float64(totalIn))
		totalOutGauge.Set(float64(totalOut))
		//fmt.Printf("totalIn = %v\n", totalIn)
		//fmt.Printf("totalOut = %v\n", totalOut)
		mu.Unlock()

		time.Sleep(time.Second * time.Duration(refresh))
	}
}
