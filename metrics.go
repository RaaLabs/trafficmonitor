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
func (m *metrics) do(IPMap map[string]map[string]data, refresh int) {
	hosts := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "hosts_src_dst",
			Help: "Number of bytes transfered between hosts",
		},
		// []string{"addr", "port", "firstSeen", "srcPort", "dstPort"},
		[]string{"addr", "port", "firstSeen", "dstPort"},
	)

	totalInOpts := prometheus.GaugeOpts{
		Name: "total_incomming",
		Help: "total incomming bytes from internet",
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

		for k1, v1 := range IPMap {
			for k2, v2 := range v1 {
				// hosts.With(prometheus.Labels{"addr": k1, "port": k2, "firstSeen": v2.firstSeen.String(), "srcPort": v2.srcPort, "dstPort": v2.dstPort}).Set(float64(v2.totalAmount))
				hosts.With(prometheus.Labels{"addr": k1, "port": k2, "firstSeen": v2.firstSeen, "dstPort": v2.dstPort}).Set(float64(v2.totalAmount))

				// ---

				splitK1 := strings.Split(k1, "->")

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

					srcAddr := splitK1[0]
					splitK1Split := strings.Split(splitK1[1], ",")
					dstAddr := splitK1Split[0]

					ok1, err := checkAddrInPrefix(srcAddr, cidr[0], maskb)
					if err != nil {
						log.Printf("error: checkAddrInPrefix failed: %v\n", err)
					}
					ok2, err := checkAddrInPrefix(dstAddr, cidr[0], maskb)
					if err != nil {
						log.Printf("error: checkAddrInPrefix failed: %v\n", err)
					}

					if ok1 && !ok2 {
						totalOut += v2.totalAmount
						// fmt.Println("totalOut += v2.totalAmount: ", totalOut)
					}
					if !ok1 && ok2 {
						totalIn += v2.totalAmount
						// fmt.Println("totalIn += v2.totalAmount: ", totalIn)
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
