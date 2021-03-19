package main

import (
	"flag"
	"strings"
)

type flagStringSlice struct {
	value  string
	ok     bool
	values []string
}

func (f *flagStringSlice) String() string {
	return ""
}

func (f *flagStringSlice) Set(s string) error {
	f.value = s
	f.Parse()
	return nil
}

func (f *flagStringSlice) Parse() error {
	if len(f.value) == 0 {
		return nil
	}

	fv := f.value
	sp := strings.Split(fv, ",")
	f.ok = true
	f.values = sp
	return nil
}

type flags struct {
	snaplen       int
	promisc       bool
	iface         string
	filter        string
	promHTTP      string
	promRefresh   int
	localIPs      flagStringSlice
	localNetworks flagStringSlice
}

func newFlags() *flags {
	f := flags{}

	flag.IntVar(&f.snaplen, "snaplen", 1500, "the snaplen. Values from 0-65535")
	flag.BoolVar(&f.promisc, "promisc", false, "set to true for promiscuous mode")
	flag.StringVar(&f.iface, "iface", "", "the name of the interface to listen on")
	flag.StringVar(&f.filter, "filter", "", "filter to use, same as nmap filters")
	flag.StringVar(&f.promHTTP, "promHTTP", ":8888", "set ip and port for prometheus to listen. Ex. localhost:8888")
	flag.IntVar(&f.promRefresh, "promRefresh", 5, "the refresh rate in seconds that prometheus should refresh the metrics")

	flag.Var(&f.localIPs, "localIPs", "comma separated list of local host adresses")

	f.localNetworks = flagStringSlice{values: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}}
	flag.Var(&f.localNetworks, "localNetworks", "The local networks of this host in comma separated CIDR notation. If values are given then defaults will be overridden, so make sure to include the defaults if you add extras and also want what was there by default. Defaults are \"10.0.0.0/8\", \"172.16.0.0/12\", \"192.168.0.0/16\"")

	flag.Parse()
	return &f
}
