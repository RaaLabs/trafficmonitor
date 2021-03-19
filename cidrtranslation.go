package main

import (
	"fmt"
	"log"
	"math"
	"strconv"
	"strings"
)

type localIPInfo struct {
	address   string
	maskBits  string
	broadcast string
}

func getLocalIPsInfo(cidrs flagStringSlice) ([]localIPInfo, error) {
	localIPsInfo := []localIPInfo{}

	for _, v := range cidrs.values {
		cidrSplit := strings.Split(v, "/")
		ipAddrString := cidrSplit[0]
		maskBitsString := cidrSplit[1]

		broadCastString, err := getBroadCastAddress(ipAddrString, maskBitsString)
		if err != nil {
			return nil, fmt.Errorf("error: getBroadcastAddress failed: %v", err)
		}

		ipInfo := localIPInfo{
			address:   ipAddrString,
			maskBits:  maskBitsString,
			broadcast: broadCastString,
		}

		localIPsInfo = append(localIPsInfo, ipInfo)
	}

	return localIPsInfo, nil
}

func getBroadCastAddress(ipAddrString string, maskBitsString string) (string, error) {
	ipUint32, err := convertDotStringToUint32(ipAddrString)
	if err != nil {
		log.Printf("error: failed to convert ip address to uint32: %v\n", err)
	}

	m, err := strconv.Atoi(maskBitsString)
	if err != nil {
		log.Printf("error: failed to convert maskbits to int: %v\n", err)
	}
	maskUint32 := convertMaskbitToUint32(m)
	invMaskUint32 := ^maskUint32

	broadcastUint32 := ipUint32 | invMaskUint32
	broadcastString := convertUint32ToDotedString(broadcastUint32)

	return broadcastString, nil
}

// Convert the uint32 representation of an ip address into
// a x.x.x.x string representation.
func convertUint32ToDotedString(u uint32) string {
	bs := make([]byte, 4)
	lsb := uint32(0x000000ff)

	for i := 3; i >= 0; i-- {
		b := byte(u & lsb)
		u = u >> 8
		bs[i] = b
	}

	ipString := fmt.Sprintf("%v.%v.%v.%v", bs[0], bs[1], bs[2], bs[3])

	return ipString
}

// Will take an address, prefix, mask bits as it's input, and return
// true if the addr where within the specified prefix.
func checkAddrInPrefix(addr string, prefix string, maskBits int) (bool, error) {
	a, err := convertDotStringToUint32(addr)
	if err != nil {
		return false, err
	}

	p, err := convertDotStringToUint32(prefix)
	if err != nil {
		return false, err
	}

	m := convertMaskbitToUint32(maskBits)

	result := p&m == a&m

	return result, nil
}

// Convert for example a 24 bits mask to its uint32 representation
func convertMaskbitToUint32(bitsSet int) uint32 {
	restBits := 32 - bitsSet
	u := uint32(math.Pow(2, float64(bitsSet)) - 1)
	u = u << uint32(restBits)

	return u
}

// Will convert string x.x.x.x of ip address into uint32
func convertDotStringToUint32(s string) (uint32, error) {
	nSplit := make([]byte, 4)

	sSplit := strings.Split(s, ".")
	for _, v := range sSplit {
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("error: strconv.Atoi failed: %v", err)
		}

		nSplit = append(nSplit, byte(n))
	}

	// Create an uint32 value of the ip address.
	var addrUint32 uint32
	for _, v := range nSplit {
		addrUint32 = addrUint32 << 8
		addrUint32 = addrUint32 | uint32(v)
	}

	return addrUint32, nil
}
