package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"
)

func main() {
	cidr := 0xf0f00000
	mask := 0xffff0000
	addr := 0xf0f0f0f0

	fmt.Printf("%b, %b, %b\n", cidr, mask, addr&mask)

	if cidr == addr&mask {
		fmt.Println("True")
	}

	// -------------------

	sAddr := "10.0.0.124"
	sStr := strings.Split(sAddr, ".")

	var hAddr uint32

	for _, v := range sStr {
		i, err := strconv.Atoi(v)
		if err != nil {
			log.Printf("error:failed to convert address: %v\n", err)
			return
		}
		fmt.Printf("i=%b\n", i)

		hAddr = hAddr << 8
		hAddr = hAddr | uint32(i)

		fmt.Printf("addr=%032b\n", hAddr)
	}
}
