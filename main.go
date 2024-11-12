package main

import (
	"github.com/scanner/arsenal/discovery"
	"time"
)

func main() {
	//ipv4
	discovery.SendIcmpV4Request("192.168.31.1", time.Second*3)
	//ipv6
	discovery.SendIcmpV6Request("fe80::20c:29ff:fe58:3451", time.Second*3)
}
