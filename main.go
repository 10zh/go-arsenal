package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/scanner/arsenal/discovery"
	"github.com/scanner/arsenal/utils"
)

func main() {
	//ipv4
	//discovery.SendIcmpV4Request("192.168.31.1", time.Second*3)
	//ipv6
	//discovery.SendIcmpV6Request("fe80::20c:29ff:fe58:3451", time.Second*3)
	//获取网卡地址
	networkInterface, err := utils.GetDefaultNetworkInterface()
	if err != nil {
		fmt.Println(err)
	}
	handle, err := pcap.OpenLive(networkInterface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = discovery.SendARPIPV4Request(handle, "192.168.31.184", "192.168.31.1")
	if err != nil {
		return
	}
}
