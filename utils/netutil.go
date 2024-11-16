package utils

import (
	"github.com/google/gopacket/pcap"
	"strings"
)

// GetDefaultNetworkInterface 获取默认网卡
func GetDefaultNetworkInterface() (pcap.Interface, error) {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return pcap.Interface{}, err
	}
	for _, ifa := range ifs {
		addrs := ifa.Addresses
		for _, addr := range addrs {
			if ip4 := addr.IP.To4(); ip4 != nil && addr.IP[0] != 127 && !addr.IP.IsLoopback() && addr.Netmask[0] == 0xff && addr.Netmask[1] == 0xff && !strings.Contains(ifa.Description, "VMware Virtual") && !strings.Contains(ifa.Description, "Docker") {
				return ifa, nil
			}
		}
	}
	return pcap.Interface{}, err
}
