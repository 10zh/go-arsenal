package discovery

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"strings"
)

// SendARPIPV4Request 向网卡发送ARP-IPV4请求
func SendARPIPV4Request(handle *pcap.Handle, sourceIp string, dstIp string) error {
	mac, err := getMacByIp(sourceIp)
	if err != nil {
		return err
	}
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       mac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   mac,
		SourceProtAddress: net.ParseIP(sourceIp).To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send one packet for every address.
	arp.DstProtAddress = net.ParseIP(dstIp).To4()
	err = gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err != nil {
		return err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}
	fmt.Printf("源IP:%s向目的IP:%s发送Arp请求成功", sourceIp, dstIp)
	return nil
}

// 根据IP地址获取MAC地址
func getMacByIp(sourceIp string) ([]byte, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if strings.Contains(addr.String(), sourceIp) {
				return iface.HardwareAddr, nil
			}
		}
	}
	return nil, errors.New("no ip found")
}
