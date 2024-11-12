package discovery

import (
	"encoding/hex"
	"fmt"
	"github.com/asaskevich/govalidator"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"os"
	"time"
)

type ICMPResponse struct {
}

// SendIcmpV4Request
// @description 发送ICMP4请求
// @author pzh
// @param address 目的主机地址
// @param timeout 请求超时时间
func SendIcmpV4Request(address string, timeout time.Duration) bool {
	if !govalidator.IsIPv4(address) {
		fmt.Printf("%s不是一个合法的IPV4地址\n", address)
		return false
	}
	conn, err := net.DialTimeout("ip4:icmp", address, timeout)
	if err != nil {
		fmt.Printf("%sICMP4请求失败\n", address)
		return false
	}
	//设置超时时间
	err = conn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		fmt.Printf("设置%s超时时间失败", address)
		return false
	}
	//关闭连接
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Println("关闭ICMP4连接失败")
		}
	}(conn)
	//发送Echo数据包
	message := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
		},
	}
	marshal, err := message.Marshal(nil)
	if err != nil {
		fmt.Printf("%sICMP4Echo数据包构造失败", address)
		return false
	}
	requestCode, err := conn.Write(marshal)
	if err != nil {
		fmt.Printf("%sICMP4数据写入失败", address)
		return false
	}
	msg := make([]byte, 100)
	responseCodeLength, err := conn.Read(msg)
	if err != nil {
		fmt.Println(err)
		return false
	}
	fmt.Printf("主机:%s通过ICMP4检测存活,ICMP4请求类型:%d,ICMP4响应数据包大小:%d\n", address, requestCode, responseCodeLength)
	return true
}

// SendIcmpV6Request
// @description 发送ICMP6请求
// @author pzh
// @param address 目的主机地址
// @param timeout 请求超时时间
func SendIcmpV6Request(address string, timeout time.Duration) bool {
	if !govalidator.IsIPv6(address) {
		fmt.Printf("%s不是一个合法的IPV6地址\n", address)
		return false
	}
	conn, err := net.DialTimeout("ip6:ipv6-icmp", address, timeout)
	if err != nil {
		fmt.Printf("%sICMP6请求失败\n", address)
		return false
	}
	//设置超时时间
	err = conn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		fmt.Printf("设置%s超时时间失败", address)
		return false
	}
	//关闭连接
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Println("关闭ICMP6连接失败")
		}
	}(conn)
	//发送Echo数据包
	data, _ := hex.DecodeString("6162636465666768696a6b6c6d6e6f7071727374757677616263646566676869")
	message := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest, Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1, Data: data,
		},
	}
	marshal, err := message.Marshal(nil)
	if err != nil {
		fmt.Printf("%sEcho数据包构造失败", address)
		return false
	}
	requestCode, err := conn.Write(marshal)
	if err != nil {
		fmt.Printf("%sICMP6数据写入失败", address)
		return false
	}
	msg := make([]byte, 100)
	responseCodeLength, err := conn.Read(msg)
	if err != nil {
		fmt.Println(err)
		return false
	}
	fmt.Printf("主机:%s通过ICMP6检测存活,ICMP6请求类型:%d,ICMP6响应数据包大小:%d\n", address, requestCode, responseCodeLength)
	return true
}
