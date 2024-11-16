package discovery

import (
	"fmt"
	"net"
	"time"
)

// SendTCPSynRequest
func SendTCPSynRequest(address string, dstPort int16, timeout time.Duration) bool {

	conn, err := net.DialTimeout("tcp", address, time.Second*3)
	if err != nil {
		fmt.Printf("主机:%s端口:%d创建TCP连接失败\n", address, dstPort)
		return false
	}

	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Println("关闭TCP连接失败:", err)
		}
	}(conn)
	return true

}
