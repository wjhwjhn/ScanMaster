package Plugins

import (
	"ScanMaster/common"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Addr struct {
	IP   string
	Port int
}

func GetProbePorts(ports string) (probePorts []int) {
	probePorts = common.ParsePort(ports)
	noPorts := common.ParsePort(common.NoPorts)
	if len(noPorts) > 0 {
		temp := map[int]struct{}{}
		for _, port := range probePorts {
			temp[port] = struct{}{}
		}

		for _, port := range noPorts {
			delete(temp, port)
		}

		var newDatas []int
		for port, _ := range temp {
			newDatas = append(newDatas, port)
		}
		probePorts = newDatas
		sort.Ints(probePorts)
	}
	return probePorts
}

func PortScan(hostslist []string, probePorts []int, timeout int64, results chan<- common.NetworkEndpoint) {
	defer close(results)

	workers := common.Threads
	Addrs := make(chan Addr, common.MaxChanSize)
	var wg sync.WaitGroup

	//多线程扫描
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range Addrs {
				PortConnect(addr, results, timeout)
				wg.Done()
			}
		}()
	}

	//添加扫描目标
	for _, port := range probePorts {
		for _, host := range hostslist {
			wg.Add(1)
			Addrs <- Addr{host, port}
		}
	}

	wg.Wait()
	close(Addrs)
}

func TcpWithDeadline(endPoint *common.NetworkEndpoint) (net.Conn, error) {
	conn, err := common.WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", endPoint.IPAddress, endPoint.Port), time.Duration(common.Timeout)*time.Second)
	if err != nil {
		return nil, err
	}

	err = conn.SetDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func DetectBase(conn net.Conn, endPoint *common.NetworkEndpoint) (string, error) {
	var service_data string
	var err error

	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	var payloads = []string{"HEAD / HTTP/1.1\r\n\r\n", "GET / HTTP/1.1\r\n\r\n"}
	for index, payload := range payloads {
		if index != 0 {
			conn, err = TcpWithDeadline(endPoint)
			if err != nil {
				return "", err
			}
		}

		_, err = conn.Write([]byte(payload))
		if err != nil {
			return "", err
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf[:])
		if err != nil {
			if err.Error() == "EOF" {
				//尝试其他 payload
				continue
			}
			return "", err
		}

		service_data = string(buf[:n])
		service_data = strings.ToLower(service_data)
		break
	}

	switch {
	case strings.Contains(service_data, "access mongodb"):
		endPoint.Protocol = "mongodb"
	case strings.HasPrefix(service_data, "http"):
		if strings.Contains(service_data, "https scheme") {
			endPoint.Protocol = "https"
		} else {
			endPoint.Protocol = "http"
		}
	case strings.Contains(service_data, "ssh"):
		endPoint.Protocol = "ssh"
	case strings.Contains(service_data, "mariadb") || strings.Contains(service_data, "mysql") || strings.Contains(service_data, "_password"):
		endPoint.Protocol = "mysql"
	case (endPoint.Port == 21 && strings.Contains(service_data, "220")) ||
		strings.Contains(service_data, "ftp") || strings.Contains(service_data, "500 command"):
		endPoint.Protocol = "ftp"
	case strings.Contains(service_data, "helo") && strings.Contains(service_data, "as"):
		endPoint.Protocol = "weblogic"
	case (endPoint.Port == 23 && strings.HasSuffix(service_data, "\r\n")) || strings.Contains(service_data, "username") || strings.Contains(service_data, "test"):
		endPoint.Protocol = "telnet"
	case (endPoint.Port == 143 && (strings.Contains(service_data, "ready.") || strings.Contains(service_data, "authentication"))) ||
		strings.Contains(service_data, "imap"):
		endPoint.Protocol = "imap"
	case (endPoint.Port == 110 &&
		(strings.Contains(service_data, "ready.") || strings.Contains(service_data, "authentication") || strings.Contains(service_data, "+ok"))) ||
		strings.Contains(service_data, "dovecot") || strings.Contains(service_data, "pop3"):
		endPoint.Protocol = "pop3"
	case strings.Contains(service_data, "smtp synchronization") ||
		(endPoint.Port == 25 || endPoint.Port == 587 || endPoint.Port == 465) && strings.Contains(service_data, "220"):
		endPoint.Protocol = "smtp"
	case endPoint.Port == 139:
		endPoint.Protocol = "netbios"
	case strings.Contains(service_data, "@rsyncd"):
		endPoint.Protocol = "rsync"
	case strings.Contains(service_data, "rtsp"):
		endPoint.Protocol = "rtsp"
	case strings.Contains(service_data, "amqp"):
		endPoint.Protocol = "amqp"
	case endPoint.Port == 465:
		endPoint.Protocol = "smtps"
	case endPoint.Port == 5060:
		endPoint.Protocol = "sip"
	default:
		//方便前期调试，但不符合文档规范
		endPoint.Protocol = "unknown: " + service_data
		return "", errors.New("unknown")
	}

	return service_data, nil
}

func DetectSMTP(endPoint *common.NetworkEndpoint) (string, error) {
	conn, err := TcpWithDeadline(endPoint)
	if err != nil {
		return "", err
	}

	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	_, err = conn.Write([]byte("EHLO scan\r\n"))
	if err != nil {
		return "", err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf[:])
	if err != nil {
		return "", err
	}

	service_data := string(buf[:n])
	service_data = strings.ToLower(service_data)

	if strings.Contains(service_data, "220") || strings.HasSuffix(service_data, "\r\n") {
		endPoint.Protocol = "smtp"
		return service_data, nil
	}

	return "", errors.New("no smtp")
}

func DetectRedis(endPoint *common.NetworkEndpoint) (string, error) {
	conn, err := TcpWithDeadline(endPoint)
	if err != nil {
		return "", err
	}

	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	_, err = conn.Write([]byte("*1\x0d\x0a$4\x0d\x0aPING\x0d\x0a"))
	if err != nil {
		return "", err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf[:])
	if err != nil {
		return "", err
	}

	service_data := string(buf[:n])
	service_data = strings.ToLower(service_data)

	if strings.Contains(service_data, "+pong\x0d\x0a") {
		endPoint.Protocol = "redis"
		return service_data, nil
	}

	return "", errors.New("no redis")
}

func DetectHttps(endPoint *common.NetworkEndpoint) (string, error) {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: time.Duration(common.Timeout) * time.Second,
	}
	client := &http.Client{Transport: tr}

	_, err := client.Head(fmt.Sprintf("https://%s:%v", endPoint.IPAddress, endPoint.Port))
	if err != nil {
		if strings.Contains(err.Error(), "server gave HTTP response") {
			endPoint.Protocol = "http"
			return "", nil
		}
		return "", err
	}
	endPoint.Protocol = "https"
	return "", nil
}

func DetectSocks(endPoint *common.NetworkEndpoint) (string, error) {
	var err error
	var status bool
	if status, err = socksHandshake(endPoint, 5); status {
		endPoint.Protocol = "socks5"
	} else if status, err = socksHandshake(endPoint, 4); status {
		endPoint.Protocol = "socks4"
	}
	return "", err
}

func socksHandshake(endPoint *common.NetworkEndpoint, version int) (bool, error) {
	conn, err := TcpWithDeadline(endPoint)
	if err != nil {
		return false, err
	}

	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	// sock4协议
	if version == 4 {
		payload := []byte{
			0x04,       // 版本号
			0x01,       // 命令（CONNECT）
			0x00, 0x50, // 目标端口
			0x00, 0x00, 0x00, 0x01, // 目标IP（使用本地DNS解析）
			0x00, // 用户标识（空）
		}
		_, err := conn.Write(payload)
		if err != nil {
			return false, err
		}

		response := make([]byte, 8)
		_, err = conn.Read(response)
		if err != nil {
			return false, err
		}

		if response[1] == 0x5A {
			return true, nil
		} else {
			return false, errors.New("sock4协议握手失败")
		}
	}

	// sock5协议
	if version == 5 {
		payload := []byte{
			0x05, // 版本号
			0x01, // 方法数量
			0x00, // 无需认证
		}
		_, err := conn.Write(payload)
		if err != nil {
			return false, err
		}

		response := make([]byte, 10)
		_, err = conn.Read(response)
		if err != nil {
			conn.Close()
			return false, err
		}

		if response[0] == 0x05 {
			return true, nil
		} else {
			return false, errors.New("sock5协议握手失败")
		}
	}

	return false, errors.New("无效的SOCKS协议版本")
}

func DetectPortProtocol(addr Addr, conn net.Conn) (common.NetworkEndpoint, error) {
	var service_app []string
	var service_data string
	var err error

	detectFunc := []func(endPoint *common.NetworkEndpoint) (string, error){
		DetectHttps,
		DetectSocks,
	}

	netEndPoint := common.NetworkEndpoint{
		IPAddress: addr.IP,
		Port:      addr.Port,
		Protocol:  "unknown",
	}

	defer func() {
		if netEndPoint.Protocol != "http" && netEndPoint.Protocol != "https" {
			service_app = extractServiceApp(service_data, true)
		}

		common.GlobalResultInfo.AddServiceWithProtocolAndApps(addr.IP, addr.Port, netEndPoint.Protocol, service_app...)

		if conn != nil {
			conn.Close()
		}
	}()

	if addr.Port == 25 || addr.Port == 587 || addr.Port == 465 {
		service_data, err = DetectSMTP(&netEndPoint)
		if err == nil {
			return netEndPoint, nil
		}
	}

	if addr.Port == 6379 {
		service_data, err = DetectRedis(&netEndPoint)
		if err == nil {
			return netEndPoint, nil
		}
	}

	service_data, err = DetectBase(conn, &netEndPoint)
	if err == nil {
		return netEndPoint, nil
	}

	for _, fn := range detectFunc {
		service_data, err = fn(&netEndPoint)
		if err == nil {
			return netEndPoint, nil
		}
	}

	switch addr.Port {
	case 445:
		netEndPoint.Protocol = "smb"
	case 995:
		netEndPoint.Protocol = "pop3s"
	case 993:
		netEndPoint.Protocol = "imaps"
	case 3389:
		netEndPoint.Protocol = "rdp"
	}

	return netEndPoint, errors.New("can't detect port protocol")
}

func PortConnect(addr Addr, respondingHosts chan<- common.NetworkEndpoint, adjustedTimeout int64) {
	host, port := addr.IP, addr.Port
	conn, err := common.WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(adjustedTimeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err == nil {
		address := host + ":" + strconv.Itoa(port)
		result := fmt.Sprintf("%s open", address)
		common.LogSuccess(result)

		protocol, err := DetectPortProtocol(addr, conn)
		if err != nil {
			return
		}
		respondingHosts <- protocol
	}
}

func NoPortScan(hostslist []string, ports string) (AliveAddress []string) {
	probePorts := common.ParsePort(ports)
	noPorts := common.ParsePort(common.NoPorts)
	if len(noPorts) > 0 {
		temp := map[int]struct{}{}
		for _, port := range probePorts {
			temp[port] = struct{}{}
		}

		for _, port := range noPorts {
			delete(temp, port)
		}

		var newDatas []int
		for port, _ := range temp {
			newDatas = append(newDatas, port)
		}
		probePorts = newDatas
		sort.Ints(probePorts)
	}
	for _, port := range probePorts {
		for _, host := range hostslist {
			address := host + ":" + strconv.Itoa(port)
			AliveAddress = append(AliveAddress, address)
		}
	}
	return
}
