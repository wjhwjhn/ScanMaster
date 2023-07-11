package Plugins

import (
	"ScanMaster/common"
	"crypto/tls"
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

func DeepDetectPortProtocol(addr Addr) (net.Conn, error) {
	//redis
	conn, err := common.WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", addr.IP, addr.Port), time.Duration(common.Timeout)*time.Second)
	if err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
	_, err = conn.Write([]byte("*1\x0d\x0a$4\x0d\x0aPING\x0d\x0a"))
	return conn, err
}

func DetectPortProtocol(addr Addr, conn net.Conn) (common.NetworkEndpoint, error) {
	var service_app []string

	netEndPoint := common.NetworkEndpoint{
		IPAddress: addr.IP,
		Port:      addr.Port,
		Protocol:  "unknown",
	}

	conn.SetReadDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	_, err := conn.Write([]byte("HEAD / HTTP/1.1\n\n"))
	if err != nil {
		return netEndPoint, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf[:])
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower("EOF")) {

			conn, err = DeepDetectPortProtocol(addr)
			if err == nil {
				n, err = conn.Read(buf[:])
			} else {
				return netEndPoint, err
			}
		} else {
			return netEndPoint, err
		}

	}

	if err != nil {
		//如果是EOF错误，则根据常用端口号识别
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower("EOF")) {
			//检查 https
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client := &http.Client{Transport: tr}

			_, err := client.Head(fmt.Sprintf("https://%s:%v", addr.IP, addr.Port))
			if err == nil {
				netEndPoint.Protocol = "https"
			} else {
				//非 https
				netEndPoint.Protocol = common.ProtocolName(addr.Port)
				//如果也不是常用端口，则跳过
				if netEndPoint.Protocol == "unknown" {
					return netEndPoint, err
				}
			}
		}

	} else {
		//如果数据有回显，则根据返回内容书别
		service_data := string(buf[:n])
		service_data = strings.ToLower(service_data)
		switch {
		case strings.Contains(service_data, "http"):
			netEndPoint.Protocol = "http"
		case strings.Contains(service_data, "ssh"):
			netEndPoint.Protocol = "ssh"
		case strings.Contains(service_data, "mariadb") || strings.Contains(service_data, "mysql") || strings.Contains(service_data, "native_password"):
			netEndPoint.Protocol = "mysql"
		case strings.Contains(service_data, "ftp") || strings.Contains(service_data, "220 ") || strings.Contains(service_data, "500 command"):
			netEndPoint.Protocol = "ftp"
		case strings.Contains(service_data, "helo") && strings.Contains(service_data, "as"):
			netEndPoint.Protocol = "weblogic"
		case strings.Contains(service_data, "+pong\x0d\x0a"):
			netEndPoint.Protocol = "redis"
		default:
			//方便前期调试，但不符合文档规范
			netEndPoint.Protocol = "unknown: " + service_data
		}
		if netEndPoint.Protocol != "http" {
			service_app = extractServiceApp(service_data, true)
		}
	}

	common.GlobalResultInfo.AddServiceWithProtocolAndApps(addr.IP, addr.Port, netEndPoint.Protocol, service_app...)
	return netEndPoint, nil
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
