package Plugins

import (
	"ScanMaster/common"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

type Addr struct {
	IP   string
	Port int
}

func PortScan(hostslist []string, ports string, timeout int64) []common.HostInfo {
	var AliveAddress []common.HostInfo
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
	workers := common.Threads

	chanSize := len(hostslist) * len(probePorts)
	if chanSize > common.MaxChanSize {
		chanSize = common.MaxChanSize
	}

	Addrs := make(chan Addr, chanSize)
	results := make(chan common.HostInfo, chanSize)
	var wg sync.WaitGroup

	//接收结果 found = 存活的 "ip:port"，并在这里对端口进行协议以及服务名的操作
	go func() {
		for found := range results {
			AliveAddress = append(AliveAddress, found)
			wg.Done()
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range Addrs {
				PortConnect(addr, results, timeout, &wg)
				wg.Done()
			}
		}()
	}

	//添加扫描目标 将其目标改为文档中的内容
	for _, port := range probePorts {
		for _, host := range hostslist {
			wg.Add(1)
			Addrs <- Addr{host, port}
		}
	}

	wg.Wait()
	close(Addrs)
	close(results)
	return AliveAddress
}

// 测试端口是否开发 若开发则直接进行信息检测
func PortConnect(addr Addr, respondingHosts chan<- common.HostInfo, adjustedTimeout int64, wg *sync.WaitGroup) {
	host, port := addr.IP, addr.Port
	d := &net.Dialer{Timeout: time.Duration(adjustedTimeout) * time.Second} //设置tcp超时时间
	conn, err := common.WrapperTCP("tcp4", fmt.Sprintf("%s:%v", host, port), d)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err == nil { //tcp连接成功 端口开发
		address := host + ":" + strconv.Itoa(port)
		fmt.Printf("%s open", address)
		//初始化 该 ip:port 信息
		hostinfo := common.HostInfo{host, strconv.Itoa(port), "", common.ProtocolName(port), common.Info{nil, "", ""}}

		WebTitle(&hostinfo, conn)       //对端口进行 http 协议检测 => web服务检测 + web蜜罐检测
		common.HPCheck(&hostinfo, conn) //蜜罐检测

		//common.LogSuccess(result)
		wg.Add(1)
		respondingHosts <- hostinfo
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
