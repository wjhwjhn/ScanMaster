package Plugins

import (
	"ScanMaster/common"
	"fmt"
	"sort"
	"strconv"
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

func PortScan(hostslist []string, probePorts []int, timeout int64, results chan<- string) {
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

func PortConnect(addr Addr, respondingHosts chan<- string, adjustedTimeout int64) {
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
		respondingHosts <- address
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
