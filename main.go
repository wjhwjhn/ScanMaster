package main

import (
	"ScanMaster/Plugins"
	"ScanMaster/common"
	"fmt"
	"sync"
)

func main() {
	hosts, err := common.ParseIP("", "ip_list.txt", common.NoHosts)
	//hosts, err := common.ParseIP("159.65.92.42,113.30.191.229,165.22.22.193,103.252.119.251,185.139.228.48", common.HostFile, common.NoHosts)
	if err != nil {
		fmt.Println("len(hosts)==0", err)
		return
	}
	var wg = sync.WaitGroup{}

	ports := Plugins.GetProbePorts("1-655365")
	chanSize := len(hosts) * len(ports)
	if chanSize < common.MaxChanSize {
		common.MaxChanSize = chanSize
	}

	var portsResults = make(chan common.NetworkEndpoint, common.MaxChanSize)

	go func() {
		Plugins.PortScan(hosts, ports, common.Timeout, portsResults)
	}()

	for found := range portsResults {
		wg.Add(1)
		go func(addr common.NetworkEndpoint) {
			Plugins.WebScan(addr)
			wg.Done()
		}(found)

		wg.Add(1)
		go func(addr common.NetworkEndpoint) {
			Plugins.HoneyPotCheck(addr)
			wg.Done()
		}(found)
	}

	wg.Wait()
}
