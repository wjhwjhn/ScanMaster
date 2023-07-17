package main

import (
	"ScanMaster/Plugins"
	"ScanMaster/common"
	"fmt"
	"sync"
)

func main() {
	var wg = sync.WaitGroup{}
	var ports []int

	hosts, err := common.ParseIP("", "iplist.txt", common.NoHosts)
	if err != nil {
		fmt.Println("len(hosts)==0", err)
		return
	}

	ports, err = common.ReadPortFile("ports.txt")
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
	common.GlobalResultInfo.JsonOutput()
	common.LogSuccess("<Done>")
}
