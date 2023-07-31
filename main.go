package main

import (
	"ScanMaster/Plugins"
	"ScanMaster/common"
	"fmt"
	"sync"
	"os"
)

func main() {
	var wg = sync.WaitGroup{}
	var ports []int

	dirName := "release"
	// 检查当前目录下是否已存在 release 文件夹
	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		if err := os.Mkdir(dirName, 0777); err != nil {
			fmt.Println("无法创建 release 文件夹:", err)
			return
		}
		fmt.Println("成功创建 release 文件夹！")
	} else {
		fmt.Println("release 文件夹已存在，无需创建。")
	}

	hosts, err := common.ParseIP("", "iplist.txt", common.NoHosts)
	if err != nil {
		fmt.Println("len(hosts)==0", err)
		return
	}

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
