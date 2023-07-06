package main

import (
	"ScanMaster/Plugins"
	"ScanMaster/WebScan/lib"
	"ScanMaster/common"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

var Mutex = &sync.Mutex{}

var PluginList = map[string]interface{}{
	"1000003": Plugins.WebTitle,
}

func AddScan(scantype string, info common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	*ch <- struct{}{}
	wg.Add(1)
	go func() {
		Mutex.Lock()
		common.Num += 1
		Mutex.Unlock()
		ScanFunc(&scantype, &info)
		Mutex.Lock()
		common.End += 1
		Mutex.Unlock()
		wg.Done()
		<-*ch
	}()
}

func ScanFunc(name *string, info *common.HostInfo) {
	f := reflect.ValueOf(PluginList[*name])
	in := []reflect.Value{reflect.ValueOf(info)}
	f.Call(in)
}

func main() {
	lib.Inithttp(common.Pocinfo)

	//Host := "16.163.13.0/24"
	Hosts, err := common.ParseIP("", "ip_list.txt", common.NoHosts)
	//Hosts, err := common.ParseIP(Host, common.HostFile, common.NoHosts)
	if err != nil {
		fmt.Println("len(hosts)==0", err)
		return
	}
	//var ch = make(chan struct{}, common.Threads)
	//var wg = sync.WaitGroup{}

	//AlivePorts := Plugins.PortScan(Hosts, fmt.Sprintf("%s,%s,%s", common.DefaultPorts, common.Webport, common.Top1KPorts), common.Timeout)
	AlivePorts := Plugins.PortScan(Hosts, "0-65535", common.Timeout)

	for _, addr := range AlivePorts {
		var info common.HostInfo
		info.Host, info.Ports = strings.Split(addr, ":")[0], strings.Split(addr, ":")[1]
		port, _ := strconv.Atoi(info.Ports)
		fmt.Printf("%s:%s %s\n", info.Host, info.Ports, common.ProtocolName(port))
		/*if info.Ports == "80" {
			AddScan("1000003", info, &ch, &wg)
		}*/
	}
	//wg.Wait()
}
