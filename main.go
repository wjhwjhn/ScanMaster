package main

import (
	"ScanMaster/Plugins"
	"ScanMaster/WebScan/lib"
	"ScanMaster/common"
	"fmt"
	"reflect"
	"strconv"
	"sync"
	"time"
)

var Mutex = &sync.Mutex{}

var PluginList = map[string]interface{}{
	//"webScan": Plugins.WebTitle,
}

//func AddScan(scantype string, info common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
//	*ch <- struct{}{}
//	wg.Add(1)
//	go func() {
//		Mutex.Lock()
//		common.Num += 1
//		Mutex.Unlock()
//		ScanFunc(&scantype, &info)
//		Mutex.Lock()
//		common.End += 1
//		Mutex.Unlock()
//		wg.Done()
//		<-*ch
//	}()
//}

func ScanFunc(name *string, info *common.HostInfo) {
	f := reflect.ValueOf(PluginList[*name])
	in := []reflect.Value{reflect.ValueOf(info)}
	f.Call(in)
}

func main() {
	lib.Inithttp(common.Pocinfo)

	Host := "134.122.46.198"
	//common.HostFile = "iplist.txt"
	Hosts, err := common.ParseIP(Host, common.HostFile, common.NoHosts)
	//Hosts, err := common.ParseIP(Host, common.HostFile, common.NoHosts)
	if err != nil {
		fmt.Println("len(hosts)==0", err)
		return
	}
	//var ch = make(chan struct{}, common.Threads)
	//var wg = sync.WaitGroup{}

	//AlivePorts := Plugins.PortScan(Hosts, fmt.Sprintf("%s,%s,%s", common.DefaultPorts, common.Webport, common.Top1KPorts), common.Timeout)
	AlivePorts := Plugins.PortScan(Hosts, "81", common.Timeout)
	var result = make(common.ResultInfo)

	for _, info := range AlivePorts { //info:[]common.HostInfo
		port, _ := strconv.Atoi(info.Ports)
		//将内容添加到 最终格式中 info内容为：每个ip:port 识别出来的内容
		if _, ok := result[info.Host]; ok {
			newServices := common.Service{port, info.Protocol, info.Info.Services}
			ipinfo := result[info.Host]
			ipinfo.Services = append(result[info.Host].Services, newServices)
			result[info.Host] = ipinfo
		} else {
			currentTime := time.Now()
			formattedTime := currentTime.Format("2006-01-02 15:04:05")
			fmt.Println(formattedTime)
			result[info.Host] = common.IpInfo{
				[]common.Service{common.Service{port, info.Protocol, []string{}}},
				"",
				[]string{""},
				formattedTime,
			}
		}
		//wg.Wait()

	}
	common.JsonOutput(result)
	//wg.Wait()
}
