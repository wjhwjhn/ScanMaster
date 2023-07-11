package common

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

type Service struct {
	Port        int      `json:"port"`
	Protocol    string   `json:"protocol"`
	Service_app []string `json:"service_app"`
}

type IPInfo struct {
	Services   []Service `json:"services"`
	Deviceinfo []string  `json:"deviceinfo"`
	Honeypot   []string  `json:"honeypot"`
	Timestamp  string    `json:"timestamp"`
}

type ResultInfo struct {
	syncMap sync.Map
}

var GlobalResultInfo ResultInfo

func init() {
	go func() {
		for {
			GlobalResultInfo.JsonOutput()
			time.Sleep(60 * time.Second)
		}
	}()
}

func (r *ResultInfo) AddService(ipPort string) {
	ip, stringPort, _ := net.SplitHostPort(ipPort)
	port, _ := strconv.Atoi(stringPort)
	value, _ := r.syncMap.LoadOrStore(ip, &IPInfo{})
	ipInfo := value.(*IPInfo)
	ipInfo.Services = append(ipInfo.Services, Service{Port: port})
}

func (r *ResultInfo) AddServiceWithProtocolAndApps(ip string, port int, protocol string, serviceApps ...string) {
	value, _ := r.syncMap.LoadOrStore(ip, &IPInfo{})
	ipInfo := value.(*IPInfo)
	ipInfo.Services = append(ipInfo.Services, Service{Port: port, Protocol: protocol, Service_app: serviceApps})
}

func (r *ResultInfo) AddServiceDeviceInfo(ip string, deviceInfo ...string) {
	value, _ := r.syncMap.LoadOrStore(ip, &IPInfo{})
	ipInfo := value.(*IPInfo)
	ipInfo.Deviceinfo = append(ipInfo.Deviceinfo, deviceInfo...)

	//去重
	uniqueMap := make(map[string]bool)
	for _, str := range ipInfo.Deviceinfo {
		uniqueMap[str] = true
	}
	uniqueStrings := make([]string, 0, len(uniqueMap))
	for str := range uniqueMap {
		uniqueStrings = append(uniqueStrings, str)
	}
	ipInfo.Deviceinfo = uniqueStrings
}

func (r *ResultInfo) AddServiceApp(ipPort string, serviceApps ...string) {
	ip, port, _ := net.SplitHostPort(ipPort)
	value, _ := r.syncMap.LoadOrStore(ip, &IPInfo{})
	ipInfo := value.(*IPInfo)

	// 遍历查找 Services 中对应端口并添加 service_app
	for i, s := range ipInfo.Services {
		if strconv.Itoa(s.Port) == port {
			ipInfo.Services[i].Service_app = append(ipInfo.Services[i].Service_app, serviceApps...)
			return
		}
	}
}

func (r *ResultInfo) SetServiceProtocol(ipPort string, newProtocol string) {
	ip, port, _ := net.SplitHostPort(ipPort)
	value, _ := r.syncMap.LoadOrStore(ip, &IPInfo{})
	ipInfo := value.(*IPInfo)

	// 遍历查找 Services 中对应端口并修改 Protocol
	for i, s := range ipInfo.Services {
		if strconv.Itoa(s.Port) == port {
			ipInfo.Services[i].Protocol = newProtocol
			return
		}
	}
}

func (r *ResultInfo) AddHoneypot(ipPort string, honeypot string) {
	ip, port, _ := net.SplitHostPort(ipPort)
	value, _ := r.syncMap.LoadOrStore(ip, &IPInfo{})
	ipInfo := value.(*IPInfo)
	ipInfo.Honeypot = append(ipInfo.Honeypot, fmt.Sprintf("%s/%s", port, honeypot))
}

func (r *ResultInfo) JsonOutput() {
	tmpMap := make(map[string]*IPInfo)
	r.syncMap.Range(func(key, value interface{}) bool {
		tmpMap[key.(string)] = value.(*IPInfo)
		return true
	})
	result, err := json.MarshalIndent(tmpMap, "", "  ")
	if err == nil {
		os.WriteFile("results.json", result, 0666)
	}
}
