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
	Deviceinfo string    `json:"deviceinfo"`
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

func (r *ResultInfo) AddServiceApp(ipPort string, service_app string) {
	ip, port, _ := net.SplitHostPort(ipPort)
	value, _ := r.syncMap.LoadOrStore(ip, &IPInfo{})
	ipInfo := value.(*IPInfo)

	// 遍历查找 Services 中对应端口并添加 service_app
	for i, s := range ipInfo.Services {
		if strconv.Itoa(s.Port) == port {
			ipInfo.Services[i].Service_app = append(ipInfo.Services[i].Service_app, service_app)
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
	file, err := os.Create("results.json")
	if err != nil {
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	r.syncMap.Range(func(key, value interface{}) bool {
		ip := key.(string)
		ipInfo := value.(*IPInfo)
		err := encoder.Encode(map[string]IPInfo{ip: *ipInfo})
		if err != nil {
			return true
		}
		return false
	})
}
