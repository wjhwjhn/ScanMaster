package common

import (
	"encoding/json"
	"fmt"
	"os"
)

type Service struct {
	Port        int      `json:"port"`
	Protocol    string   `json:"protocol"`
	Service_app []string `json:"service_app"`
}

type IpInfo struct {
	Services   []Service `json:"services"`
	Deviceinfo string    `json:"deviceinfo"`
	Honeypot   []string  `json:"honeypot"`
	Timestamp  string    `json:"timestamp"`
}

// ip:IpInfo
type ResultInfo map[string](IpInfo)

func JsonOutput(result ResultInfo) {
	//json 格式输出到文件里
	Jd, err := json.Marshal(result)
	fmt.Println(string(Jd), err)
	os.WriteFile("results", Jd, 0666)
}
