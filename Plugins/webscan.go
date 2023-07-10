package Plugins

import (
	"ScanMaster/common"
	"fmt"
)

func WebScan(addr string) {
	fmt.Println("WebScan: ", addr)
	common.GlobalResultInfo.AddServiceApp(addr, "web")
}
