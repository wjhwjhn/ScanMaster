package Plugins

import (
	"ScanMaster/common"
	"fmt"
)

func HoneyPotCheck(addr string) {
	fmt.Println("HoneyPot Scan: ", addr)
	common.GlobalResultInfo.AddHoneypot(addr, "honeypot")
}
