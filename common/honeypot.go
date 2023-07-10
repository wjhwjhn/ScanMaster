package common

import (
	//"ScanMaster/WebScan"
	"bufio"
	"fmt"
	"net"
	"regexp"
)

/*蜜罐检测
产品：
['whoisscanme', 'Cowrie', 'Amun', 'Dionaea', 'Dionaea', 'Kojoney', 'Nepenthes', 'Nepenthes', 'Conpot', 'Conpot', 'Dionaea', 'Dionaea']
协议：
['TCP', 'TELNET', 'IMAP', 'FTP', 'MSSQL', 'SSH', 'FTP', 'NETBIOS', 'S7', 'MODBUS', 'Memcached', 'SIPD', 'SSH']
端口：
['ALL', '23/23', '23', '143', '21', '1443', '22/2222', '21', '2103', '102', '502', '11211', '5060']
请求数据：
['', '', '\r\n\r\n', '', '', '', '', '', '', '', '', '', '']
响应内容特征：
['whoisscanme:https://github.com/bg6cq/whoisscanme', 'ÿý\x1flogin:', 'a001 0K LOGIN completed', '220 Welcome to the ftp service\r\n', '\x04\x01\x00+\x00\x00\x00\x00\x00\x00\x1a\x00\x06\x01\x00 \x00\x01\x02\x00!\x00\x01\x03\x00"\x00\x00\x04\x00"\x00\x01ÿ\x08\x00\x02\x10\x00\x00\x02\x00\x00', 'SSH-2.0-Twisted\r\n', '---freeFTPd 1.0---warFTPd 165---\r\n', ['\x82\x00\x00\x00\x00\x00\x00\x00\x00\x00x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', '\x00\x00\x00x00\x00\x00\x00\x00\x00\x00x00\x00\x00x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x00\x00\x00\x00'], 'Serial number of module: 88111222', 'Device Identification: Siemens SIMATIC S7-200', 'version: "1.4.25”AND response:"pointer_size64" AND response:"STAT rusage_user 0.550000"', 'SIP/2\\.0 200 0K\r\nContent-Length: 0\r\nVia:SIP/2\\.0/TCPnm;branch=foo\r\nFrom:sip:nm@nm;tag=root\r\nAccept:application/sdp\r\nTo:\nsip:nm2@nm2\r\nContact:sip:nm2@nm2\r\nCSeq:42 0PTIONS\rnAllow:REGISTER，OPTIONS， INVITE， CANCEL， BYEACK\r\nCall-ID:50000\r\nAccept-Language:en\r\n\r\n', 'SSH-2.0-sshesame']

HFish 8080 WordPress登录页面 存在x.js的javascript文件
honeypot_info={
	"端口号":[
		{
			"name":
			protocol：
			request-data：
			respones-feature：
		},
	]


}

*/

type HoneyPot struct {
	Name     string
	Port     string
	Protocol string
	ReqData  string
	Rule     string
}

type request struct {
	Method string
	Url    string
}

// webhonypot
type WHPRule struct {
	Name string
	Port string
	Url  []request
	Rule map[string](string)
}

// 80 9200 9000 9001 8000 8001 7001
var WHPRuleData = []WHPRule{
	{"glastopf", "80", []request{{"GET", "/"}}, map[string]string{"body": "(Blog CommentsANDPlease post your comments for the blog)"}},
	{"Amun", "80", []request{{"GET", "/"}}, map[string]string{"body": "(johan83@freenet.deANDtim.bohn@gmx.net)"}},
	{"elastichoney", "9200", []request{{"GET", "/"}}, map[string]string{"body": "(Green Goblin)", "hash": "(89d3241d670db65f994242c8e838b169779e2d4)"}},
	{"elasticpot", "9200", []request{{"GET", "/"}}, map[string]string{"body": "(13.1)", "hash": "(1cfOaa9d61f185b59f643939f862c01f89b21360|db18744ea5570fa9bf868df44fecd4b58332ff24)"}},
	{"Honeypy", "9200", []request{{"GET", "/"}}, map[string]string{"hash": "(61ccbdflfab017166ec4b96a88e82e8ab88f43fcANDFlake)"}},
	{"Hfish", "80/9000/9001", []request{{"GET", "/"}, {"GET", "/login"}}, map[string]string{"body": "(/w-logo-blue.png?ver=20131202AND?ver=5.2.2ANDstatic/x.js)", "hash": "(f9dbaf9282d400fe42529b38313b0cc8)"}},
	{"opencanary", "8000/8001", []request{{"GET", "/"}}, map[string]string{"body": "`content=后台管理系统.*favicon:.*2c91caed2c74490e90cf60526f073165.*`", "hash": "(a48b8dd24ef826c81980835511c550e9|0d79017b8361638a76ea0a496287bef1)"}},
	{"weblogic_honeypot", "7001", []request{{"GET", "/"}}, map[string]string{"body": "`/.*Content-Length.*PSU Patch.*TUE.*Server Module Dependencies.*Oracle WebLogic Server on JRockit Virtual Edition Module Dependencies.*/i`"}},
}

// 23 143 21 1443 22 21 2103 102 502 11211 5060 2022
var HPRuleData = []HoneyPot{
	{"whoisscanme", "ALL", "tcp", "", "(whoisscanme:https://github.com/bg6cq/whoisscanme)"},
	{"Cowrie", "23", "telnet", "", "(\u00ff\u00fd\u001flogin:)"},
	{"Amun", "143", "imap", "\r\n\r\n", "(a001 0K LOGIN completed)"},
	{"Dionaea", "21", "ftp", "", "(220 Welcome to the ftp service\r\n)"},
	{"Dionaea", "1443", "mssql", "", "(\u0004\u0001 +      \u001A \u0006\u0001   \u0001\u0002 ! \u0001\u0003 \"  \u0004 \" \u0001ÿ\b \u0002\u0010  \u0002  )"},
	{"Kojoney", "22", "ssh", "", "(SSH-2.0-Twisted)"},
	{"Nepenthes", "21", "ftp", "", "(---freeFTPd 1.0---warFTPd 165---)"},
	{"Nepenthes", "2103", "netbios", "", "(\u0082\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000)"},
	{"Conpot", "102", "s7", "", "(Serial number of module: 88111222)"},
	{"Conpot", "502", "modbus", "", "(Device Identification: Siemens SIMATIC S7-200)"},
	{"Dionaea", "11211", "memcached", "", "(version: \"1.4.25\"|pointer_size64|STAT rusage_user 0.5500)"},
	{"Dionaea", "5060", "sipd", "", "(SIP/2\\.0 200 0K\r\nContent-Length: 0\r\nVia:SIP/2\\.0/TCP|nm;branch=foo\r\nFrom:sip:nm@nm;tag=root\r\nAccept:application/sdp\r\nTo:|\nsip:nm2@nm2\r\nContact:sip:nm2@nm2\r\nCSeq:42 0PTIONS\r\nAllow:REGISTER,OPTIONS,INVITE,CANCEL,BYE,ACK\r\nCall-ID:50000\r\nAccept-Language:en\r\n\r\n)"},
	{"sshesame", "2022", "ssh", "", "(SSH-2.0-sshesame)"},
}

// 端口：[{honeypot1},{honeypot2}]
//type HPInfo map[string]([]HoneyPot)
//
//// var honeypots = HPInfo{'13','123','123',['123']}
//var a = HoneyPot{Name: "asd", Protocol: "asd", ReqData: "asd", RespData: []string{"asd"}}
//var honeypots = HPInfo{"21": []HoneyPot{a}}

//func main() {
//	fmt.Println(json.Marshal(honeypots))
//}

func HPCheck(info *HostInfo, conn net.Conn) {
	for _, datum := range HPRuleData {
		if datum.Port == info.Ports { //端口匹配
			reader := bufio.NewReader(conn)
			fmt.Fprintf(conn, datum.ReqData)         //发送数据
			response, err := reader.ReadString('\n') //接受返回数据
			//s := datum.Rule
			a, err := regexp.MatchString(datum.Rule, response) //匹配特征
			if err == nil && a {
				info.Info.Honeypot = info.Ports + "/" + datum.Name
			}
		}
	}
}

// 对web的信息进行蜜罐检测

//func removeDuplicateElement(languages []string) []string {
//	result := make([]string, 0, len(languages))
//	temp := map[string]struct{}{}
//	for _, item := range languages {
//		if _, ok := temp[item]; !ok {
//			temp[item] = struct{}{}
//			result = append(result, item)
//		}
//	}
//	return result
//}
