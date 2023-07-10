package Plugins

import (
	"ScanMaster/common"
	"bufio"
	"compress/gzip"
	"crypto/md5"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/text/encoding/simplifiedchinese"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"time"
	"unicode/utf8"
)

type HoneyPot struct {
	name     string
	port     string
	protocol string
	reqData  string
	rule     string
}

type request struct {
	Method string
	Url    string
}

// WebHonyPotRule
type WebHonyPotRule struct {
	Name string
	Port string
	Url  []request
	Rule map[string](string)
}

// 23 143 21 1443 22 21 2103 102 502 11211 5060 2022
//var HoneyPotRuleData = []HoneyPot{
//	{"whoisscanme", "ALL", "tcp", "", "(whoisscanme:https://github.com/bg6cq/whoisscanme)"},
//	{"Cowrie", "23", "telnet", "", "(\u00ff\u00fd\u001flogin:)"},
//	{"Amun", "143", "imap", "\r\n\r\n", "(a001 0K LOGIN completed)"},
//	{"Dionaea", "21", "ftp", "", "(220 Welcome to the ftp service\r\n)"},
//	{"Dionaea", "1443", "mssql", "", "(\u0004\u0001 +      \u001A \u0006\u0001   \u0001\u0002 ! \u0001\u0003 \"  \u0004 \" \u0001ÿ\b \u0002\u0010  \u0002  )"},
//	{"Kojoney", "22", "ssh", "", "(SSH-2.0-Twisted)"},
//	{"Nepenthes", "21", "ftp", "", "(---freeFTPd 1.0---warFTPd 165---)"},
//	{"Nepenthes", "2103", "netbios", "", "(\u0082\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000)"},
//	{"Conpot", "102", "s7", "", "(Serial number of module: 88111222)"},
//	{"Conpot", "502", "modbus", "", "(Device Identification: Siemens SIMATIC S7-200)"},
//	{"Dionaea", "11211", "memcached", "", "(version: \"1.4.25\"|pointer_size64|STAT rusage_user 0.5500)"},
//	{"Dionaea", "5060", "sipd", "", "(SIP/2\\.0 200 0K\r\nContent-Length: 0\r\nVia:SIP/2\\.0/TCP|nm;branch=foo\r\nFrom:sip:nm@nm;tag=root\r\nAccept:application/sdp\r\nTo:|\nsip:nm2@nm2\r\nContact:sip:nm2@nm2\r\nCSeq:42 0PTIONS\r\nAllow:REGISTER,OPTIONS,INVITE,CANCEL,BYE,ACK\r\nCall-ID:50000\r\nAccept-Language:en\r\n\r\n)"},
//	{"sshesame", "2022", "ssh", "", "(SSH-2.0-sshesame)"},
//	{"Hfish"},
//}

var HoneyPotRuleData = []HoneyPot{
	{"HFish", "23", "telnet", "\r\n", "test"},
	{"Kippo", "2222", "ssh", "SSH-1.9-OpenSSH_5.9p1\r\n", "(bad version)"},
}

// 80 9200 9000 9001 8000 8001 7001
var WHPRuleData = []WebHonyPotRule{
	{"glastopf", "80", []request{{"GET", "/"}}, map[string]string{"body": "(Blog Comments.*Please post your comments for the blog)"}},
	{"Hfish", "80/9000/9001", []request{{"GET", "/"}, {"GET", "/login"}}, map[string]string{"body": `w-logo-blue.png.*ver=20131202.*ver=5.2.2.*static/x.js`, "hash": "(f9dbaf9282d400fe42529b38313b0cc8)"}},
}

// HoneyPotCheck 传入 ip:port
func HoneyPotCheck(addr string) {
	fmt.Println("HoneyPot Scan: ", addr)
	host, port, _ := net.SplitHostPort(addr)
	name := honeypotCheck(host, port)
	if name != "" {
		common.GlobalResultInfo.AddHoneypot(addr, name)
		return
	}
	name1 := WHPInfoCheck(addr)
	if name1 != "" {
		common.GlobalResultInfo.AddHoneypot(addr, name)
	}
}

func honeypotCheck(host string, port string) string {
	if port == "22" {
		if res := TestHfishSSH(host); res {
			return "HFish"
		}
	}
	for _, datum := range HoneyPotRuleData {
		if datum.port == port { //端口匹配
			conn, err := common.WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(common.Timeout)*time.Second)
			reader := bufio.NewReader(conn)
			fmt.Fprintf(conn, datum.reqData)         //发送数据
			response, err := reader.ReadString('\n') //接受返回数据
			//s := datum.rule
			a, err := regexp.MatchString(datum.rule, response) //匹配特征
			if err == nil && a {
				conn.Close()
				return datum.name
			}
			conn.Close()
		}
	}
	return ""
}

func TestHfishSSH(host string) bool {
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.Password(""),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	conn, err := ssh.Dial("tcp", host+":22", config)
	if err != nil {
		//log.Fatalf("Failed to dial: %s", err)
		return false
	}
	defer conn.Close()

	// 执行远程命令
	session, err := conn.NewSession()
	if err != nil {
		log.Fatalf("Failed to create session: %s", err)
		return false
	}
	defer session.Close()

	// 执行命令并获取输出
	output, err := session.Output("\n")
	if err != nil {
		log.Fatalf("Failed to execute command: %s", err)
		return false
	}
	if string(output) == "test" {
		return true
	}
	return false
}

type CheckDatas struct {
	Body    []byte
	Headers string
}

// WHPInfoCheck 检测 web honeypot
func WHPInfoCheck(host string) string {
	var matched1 bool
	var matched2 bool
	var preUrl = ""
	var Url = ""
	for _, rule := range WHPRuleData {
		for _, url := range rule.Url {
			matched1 = false
			matched2 = false
			method := url.Method
			if preUrl == "" || preUrl != url.Url {
				preUrl = url.Url
				Url = "http://" + host + url.Url
			}
			//method : GET/POST    Url : http://ip:port/login
			data, err := getCheckData(method, Url)
			if err != nil {
				continue
			}
			if hash, ok := rule.Rule["hash"]; ok {
				has := md5.Sum(data.Body)
				md5str := fmt.Sprintf("%x", has)
				res, _ := regexp.MatchString(hash, md5str)
				matched1 = res
			}
			if body, ok := rule.Rule["body"]; ok {
				res1, _ := regexp.MatchString(body, data.Headers)
				res2, _ := regexp.MatchString(body, string(data.Body))
				matched2 = res1 || res2
			}
			if matched1 && matched2 { //匹配到 则返回蜜罐名称
				return rule.Name
			}
		}
	}
	return ""
}

func getCheckData(method string, url string) (CheckDatas, error) {
	/*根据method 和 url 进行请求返回 CheckData
	 */
	data := CheckDatas{nil, ""}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return data, err
	}
	req.Header.Set("User-agent", common.UserAgent)
	req.Header.Set("Accept", common.Accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if common.Cookie != "" {
		req.Header.Set("Cookie", common.Cookie)
	}
	req.Header.Set("Connection", "close")
	//var client *http.Client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return data, err
	}
	defer resp.Body.Close()
	body, err := getRespBody(resp)
	if err != nil {
		return data, err
	}
	if !utf8.Valid(body) {
		body, _ = simplifiedchinese.GBK.NewDecoder().Bytes(body)
	}
	data.Body, data.Headers = body, fmt.Sprintf("%s", resp.Header)
	return data, nil
}

func getRespBody(oResp *http.Response) ([]byte, error) {
	var body []byte
	if oResp.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(oResp.Body)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		for {
			buf := make([]byte, 1024)
			n, err := gr.Read(buf)
			if err != nil && err != io.EOF {
				return nil, err
			}
			if n == 0 {
				break
			}
			body = append(body, buf...)
		}
	} else {
		raw, err := ioutil.ReadAll(oResp.Body)
		if err != nil {
			return nil, err
		}
		body = raw
	}
	return body, nil
}
