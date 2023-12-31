package Plugins

import (
	"ScanMaster/common"
	"bufio"
	"compress/gzip"
	"crypto/md5"
	"database/sql"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/text/encoding/simplifiedchinese"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type HoneyPotRule struct {
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

type WebHoneyPotRule struct {
	Name string
	Port string
	Url  []request
	Rule map[string]string
}

type SSH struct {
	username string
	passwd   string
}

type SSHHoneyPotRule struct {
	name string
	ssh  SSH
	cmd  string
}

var HPRuleDatas = []HoneyPotRule{
	{"HFish", "23", "telnet", "\r\n", "test"}, //tested is work
	//{"Kippo", "2222", "ssh", "SSH-1.9-OpenSSH_5.9p1\r\n", "(bad version)"}, // not work
}

var WHPRuleDatas = []WebHoneyPotRule{
	{"glastopf", "80", []request{{"GET", "/"}}, map[string]string{"body": "Blog&Comments&Please post your comments for the blog"}},
	{"HFish", "80", []request{
		{"GET", "/"},
		{"GET", "/login"},
	},
		map[string]string{
			"body": "w-logo-blue.png|" +
				"static/x.js|" +
				"89d3241d670db65f994242c8e838b169779e2d4",

			"hash": "f9dbaf9282d400fe42529b38313b0cc8|" +
				"bf887ab8d1dd033d9fea3e636af5b785",
		},
	},
}

var SSHDatas = []SSHHoneyPotRule{
	{"Kippo", SSH{username: "root", passwd: "123456"}, "ls"},
	{"HFish", SSH{username: "root", passwd: "root"}, ""},
}

// HoneyPotCheck 传入 ip:port-协议
func HoneyPotCheck(target common.NetworkEndpoint) {
	if target.Protocol != "http" && target.Protocol != "ssh" && target.Protocol != "mysql" && target.Protocol != "telnet" {
		return
	}

	common.LogSuccess(fmt.Sprintf("[Plugin/HoneyPotScan] %s://%s:%d", target.Protocol, target.IPAddress, target.Port))

	addr := target.IPAddress + ":" + strconv.Itoa(target.Port)
	if target.Protocol == "http" {
		if name := WebHoneyPotCheck(addr); name != "" {
			common.GlobalResultInfo.AddHoneypot(addr, name)
		}
	} else {
		if name := honeypotCheck(target); name != "" {
			common.GlobalResultInfo.AddHoneypot(addr, name)
		}
	}
}

func honeypotCheck(target common.NetworkEndpoint) string {
	host, port := target.IPAddress, strconv.Itoa(target.Port)
	if target.Protocol == "ssh" {
		return SSHCheck(host, port)
	}
	if target.Protocol == "mysql" && MysqlHoneyPotCheck(host, port) {
		return "HFish"
	}
	for _, datum := range HPRuleDatas {
		if datum.protocol == target.Protocol { //协议匹配
			conn, err := common.WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(common.Timeout)*time.Second)
			if err != nil {
				return ""
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
			reader := bufio.NewReader(conn)
			_, err = fmt.Fprintf(conn, datum.reqData) //发送数据
			if err != nil {
				return ""
			}
			response, err := reader.ReadString('\n') //接受返回数据
			if err != nil {
				return ""
			}
			a, err := regexp.MatchString(datum.rule, response) //匹配特征
			if err == nil && a {
				return datum.name
			}
		}
	}
	return ""
}

func MysqlHoneyPotCheck(addr string, port string) bool {
	/*mysql蜜罐一般设置为无密码即可连接 连上后判断能否正常执行mysql查询命令 若不能则判断为蜜罐 */
	db, err := sql.Open("mysql", "root:@tcp("+addr+":"+port+")/mysql?charset=utf8mb4&allowAllFiles=true")
	if err != nil {
		return false
	}
	query := "show databases"
	// 执行查询
	row, err := db.Query(query)
	if err != nil {
		return true
	}
	row.Close()
	return false
}

// SSHCheck 尝试 能否登录 并发信息验证
func SSHCheck(host string, port string) string {
	for _, data := range SSHDatas {
		config := &ssh.ClientConfig{
			User: data.ssh.username,
			Auth: []ssh.AuthMethod{
				ssh.Password(data.ssh.passwd),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         time.Duration(common.Timeout) * time.Second,
		}
		conn, err := ssh.Dial("tcp", host+":"+port, config)
		if conn != nil {
			defer conn.Close()
		}
		if a := SSHOutCheck(conn, err, data); a != "" {
			return a
		}
	}
	return ""
}

func SSHOutCheck(conn *ssh.Client, err error, data SSHHoneyPotRule) string {
	switch data.name {
	case "Kippo":
		if err != nil && err.Error() == "ssh: handshake failed: ssh: disconnect, reason 3: couldn't match all kex parts" {
			return "Kippo"
		}
	case "HFish":
		if output, _ := SSHSentData(conn, err, data.cmd); output != nil && string(output) != "" {
			return "HFish"
		}
	}
	return ""
}

func SSHSentData(conn *ssh.Client, err error, cmd string) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	// 执行远程命令
	session, err := conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	// 执行命令并获取输出
	output, err := session.Output(cmd)
	if err != nil {
		return output, err
	}
	return nil, nil
}

type checkDatas struct {
	Body    []byte
	Headers string
}

// WebHoneyPotCheck 检测 web honeypot host => ip:port
func WebHoneyPotCheck(host string) string {
	var matched1 bool
	var matched2 bool
	var preUrl = ""
	var Url = ""
	var data checkDatas
	var err error
	for _, rule := range WHPRuleDatas {
		for _, url := range rule.Url {
			matched1 = false
			matched2 = false
			method := url.Method
			if preUrl == "" || preUrl != url.Url {
				preUrl = url.Url
				Url = "http://" + host + url.Url
				data, err = getCheckData(method, Url)
				if err != nil {
					continue
				}
			}
			//method : GET/POST    Url : http://ip:port/login
			//data, err := getCheckData(method, Url)
			if a := getWebTitle(data.Body); strings.Contains(a, "Apache Tomcat/8") {
				if res := tomcatCheck(Url); res {
					return "Hfish"
				}
			}
			if hash, ok := rule.Rule["hash"]; ok {
				has := md5.Sum(data.Body)
				md5str := fmt.Sprintf("%x", has)
				//out := fmt.Sprintf("%s    %x\n", host, md5str)
				//f, _ := os.OpenFile("hash", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
				//f.Write([]byte(out))
				matched1, _ = regexp.MatchString(hash, md5str)
			}
			if body, ok := rule.Rule["body"]; ok {
				matched2 = WebRuleCheck(data, body)
			}
			if matched1 || matched2 { //匹配到 则返回蜜罐名称
				return rule.Name
			}
		}
	}
	return ""
}

func WebRuleCheck(data checkDatas, rule string) bool {
	ruleOr := strings.Split(rule, "|")
	for _, s := range ruleOr {
		ruleAnd := strings.Split(s, "&")
		flag := 1
		for _, s2 := range ruleAnd {
			if !strings.Contains(data.Headers, s2) && !strings.Contains(string(data.Body), s2) {
				flag = 0
				break
			}
		}
		if flag == 1 {
			return true
		}
	}
	return false
}

func tomcatCheck(url string) bool {
	//path := []string{"/host-manager/html", "/manager/status", "/manager/html"}
	url = url + "/manager/status"
	data, err := getCheckData("GET", url)
	if err == nil && string(data.Body) == "404 page not found" {
		return true
	}
	return false
}

func getCheckData(method string, url string) (checkDatas, error) {
	/*根据method 和 url 进行请求返回 CheckData
	 */
	data := checkDatas{nil, ""}
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
func getWebTitle(body []byte) (title string) {
	re := regexp.MustCompile("(?ims)<title>(.*?)</title>")
	find := re.FindSubmatch(body)
	if len(find) > 0 {
		title = string(find[1])
		title = strings.TrimSpace(title)
		title = strings.Replace(title, "\n", "", -1)
		title = strings.Replace(title, "\r", "", -1)
		title = strings.Replace(title, "&nbsp;", " ", -1)
		if len(title) > 100 {
			title = title[:100]
		}
	}
	if title == "" {
		title = "None"
	}
	return
}

// 23 143 21 1443 22 21 2103 102 502 11211 5060 2022
//var HPRuleDatas = []HoneyPotRule{
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
