package Plugins

import (
	"ScanMaster/common"
	"compress/gzip"
	"crypto/tls"
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/net/proxy"
	"golang.org/x/text/encoding/simplifiedchinese"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	Client           *http.Client
	ClientNoRedirect *http.Client
	dialTimout       = 5 * time.Second
	keepAlive        = 5 * time.Second
)

type Flag int

const (
	NoFlag Flag = iota
	FirstTryFlag
	FaviconFlag
	RedirectFlag
	HttpsFlag
)

type checkData struct {
	Body    []byte
	Headers string
	Title   string
	Server  string
}

type scanInfo struct {
	Host       string
	Port       string
	Url        string
	Protocol   string
	Check      []checkData
	ServiceApp []string
}

func init() {
	Inithttp()
}

// #region HttpClient 初始化
func Inithttp() {
	err := InitHttpClient(common.Threads, common.Proxy, time.Duration(common.WebTimeout)*time.Second)
	if err != nil {
		log.Fatal(err)
	}
}

func InitHttpClient(ThreadsNum int, DownProxy string, Timeout time.Duration) error {
	type DialContext = func(ctx context.Context, network, addr string) (net.Conn, error)
	dialer := &net.Dialer{
		Timeout:   dialTimout,
		KeepAlive: keepAlive,
	}

	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxConnsPerHost:     5,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: ThreadsNum * 2,
		IdleConnTimeout:     keepAlive,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   false,
	}

	if common.Socks5Proxy != "" {
		dialSocksProxy, err := common.Socks5Dailer(dialer)
		if err != nil {
			return err
		}
		if contextDialer, ok := dialSocksProxy.(proxy.ContextDialer); ok {
			tr.DialContext = contextDialer.DialContext
		} else {
			return errors.New("Failed type assertion to DialContext")
		}
	} else if DownProxy != "" {
		if DownProxy == "1" {
			DownProxy = "http://127.0.0.1:8080"
		} else if DownProxy == "2" {
			DownProxy = "socks5://127.0.0.1:1080"
		} else if !strings.Contains(DownProxy, "://") {
			DownProxy = "http://127.0.0.1:" + DownProxy
		}
		if !strings.HasPrefix(DownProxy, "socks") && !strings.HasPrefix(DownProxy, "http") {
			return errors.New("no support this proxy")
		}
		u, err := url.Parse(DownProxy)
		if err != nil {
			return err
		}
		tr.Proxy = http.ProxyURL(u)
	}

	Client = &http.Client{
		Transport: tr,
		Timeout:   Timeout,
	}
	ClientNoRedirect = &http.Client{
		Transport:     tr,
		Timeout:       Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	return nil
}

//#endregion

// #region 辅助函数

func versionToFloat64(versionStr string) float64 {
	if versionStr == "N" {
		return 0
	} else {
		version, err := strconv.ParseFloat(versionStr, 64)
		if err != nil {
			return 0
		}
		return version
	}
}

func filterServiceApp(arr []string) []string {
	filtered := make(map[string]string)
	for _, element := range arr {
		parts := strings.Split(element, "/")
		name := parts[0]
		versionStr := parts[1]

		//如果没有这个服务，则直接插入
		existingVersion, ok := filtered[name]
		if !ok {
			filtered[name] = versionStr
			continue
		}

		//如果有这个服务，则进行版本比较，留下高版本的
		oldVersion := versionToFloat64(existingVersion)
		newVersion := versionToFloat64(versionStr)
		if newVersion > oldVersion {
			filtered[name] = versionStr
		}
	}

	result := make([]string, 0, len(filtered))
	for name, version := range filtered {
		result = append(result, fmt.Sprintf("%s/%s", name, version))
	}
	return result
}

func extractServiceApp(text string, server bool) []string {
	var keywords []string
	var versions []string

	if text == "" {
		return versions
	}

	if server {
		keywords = []string{"windows", "centos", "ubuntu", "openssh", "openssl", "java", "node.js", "asp.net", "php", "microsoft-httpapi", "apache", "iis", "nginx", "micro_httpd", "openresty", "weblogic", "debian", "express", "next.js", "nest", "jsp", "litespeed", "jetty"}
	} else {
		keywords = []string{"wordpress", "litespeed", "rabbitmq", "grafana", "lucene_version"}
	}

	text = strings.ToLower(text)
	text = strings.ReplaceAll(text, " ", "")
	text = strings.ReplaceAll(text, "\n", "")
	text = strings.ReplaceAll(text, "\r", "")
	text = strings.ReplaceAll(text, "\t", "")
	text = strings.ReplaceAll(text, "&nbsp;", " ")
	text = strings.TrimSpace(text)

	for _, keyword := range keywords {
		index := strings.Index(text, keyword)
		if index != -1 {
			start := index + len(keyword)
			version := ""

			//跳过内容包含javascript时候的java匹配
			if keyword == "java" && strings.HasPrefix(text[index:], "javascript") {
				continue
			}

			//如果关键字后为斜杠或者空格则跳过
			if start < len(text) && text[start] == '-' {
				for start += 1; start < len(text); start++ {
					if !unicode.IsLetter(rune(text[start])) {
						break
					}
				}
			}

			if start < len(text) && (text[start] == '/' || text[start] == '_' || text[start] == '-' || text[start] == '(') {
				start += 1
			}

			//如果后续字符串长度足够，则取出版本号
			end := start
			if end < len(text) {
				for ; end < len(text); end++ {
					if !unicode.IsDigit(rune(text[end])) && text[end] != '.' {
						break
					}
				}
				version = text[start:end]
			}

			if strings.HasSuffix(version, ".") {
				version = strings.TrimSuffix(version, ".")
			}

			if strings.HasPrefix(version, ".") {
				version = strings.TrimPrefix(version, ".")
			}

			if version == "" {
				version = "N"
			}

			//elasticsearch
			if keyword == "lucene_version" {
				re := regexp.MustCompile(`"lucene_version":"(.*?)"`)
				match := re.FindStringSubmatch(text)
				if len(match) > 1 {
					version = match[1]
				} else {
					//不匹配
					continue
				}
				keyword = "elasticsearch"
			}

			if keyword == "next.js" || keyword == "nest" {
				versions = append(versions, "node.js/N")
				continue
			}

			if keyword == "jsp" {
				versions = append(versions, "java/N")
				continue
			}

			if keyword == "express" {
				versions = append(versions, "node.js/N")
			}

			if keyword == "ubuntu" {
				if strings.HasPrefix(version, "0.") {
					version = strings.TrimPrefix(version, "0.")
				}
			}

			versions = append(versions, fmt.Sprintf("%s/%s", keyword, version))
		}
	}
	return versions
}

func extractDeviceTypes(input string) []string {
	deviceTypes := make([]string, 0)

	var deviceRuleData = []common.RuleData{
		{"firewall/pfsense", "body", "pfsense"},
		{"webcam/hikvision", "body", "/doc/page/login.asp"},
		{"webcam/hikvision", "body", "/doc/index.html"},
		{"webcam/hikvision", "body", "DNVRS-WEBS"},
		{"webcam/dahua", "body", "dhvideowhmode"},
		{"switch/cisco", "body", "cisco"},
		{"nas/synology", "body", "synology"},
	}

	inputLower := strings.ToLower(input)

	for _, rule := range deviceRuleData {
		if strings.Contains(inputLower, strings.ToLower(rule.Rule)) {
			deviceTypes = append(deviceTypes, fmt.Sprintf("%s", rule.Name))
		}
	}

	return deviceTypes
}

/*
从返回的body中提取出Redirect跳转的url
*/
func getRedirectUrl(body []byte, info *scanInfo) (url string) {
	//os.WriteFile("body", body, 0666)
	re := regexp.MustCompile("(?ims)<title>redirect</title>")
	find := re.FindSubmatch(body)
	if len(find) > 0 { //存在redirect关键字 跳转 去除url
		url = regexp.QuoteMeta(info.Url)
		re = regexp.MustCompile("(?im)" + url + "(/.*)*\"$")
		find = re.FindSubmatch(body)
		if len(find) > 0 {
			url = string(find[0])
			url = strings.Replace(url, "\"", "", -1)
			return url
		}
	}
	return ""
}

// 判断是否是https协议
func GetProtocol(host string, Timeout int64) (protocol string) {
	protocol = "http"
	//如果端口是80或443,跳过Protocol判断
	if strings.HasSuffix(host, ":80") || !strings.Contains(host, ":") {
		return
	} else if strings.HasSuffix(host, ":443") {
		protocol = "https"
		return
	}

	socksconn, err := common.WrapperTcpWithTimeout("tcp", host, time.Duration(Timeout)*time.Second)
	if err != nil {
		return
	}
	conn := tls.Client(socksconn, &tls.Config{InsecureSkipVerify: true})
	defer func() {
		if conn != nil {
			defer func() {
				if err := recover(); err != nil {
					common.LogError(fmt.Sprintf("[Plugin/WebScan] GetProtocol Error: %v", err))
				}
			}()
			conn.Close()
		}
	}()
	conn.SetDeadline(time.Now().Add(time.Duration(Timeout) * time.Second))
	err = conn.Handshake()
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		protocol = "https"
	}
	return protocol
}

func getUrl(info *scanInfo, flag Flag) (string, error) {
	Url := info.Url
	if flag == FaviconFlag {
		URL, err := url.Parse(Url)
		if err == nil {
			Url = fmt.Sprintf("%s://%s/favicon.ico", URL.Scheme, URL.Host)
		} else {
			Url += "/favicon.ico"
		}
	}

	common.LogSuccess(fmt.Sprintf("[Plugin/WebScan] GET: %s", Url))

	req, err := http.NewRequest("GET", Url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-agent", common.UserAgent)
	req.Header.Set("Accept", common.Accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if common.Cookie != "" {
		req.Header.Set("Cookie", common.Cookie)
	}

	req.Header.Set("Connection", "close")
	var client *http.Client

	switch flag {
	case FirstTryFlag:
		client = ClientNoRedirect
	default:
		client = Client
	}

	resp, err := client.Do(req) //请求
	if err != nil {
		return "https", err
	}

	defer resp.Body.Close()
	var title string
	body, err := getWebRespBody(resp)

	if err != nil {
		return "https", err
	}

	if !utf8.Valid(body) {
		body, _ = simplifiedchinese.GBK.NewDecoder().Bytes(body)
	}

	check := checkData{
		Body:    body,
		Headers: fmt.Sprintf("%s", resp.Header),
	}

	var reurl string
	if flag != FaviconFlag {
		title = getTitle(body)
		length := resp.Header.Get("Content-Length")
		if length == "" {
			length = fmt.Sprintf("%v", len(body))
		}

		server := resp.Header.Get("Server")

		redirURL, err1 := resp.Location()
		if err1 == nil {
			reurl = redirURL.String()
		} else {
			redirectUrl := getRedirectUrl(body, info)
			if redirectUrl != "" {
				reurl = redirectUrl
			}
		}

		check.Title = title
		check.Server = server
	}

	info.Check = append(info.Check, check)

	if reurl != "" {
		return reurl, nil
	}

	if resp.StatusCode == 400 && !strings.HasPrefix(info.Url, "https") {
		return "https", nil
	}

	return "", nil
}

func getWebRespBody(oResp *http.Response) ([]byte, error) {
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

func getTitle(body []byte) (title string) {
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

func removeDuplicateElement(data []string) []string {
	result := make([]string, 0, len(data))
	temp := map[string]struct{}{}
	for _, item := range data {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

//#endregion

func WebScan(endpoint common.NetworkEndpoint) {
	addr := fmt.Sprintf("%s:%v", endpoint.IPAddress, endpoint.Port)
	var info scanInfo
	info.Host, info.Port = endpoint.IPAddress, strconv.Itoa(endpoint.Port)
	if endpoint.Protocol != "http" && endpoint.Protocol != "https" {
		return
	}

	common.LogSuccess(fmt.Sprintf("[Plugin/WebScan] %s", addr))

	err := GOWebTitle(&info)
	if err != nil {
		common.LogError(fmt.Sprintf("[Plugin/WebScan] GoWebTitle Error: %s", err.Error()))
		return
	}

	var server_app []string
	var device_app []string

	for _, data := range info.Check {
		server_app = append(server_app, extractServiceApp(data.Server, true)...)
		server_app = append(server_app, extractServiceApp(data.Title, true)...)
		server_app = append(server_app, extractServiceApp(string(data.Body), false)...)
		server_app = append(server_app, extractServiceApp(data.Headers, true)...)

		device_app = append(device_app, extractDeviceTypes(string(data.Body))...)
		device_app = append(device_app, extractDeviceTypes(data.Headers)...)
	}
	server_app = filterServiceApp(server_app)

	common.GlobalResultInfo.AddServiceApp(addr, server_app...)
	common.GlobalResultInfo.AddServiceDeviceInfo(endpoint.IPAddress, device_app...)
	//修正协议
	if info.Protocol == "https" {
		common.GlobalResultInfo.SetServiceProtocol(addr, "https")
	}
	//InfoCheck(&info)
}

func GOWebTitle(info *scanInfo) (err error) {
	if info.Url == "" {
		switch info.Port {
		case "80":
			info.Protocol = "http"
			info.Url = fmt.Sprintf("http://%s", info.Host)
		case "443":
			info.Protocol = "https"
			info.Url = fmt.Sprintf("https://%s", info.Host)
		default:
			host := fmt.Sprintf("%s:%s", info.Host, info.Port)
			info.Protocol = GetProtocol(host, common.Timeout)
			info.Url = fmt.Sprintf("%s://%s:%s", info.Protocol, info.Host, info.Port)
		}
	} else {
		if !strings.Contains(info.Url, "://") {
			host := strings.Split(info.Url, "/")[0]
			info.Protocol = GetProtocol(host, common.Timeout)
			info.Url = fmt.Sprintf("%s://%s", info.Protocol, info.Url)
		}
	}

	result, err := getUrl(info, FirstTryFlag)
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		return
	}

	//有跳转
	if strings.Contains(result, "://") {
		info.Url = result
		result, err = getUrl(info, RedirectFlag)
		if err != nil {
			return
		}
	}

	//判断是否需要以https来请求
	if result == "https" && !strings.HasPrefix(info.Url, "https://") {
		info.Url = strings.Replace(info.Url, "http://", "https://", 1)
		result, err = getUrl(info, FirstTryFlag)
		//有跳转
		if strings.Contains(result, "://") {
			info.Url = result
			result, err = getUrl(info, RedirectFlag)
			if err != nil {
				return
			}
		}
	}

	//是否访问图标
	//_, err = getUrl(info, FaviconFlag)
	//if err != nil {
	//	return
	//}
	return
}

/*func InfoCheck(info *scanInfo) {
	var matched bool
	var infoname []string

	for _, data := range info.Check {
		for _, rule := range RuleDatas {
			if rule.Type == "code" {
				matched, _ = regexp.MatchString(rule.Rule, string(data.Body))
			} else {
				matched, _ = regexp.MatchString(rule.Rule, data.Headers)
			}
			if matched == true {
				infoname = append(infoname, rule.Name)
			}
		}
		flag, name := CalcMd5(data.Body)

		if flag == true {
			infoname = append(infoname, name)
		}
	}
	infoname = removeDuplicateElement(infoname)
	for _, name := range infoname {
		common.GlobalResultInfo.AddServiceApp(fmt.Sprintf("%s:%s", info.Host, info.Port), name)
	}
}
func CalcMd5(Body []byte) (bool, string) {
	has := md5.Sum(Body)
	md5str := fmt.Sprintf("%x", has)
	for _, md5data := range Md5Datas {
		if md5str == md5data.Md5Str {
			return true, md5data.Name
		}
	}
	return false, ""
}
*/
