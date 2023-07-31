package Plugins

import (
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"ScanMaster/WebScan"
	"ScanMaster/WebScan/lib"
	"ScanMaster/common"
	"golang.org/x/text/encoding/simplifiedchinese"
)

func WebTitle(info *common.HostInfo, conn net.Conn) error {

	err, CheckData := GOWebTitle(info, conn) //CheckData需要被检查的信息  [{Body:,Headers:}]
	//fmt.Println(CheckData)
	info.Info.Services = WebScan.InfoCheck(info.Url, &CheckData)    //web服务应用检测
	info.Info.Honeypot = WebScan.WHPInfoCheck(info.Url, &CheckData) //web蜜罐检测
	/*if common.IsWebCan == false && err == nil {
		WebScan.WebScan(info)
	} else {
		errlog := fmt.Sprintf("[-] webtitle %v %v", info.Url, err)
		common.LogError(errlog)
	}*/
	return err
}

func GOWebTitle(info *common.HostInfo, conn net.Conn) (err error, CheckData []WebScan.CheckDatas) {
	if info.Url == "" {
		switch info.Ports {
		case "80":
			info.Url = fmt.Sprintf("http://%s", info.Host)
		case "443":
			info.Url = fmt.Sprintf("https://%s", info.Host)
		default:
			host := fmt.Sprintf("%s:%s", info.Host, info.Ports)
			info.Protocol = GetProtocol(host, common.Timeout, conn)
			info.Url = fmt.Sprintf("%s://%s:%s", info.Protocol, info.Host, info.Ports)
		}
	} else {
		if !strings.Contains(info.Url, "://") {
			host := strings.Split(info.Url, "/")[0]
			info.Protocol = GetProtocol(host, common.Timeout, conn)
			info.Url = fmt.Sprintf("%s://%s", info.Protocol, info.Url)
		}
	}

	err, result, CheckData := getUrl(info, 1, CheckData)
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		return
	}

	//有跳转
	if strings.Contains(result, "://") {
		info.Url = result
		err, result, CheckData = getUrl(info, 3, CheckData)
		if err != nil {
			return
		}
	}

	//判断是否需要以https来请求
	if result == "https" && !strings.HasPrefix(info.Url, "https://") {
		info.Url = strings.Replace(info.Url, "http://", "https://", 1)
		err, result, CheckData = getUrl(info, 1, CheckData)
		//有跳转
		if strings.Contains(result, "://") {
			info.Url = result
			err, result, CheckData = getUrl(info, 3, CheckData)
			if err != nil {
				return
			}
		}
	}
	//是否访问图标
	//err, _, CheckData = getUrl(info, 2, CheckData)
	if err != nil {
		return
	}
	return
}

// 对url发起https请求
func getUrl(info *common.HostInfo, flag int, CheckData []WebScan.CheckDatas) (error, string, []WebScan.CheckDatas) {
	//flag 1 first try
	//flag 2 /favicon.ico
	//flag 3 302 /301 重定向
	//flag 4 400 -> https

	Url := info.Url
	if flag == 2 {
		URL, err := url.Parse(Url)
		if err == nil {
			Url = fmt.Sprintf("%s://%s/favicon.ico", URL.Scheme, URL.Host)
		} else {
			Url += "/favicon.ico"
		}
	}
	fmt.Println("GET:", Url)
	req, err := http.NewRequest("GET", Url, nil)
	if err != nil {
		return err, "", CheckData
	}
	req.Header.Set("User-agent", common.UserAgent)
	req.Header.Set("Accept", common.Accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if common.Cookie != "" {
		req.Header.Set("Cookie", common.Cookie)
	}
	//if common.Pocinfo.Cookie != "" {
	//	req.Header.Set("Cookie", "rememberMe=1;"+common.Pocinfo.Cookie)
	//} else {
	//	req.Header.Set("Cookie", "rememberMe=1")
	//}
	req.Header.Set("Connection", "close")
	var client *http.Client
	if flag == 1 {
		client = lib.ClientNoRedirect
	} else {
		client = lib.Client
	}

	resp, err := client.Do(req) //请求
	if err != nil {
		return err, "https", CheckData
	}

	defer resp.Body.Close()
	var title string
	body, err := getRespBody(resp)
	if err != nil {
		return err, "https", CheckData
	}
	if !utf8.Valid(body) {
		body, _ = simplifiedchinese.GBK.NewDecoder().Bytes(body)
	}
	CheckData = append(CheckData, WebScan.CheckDatas{Body: body, Headers: fmt.Sprintf("%s", resp.Header)})
	var reurl string
	if flag != 2 {
		title = getTitle(body)
		length := resp.Header.Get("Content-Length")
		if length == "" {
			length = fmt.Sprintf("%v", len(body))
		}

		server := resp.Header.Get("Server")

		redirURL, err1 := resp.Location()
		if err1 == nil {
			reurl = redirURL.String()
		} else if url := getRedirectUrl(body, info); url != "" {
			reurl = url
		}
		result := fmt.Sprintf("[*] WebTitle: %-25v code:%-3v len:%-6v title:%v server:%v", resp.Request.URL, resp.StatusCode, length, title, server)
		if reurl != "" {
			result += fmt.Sprintf(" 跳转url: %s", reurl)
		}
		common.LogSuccess(result)
	}
	if reurl != "" {
		return nil, reurl, CheckData
	}
	if resp.StatusCode == 400 && !strings.HasPrefix(info.Url, "https") {
		return nil, "https", CheckData
	}
	return nil, "", CheckData
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

/*
TODO: 从返回的body中提取出Redirect跳转的url
跳转的url 需要和当前info.Url 同ip:port
也就是匹配出返回的body 中的 info.Url后面的路径
例子：访问http://134.122.46.198:81 返回如下内容 当前程序采用返回有的location 但对此不起作用 所以需要从body中提取
If you are not redirected automatically, follow this <a href="http://134.122.46.198:81/crm/suspended-service" id="redirect-link-old">link</a><a href="/crm/suspended-service/0.0.0.0" id="redirect-link-new" data-hostname="techgurusupport.uisp.com" style="display:none;">link</a>.

	</p>

提取如下内容：return
http://134.122.46.198:81/crm/suspended-service
*/
func getRedirectUrl(body []byte, info *common.HostInfo) (url string) {
	//os.WriteFile("body", body, 0666)
	re := regexp.MustCompile("(?ims)redirect")
	find := re.FindSubmatch(body)
	if len(find) > 0 { //存在redirect关键字 跳转 去除url
		re = regexp.MustCompile("(?ims)" + info.Url + "/.*\"$")
		find = re.FindSubmatch(body)
		if len(find) > 0 {
			url = string(find[0])
			url = strings.TrimSpace(url)
			url = strings.Replace(url, "\n", "", -1)
			url = strings.Replace(url, "\r", "", -1)
			url = strings.Replace(url, "&nbsp;", " ", -1)
			if len(url) > 100 {
				url = url[:100]
			}
			return url
		}
	}
	return ""
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

// 判断是否是https协议
func GetProtocol(host string, Timeout int64, socksconn net.Conn) (protocol string) {
	protocol = "http"
	//如果端口是80或443,跳过Protocol判断
	if strings.HasSuffix(host, ":80") || !strings.Contains(host, ":") {
		return
	} else if strings.HasSuffix(host, ":443") {
		protocol = "https"
		return
	}
	//d := &net.Dialer{Timeout: time.Duration(Timeout) * time.Second}
	//socksconn, err := common.WrapperTCP("tcp", host, d)
	//if err != nil {
	//	return
	//}
	conn := tls.Client(socksconn, &tls.Config{InsecureSkipVerify: true})
	defer func() {
		if conn != nil {
			defer func() {
				if err := recover(); err != nil {
					common.LogError(err)
				}
			}()
			conn.Close()
		}
	}()
	conn.SetDeadline(time.Now().Add(time.Duration(Timeout) * time.Second))
	err := conn.Handshake()
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		protocol = "https"
	}
	return protocol
}
