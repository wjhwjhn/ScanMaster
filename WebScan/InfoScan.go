package WebScan

import (
	"ScanMaster/WebScan/info"
	"ScanMaster/common"
	"crypto/md5"
	"fmt"
	"regexp"
)

type CheckDatas struct {
	Body    []byte
	Headers string
}

// 检测webhoneypot
func WHPInfoCheck(Url string, CheckData *[]CheckDatas) string {
	var matched1 bool
	var matched2 bool
	for _, data := range *CheckData {
		for _, rule := range common.WHPRuleData {
			for _, url := range rule.Url {
				matched1 = false
				matched2 = false
				if Url == url.Url {

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
	}
	//InfoName = removeDuplicateElement(InfoName)
	//
	//if len(InfoName) > 0 {
	//	result := fmt.Sprintf("[+] InfoScan: %-25v %s ", Url, InfoName)
	//	LogSuccess(result)
	//	return InfoName
	//}
	return ""
}

func InfoCheck(Url string, CheckData *[]CheckDatas) []string {
	var matched bool
	var infoname []string

	for _, data := range *CheckData {
		for _, rule := range info.RuleDatas {
			if rule.Type == "code" || rule.Type == "body" {
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

	if len(infoname) > 0 {
		result := fmt.Sprintf("[+] InfoScan: %-25v %s ", Url, infoname)
		common.LogSuccess(result)
		return infoname
	}
	return []string{""}
}

func CalcMd5(Body []byte) (bool, string) {
	has := md5.Sum(Body)
	md5str := fmt.Sprintf("%x", has)
	for _, md5data := range info.Md5Datas {
		if md5str == md5data.Md5Str {
			return true, md5data.Name
		}
	}
	return false, ""
}

func removeDuplicateElement(languages []string) []string {
	result := make([]string, 0, len(languages))
	temp := map[string]struct{}{}
	for _, item := range languages {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
