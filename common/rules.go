package common

type RuleData struct {
	Name string
	Type string
	Rule string
}

type Md5Data struct {
	Name   string
	Md5Str string
}

type PocData struct {
	Name  string
	Alias string
}

type NetworkEndpoint struct {
	IPAddress string
	Port      int
	Protocol  string
}
