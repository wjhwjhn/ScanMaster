package common

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var Results = make(chan *string)
var LogSucTime int64
var LogErrTime int64
var Silent bool
var LogWG sync.WaitGroup

func init() {
	LogSucTime = time.Now().Unix()
	go SaveLog()
}

func LogSuccess(result string) {
	LogWG.Add(1)
	LogSucTime = time.Now().Unix()
	Results <- &result
}

func SaveLog() {
	for result := range Results {
		if Silent == false || strings.Contains(*result, "[+]") || strings.Contains(*result, "[*]") {
			fmt.Println(*result)
		}
		if IsSave {
			WriteFile(*result, Outputfile)
		}
		LogWG.Done()
	}
}

func WriteFile(result string, filename string) {
	var text = []byte(result + "\n")
	fl, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Open %s error, %v\n", filename, err)
		return
	}
	_, err = fl.Write(text)
	fl.Close()
	if err != nil {
		fmt.Printf("Write %s error, %v\n", filename, err)
	}
}

func LogError(result string) {
	LogWG.Add(1)
	LogErrTime = time.Now().Unix()
	Results <- &result
}

func CheckErrs(err error) bool {
	if err == nil {
		return false
	}
	errs := []string{
		"closed by the remote host", "too many connections",
		"i/o timeout", "EOF", "A connection attempt failed",
		"established connection failed", "connection attempt failed",
		"Unable to read", "is not allowed to connect to this",
		"no pg_hba.conf entry",
		"No connection could be made",
		"invalid packet size",
		"bad connection",
	}
	for _, key := range errs {
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(key)) {
			return true
		}
	}
	return false
}
