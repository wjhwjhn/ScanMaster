package common

import (
	"runtime"
	"runtime/debug"
	"time"
)

func init() {
	go func() {
		for {
			GC()
			time.Sleep(10 * time.Second)
		}
	}()
}

func GC() {
	runtime.GC()
	debug.FreeOSMemory()
}
