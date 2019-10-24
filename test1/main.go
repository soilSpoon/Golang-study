package main

import "C"
import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	portScanner "github.com/anvie/port-scanner"
	"golang.org/x/sync/semaphore"
)

const MaxThreadCount = 16
const DefaultTimeout = 100 * time.Millisecond

//export ScanPortRange
func ScanPortRange(ip *C.char, start int, end int, Output **C.int) int {
	runtime.GOMAXPROCS(runtime.NumCPU())

	ps := portScanner.NewPortScanner(C.GoString(ip), DefaultTimeout, MaxThreadCount)
	ports := ps.GetOpenedPort(start, end)

	/*
		//포트 스캐너 기본 옵션
		ps := &PortScanner{
			ip:   C.GoString(ip),
			lock: semaphore.NewWeighted(MaxThreadCount),
		}

		ports := ps.Start(start, end, DefaultTimeout)
	*/

	cArray := C.malloc(C.size_t(len(ports)) * C.size_t(unsafe.Sizeof(uintptr(0))))

	// convert the C array to a Go Array so we can index it
	tmp := (*[1<<30 - 1]C.int)(cArray)

	for idx, num := range ports {
		tmp[idx] = C.int(num)
	}

	*Output = (*C.int)(cArray)

	return len(ports)
}

type PortScanner struct {
	ip   string
	lock *semaphore.Weighted
}

func ScanPort(ip string, port int, timeout time.Duration) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(timeout)
			return ScanPort(ip, port, timeout)
		} else {
			return false
		}
	}

	conn.Close()

	return true
}

func (ps *PortScanner) Start(start, end int, timeout time.Duration) []int {
	runtime.GOMAXPROCS(runtime.NumCPU())

	var ports []int

	wg := sync.WaitGroup{}
	defer wg.Wait()

	for port := start; port <= end; port++ {
		ps.lock.Acquire(context.TODO(), 1)
		wg.Add(1)
		go func(port int) {
			defer ps.lock.Release(1)
			defer wg.Done()
			if ScanPort(ps.ip, port, timeout) {
				ports = append(ports, port)
			}
		}(port)
	}

	return ports
}

func main() {
	//비워둬야 함
}
