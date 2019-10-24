package main

import (
	"encoding/binary"
	"fmt"
	"github.com/mdlayher/arp"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
)

var ips = []net.IP{}
var cnt = 0;


func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func worker(wg *sync.WaitGroup, targetIP string, wb []byte, i int) {
	defer wg.Done()

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("listen err, %s", err)
	}
	defer func() {
		err := c.Close()
		if err != nil {
			log.Fatalf("Close err, %s", err)
		}
	}()

	if _, err := c.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(targetIP)}); err != nil {
		log.Fatalf("WriteTo err, %s", err)
	}

	rb := make([]byte, 1500)
	n, peer, err := c.ReadFrom(rb)
	if err != nil {
		log.Fatal(err)
	}

	rm, err := icmp.ParseMessage(1, rb[:n])
	if err != nil {
		log.Fatal(err)
	}

	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		log.Printf("got reflection from %v", peer)
		cnt ++
	default:
		if i != 10 {
			wg.Add(1)
			arp.New()
			go worker(wg, targetIP, wb, i+1)
		} else if i==10 {
			log.Printf("got %+v; want echo reply", rm)
		}
	}
}

func getMyIP() (net.IP) {
	addrs, err := net.InterfaceAddrs()

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, address := range addrs {

		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP
			}

		}
	}

	return nil
}

func main(){
	runtime.GOMAXPROCS(runtime.NumCPU())

	var wg sync.WaitGroup

	startIP := net.ParseIP("192.168.100.1")
	endIP := net.ParseIP("192.168.100.254")

	myIP := getMyIP()

	for i := ip2int(startIP); i <= ip2int(endIP); i++ {
		ip:=int2ip(i)
		if ip.Equal(myIP) {
			continue
		}
		ips = append(ips, ip)
	}

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		log.Fatal(err)
	}

	for _, targetIP := range ips {
		wg.Add(1)

		go worker(&wg, targetIP.String(), wb, 0)
	}

	wg.Wait()

	fmt.Println(cnt)
}
