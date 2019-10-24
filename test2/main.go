// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// arpscan implements ARP scanning of all interfaces' local networks using
// gopacket and its subpackages.  This example shows, among other things:
//   * Generating and sending packet data
//   * Reading in packet data and interpreting it
//   * Use of the 'pcap' subpackage for reading/writing
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Get a list of all interfaces.

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	for _, device := range devices {
		if addresses := device.Addresses; len(addresses) > 0 {
			for _, address := range addresses {
				if ip := address.IP; ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
					fmt.Println("\nName: ", device.Name)
					fmt.Println("- IP address: ", ip)
					network := getNetworkMask(ip)
					fmt.Println("- Network: ", network)

					for _, iface := range interfaces {
						if addr, err := getNetwork(&iface); err == nil && network.Equal(getNetworkMask(addr.IP)) {
							fmt.Printf("%v", iface)
							_ = scan(&iface, device.Name)
						}
					}
				}
			}
		}
	}
return
	/*
	var wg sync.WaitGroup
	for _, iface := range interfaces {
		wg.Add(1)
		// Start up a scan on each interface.

		go func(iface net.Interface) {
			defer wg.Done()
			if err := scan(&iface); err != nil {
				log.Printf("interface %v: %v", iface.Name, err)
			}
		}(iface)
	}
	// Wait for all interfaces' scans to complete.  They'll try to run
	// forever, but will stop on an error, so if we get past this Wait
	// it means all attempts to write have failed.
	wg.Wait()
	 */
}

func getNetworkMask(ip net.IP) net.IP {
	mask := ip.DefaultMask()
	return ip.Mask(mask)
}

func getNetwork(iface *net.Interface) (*net.IPNet, error) {
	var network *net.IPNet

	if addresses, err := iface.Addrs(); err != nil {
		return nil, err
	} else {
		for _, a := range addresses {
			if ipNet, ok := a.(*net.IPNet); ok {
				if ip4 := ipNet.IP.To4(); ip4 != nil {
					network = &net.IPNet{
						IP:   ip4,
						Mask: ipNet.Mask[len(ipNet.Mask)-4:],
					}
				}
			}
		}
	}

	// Sanity-check that the interface has a good address.
	if network == nil {
		return nil, errors.New("no good IP network found")
	} else if network.IP[0] == 127 {
		return nil, errors.New("skipping localhost")
	} else if network.Mask[0] != 0xff || network.Mask[1] != 0xff {
		return nil, errors.New("mask means network is too large")
	}

	return network, nil
}

// scan scans an individual interface's local network for machines using ARP requests/replies.
//
// scan loops forever, sending packets out regularly.  It returns an error if
// it's ever unable to write a packet.
func scan(iface *net.Interface, deviceName string) error {
	addr, err := getNetwork(iface)
	if err != nil {
		return err
	}

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(deviceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	go readARP(handle, iface, stop)
	defer close(stop)
	for {
		// Write our scan packets out to the handle.
		if err := writeARP(handle, iface, addr); err != nil {
			log.Printf("error writing packets on %v: %v", iface.Name, err)
			return err
		}
		// We don't know exactly how long it'll take for packets to be
		// sent back to us, but 10 seconds should be more than enough
		// time ;)
		time.Sleep(10 * time.Second)
	}
}

// readARP watches a handle for incoming ARP responses we might care about, and prints them.
//
// readARP loops until 'stop' is closed.
func readARP(handle *pcap.Handle, iface *net.Interface, stop chan struct{}) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
				// This is a packet I sent.
				continue
			}
			// Note:  we might get some packets here that aren't responses to ones we've sent,
			// if for example someone else sends US an ARP request.  Doesn't much matter, though...
			// all information is good information :)
			log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
		}
	}
}

// writeARP writes an ARP request for each address on our local network to the
// pcap handle.
func writeARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send one packet for every address.
	for _, ip := range ips(addr) {
		arp.DstProtAddress = []byte(ip)
		_ = gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// ips is a simple and not very good method for getting all IPv4 addresses from a
// net.IPNet.  It returns all IPs it can over the channel it sends back, closing
// the channel when done.
func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	num &= mask
	for mask < 0xffffffff {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], num)
		out = append(out, net.IP(buf[:]))
		mask++
		num++
	}
	return
}
