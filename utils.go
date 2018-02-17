package main

import (
	"net"
	"strings"
)

func isPrivateHostname(hostname string) bool {
	_, localBitBlock, _ := net.ParseCIDR("127.0.0.0/8")
	_, private24BitBlock, _ := net.ParseCIDR("10.0.0.0/8")
	_, private20BitBlock, _ := net.ParseCIDR("172.16.0.0/12")
	_, private16BitBlock, _ := net.ParseCIDR("192.168.0.0/16")
	_, localBitBlockIPv6, _ := net.ParseCIDR("::1/128")
	_, privateIPv6, _ := net.ParseCIDR("fd00::/8")
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return false
		}
		if localBitBlock.Contains(ip) || localBitBlockIPv6.Contains(ip) || private24BitBlock.Contains(ip) || private20BitBlock.Contains(ip) ||
			private16BitBlock.Contains(ip) || privateIPv6.Contains(ip) {
			return true
		}
	}
	return false
}

func isPrivateHost(host string) bool {
	hostname := strings.SplitN(host, ":", 2)[0]
	return isPrivateHostname(hostname)
}
