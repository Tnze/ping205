package main

import (
	"fmt"
	"net"
	"os"
	"ping205"
	"strings"
)

func main() {
	ips, err := ping205.GetArpTable()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Get arp table error: %v\n", err)
		os.Exit(-1)
	}
	for _, ip := range ips {
		names, err := net.LookupAddr(ip.String())
		if err != nil {
			fmt.Println(ip.String())
		} else {
			fmt.Println(strings.Join(names, "|"))
		}
	}
}
