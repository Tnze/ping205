package ping205

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Ullaakut/nmap/v2"
)

func NmapScan(target string, timeout time.Duration) (ips []net.IP, err error) {
	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(target),
		//nmap.WithPingScan(),	// or
		nmap.WithListScan(), // or
		nmap.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create scanner: %w", err)
	}

	result, _, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("unable to run nmap: %w", err)
	}
	for _, host := range result.Hosts {
		for _, addr := range host.Addresses {
			ips = append(ips, net.ParseIP(addr.Addr))
		}
	}
	return
}
