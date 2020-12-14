package ping205

import (
	"net"
	"strings"
)

func IpsString(ips []net.IP) string {
	var sb strings.Builder
	for _, ip := range ips {
		sb.WriteString(" - ")
		names, err := net.LookupAddr(ip.String())
		if err != nil {
			sb.WriteString(ip.String() + "\n")
		} else {
			sb.WriteString(strings.Join(names, "|") + "\n")
		}
	}
	return strings.TrimSuffix(sb.String(), "\n")
}
