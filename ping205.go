package ping205

import (
	"net"
	"strings"
)

func IpsString(ips []string) string {
	var sb strings.Builder
	for _, ip := range ips {
		sb.WriteString(" - ")
		names, err := net.LookupAddr(ip)
		if err != nil {
			sb.WriteString(ip + "\n")
		} else {
			sb.WriteString(strings.Join(names, "|") + "\n")
		}
	}
	return strings.TrimSuffix(sb.String(), "\n")
}
