// +build linux darwin

package ping205

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
)

func GetArpTable() (ips []net.IP, err error) {
	const filename = "/proc/net/arp"
	arpinfo, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read file %s error: %w", filename, err)
	}
	arplines := bytes.Split(arpinfo, []byte{'\n'})
	if len(arplines) < 1 {
		return nil, fmt.Errorf("%s format error", filename)
	}
	// skip the first line, it' s label
	ips = make([]net.IP, 0, len(arplines)-1)
	for _, arp := range arplines[1:] {
		fields := bytes.Fields(arp)
		if len(fields) != 6 {
			continue
		}
		// parse flags
		var flags uint8

		//flags, err := strconv.ParseUint(string(fields[2]), 16, 0)
		if _, err := fmt.Sscan(string(fields[2]), &flags); err != nil {
			return nil, fmt.Errorf("parse flag %q error: %w", string(fields[2]), err)
		}
		if flags&0x2 == 0 {
			continue // skip
		}
		ips = append(ips, net.ParseIP(string(fields[0])))
	}
	return
}
