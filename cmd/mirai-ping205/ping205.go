package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"ping205"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/tatsushid/go-fastping"
)

var (
	nmapAddr    = flag.String("nmapAddr", "", "Address using in nmap, left empty for read arp table")
	nmapTimeout = flag.Int("nmapTimeout", 10_000, "Timeout for nmap scanning, (ms)")
	host        = flag.String("host", "127.0.0.1:8080", "Hostname of mirai-api-http")
	report      = flag.String("report", "127.0.0.1:12031", "Report destinations (where this program listen)")
	authKey     = flag.String("authkey", "", "Auth Key")
	Id          = flag.Int64("qq", 0, "QQ number")
	GroupID     = flag.Int64("groupid", 0, "Group ID")
	DebugMode   = flag.Bool("debug", false, "Debug mode")
)
var c = &http.Client{}

func main() {
	flag.Parse()
	nmapCache.ips = make(map[string]struct{})

	UpdateNmapList()
	c := cron.New()
	c.AddFunc("* * * * *", UpdateNmapList)
	c.Start()

	http.HandleFunc("/post", HandleMirai)
	if err := http.ListenAndServe(*report, nil); err != nil {
		log.Fatalf("Listen error: %v", err)
	}
}

var nmapCache struct {
	ips map[string]struct{}
	sync.Mutex
}

func UpdateNmapList() {
	ips, err := ping205.NmapScan(*nmapAddr, time.Millisecond*time.Duration(*nmapTimeout))
	if err != nil {
		log.Printf("Run nmap error: %v", err)
		return
	}

	nmapCache.Lock()
	for _, ip := range ips {
		nmapCache.ips[ip.String()] = struct{}{}
	}
	nmapCache.Unlock()
}

func HandleMirai(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		Type         string `json:"type"`
		MessageChain []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"messageChain"`
		Sender struct {
			ID         int64  `json:"id"`
			MemberName string `json:"memberName"`
			Group      struct {
				ID   int64  `json:"id"`
				Name string `json:"name"`
			} `json:"group"`
		} `json:"sender"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Decode request error: %v", err)
	}
	if req.Sender.Group.ID == *GroupID &&
		len(req.MessageChain) > 1 &&
		req.MessageChain[1].Type == "Plain" {
		go OnGroupMsg(strings.Fields(req.MessageChain[1].Text))
	}
}

func OnGroupMsg(args []string) {
	if len(args) < 1 || args[0] != "ping205" {
		return
	}
	force := len(args) < 2 || args[1] == "-f"

	session, err := NewSession(*authKey, *Id)
	if err != nil {
		log.Printf("Start session error: %v", err)
		return
	}
	defer func() {
		if err := session.Close(); err != nil {
			log.Printf("Release session key error: %v", err)
		}
	}()
	send := func(ips []string) {
		str := ping205.IpsString(ips)
		if _, err := session.SendGroupMsg(str); err != nil {
			log.Printf("Cannot send message: [%s]%v", str, err)
		}
	}

	// get ip list
	pinger := fastping.NewPinger()
	pinger.MaxRTT = time.Second * 10

	if force {
		UpdateNmapList()
	}

	nmapCache.Lock()
	for ip := range nmapCache.ips {
		if err := pinger.AddIP(ip); err != nil {
			msg := fmt.Sprintf("Ping ip[%s] error: %v", ip, err)
			if _, err := session.SendGroupMsg(msg); err != nil {
				log.Printf("Cannot send message: [%s]%v", msg, err)
				nmapCache.Unlock()
				return
			}
		}
	}
	nmapCache.Unlock()

	var aliveIps []string
	var mutAlv sync.Mutex
	ctx, cancel := context.WithCancel(context.TODO())
	finish := make(chan struct{})
	go func(ctx context.Context) {
		ticker := time.NewTicker(time.Second)
		for {
			select {
			case <-ticker.C:
				mutAlv.Lock()
				if len(aliveIps) > 0 {
					send(aliveIps)
					aliveIps = aliveIps[:0]
				}
				mutAlv.Unlock()
			case <-ctx.Done():
				ticker.Stop()
				finish <- struct{}{}
				return
			}
		}
	}(ctx)

	pinger.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
		mutAlv.Lock()
		aliveIps = append(aliveIps, addr.IP.String())
		mutAlv.Unlock()
	}

	if err := pinger.Run(); err != nil {
		str := fmt.Sprintf("Ping error: %v", err)
		if _, err := session.SendGroupMsg(str); err != nil {
			log.Printf("Cannot send message: [%s]%v", str, err)
		}
	}

	cancel()
	<-finish

	if len(aliveIps) > 0 {
		send(aliveIps)
	}

	if *DebugMode {
		log.Printf("Ping finished")
	}
}
