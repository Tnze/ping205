package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"ping205"
	"strings"
	"time"
)

var (
	host    = flag.String("host", "127.0.0.1:8080", "Hostname of mirai-api-http")
	authKey = flag.String("authkey", "", "Auth Key")
	Id      = flag.Int64("qq", 0, "QQ number")
	GroupID = flag.Int64("groupid", 0, "Group ID")
)

func main() {
	flag.Parse()
	session, err := GetSession()
	if err != nil {
		log.Fatalf("Get session key error: %v", session)
	}
	if err := BindQQ(session, *Id); err != nil {
		log.Fatalf("Bind QQ error: %v", err)
	}
	time.Sleep(time.Second * 10)
	if _, err := SendGroupMsg(session, "hello!"); err != nil {
		log.Fatalf("Send message error: %v", err)
	}

	OnGroupMsg()
}

func GetSession() (string, error) {
	var c http.Client
	link := url.URL{
		Host: *host, Scheme: "http", Path: "auth",
	}
	var resp struct {
		Code    int    `json:"code"`
		Session string `json:"session"`
	}
	if respJson, err := c.Post(
		link.String(), "application/json",
		strings.NewReader(`{"authKey":"`+*authKey+`"}`)); err != nil {
		return "", fmt.Errorf("auth error: %w", err)
	} else if err := json.NewDecoder(respJson.Body).Decode(&resp); err != nil {
		return "", fmt.Errorf("decode auth response error: %w", err)
	} else if resp.Code != 0 {
		return "", fmt.Errorf("decode auth response status error: %d", resp.Code)
	}
	return resp.Session, nil
}

func BindQQ(session string, qq int64) error {
	var c http.Client
	link := url.URL{
		Host: *host, Scheme: "http", Path: "verify",
	}
	var resp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if respJson, err := c.Post(
		link.String(), "application/json",
		strings.NewReader(fmt.Sprintf(`{"sessionKey": %q,"qq": %d}`, session, qq))); err != nil {
		return fmt.Errorf("verify error: %w", err)
	} else if err := json.NewDecoder(respJson.Body).Decode(&resp); err != nil {
		return fmt.Errorf("decode verify response error: %w", err)
	} else if resp.Code != 0 {
		return fmt.Errorf("verify error: [%d]%s", resp.Code, resp.Msg)
	}
	log.Printf("Verify success: [%d]%s", resp.Code, resp.Msg)
	return nil
}

func SendGroupMsg(session, msg string) (int, error) {
	c := http.Client{}
	var resp struct {
		Code  int    `json:"code"`
		Msg   string `json:"msg"`
		MsgID int    `json:"messageId"`
	}
	link := url.URL{
		Host: *host, Scheme: "http", Path: "sendFriendMessage",
	}
	var paylod = struct {
		SessionKey   string `json:"sessionKey"`
		Target       int64  `json:"target"`
		MessageChain []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"messageChain"`
	}{
		SessionKey: session,
		Target:     *GroupID,
		MessageChain: []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{
			{Type: "Plain", Text: msg},
		},
	}
	if pl, err := json.Marshal(paylod); err != nil {
		return 0, fmt.Errorf("marshal payload error: %w", err)
	} else if respJson, err := c.Post(
		link.String(), "application/json",
		bytes.NewReader(pl)); err != nil {
		return 0, fmt.Errorf("verify error: %w", err)
	} else if err := json.NewDecoder(respJson.Body).Decode(&resp); err != nil {
		return 0, fmt.Errorf("decode verify response error: %w", err)
	} else if resp.Code != 0 {
		log.Printf("Json payload: %s", pl)
		return 0, fmt.Errorf("send group message error: [%d]%s", resp.Code, resp.Msg)
	}
	return resp.MsgID, nil
}

func OnGroupMsg() {
	// read arp table
	ips, err := ping205.GetArpTable()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Get arp table error: %v\n", err)
		os.Exit(-1)
	}
	var names []string
	for _, ip := range ips {
		names, err := net.LookupAddr(ip.String())
		if err != nil {
			names = append(names, ip.String())
		} else {
			names = append(names, strings.Join(names, "|"))
		}
	}
	msg := strings.Join(names, "\n")
	log.Println(msg)
}
