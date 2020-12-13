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
)

var (
	host      = flag.String("host", "127.0.0.1:8080", "Hostname of mirai-api-http")
	report    = flag.String("report", "127.0.0.1:12031", "Report destinations (where this program listen)")
	authKey   = flag.String("authkey", "", "Auth Key")
	Id        = flag.Int64("qq", 0, "QQ number")
	GroupID   = flag.Int64("groupid", 0, "Group ID")
	DebugMode = flag.Bool("debug", false, "Debug mode")
)

var c = &http.Client{}

func main() {
	flag.Parse()
	if err := http.ListenAndServe(*report, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
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
			req.MessageChain[1].Type == "Plain" &&
			req.MessageChain[1].Text == "ping205" {
			OnGroupMsg()
		}
	})); err != nil {
		log.Fatalf("Listen error: %v", err)
	}
}

func GetSession() (string, error) {
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

func ReleaseSession(session string, qq int64) error {
	link := url.URL{
		Host: *host, Scheme: "http", Path: "release",
	}
	var resp struct {
		Code    int    `json:"code"`
		Session string `json:"session"`
	}
	if respJson, err := c.Post(
		link.String(), "application/json",
		strings.NewReader(fmt.Sprintf(`{"sessionKey": %q,"qq": %d}`, session, qq))); err != nil {
		return fmt.Errorf("auth error: %w", err)
	} else if err := json.NewDecoder(respJson.Body).Decode(&resp); err != nil {
		return fmt.Errorf("decode auth response error: %w", err)
	} else if resp.Code != 0 {
		return fmt.Errorf("decode auth response status error: %d", resp.Code)
	}
	return nil
}

func BindQQ(session string, qq int64) error {
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
	if *DebugMode {
		log.Printf("Verify success: [%d]%s", resp.Code, resp.Msg)
	}
	return nil
}

func SendGroupMsg(session, msg string) (int, error) {
	var resp struct {
		Code  int    `json:"code"`
		Msg   string `json:"msg"`
		MsgID int    `json:"messageId"`
	}
	link := url.URL{
		Host: *host, Scheme: "http", Path: "sendGroupMessage",
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
	var req *http.Request
	if pl, err := json.Marshal(paylod); err != nil {
		return 0, fmt.Errorf("marshal payload error: %w", err)
	} else if req, err = http.NewRequest(http.MethodPost,
		link.String(), bytes.NewReader(pl)); err != nil {
		return 0, fmt.Errorf("make request error: %w", err)
	} else {
		req.Header.Add("User-Agent", "ping205-golang")
		if *DebugMode {
			log.Printf("Json payload: [%s]%s", link.String(), pl)
		}
		if respJson, err := c.Do(req); err != nil {
			return 0, fmt.Errorf("send request error: %w", err)
		} else if err := json.NewDecoder(respJson.Body).Decode(&resp); err != nil {
			return 0, fmt.Errorf("decode verify response error: %w", err)
		} else if resp.Code != 0 {
			return 0, fmt.Errorf("send group message error: [%d]%s", resp.Code, resp.Msg)
		}
		return resp.MsgID, nil
	}
}

func OnGroupMsg() {
	// read arp table
	ips, err := ping205.GetArpTable()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Get arp table error: %v\n", err)
		os.Exit(-1)
	}
	var sb strings.Builder
	for _, ip := range ips {
		names, err := net.LookupAddr(ip.String())
		if err != nil {
			sb.WriteString(ip.String() + "\n")
		} else {
			sb.WriteString(strings.Join(names, "|") + "\n")
		}
	}

	session, err := GetSession()
	if err != nil {
		log.Fatalf("Get session key error: %v", session)
	}
	if err := BindQQ(session, *Id); err != nil {
		log.Fatalf("Bind QQ error: %v", err)
	}
	if msgID, err := SendGroupMsg(session, sb.String()); err != nil {
		log.Fatalf("Send message error: %v", err)
	} else if *DebugMode {
		fmt.Printf("Send message success: %d", msgID)
	}
	if err := ReleaseSession(session, *Id); err != nil {
		log.Fatalf("Release session key error: %v", err)
	}
}
