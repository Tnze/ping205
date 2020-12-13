package main

import (
	"flag"
	"fmt"
	"github.com/wangnengjie/mirai-go"
	"github.com/wangnengjie/mirai-go/model"
	"net"
	"os"
	"ping205"
	"strings"
)

var (
	host    = flag.String("host", "", "Hostname of mirai-api-http")
	authKey = flag.String("authkey", "", "Auth Key")
	Id      = flag.Int64("qq", 0, "QQ number")
	Debug   = flag.Bool("debug", false, "Debug")
	GroupID = flag.Int64("groupid", 0, "Group ID")
)

func main() {
	flag.Parse()
	bot := mirai.NewBot(mirai.BotConfig{
		Host:      *host,
		AuthKey:   *authKey,
		Id:        model.QQId(*Id),
		Websocket: false,
		RecvMode:  mirai.RecvAll,
		Debug:     *Debug,
	})
	err := bot.Connect()
	if err != nil {
		bot.Log.Error(err)
	}
	bot.On(model.GroupMessage, repeat)
	bot.Loop()
}

func repeat(ctx *mirai.Context) {
	m, _ := ctx.Message.(*model.GroupMsg)
	if len(m.MessageChain) < 2 {
		fmt.Printf("%v\n", m.MessageChain[1].(*model.Plain).Text)
		return
	} else if msg, ok := m.MessageChain[1].(*model.Plain); !ok {
		return
	} else if !strings.HasPrefix(msg.Text, "ping205") {
		return
	}

	if m.Sender.Group.Id != model.GroupId(*GroupID) {
		return
	}
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
	// 0 代表不回复消息，msgId是发出的消息的id
	// chain中第一位为source
	msgId, err := ctx.Bot.SendGroupMessage(m.Sender.Group.Id,
		model.MsgChain{
			&model.Plain{Text: strings.Join(names, "\n")},
		}, 0)
	// msgId 是刚刚发送的这条消息的id
	if err != nil {
		ctx.Bot.Log.Error(err)
	} else {
		ctx.Bot.Log.Info(msgId)
	}
}
