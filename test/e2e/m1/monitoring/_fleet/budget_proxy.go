package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var (
	publishAck = []byte(`{"stream":"KV_ts-alert-email","seq":`)
	ledgerRead = []byte("Nats-Subject: $KV.ts-alert-email.ledger")
)

func budgetProxy(ctx context.Context, mode, listen, upstream string) error {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	var fired atomic.Bool
	fmt.Println("budget proxy ready")
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		server, err := net.Dial("tcp", upstream)
		if err != nil {
			_ = client.Close()
			continue
		}
		go func() {
			_, _ = io.Copy(server, client)
			_ = server.Close()
		}()
		go func() {
			forwardServer(client, server, mode, &fired)
			_ = client.Close()
		}()
	}
}

func forwardServer(client io.Writer, server io.Reader, mode string, fired *atomic.Bool) {
	reader := bufio.NewReader(server)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(string(line))
		if len(fields) > 0 && (fields[0] == "MSG" || fields[0] == "HMSG") {
			size, err := strconv.Atoi(fields[len(fields)-1])
			if err != nil {
				return
			}
			payload := make([]byte, size+2)
			if _, err := io.ReadFull(reader, payload); err != nil {
				return
			}
			switch {
			case mode == "lose-ack" && bytes.Contains(payload, publishAck) && fired.CompareAndSwap(false, true):
				fmt.Println("dropped publish ack")
				continue
			case mode == "slow-read" && bytes.Contains(payload, ledgerRead) && fired.CompareAndSwap(false, true):
				<-time.After(2500 * time.Millisecond)
				fmt.Println("delayed ledger read 2.5s")
			}
			line = append(line, payload...)
		}
		if _, err := client.Write(line); err != nil {
			return
		}
	}
}
