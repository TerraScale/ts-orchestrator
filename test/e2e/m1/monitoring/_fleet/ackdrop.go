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
)

var publishAck = []byte(`{"stream":"KV_ts-alert-email","seq":`)

func dropFirstAck(ctx context.Context, listen, upstream string) error {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	var dropped atomic.Bool
	fmt.Println("ack proxy ready")
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
			forwardServer(client, server, &dropped)
			_ = client.Close()
		}()
	}
}

func forwardServer(client io.Writer, server io.Reader, dropped *atomic.Bool) {
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
			if bytes.Contains(payload, publishAck) && dropped.CompareAndSwap(false, true) {
				fmt.Println("dropped publish ack")
				continue
			}
			line = append(line, payload...)
		}
		if _, err := client.Write(line); err != nil {
			return
		}
	}
}
