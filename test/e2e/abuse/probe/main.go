package main

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
)

func main() {
	if len(os.Args) != 4 {
		os.Exit(2)
	}
	port, err := strconv.Atoi(os.Args[2])
	if assigned := os.Getenv("PORT"); assigned != "" {
		port, err = strconv.Atoi(assigned)
	}
	if err != nil || port < 1024 || port > 65535 {
		os.Exit(2)
	}
	mode := os.Args[3]
	var leak sync.Once
	var mu sync.Mutex
	var cancel context.CancelFunc
	var memory [][]byte
	var requests, failures atomic.Uint64
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if mode == "postgres" {
			conn, err := net.Dial("tcp", "127.0.0.1:18105")
			if err != nil {
				w.WriteHeader(503)
				return
			}
			conn.Close()
		}
		fmt.Fprint(w, os.Getenv("ABUSE_TENANT"))
	})
	http.HandleFunc("/read", func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		fmt.Fprint(w, n)
	})
	http.HandleFunc("/work", func(w http.ResponseWriter, r *http.Request) {
		data := [32]byte{}
		for range 100000 {
			data = sha256.Sum256(data[:])
		}
		fmt.Fprintf(w, "%x", data)
	})
	http.HandleFunc("/leak", func(w http.ResponseWriter, r *http.Request) {
		if mode != "leak" || r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		w.WriteHeader(202)
		w.(http.Flusher).Flush()
		leak.Do(func() {
			go func() {
				for {
					block := make([]byte, 1<<20)
					for i := range block {
						block[i] = byte(i)
					}
					memory = append(memory, block)
				}
			}()
		})
	})
	http.HandleFunc("/noise", func(w http.ResponseWriter, r *http.Request) {
		if mode != "noisy" {
			w.WriteHeader(405)
			return
		}
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]uint64{"requests": requests.Load(), "errors": failures.Load()})
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if cancel != nil {
			cancel()
			cancel = nil
		}
		if r.Method == http.MethodPost {
			ctx, stop := context.WithCancel(context.Background())
			cancel = stop
			for range 32 {
				go func() {
					transport := http.DefaultTransport.(*http.Transport).Clone()
					transport.Proxy = nil
					defer transport.CloseIdleConnections()
					client := &http.Client{Transport: transport}
					for ctx.Err() == nil {
						request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/work", port), nil)
						if err != nil {
							failures.Add(1)
							return
						}
						response, err := client.Do(request)
						if err != nil {
							failures.Add(1)
							return
						}
						_, err = io.Copy(io.Discard, response.Body)
						response.Body.Close()
						if err != nil || response.StatusCode != 200 {
							failures.Add(1)
							return
						}
						requests.Add(1)
					}
				}()
			}
		}
		w.WriteHeader(204)
	})
	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			w.WriteHeader(400)
			return
		}
		conn, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		digest := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		fmt.Fprintf(buffer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(digest[:]))
		if buffer.Flush() != nil {
			return
		}
		for {
			head := [2]byte{}
			if _, err := io.ReadFull(buffer, head[:]); err != nil {
				return
			}
			n := int(head[1] & 127)
			if head[1]&128 == 0 || n > 125 || head[0]&15 == 8 {
				return
			}
			frame := make([]byte, n+4)
			if _, err := io.ReadFull(buffer, frame); err != nil {
				return
			}
			for i := range n {
				frame[i+4] ^= frame[i%4]
			}
			if _, err := buffer.Write(append([]byte{head[0], byte(n)}, frame[4:]...)); err != nil {
				return
			}
			if buffer.Flush() != nil {
				return
			}
		}
	})
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		os.Exit(1)
	}
	fmt.Println("abuse-probe-ready")
	if http.Serve(listener, nil) != nil {
		os.Exit(1)
	}
}
