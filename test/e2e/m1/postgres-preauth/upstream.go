package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func budgetEdge() {
	public := edge.New(os.Args[1])
	routes := map[string]int{}
	for i, name := range []string{"warm", "busy-0", "busy-1"} {
		port, err := strconv.Atoi(os.Args[i+5])
		step("backend port", err)
		routes[name+".e2e.test"] = port
	}
	routes[os.Args[3]] = routes["warm.e2e.test"]
	public.SetRoutes(routes, nil)
	errCh := make(chan error, 1)
	go func() { errCh <- public.Run(context.Background()) }()
	step("budget listeners", waitListening(errCh))
	for deadline := time.Now().Add(failAfter); ; {
		var metrics strings.Builder
		observability.WriteEdgeListenerMetrics(&metrics)
		if strings.Contains(metrics.String(), "protocol=\"http\"} 1") {
			break
		}
		if time.Now().After(deadline) {
			step("budget HTTP listener", fmt.Errorf("not ready"))
		}
		runtime.Gosched()
	}
	fmt.Println("budget-ready")
	commands := bufio.NewScanner(os.Stdin)
	for commands.Scan() {
		if commands.Text() == "task" {
			step("shared task budget", budgetTask())
		}
		public.WriteRequestMetrics(os.Stdout)
		observability.WriteEdgeResponseMetrics(os.Stdout)
		fds, err := os.ReadDir("/proc/self/fd")
		step("descriptor snapshot", err)
		var limit syscall.Rlimit
		step("descriptor limit", syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit))
		fmt.Printf("fds %d\nlimit %d\nbudget-end\n", len(fds), limit.Cur)
	}
	step("budget commands", commands.Err())
}

func budgetTask() error {
	pem, err := os.ReadFile(os.Args[2])
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("empty CA")
	}
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{RootCAs: roots, ServerName: os.Args[3]},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: failAfter}).DialContext(ctx, "tcp", "127.0.0.1:443")
		},
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequest(http.MethodGet, "https://"+os.Args[3]+"/task-limit", nil)
	if err != nil {
		return err
	}
	request.Host = "busy-0.e2e.test"
	request.Header.Set("Content-Type", "application/grpc")
	response, err := (&http.Client{Transport: transport, Timeout: failAfter}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return err
	}
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusServiceUnavailable {
		return fmt.Errorf("task limit: protocol=%s HTTP=%d", response.Proto, response.StatusCode)
	}
	return nil
}

func budgetLoad() {
	pem, err := os.ReadFile(os.Args[2])
	step("load CA", err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		step("load CA", fmt.Errorf("empty CA"))
	}
	n, err := strconv.Atoi(os.Args[6])
	step("load count", err)
	config := &tls.Config{RootCAs: roots, ServerName: os.Args[3], NextProtos: []string{"h2"}}
	transport := &http2.Transport{}
	var connections []*http2.ClientConn
	defer func() {
		for _, conn := range connections {
			conn.Close()
		}
	}()
	var ready, done sync.WaitGroup
	ready.Add(n)
	done.Add(n)
	for offset := 0; offset < n; offset += 128 {
		conn, err := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: failAfter}, Config: config}).DialContext(context.Background(), "tcp", "127.0.0.1:443")
		if err != nil {
			step("load connection", err)
		}
		client, err := transport.NewClientConn(conn)
		if err != nil {
			step("load HTTP/2", err)
		}
		connections = append(connections, client)
		for range min(128, n-offset) {
			go func() {
				defer done.Done()
				request, err := http.NewRequest(http.MethodGet, "https://"+os.Args[3]+"/healthz", nil)
				if err != nil {
					step("load request", err)
				}
				request.Host = os.Args[5] + ".e2e.test"
				response, err := client.RoundTrip(request)
				if err != nil {
					step("load headers", err)
				}
				if response.ProtoMajor != 2 || response.StatusCode != http.StatusOK {
					step("load response", fmt.Errorf("protocol=%s HTTP=%d", response.Proto, response.StatusCode))
				}
				ready.Done()
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					step("load body", err)
				}
				if string(body) != "0" {
					step("load body", fmt.Errorf("unexpected body %q", body))
				}
			}()
		}
	}
	ready.Wait()
	fmt.Println("load-ready")
	done.Wait()
	fmt.Println("load-done")
}
