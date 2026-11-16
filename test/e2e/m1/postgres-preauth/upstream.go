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
