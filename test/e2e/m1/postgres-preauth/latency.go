package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

func (c edgeClient) latency() error {
	for run := range 3 {
		for _, fresh := range []bool{true, false} {
			var conn net.Conn
			var reader *bufio.Reader
			samples := make([]time.Duration, 100)
			if !fresh {
				var err error
				conn, err = c.open("198.18.2.1", 443)
				if err != nil {
					return err
				}
				reader = bufio.NewReader(conn)
			}
			for i := range samples {
				start := time.Now()
				if conn == nil {
					var err error
					conn, err = c.open("198.18.2.1", 443)
					if err != nil {
						return err
					}
					reader = bufio.NewReader(conn)
				}
				conn.SetDeadline(time.Now().Add(failAfter))
				if _, err := fmt.Fprintf(conn, "GET /healthz HTTP/1.1\r\nHost: %s\r\n\r\n", c.host); err != nil {
					conn.Close()
					return err
				}
				if _, err := reader.Peek(1); err != nil {
					conn.Close()
					return err
				}
				samples[i] = time.Since(start)
				response, err := http.ReadResponse(reader, nil)
				if err != nil {
					conn.Close()
					return err
				}
				_, err = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != 200 {
					conn.Close()
					return fmt.Errorf("status %d: %v", response.StatusCode, err)
				}
				if fresh {
					conn.Close()
					conn = nil
				}
			}
			if conn != nil {
				conn.Close()
			}
			slices.Sort(samples)
			fmt.Printf("first byte run %d fresh=%t: p50=%s p95=%s (100 requests)\n", run+1, fresh, samples[50], samples[95])
		}
	}
	return nil
}

func (c edgeClient) resumption() error {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		config := &tls.Config{RootCAs: c.roots, ServerName: c.host, MinVersion: version, MaxVersion: version, ClientSessionCache: tls.NewLRUClientSessionCache(1)}
		for reconnect := range 2 {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: failAfter}, "tcp", "127.0.0.1:443", config)
			if err != nil {
				return err
			}
			conn.SetDeadline(time.Now().Add(failAfter))
			fmt.Fprintf(conn, "GET /healthz HTTP/1.1\r\nHost: %s\r\n\r\n", c.host)
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err == nil {
				_, err = io.Copy(io.Discard, response.Body)
				response.Body.Close()
			}
			resumed := conn.ConnectionState().DidResume
			conn.Close()
			if err != nil || reconnect == 1 && !resumed {
				return fmt.Errorf("TLS %x resumption=%t: %v", version, resumed, err)
			}
		}
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: failAfter}, "tcp", "127.0.0.1:443", &tls.Config{RootCAs: c.roots, ServerName: c.host, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		return err
	}
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		return errors.New("h2 not negotiated")
	}
	return nil
}

func (c edgeClient) pool(entered <-chan struct{}, release [2]chan struct{}, connections *atomic.Uint64, enforce bool) error {
	var warm uint64
	for wave := range 2 {
		results := make(chan error, 16)
		for range 16 {
			go func() {
				conn, response, err := c.requestPath("198.18.2.1", 443, fmt.Sprintf("/pool?%d", wave), "")
				if conn != nil {
					conn.Close()
				}
				if err == nil && response.StatusCode != 200 {
					err = fmt.Errorf("pool HTTP %d", response.StatusCode)
				}
				results <- err
			}()
		}
		deadline := time.NewTimer(failAfter)
		for range 16 {
			select {
			case <-entered:
			case <-deadline.C:
				close(release[wave])
				return errors.New("pool wave did not reach 16 concurrent requests")
			}
		}
		deadline.Stop()
		close(release[wave])
		for range 16 {
			if err := <-results; err != nil {
				return err
			}
		}
		if wave == 0 {
			warm = connections.Load()
		}
	}
	added := connections.Load() - warm
	fmt.Printf("upstream connections opened in second 16-request burst: %d\n", added)
	if added != 0 && enforce {
		return fmt.Errorf("warm burst opened %d connections", added)
	}
	return nil
}

func (c edgeClient) latencyMetrics(public *edge.Edge) error {
	conn, err := c.open("198.18.2.1", 443)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(failAfter))
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: unknown.e2e.test\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 404 {
		return fmt.Errorf("unknown Host HTTP %d", response.StatusCode)
	}
	var metrics strings.Builder
	public.WriteRequestMetrics(&metrics)
	var total, upstream, count float64
	for line := range strings.SplitSeq(metrics.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return err
		}
		if strings.HasPrefix(line, "ts_orch_edge_request_duration_seconds_sum") {
			if strings.Contains(line, `stage="total"`) {
				total += value
			} else {
				upstream += value
			}
		}
		if strings.HasPrefix(line, "ts_orch_edge_request_duration_seconds_count") && strings.Contains(line, `stage="total"`) {
			count += value
		}
	}
	if strings.Contains(metrics.String(), "unknown.e2e.test") {
		return errors.New("unknown Host allocated duration labels")
	}
	if count < 600 || upstream <= 0 || total < upstream || !strings.Contains(metrics.String(), `le="+Inf"`) {
		return fmt.Errorf("invalid histograms: count=%g total=%g upstream=%g", count, total, upstream)
	}
	fmt.Printf("edge histogram: requests=%.0f mean_total=%.3fms mean_upstream=%.3fms mean_overhead=%.3fms\n", count, total/count*1000, upstream/count*1000, (total-upstream)/count*1000)
	return nil
}

func (c edgeClient) drain(public *edge.Edge, stop func(), done <-chan error, entered <-chan struct{}, release chan struct{}) error {
	if os.Args[4] == "baseline" {
		return nil
	}
	public.SetPeerEdges(func() []mesh.WorkerPeer { return nil })
	if err := c.served("198.18.2.1", 80, "", http.StatusOK); err != nil {
		return err
	}
	result := make(chan error, 1)
	go func() {
		conn, err := c.open("198.18.2.1", 443)
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		fmt.Fprintf(conn, "GET /drain HTTP/1.1\r\nHost: %s\r\n\r\n", c.host)
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err == nil {
			_, err = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != 200 {
				err = fmt.Errorf("in-flight HTTP %d", response.StatusCode)
			}
		}
		result <- err
	}()
	defer close(release)
	select {
	case <-entered:
	case <-time.After(failAfter):
		return errors.New("drain request did not reach backend")
	}
	started := time.Now()
	public.Drain()
	stop()
	health, response, err := c.requestPath("198.18.2.1", 80, "/readyz", "Connection: close\r\n")
	if health != nil {
		health.Close()
	}
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusServiceUnavailable {
		return fmt.Errorf("drain health HTTP %d", response.StatusCode)
	}
	propagating, response, err := c.requestPath("198.18.2.1", 443, "/during-drain", "")
	if err != nil {
		return err
	}
	defer propagating.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("propagation HTTP %d", response.StatusCode)
	}
	propagating.SetReadDeadline(started.Add(30 * time.Second))
	var probe [1]byte
	_, err = propagating.Read(probe[:])
	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("propagation connection close: %w", err)
	}
	if elapsed := time.Since(started); elapsed < 20*time.Second {
		return fmt.Errorf("HTTPS admission stopped before NLB propagation: %s", elapsed)
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:443", failAfter)
	if err == nil {
		conn.Close()
		return errors.New("HTTPS admission continued after propagation")
	}
	release <- struct{}{}
	select {
	case err := <-result:
		if err != nil {
			return err
		}
	case <-time.After(failAfter):
		return errors.New("in-flight request did not finish")
	}
	select {
	case err := <-done:
		return err
	case <-time.After(failAfter):
		return errors.New("edge did not finish graceful shutdown")
	}
}
