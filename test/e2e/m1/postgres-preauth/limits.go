package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type edgeClient struct {
	roots *x509.CertPool
	host  string
}

func (c edgeClient) open(source string, port int) (net.Conn, error) {
	raw, err := (&net.Dialer{Timeout: failAfter, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}).Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil || port == 80 {
		return raw, err
	}
	conn := tls.Client(raw, &tls.Config{RootCAs: c.roots, ServerName: c.host})
	_ = conn.SetDeadline(time.Now().Add(failAfter))
	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (c edgeClient) request(source string, port int, headers string) (net.Conn, *http.Response, error) {
	conn, err := c.open(source, port)
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(failAfter))
	_, err = fmt.Fprintf(conn, "GET /healthz HTTP/1.1\r\nHost: %s\r\n%s\r\n", c.host, headers)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		_, err = io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, response, err
}

func (c edgeClient) served(source string, port int, headers string, status int) error {
	conn, response, err := c.request(source, port, headers+"Connection: close\r\n")
	if err != nil {
		return err
	}
	defer conn.Close()
	if response.StatusCode != status {
		return fmt.Errorf("status %d, want %d", response.StatusCode, status)
	}
	if (status == 429 || status == 503) && response.Header.Get("Retry-After") != "1" {
		return fmt.Errorf("missing Retry-After: %v", response.Header)
	}
	return nil
}

func limitsMain() {
	state, caPath, host := os.Args[1], os.Args[2], os.Args[3]
	pem, err := os.ReadFile(caPath)
	step("read CA", err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		step("CA", errors.New("empty CA"))
	}
	pgBackend, err := net.Listen("tcp", "127.0.0.1:0")
	step("postgres backend", err)
	go serveBackend(pgBackend)
	entered, release := make(chan struct{}, 16), make(chan struct{})
	web, err := net.Listen("tcp", "127.0.0.1:0")
	step("HTTP backend", err)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	go (&http.Server{Protocols: protocols, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			conn, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			digest := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(digest[:]))
			for {
				var head [2]byte
				if _, err := io.ReadFull(conn, head[:]); err != nil {
					return
				}
				n := int(head[1] & 127)
				if head[0] != 0x81 || head[1]&128 == 0 || n > 125 {
					return
				}
				frame := make([]byte, n+4)
				if _, err := io.ReadFull(conn, frame); err != nil {
					return
				}
				for i := range n {
					frame[i+4] ^= frame[i%4]
				}
				if _, err := conn.Write(append([]byte{0x81, byte(n)}, frame[4:]...)); err != nil {
					return
				}
			}
		}
		if r.Header.Get("Content-Type") == "application/grpc" {
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(http.StatusOK)
			http.NewResponseController(w).Flush()
			io.Copy(streamFlush{w}, r.Body)
			return
		}
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			return
		}
		if r.URL.Path == "/hold" {
			entered <- struct{}{}
			<-release
		}
		fmt.Fprint(w, n)
	})}).Serve(web)
	public := edge.New(state)
	public.SetServiceRoutes(map[string]int{host: web.Addr().(*net.TCPAddr).Port}, map[string]int{host: pgBackend.Addr().(*net.TCPAddr).Port}, nil, nil)
	key := make([]byte, 32)
	_, err = rand.Read(key)
	step("peer credential", err)
	secret := hex.EncodeToString(key)
	step("peer proof", public.SetRequestProofSecret(secret))
	errCh := make(chan error, 1)
	go func() { errCh <- public.Run(context.Background()) }()
	step("edge listeners", waitListening(errCh))
	for deadline := time.Now().Add(failAfter); ; {
		var metrics strings.Builder
		observability.WriteEdgeListenerMetrics(&metrics)
		if strings.Contains(metrics.String(), `protocol="https"} 1`) && strings.Contains(metrics.String(), `protocol="http"} 1`) {
			break
		}
		if time.Now().After(deadline) {
			step("HTTP listeners", errors.New("not ready"))
		}
	}
	c := edgeClient{roots, host}
	var failures []error
	check := func(name string, err error) {
		if err != nil {
			fmt.Printf("FAIL %s: %v\n", name, err)
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
		} else {
			fmt.Printf("ok %s at %s\n", name, time.Since(started).Round(time.Millisecond))
		}
	}
	check("request p50", c.latency())
	if os.Args[4] == "latency" {
		step("latency lane", errors.Join(failures...))
		return
	}
	check("HTTPS public source and private peer", c.connectionCap(443, secret))
	check("HTTP public source and private peer", c.connectionCap(80, secret))
	check("node HTTP connection budget", c.nodeConnections())
	check("Postgres source sessions", c.postgresSessions())
	check("Postgres node sessions", c.postgresNode())
	check("WebSocket source and node budgets", c.websockets())
	check("replay body budget", c.spoolBudget(entered, release))
	idle, err := connect(net.ParseIP("198.18.3.1"), host, roots)
	check("Postgres idle session established", err)
	idleResult := make(chan error, 1)
	if idle != nil {
		go func() {
			defer idle.Close()
			_ = idle.SetReadDeadline(time.Now().Add(120*time.Second + failAfter))
			var b [1]byte
			_, err := idle.Read(b[:])
			if err == nil {
				err = errors.New("idle session returned data")
			} else if errors.Is(err, io.EOF) {
				err = nil
			}
			idleResult <- err
		}()
	}
	ws, err := c.socket("10.80.1.2")
	check("long WebSocket established", err)
	stream, finish, err := c.grpcStream()
	check("gRPC stream established", err)
	check("HTTPS slow body cut", c.slowBody(443))
	check("HTTP slow body cut", c.slowBody(80))
	check("HTTP/2 slow body cut", c.slowHTTP2())
	check("30 MiB steady upload", c.steadyUpload())
	if idle != nil {
		check("Postgres idle cut", <-idleResult)
	}
	if ws != nil {
		check("WebSocket after idle interval", echoSocket(ws))
		ws.Close()
	}
	if stream != nil {
		check("gRPC after idle interval", finish())
	}
	var metrics strings.Builder
	observability.WriteEdgeResponseMetrics(&metrics)
	for _, reason := range []string{"connection_source", "connection_node", "postgres_source", "postgres_node", "postgres_idle", "websocket_source", "websocket_node", "spool_budget", "body_rate"} {
		if !strings.Contains(metrics.String(), `reason="`+reason+`"`) {
			check("refusal metric "+reason, errors.New("missing reason series"))
		}
	}
	step("edge abuse lane", errors.Join(failures...))
}

func (c edgeClient) latency() error {
	conn, err := c.open("198.18.2.1", 443)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(failAfter))
	reader := bufio.NewReader(conn)
	for run := range 3 {
		samples := make([]time.Duration, 250)
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for i := range samples {
			start := time.Now()
			if _, err := fmt.Fprintf(conn, "GET /healthz HTTP/1.1\r\nHost: %s\r\n\r\n", c.host); err != nil {
				return err
			}
			response, err := http.ReadResponse(reader, nil)
			if err != nil {
				return err
			}
			_, err = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 {
				return fmt.Errorf("status %d, read %v", response.StatusCode, err)
			}
			samples[i] = time.Since(start)
		}
		runtime.ReadMemStats(&after)
		slices.Sort(samples)
		fmt.Printf("request p50 run %d: %s (250 requests, TLS keepalive)\n", run+1, samples[len(samples)/2])
		fmt.Printf("allocations/request run %d: %.2f (client, edge and backend)\n", run+1, float64(after.Mallocs-before.Mallocs)/float64(len(samples)))
	}
	return nil
}

func (c edgeClient) connectionCap(port int, secret string) error {
	var held []net.Conn
	defer func() { closeAll(held) }()
	for range 64 {
		conn, response, err := c.request("198.18.1.1", port, "")
		if err != nil {
			return err
		}
		held = append(held, conn)
		if response.StatusCode != 200 {
			return fmt.Errorf("admitted status %d", response.StatusCode)
		}
	}
	if err := c.served("198.18.1.1", port, "X-Forwarded-For: 198.18.2.1\r\n", 429); err != nil {
		return err
	}
	if port == 443 {
		client := c.client("198.18.1.1")
		defer client.CloseIdleConnections()
		response, err := client.Get("https://" + c.host + "/healthz")
		if err != nil {
			return err
		}
		response.Body.Close()
		if response.ProtoMajor != 2 || response.StatusCode != 429 || response.Header.Get("Retry-After") != "1" {
			return fmt.Errorf("HTTP/2 refusal %s status %d", response.Proto, response.StatusCode)
		}
	}
	if err := c.served("198.18.2.1", port, "", 200); err != nil {
		return err
	}
	headers := "X-TerraScale-Edge-Hop: 1\r\nX-TerraBase-Peer-Credential: " + secret + "\r\n"
	if err := c.served("10.80.1.1", port, headers, 200); err != nil {
		return fmt.Errorf("private hop: %w", err)
	}
	if err := c.served("10.80.1.1", port, "X-TerraScale-Edge-Hop: 1\r\nX-TerraBase-Peer-Credential: invalid\r\n", 403); err != nil {
		return fmt.Errorf("private invalid credential: %w", err)
	}
	closeAll(held)
	held = nil
	return c.served("198.18.1.1", port, "", 200)
}

func (c edgeClient) nodeConnections() error {
	var held []net.Conn
	defer func() { closeAll(held) }()
	for range 1024 {
		conn, response, err := c.request("10.80.1.1", 443, "")
		if err != nil {
			return err
		}
		held = append(held, conn)
		if response.StatusCode != 200 {
			return fmt.Errorf("node connection %d: %d", len(held), response.StatusCode)
		}
	}
	return errors.Join(c.served("198.18.2.1", 443, "", 503), c.served("198.18.2.1", 80, "", 503))
}

func (c edgeClient) postgresSessions() error {
	var held []net.Conn
	defer func() { closeAll(held) }()
	for range 64 {
		conn, err := connect(net.ParseIP("198.18.1.1"), c.host, c.roots)
		if err != nil {
			return err
		}
		held = append(held, conn)
	}
	conn, err := connect(net.ParseIP("198.18.1.1"), c.host, c.roots)
	if conn != nil {
		conn.Close()
	}
	if err == nil || err.Error() != "53300" {
		return fmt.Errorf("65th source session: %v", err)
	}
	if err := freshQuery(net.ParseIP("198.18.2.1"), c.host, c.roots); err != nil {
		return err
	}
	closeAll(held)
	held = nil
	return freshQuery(net.ParseIP("198.18.1.1"), c.host, c.roots)
}

func (c edgeClient) postgresNode() error {
	var held []net.Conn
	defer func() { closeAll(held) }()
	for range 1024 {
		conn, err := connect(net.ParseIP("10.80.1.1"), c.host, c.roots)
		if err != nil {
			return fmt.Errorf("node session %d: %w", len(held), err)
		}
		held = append(held, conn)
	}
	conn, err := connect(net.ParseIP("198.18.2.1"), c.host, c.roots)
	if conn != nil {
		conn.Close()
	}
	if err == nil || err.Error() != "53300" {
		return fmt.Errorf("1025th node session: %v", err)
	}
	return nil
}

func (c edgeClient) socket(source string) (net.Conn, error) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	conn, response, err := c.request(source, 443, "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+key+"\r\n")
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 101 {
		conn.Close()
		return nil, fmt.Errorf("socket status %d", response.StatusCode)
	}
	return conn, nil
}

func echoSocket(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(failAfter))
	frame := []byte{0x81, 0x82, 1, 2, 3, 4, 'o' ^ 1, 'k' ^ 2}
	if _, err := conn.Write(frame); err != nil {
		return err
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, []byte{0x81, 2, 'o', 'k'}) {
		return fmt.Errorf("echo %x", got)
	}
	return conn.SetDeadline(time.Time{})
}

func (c edgeClient) websockets() error {
	var held []net.Conn
	var sourceErr error
	defer func() { closeAll(held) }()
	for source := range 8 {
		address := fmt.Sprintf("10.80.1.%d", source+1)
		for range 64 {
			conn, err := c.socket(address)
			if err != nil {
				return err
			}
			held = append(held, conn)
		}
		if source == 0 {
			key := base64.StdEncoding.EncodeToString(make([]byte, 16))
			conn, response, err := c.request(address, 443, "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+key+"\r\n")
			if err != nil {
				return err
			}
			conn.Close()
			if response.StatusCode != 429 || response.Header.Get("Retry-After") != "1" {
				sourceErr = fmt.Errorf("65th WebSocket: %d", response.StatusCode)
			}
			if err := c.served("198.18.2.1", 443, "", 200); err != nil {
				return err
			}
		}
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	conn, response, err := c.request("10.80.1.9", 443, "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+key+"\r\n")
	if err != nil {
		return err
	}
	conn.Close()
	if response.StatusCode != 503 || response.Header.Get("Retry-After") != "1" {
		return errors.Join(sourceErr, fmt.Errorf("513th WebSocket: %d", response.StatusCode))
	}
	return errors.Join(sourceErr, echoSocket(held[0]))
}

func (c edgeClient) client(source string) *http.Client {
	return &http.Client{Timeout: failAfter, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: c.roots, ServerName: c.host}, ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}).DialContext(ctx, "tcp4", "127.0.0.1:443")
		}}}
}

func (c edgeClient) spoolBudget(entered <-chan struct{}, release chan<- struct{}) (result error) {
	client := c.client("198.18.1.1")
	defer client.CloseIdleConnections()
	body := make([]byte, 8<<20)
	var pending sync.WaitGroup
	results := make(chan error, 8)
	defer func() {
		close(release)
		pending.Wait()
		close(results)
		for err := range results {
			result = errors.Join(result, err)
		}
	}()
	for range 8 {
		pending.Go(func() {
			response, err := client.Post("https://"+c.host+"/hold", "application/octet-stream", bytes.NewReader(body))
			if err == nil {
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if response.StatusCode != 200 {
					err = fmt.Errorf("held body status %d", response.StatusCode)
				}
			}
			results <- err
		})
		select {
		case <-entered:
		case err := <-results:
			return fmt.Errorf("hold: %v", err)
		case <-time.After(failAfter):
			return errors.New("body never reached backend")
		}
	}
	response, err := client.Post("https://"+c.host+"/probe", "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 503 || response.Header.Get("Retry-After") != "1" {
		return fmt.Errorf("exhausted spool status %d", response.StatusCode)
	}
	return c.served("198.18.2.1", 443, "", 200)
}

func (c edgeClient) slowHTTP2() error {
	client := c.client("198.18.1.1")
	client.Timeout = 12 * time.Second
	defer client.CloseIdleConnections()
	reader, writer := io.Pipe()
	defer writer.Close()
	request, _ := http.NewRequest(http.MethodPost, "https://"+c.host+"/upload", reader)
	request.ContentLength = 1 << 20
	go writer.Write([]byte{'x'})
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != 429 || response.Header.Get("Retry-After") != "1" {
		return fmt.Errorf("slow body %s status %d", response.Proto, response.StatusCode)
	}
	return nil
}

func (c edgeClient) slowBody(port int) error {
	conn, err := c.open("198.18.1.1", port)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET /healthz HTTP/1.1\r\nHost: %s\r\nContent-Length: 1048576\r\n\r\nx", c.host); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 429 || response.Header.Get("Retry-After") != "1" {
		return fmt.Errorf("slow body status %d", response.StatusCode)
	}
	return nil
}

func (c edgeClient) steadyUpload() error {
	conn, err := c.open("198.18.1.1", 443)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(25 * time.Second))
	if _, err := fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", c.host, 30<<20); err != nil {
		return err
	}
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	chunk := make([]byte, 1<<20)
	for range 30 {
		<-tick.C
		if _, err := conn.Write(chunk); err != nil {
			return err
		}
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	got, err := io.ReadAll(response.Body)
	if err != nil || string(got) != strconv.Itoa(30<<20) || response.StatusCode != 200 {
		return fmt.Errorf("upload status %d, bytes %q: %v", response.StatusCode, got, err)
	}
	return nil
}

type streamFlush struct{ http.ResponseWriter }

func (w streamFlush) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if err == nil {
		err = http.NewResponseController(w.ResponseWriter).Flush()
	}
	return n, err
}

func (c edgeClient) grpcStream() (io.Closer, func() error, error) {
	client := c.client("198.18.2.1")
	client.Timeout = 0
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+c.host+"/grpc", reader)
	request.Header.Set("Content-Type", "application/grpc")
	establish := time.AfterFunc(failAfter, cancel)
	response, err := client.Do(request)
	establish.Stop()
	if err != nil {
		cancel()
		writer.Close()
		return nil, nil, err
	}
	return response.Body, func() error {
		stop := time.AfterFunc(failAfter, cancel)
		defer stop.Stop()
		defer cancel()
		defer response.Body.Close()
		defer writer.Close()
		defer client.CloseIdleConnections()
		frame := []byte{0, 0, 0, 0, 2, 'o', 'k'}
		if _, err := writer.Write(frame); err != nil {
			return err
		}
		got := make([]byte, len(frame))
		if _, err := io.ReadFull(response.Body, got); err != nil {
			return err
		}
		if response.ProtoMajor != 2 || !bytes.Equal(frame, got) {
			return fmt.Errorf("gRPC %s frame %x", response.Proto, got)
		}
		return nil
	}, nil
}
