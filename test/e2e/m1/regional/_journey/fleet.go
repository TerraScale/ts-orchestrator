package edge

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

type fleetListener struct {
	net.Listener
	once     sync.Once
	accepted chan<- struct{}
}

func (l *fleetListener) Accept() (net.Conn, error) {
	l.once.Do(func() { l.accepted <- struct{}{} })
	return l.Listener.Accept()
}

type fleetHost struct {
	edge    *Edge
	address string
	port    int
	backend *http.Server
	ready   atomic.Bool
	stop    func()
}

func newFleetHost(ctx context.Context, root, address string, node *mesh.Node, secret string) (*fleetHost, error) {
	host := &fleetHost{address: address}
	host.ready.Store(true)
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	host.port = backend.Addr().(*net.TCPAddr).Port
	host.backend = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			if !host.ready.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			return
		}
		fmt.Fprint(w, address)
	})}
	go host.backend.Serve(backend)
	state := filepath.Join(root, "edge-"+address)
	if err := os.MkdirAll(filepath.Join(state, "edge-certs"), 0700); err != nil {
		return nil, err
	}
	cert, err := os.ReadFile(filepath.Join(root, "regional", "edge-certs", "fleet.e2e.test"))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(state, "edge-certs", "fleet.e2e.test"), cert, 0600); err != nil {
		return nil, err
	}
	host.edge = New(state)
	host.edge.SetMesh(node)
	if err := host.edge.SetRequestProofSecret(secret); err != nil {
		return nil, err
	}
	host.routes(true)
	host.edge.SetReadinessRoutes([]ReadinessRoute{{Host: "fleet.e2e.test", Port: host.port, Path: "/readyz"}})
	accepted := make(chan struct{}, 4)
	host.edge.listen = func(network, endpoint string) (net.Listener, error) {
		_, port, err := net.SplitHostPort(endpoint)
		if err != nil {
			return nil, err
		}
		listener, err := net.Listen(network, net.JoinHostPort(address, port))
		if err != nil {
			return nil, err
		}
		return &fleetListener{Listener: listener, accepted: accepted}, nil
	}
	running, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- host.edge.Run(running) }()
	host.stop = sync.OnceFunc(func() { cancel(); <-done; host.backend.Close() })
	for range 4 {
		select {
		case <-accepted:
		case err := <-done:
			cancel()
			host.backend.Close()
			return nil, fmt.Errorf("edge stopped before listeners served: %w", err)
		case <-ctx.Done():
			host.stop()
			return nil, ctx.Err()
		}
	}
	return host, nil
}

func (h *fleetHost) routes(ready bool) {
	services := []string{}
	if ready {
		services = append(services, "stateless")
	}
	h.edge.SetServiceRoutes(map[string]int{"fleet.e2e.test": h.port}, nil,
		map[string]string{"fleet.e2e.test": "stateless"}, services)
}

func fleetGet(ctx context.Context, client *http.Client, address, path string) (int, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://fleet.e2e.test"+path, nil)
	if err != nil {
		return 0, "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	return response.StatusCode, string(data), err
}

func FleetEdgeJourney(root string, nodes []*mesh.Node) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pem, err := os.ReadFile(filepath.Join(root, "ca.pem"))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("missing fleet root CA")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	for region := range 3 {
		first, err := newFleetHost(ctx, root, fmt.Sprintf("127.0.0.%d", 10+2*region), nodes[2*region], hex.EncodeToString(secret))
		if err != nil {
			return err
		}
		defer first.stop()
		second, err := newFleetHost(ctx, root, fmt.Sprintf("127.0.0.%d", 11+2*region), nodes[2*region+1], hex.EncodeToString(secret))
		if err != nil {
			return err
		}
		defer second.stop()
		first.edge.SetPeerEdges(func() []mesh.WorkerPeer {
			return []mesh.WorkerPeer{{Node: "second", Address: second.address, ReadyServices: second.edge.ReadyServices()}}
		})
		second.edge.SetPeerEdges(func() []mesh.WorkerPeer {
			return []mesh.WorkerPeer{{Node: "first", Address: first.address, ReadyServices: first.edge.ReadyServices()}}
		})
		for _, host := range []*fleetHost{first, second} {
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DisableKeepAlives: true}
			transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(host.address, "443"))
			}
			client := &http.Client{Transport: transport}
			status, _, err := fleetGet(ctx, client, host.address, "/edge/ready")
			if err != nil || status != http.StatusOK {
				return fmt.Errorf("host %s ready: HTTP %d, %w", host.address, status, err)
			}
			counts := map[string]int{}
			for range 12 {
				status, body, err := fleetGet(ctx, client, host.address, "/payload")
				if err != nil || status != http.StatusOK {
					return fmt.Errorf("host %s payload: HTTP %d, %w", host.address, status, err)
				}
				counts[body]++
			}
			transport.CloseIdleConnections()
			if counts[first.address] != 6 || counts[second.address] != 6 {
				return fmt.Errorf("host %s balance: %v", host.address, counts)
			}
		}
		plain := &http.Client{Transport: &http.Transport{Proxy: nil}}
		checkReady := func(host *fleetHost, want int) error {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(host.address, "80")+"/edge/ready", nil)
			if err != nil {
				return err
			}
			response, err := plain.Do(request)
			if err != nil {
				return err
			}
			response.Body.Close()
			if response.StatusCode != want {
				return fmt.Errorf("host %s edge readiness: got %d, want %d", host.address, response.StatusCode, want)
			}
			return nil
		}
		first.ready.Store(false)
		first.routes(false)
		if err := checkReady(first, http.StatusOK); err != nil {
			return err
		}
		first.edge.Drain()
		if err := checkReady(first, http.StatusServiceUnavailable); err != nil {
			return err
		}
		if len(first.edge.ReadyServices()) != 0 {
			return errors.New("draining edge advertises ready services")
		}
		first.stop()
		if err := checkReady(second, http.StatusOK); err != nil {
			return err
		}
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DisableKeepAlives: true}
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(second.address, "443"))
		}
		client := &http.Client{Transport: transport}
		for range 6 {
			status, body, err := fleetGet(ctx, client, second.address, "/payload")
			if err != nil || status != http.StatusOK || body != second.address {
				return fmt.Errorf("surviving host response: %d %q, %w", status, body, err)
			}
		}
		second.ready.Store(false)
		second.routes(false)
		if err := checkReady(second, http.StatusServiceUnavailable); err != nil {
			return err
		}
		status, body, err := fleetGet(ctx, client, second.address, "/payload")
		if err != nil || status != http.StatusServiceUnavailable || body != "" {
			return fmt.Errorf("unready backend was not withdrawn: %d %q, %w", status, body, err)
		}
		transport.CloseIdleConnections()
		plain.CloseIdleConnections()
		second.stop()
		fmt.Printf("ok %s: each edge balances 6/6, withdraws unready services, forwards readiness, drains and survives peer stop\n", nodes[2*region].Region())
	}
	return nil
}
