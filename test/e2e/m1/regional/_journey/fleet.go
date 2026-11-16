package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/nodelist"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

var fleetWeb = map[string]int{"dash.e2e.test": 18101, "auth.e2e.test": 18103}

var fleetServices = map[string]string{"dash.e2e.test": "ts-dashboard", "auth.e2e.test": "ts-auth"}

const fleetWriter = "api.e2e.test"

const fleetNetBirdPort = 18104

const fleetSpoofHeader = "X-TerraScale-Edge-Unavailable"

const fleetPostgres = "pg.e2e.test"

func fleetAwait(ctx context.Context, ready func() bool) error {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for !ready() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
	return nil
}

func FleetHost(args []string) error {
	root, region, name, address, peer, role, seedHex, secret := args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]
	commands := bufio.NewScanner(os.Stdin)
	if !commands.Scan() || commands.Text() != "go" {
		return errors.New("host network was not configured")
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return err
	}
	node, err := mesh.FleetHostNode(root, region, name, address, peer, seed)
	if err != nil {
		return err
	}
	var ready, slow, hang atomic.Bool
	var inflight atomic.Int64
	var failing atomic.Pointer[chan struct{}]
	var deletes atomic.Int64
	ready.Store(true)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		held := failing.Load()
		switch {
		case r.URL.Path == "/payload" && held != nil:
			inflight.Add(1)
			defer inflight.Add(-1)
			select {
			case <-*held:
			case <-r.Context().Done():
				return
			}
			http.Error(w, "backend unavailable", http.StatusServiceUnavailable)
		case r.URL.Path == "/client503":
			http.Error(w, "request-specific failure", http.StatusServiceUnavailable)
		case r.URL.Path == "/payload" && hang.Load():
			inflight.Add(1)
			defer inflight.Add(-1)
			<-r.Context().Done()
		case r.Method == http.MethodDelete:
			if marker := r.Header.Get(fleetSpoofHeader); marker != "" {
				w.Header().Set(fleetSpoofHeader, marker)
			}
			fmt.Fprintf(w, "%s %d", name, deletes.Add(1))
		case r.URL.Path == "/readyz" && slow.Load():
			<-r.Context().Done()
		case r.URL.Path == "/readyz":
			if !ready.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		case r.URL.Path == "/journey.Service/LongUnary":
			inflight.Add(1)
			defer inflight.Add(-1)
			timer := time.NewTimer(31 * time.Second)
			defer timer.Stop()
			select {
			case <-r.Context().Done():
				return
			case <-timer.C:
			}
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "Grpc-Status")
			w.Header().Set("X-Journey-Host", name)
			w.Write([]byte{0, 0, 0, 0, 0})
			w.Header().Set("Grpc-Status", "0")
		case r.URL.Path == "/half-close" && r.Header.Get("Upgrade") == "tcp":
			conn, buffered, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			fmt.Fprint(buffered, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: tcp\r\nConnection: Upgrade\r\n\r\n")
			if buffered.Flush() != nil {
				return
			}
			data, err := io.ReadAll(buffered)
			if err == nil {
				fmt.Fprintf(conn, "%s received %s", name, data)
			}
		case r.URL.Path == "/ws" && r.Header.Get("Upgrade") == "websocket":
			conn, buffered, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			fmt.Fprint(buffered, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			if buffered.Flush() != nil {
				return
			}
			for {
				line, err := buffered.ReadString('\n')
				if err != nil {
					return
				}
				fmt.Fprintf(buffered, "%s %s", name, line)
				if buffered.Flush() != nil {
					return
				}
			}
		default:
			fmt.Fprint(w, name)
		}
	})
	servers := map[int]*http.Server{}
	serve := func(port int) error {
		listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			return err
		}
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		servers[port] = &http.Server{Handler: app, Protocols: protocols}
		go servers[port].Serve(listener)
		return nil
	}
	for _, port := range append(slices.Collect(maps.Values(fleetWeb)), fleetNetBirdPort) {
		if err := serve(port); err != nil {
			return err
		}
	}
	writer := "ts-" + region + "-1"
	var writes atomic.Int64
	internal, err := net.Listen("tcp", net.JoinHostPort(address, strconv.Itoa(TerraBaseInternalPort)))
	if err != nil {
		return err
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	terrabase := &http.Server{Protocols: protocols, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(peerCredentialHeader) != secret {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/v1/rollout/status":
			fmt.Fprintf(w, `{"node":%q,"owner":%q,"epoch":1,"writer":%t,"ready":true}`, name, writer, name == writer)
		case "/v1/sql":
			if name != writer || r.Method != http.MethodPost {
				w.WriteHeader(http.StatusConflict)
				return
			}
			fmt.Fprintf(w, "%s %d", name, writes.Add(1))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	go terrabase.Serve(internal)
	database, err := net.Listen("tcp", "127.0.0.1:15432")
	if err != nil {
		return err
	}
	go func() {
		for {
			conn, err := database.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, err := conn.Read(make([]byte, 4096)); err != nil {
					return
				}
				if _, err := conn.Write(postgresError("XX000", name)); err != nil {
					return
				}
				conn.(*net.TCPConn).CloseWrite()
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	state := filepath.Join(root, "state-"+name)
	if err := os.MkdirAll(filepath.Join(state, "edge-certs"), 0700); err != nil {
		return err
	}
	for _, host := range append(slices.Sorted(maps.Keys(fleetWeb)), fleetPostgres, fleetWriter, netbirdHost) {
		cert, err := os.ReadFile(filepath.Join(root, "regional", "edge-certs", host))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(state, "edge-certs", host), cert, 0600); err != nil {
			return err
		}
	}
	public := New(state)
	if role != "founder" {
		public.SetInventoryFollower()
	}
	authPort := fleetWeb["auth.e2e.test"]
	dashPort := fleetWeb["dash.e2e.test"]
	entered, restarting := make(chan struct{}, 1), make(chan struct{}, 1)
	var restartArmed atomic.Bool
	inner := public.local
	public.local = roundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Port() == strconv.Itoa(dashPort) && r.URL.Path == "/payload" && restartArmed.CompareAndSwap(true, false) {
			restarting <- struct{}{}
		}
		if r.URL.Port() == strconv.Itoa(authPort) && r.URL.Path == "/payload" && handoff.Held(uint16(authPort)) {
			select {
			case entered <- struct{}{}:
			default:
			}
		}
		return inner.RoundTrip(r)
	})
	public.proxy.Transport = public.local
	public.JoinMesh(node)
	web := maps.Clone(fleetWeb)
	web[fleetWriter] = 8080
	web[netbirdHost] = fleetNetBirdPort
	services := maps.Clone(fleetServices)
	services[netbirdHost] = "netbird-server"
	inventory := mesh.EdgeInventory{Web: web, Postgres: map[string]int{fleetPostgres: 15432}, Services: services, ProofRef: "fleet"}
	var published atomic.Pointer[mesh.EdgeInventory]
	for host, port := range fleetWeb {
		inventory.Readiness = append(inventory.Readiness, mesh.EdgeRoute{Host: host, Port: port, Path: "/readyz"})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var source func() (mesh.EdgeInventory, bool)
	if role == "founder" {
		published.Store(&inventory)
		source = func() (mesh.EdgeInventory, bool) { return *published.Load(), true }
		go func() {
			tick := time.NewTicker(time.Second)
			defer tick.Stop()
			for {
				if err := node.PublishEdgeInventory(state, *published.Load()); err != nil {
					fmt.Fprintln(os.Stderr, "fleet inventory publication:", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
				}
			}
		}()
	} else {
		source = node.FollowEdgeInventory(state)
	}
	go public.Run(ctx)
	go public.FollowInventory(ctx, source, func(_ context.Context, ref string) error {
		switch ref {
		case "":
			return public.SetRequestProofSecret("")
		case "fleet":
			return public.SetRequestProofSecret(secret)
		}
		return errors.New("unexpected request proof reference")
	})
	started, stop := context.WithTimeout(ctx, time.Minute)
	defer stop()
	err = fleetAwait(started, func() bool {
		peers := public.peerEdges.Load()
		if role == "orphan" {
			return public.listeners.Load() == 15
		}
		return public.Readiness(started).Ready && len(public.ReadyServices()) == len(fleetWeb) && (role == "alone" || peers != nil &&
			slices.ContainsFunc((*peers)(), func(peer mesh.WorkerPeer) bool { return len(peer.ReadyServices) == len(fleetWeb) }))
	})
	if err != nil {
		return fmt.Errorf("%s never served as %s: %w (%+v)", name, role, err, public.Readiness(ctx))
	}
	first, _ := os.ReadFile(filepath.Join(state, "edge-inventory.json"))
	firstGeneration := mesh.FleetEdgeInventoryGeneration(node)
	fmt.Println("ready")
	for commands.Scan() {
		switch commands.Text() {
		case "unready":
			ready.Store(false)
			if err := fleetAwait(ctx, func() bool { return len(public.ReadyServices()) == 0 }); err != nil {
				return fmt.Errorf("%s kept advertising unready services: %w", name, err)
			}
		case "ready":
			ready.Store(true)
			if err := fleetAwait(ctx, func() bool { return len(public.ReadyServices()) == len(fleetWeb) }); err != nil {
				return fmt.Errorf("%s never advertised its ready services: %w", name, err)
			}
		case "drain":
			public.Drain()
		case "await-peer":
			if err := fleetAwait(ctx, func() bool {
				return slices.ContainsFunc((*public.peerEdges.Load())(), func(peer mesh.WorkerPeer) bool {
					_, down := public.peerDown.Load(peer.Address)
					return !down && len(peer.ReadyServices) == len(fleetWeb)
				})
			}); err != nil {
				return fmt.Errorf("%s never heard a ready peer: %w", name, err)
			}
		case "await-no-peer":
			if err := fleetAwait(ctx, func() bool {
				return !slices.ContainsFunc((*public.peerEdges.Load())(), func(peer mesh.WorkerPeer) bool { return len(peer.ReadyServices) != 0 })
			}); err != nil {
				return fmt.Errorf("%s still hears a ready peer: %w", name, err)
			}
		case "hang":
			hang.Store(true)
		case "unhang":
			hang.Store(false)
		case "deletes":
			fmt.Println("deletes", deletes.Load())
		case "drop-proof":
			if err := public.SetRequestProofSecret(""); err != nil {
				return err
			}
		case "restore-proof":
			if err := public.SetRequestProofSecret(secret); err != nil {
				return err
			}
		case "restart-dash":
			servers[dashPort].Close()
			restartArmed.Store(true)
			go func() {
				<-restarting
				time.AfterFunc(300*time.Millisecond, func() { serve(dashPort) })
			}()
		case "slow":
			slow.Store(true)
		case "stop-app":
			servers[fleetWeb["dash.e2e.test"]].Close()
		case "await-inflight":
			if err := fleetAwait(ctx, func() bool { return inflight.Load() >= 3 }); err != nil {
				return fmt.Errorf("%s never held the journey's three in-flight requests: %w", name, err)
			}
		case "await-one-inflight":
			if err := fleetAwait(ctx, func() bool { return inflight.Load() >= 1 }); err != nil {
				return fmt.Errorf("%s never held the in-flight request: %w", name, err)
			}
		case "peer-down":
			down := 0
			public.peerDown.Range(func(any, any) bool { down++; return true })
			fmt.Println("peer-down", down)
		case "fail-hold":
			release := make(chan struct{})
			failing.Store(&release)
		case "fail-release":
			close(*failing.Load())
		case "fail-clear":
			failing.Store(nil)
		case "await-app-unready":
			if err := fleetAwait(ctx, func() bool { return !slices.Contains(public.ReadyServices(), fleetServices["dash.e2e.test"]) }); err != nil {
				return fmt.Errorf("%s kept advertising its stopped application: %w", name, err)
			}
		case "start-app":
			if err := serve(dashPort); err != nil {
				return err
			}
		case "mute":
			mesh.FleetMuteAnnouncements(true)
		case "unmute":
			mesh.FleetMuteAnnouncements(false)
		case "malformed-proof":
			current := *published.Load()
			malformed := []*api.Service{{Spec: api.ServiceSpec{Annotations: api.Annotations{Labels: map[string]string{
				swarmruntime.LabelServiceSpec: "terrabase", swarmruntime.LabelSecretRefs: "{"}}}}}
			ref, err := RequestProofRef(malformed, current.ProofRef)
			if err == nil || ref != current.ProofRef {
				return fmt.Errorf("a malformed TerraBase secret-refs label gave proof reference %q (%v), want the last good %q kept with an error", ref, err, current.ProofRef)
			}
			current.ProofRef = ref
			published.Store(&current)
		case "hold":
			handoff.Hold(uint16(authPort))
			servers[authPort].Close()
		case "release":
			select {
			case <-entered:
			case <-ctx.Done():
			}
			if err := serve(authPort); err != nil {
				return err
			}
			ready.Store(true)
			handoff.Release(uint16(authPort))
		case "health":
			if err := public.Readiness(ctx).InfraErr(); err != nil {
				fmt.Println("health", err)
			} else {
				fmt.Println("health ok")
			}
		case "refresh":
			mesh.FleetRefreshEdgeInventory(node)
		case "forge":
			if err := fleetAwait(ctx, func() bool { return mesh.FleetEdgeInventoryGeneration(node) > firstGeneration }); err != nil {
				return fmt.Errorf("%s never followed a newer manager inventory: %w", name, err)
			}
			if err := mesh.FleetForgeEdgeInventory(node, state, first); err != nil {
				return err
			}
		}
		fmt.Println("ok")
	}
	return nil
}

type fleetProcess struct {
	name, address, veth string
	cmd                 *exec.Cmd
	stdin               io.WriteCloser
	lines               chan string
}

func (p *fleetProcess) expect(ctx context.Context, want string) error {
	select {
	case line, ok := <-p.lines:
		if !ok || line != want {
			return fmt.Errorf("%s answered %q, want %q", p.name, line, want)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%s did not answer %q: %w", p.name, want, ctx.Err())
	}
}

func (p *fleetProcess) query(ctx context.Context, command, want string) error {
	if _, err := fmt.Fprintln(p.stdin, command); err != nil {
		return err
	}
	if err := p.expect(ctx, want); err != nil {
		return err
	}
	return p.expect(ctx, "ok")
}

func (p *fleetProcess) command(ctx context.Context, command string) error {
	if _, err := fmt.Fprintln(p.stdin, command); err != nil {
		return err
	}
	return p.expect(ctx, "ok")
}

func (p *fleetProcess) kill() {
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
	_ = exec.Command("ip", "link", "del", p.veth).Run()
}

func fleetRun(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}
	return nil
}

func fleetHostName(index int, region string) string {
	return fmt.Sprintf("ts-%s-%d", region, index%2+1)
}

func startFleetHost(root, self string, index int, region, role, seed, secret string, start int) (*fleetProcess, error) {
	p := &fleetProcess{name: fleetHostName(index, region), address: fmt.Sprintf("10.77.0.%d", 10+index), lines: make(chan string, 4)}
	log, err := os.OpenFile(filepath.Join(root, p.name+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	peer := fmt.Sprintf("10.77.0.%d", 11+index)
	if index%2 == 1 {
		peer = fmt.Sprintf("10.77.0.%d", 9+index)
	}
	p.cmd = exec.Command(self, "host", root, region, p.name, p.address, peer, role, seed, secret)
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	p.cmd.Stderr = log
	if p.stdin, err = p.cmd.StdinPipe(); err != nil {
		return nil, err
	}
	stdout, err := p.cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := p.cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		defer close(p.lines)
		lines := bufio.NewScanner(stdout)
		for lines.Scan() {
			p.lines <- lines.Text()
		}
	}()
	pid := strconv.Itoa(p.cmd.Process.Pid)
	veth := fmt.Sprintf("fv%d-%d", index, start)
	p.veth = veth
	for _, step := range [][]string{
		{"ip", "link", "add", veth, "type", "veth", "peer", "name", "eth0", "netns", pid},
		{"ip", "link", "set", veth, "master", "fleet0", "up"},
		{"nsenter", "-t", pid, "-n", "ip", "link", "set", "lo", "up"},
		{"nsenter", "-t", pid, "-n", "ip", "link", "set", "eth0", "up"},
		{"nsenter", "-t", pid, "-n", "ip", "addr", "add", p.address + "/24", "dev", "eth0"},
	} {
		if err := fleetRun(step[0], step[1:]...); err != nil {
			p.kill()
			return nil, err
		}
	}
	if _, err := fmt.Fprintln(p.stdin, "go"); err != nil {
		p.kill()
		return nil, err
	}
	return p, nil
}

func (p *fleetProcess) awaitReady(ctx context.Context, root string) error {
	if err := p.expect(ctx, "ready"); err != nil {
		log, _ := os.ReadFile(filepath.Join(root, p.name+".log"))
		return fmt.Errorf("%w: %s", err, log[max(0, len(log)-2000):])
	}
	return nil
}

func fleetNodeList(root string, regions []string) error {
	list := nodelist.List{Sequence: 1}
	for index, region := range regions {
		name := fleetHostName(index, region)
		keys, err := nodelist.Keys(filepath.Join(root, "state-"+name))
		if err != nil {
			return err
		}
		meshIP, err := nodelist.MeshIP(name, region)
		if err != nil {
			return err
		}
		list.Nodes = append(list.Nodes, nodelist.Node{Name: name, Region: region, PublicIP: fmt.Sprintf("198.51.100.%d", 10+index),
			PrivateIP: fmt.Sprintf("10.77.0.%d", 10+index), MeshIP: meshIP, WGPublicKey: keys.WGPublicKey, TLSSPKISHA256: keys.TLSSPKISHA256})
	}
	if err := list.Validate(); err != nil {
		return err
	}
	wire, err := protocol.EncodeJSON(list)
	if err != nil {
		return err
	}
	for index, region := range regions {
		if err := os.WriteFile(filepath.Join(root, "state-"+fleetHostName(index, region), "node", "nodes.json"), wire, 0o600); err != nil {
			return err
		}
	}
	return nil
}

type fleetClient struct {
	roots *x509.CertPool
	plain *http.Client
}

func (c fleetClient) get(ctx context.Context, host *fleetProcess, name string) (int, string, error) {
	return c.do(ctx, host, http.MethodGet, "https://"+name+"/payload", nil)
}

func (c fleetClient) write(ctx context.Context, through, writer *fleetProcess, want int) error {
	for range 2 {
		status, body, err := c.do(ctx, through, http.MethodPost, "https://"+fleetWriter+"/v1/sql", strings.NewReader("insert into fleet values (1)"))
		if err != nil || status != http.StatusOK || body != fmt.Sprintf("%s %d", writer.name, want) {
			return fmt.Errorf("SQL write via %s on :8080: HTTP %d %q, want %s %d, %w", through.name, status, body, writer.name, want, err)
		}
		want++
	}
	return nil
}

func (c fleetClient) hop(ctx context.Context, host *fleetProcess, name, secret string) (int, http.Header, string, error) {
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: c.roots}, DisableKeepAlives: true}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(host.address, "443"))
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+name+"/payload", nil)
	if err != nil {
		return 0, nil, "", err
	}
	request.Header.Set(edgeHopHeader, "1")
	request.Header.Set(peerCredentialHeader, secret)
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return 0, nil, "", err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	return response.StatusCode, response.Header, string(data), err
}

func (c fleetClient) websocket(ctx context.Context, through *fleetProcess, name string) (string, error) {
	conn, err := (&tls.Dialer{Config: &tls.Config{RootCAs: c.roots, ServerName: name, NextProtos: []string{"http/1.1"}}}).DialContext(ctx, "tcp", net.JoinHostPort(through.address, "443"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", name)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		return "", fmt.Errorf("WebSocket via %s answered %s", through.name, response.Status)
	}
	if _, err := fmt.Fprint(conn, "ping\n"); err != nil {
		return "", err
	}
	line, err := reader.ReadString('\n')
	return strings.TrimSpace(line), err
}

func (c fleetClient) halfClose(ctx context.Context, through *fleetProcess) (string, error) {
	conn, err := (&tls.Dialer{Config: &tls.Config{RootCAs: c.roots, ServerName: "dash.e2e.test", NextProtos: []string{"http/1.1"}}}).DialContext(ctx, "tcp", net.JoinHostPort(through.address, "443"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	fmt.Fprint(conn, "GET /half-close HTTP/1.1\r\nHost: dash.e2e.test\r\nUpgrade: tcp\r\nConnection: Upgrade\r\n\r\n")
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		return "", fmt.Errorf("upgrade via %s answered %s", through.name, response.Status)
	}
	if _, err := fmt.Fprint(conn, "upload"); err != nil {
		return "", err
	}
	if err := conn.(*tls.Conn).CloseWrite(); err != nil {
		return "", err
	}
	data, err := io.ReadAll(reader)
	return string(data), err
}

func (c fleetClient) longGRPC(ctx context.Context, through, backend *fleetProcess) error {
	transport := &http.Transport{ForceAttemptHTTP2: true, Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: c.roots}}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(through.address, "443"))
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://dash.e2e.test/journey.Service/LongUnary", bytes.NewReader([]byte{0, 0, 0, 0, 0}))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/grpc")
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || response.ProtoMajor != 2 || response.StatusCode != http.StatusOK || !bytes.Equal(data, []byte{0, 0, 0, 0, 0}) || response.Trailer.Get("Grpc-Status") != "0" || response.Header.Get("X-Journey-Host") != backend.name {
		return fmt.Errorf("31-second gRPC via %s: %s HTTP %d body %x trailer %q host %q, %v; want the same successful call as main from %s", through.name, response.Proto, response.StatusCode, data, response.Trailer.Get("Grpc-Status"), response.Header.Get("X-Journey-Host"), err, backend.name)
	}
	return nil
}

func (c fleetClient) stoppedPeer(ctx context.Context, founder, worker *fleetProcess, signal func(*fleetProcess, syscall.Signal) error) error {
	if err := worker.command(ctx, "hang"); err != nil {
		return err
	}
	deleted := make(chan error, 1)
	go func() {
		began := time.Now()
		status, _, err := c.do(ctx, founder, http.MethodDelete, "https://dash.e2e.test/payload", nil)
		if took := time.Since(began); err != nil || status != http.StatusBadGateway || took > peerLayerBudget+time.Second {
			err = fmt.Errorf("a DELETE sent to a peer that never answers: HTTP %d after %s, %v, want main's 502 within %s and no resend", status, took, err, peerLayerBudget)
		}
		deleted <- err
	}()
	if err := worker.command(ctx, "await-one-inflight"); err != nil {
		return err
	}
	refuse := func(action string) error {
		return fleetRun("nsenter", "-t", strconv.Itoa(worker.cmd.Process.Pid), "-n", "iptables", action, "INPUT", "-p", "tcp", "--dport", "443",
			"-m", "conntrack", "--ctstate", "NEW", "-j", "REJECT", "--reject-with", "tcp-reset")
	}
	if err := errors.Join(refuse("-I"), worker.command(ctx, "mute")); err != nil {
		return err
	}
	if status, body, err := c.get(ctx, founder, "dash.e2e.test"); err != nil || status != http.StatusOK || body != founder.name {
		return fmt.Errorf("a request whose peer edge refused the connection did not fall back to main's local path: HTTP %d %q, %v", status, body, err)
	}
	if err := founder.query(ctx, "peer-down", "peer-down 1"); err != nil {
		return fmt.Errorf("a peer edge that refused the connection was not excluded: %w", err)
	}
	if err := errors.Join(refuse("-D"), worker.command(ctx, "unmute"), founder.command(ctx, "await-peer")); err != nil {
		return fmt.Errorf("a refused peer did not count again after its next fresh advertisement: %w", err)
	}
	if err := <-deleted; err != nil {
		return err
	}
	if err := founder.query(ctx, "deletes", "deletes 0"); err != nil {
		return fmt.Errorf("a DELETE that failed on the peer was resent locally: %w", err)
	}
	if err := worker.command(ctx, "unhang"); err != nil {
		return err
	}
	if status, body, err := c.get(ctx, founder, "auth.e2e.test"); err != nil || status != http.StatusOK || body != worker.name {
		return fmt.Errorf("a request that outlived the peer header budget excluded a healthy peer: HTTP %d %q, %v, want %s", status, body, err, worker.name)
	}
	if err := signal(worker, syscall.SIGSTOP); err != nil {
		return err
	}
	if err := founder.command(ctx, "await-no-peer"); err != nil {
		return err
	}
	if status, body, err := c.get(ctx, founder, "dash.e2e.test"); err != nil || status != http.StatusOK || body != founder.name {
		return fmt.Errorf("with its peer stopped the manager did not take main's local path: HTTP %d %q, %v", status, body, err)
	}
	if err := founder.command(ctx, "hold"); err != nil {
		return err
	}
	answered := make(chan error, 1)
	go func() {
		status, body, err := c.get(ctx, founder, "auth.e2e.test")
		if err == nil && (status != http.StatusOK || body != founder.name) {
			err = fmt.Errorf("held request answered HTTP %d %q", status, body)
		}
		answered <- err
	}()
	released := make(chan error, 1)
	go func() { released <- founder.command(ctx, "release") }()
	if err := errors.Join(<-answered, <-released); err != nil {
		return err
	}
	return signal(worker, syscall.SIGCONT)
}

func (c fleetClient) readyWithin(ctx context.Context, host *fleetProcess, want int, within time.Duration) error {
	deadline := time.Now().Add(within)
	for {
		err := c.ready(ctx, host, want)
		if err == nil || time.Now().After(deadline) {
			return err
		}
	}
}

func (c fleetClient) unservedVia(ctx context.Context, worker, peer *fleetProcess) error {
	if err := worker.query(ctx, "health", "health edge not ready: backend unavailable"); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if status, body, err := c.do(bounded, worker, http.MethodDelete, "https://dash.e2e.test/payload", nil); err == nil && status == http.StatusOK {
		return fmt.Errorf("a new DELETE through %s was answered %q after its peer stopped counting", worker.name, body)
	}
	if err := peer.query(ctx, "deletes", "deletes 0"); err != nil {
		return fmt.Errorf("a new request reached %s after it stopped counting as a peer: %w", peer.name, err)
	}
	return nil
}

func (c fleetClient) stalePeer(ctx context.Context, founder, worker *fleetProcess) error {
	prepared := make(chan error, 1)
	go func() { prepared <- founder.command(ctx, "ready") }()
	if err := errors.Join(worker.command(ctx, "stop-app"), worker.command(ctx, "await-app-unready"), <-prepared); err != nil {
		return err
	}
	if err := c.ready(ctx, worker, http.StatusOK); err != nil {
		return fmt.Errorf("a worker whose application is down but whose manager is a fresh ready peer: %w", err)
	}
	if status, body, err := c.get(ctx, worker, "dash.e2e.test"); err != nil || status != http.StatusOK || body != founder.name {
		return fmt.Errorf("a worker with a fresh ready peer did not forward to it: HTTP %d %q, %v", status, body, err)
	}
	if err := founder.command(ctx, "mute"); err != nil {
		return err
	}
	if err := c.readyWithin(ctx, worker, http.StatusServiceUnavailable, 3*mesh.FleetAdvertiseEvery); err != nil {
		return fmt.Errorf("a silent peer still counted for readiness %s after it stopped advertising: %w", 3*mesh.FleetAdvertiseEvery, err)
	}
	if err := c.unservedVia(ctx, worker, founder); err != nil {
		return err
	}
	if err := founder.command(ctx, "unmute"); err != nil {
		return err
	}
	if err := c.readyWithin(ctx, worker, http.StatusOK, 3*mesh.FleetAdvertiseEvery); err != nil {
		return fmt.Errorf("a peer advertising again did not count within %s: %w", 3*mesh.FleetAdvertiseEvery, err)
	}
	if status, body, err := c.do(ctx, worker, http.MethodGet, "https://dash.e2e.test/client503", nil); err != nil || status != http.StatusServiceUnavailable || body != "request-specific failure\n" {
		return fmt.Errorf("a request-specific 503 through a healthy peer: HTTP %d %q, %v", status, body, err)
	}
	if err := c.ready(ctx, worker, http.StatusOK); err != nil {
		return fmt.Errorf("a request-specific 503 through a healthy, advertising peer changed the worker's readiness: %w", err)
	}
	if err := worker.query(ctx, "health", "health ok"); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	status, body, err := c.get(bounded, worker, "dash.e2e.test")
	cancel()
	if err != nil || status != http.StatusOK || body != founder.name {
		return fmt.Errorf("the next request after a request-specific 503 did not reach the same healthy peer: HTTP %d %q, %v", status, body, err)
	}
	if err := founder.command(ctx, "fail-hold"); err != nil {
		return err
	}
	failed := make(chan error, 1)
	go func() {
		status, body, err := c.get(ctx, worker, "dash.e2e.test")
		if err == nil && (status != http.StatusServiceUnavailable || body != "backend unavailable\n") {
			err = fmt.Errorf("a request through a failing peer: HTTP %d %q, want its 503", status, body)
		}
		failed <- err
	}()
	if err := founder.command(ctx, "await-one-inflight"); err != nil {
		return err
	}
	if err := errors.Join(founder.command(ctx, "mute"), founder.command(ctx, "fail-release"), <-failed); err != nil {
		return err
	}
	if err := c.readyWithin(ctx, worker, http.StatusServiceUnavailable, 3*mesh.FleetAdvertiseEvery); err != nil {
		return fmt.Errorf("a silent peer whose backend fails still counted past the freshness bound of %s: %w", 3*mesh.FleetAdvertiseEvery, err)
	}
	if err := worker.query(ctx, "health", "health edge not ready: backend unavailable"); err != nil {
		return err
	}
	if err := errors.Join(founder.command(ctx, "fail-clear"), founder.command(ctx, "unmute")); err != nil {
		return err
	}
	if err := c.readyWithin(ctx, worker, http.StatusOK, 3*mesh.FleetAdvertiseEvery); err != nil {
		return fmt.Errorf("a fresh ready advertisement did not restore the peer within %s: %w", 3*mesh.FleetAdvertiseEvery, err)
	}
	if err := founder.command(ctx, "unready"); err != nil {
		return err
	}
	if err := c.readyWithin(ctx, worker, http.StatusServiceUnavailable, mesh.FleetAdvertiseEvery); err != nil {
		return fmt.Errorf("a peer that became unready still counted %s later: %w", mesh.FleetAdvertiseEvery, err)
	}
	if err := c.unservedVia(ctx, worker, founder); err != nil {
		return err
	}
	if err := errors.Join(worker.command(ctx, "start-app"), worker.command(ctx, "ready")); err != nil {
		return err
	}
	return founder.command(ctx, "await-peer")
}

func (c fleetClient) sameAsMainStreams(ctx context.Context, ingress, backend *fleetProcess, inFlight func() error) error {
	results := make(chan error, 2)
	for _, through := range []*fleetProcess{backend, ingress} {
		go func() { results <- c.longGRPC(ctx, through, backend) }()
	}
	var failures []error
	for _, through := range []*fleetProcess{backend, ingress} {
		if reply, err := c.halfClose(ctx, through); err != nil || reply != backend.name+" received upload" {
			failures = append(failures, fmt.Errorf("client half-close via %s: %q, %v; want the same backend reply after EOF as main", through.name, reply, err))
		}
	}
	if err := inFlight(); err != nil {
		failures = append(failures, err)
	}
	for range 2 {
		if err := <-results; err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (c fleetClient) request(ctx context.Context, host *fleetProcess, method, url string, header http.Header) (int, string, error) {
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: c.roots}, DisableKeepAlives: true}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(host.address, "443"))
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, "", err
	}
	request.Header = header
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	return response.StatusCode, string(data), err
}

func (c fleetClient) do(ctx context.Context, host *fleetProcess, method, url string, body io.Reader) (int, string, error) {
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: c.roots}, DisableKeepAlives: true}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(host.address, "443"))
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return 0, "", err
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	return response.StatusCode, string(data), err
}

func (c fleetClient) ready(ctx context.Context, host *fleetProcess, want int) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(host.address, "80")+"/edge/ready", nil)
	if err != nil {
		return err
	}
	response, err := c.plain.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode != want || len(body) != 0 {
		return fmt.Errorf("%s public /edge/ready: got %d with %q, want %d and no body", host.name, response.StatusCode, body, want)
	}
	return nil
}

func (c fleetClient) postgres(ctx context.Context, host *fleetProcess) (string, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host.address, "5432"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 8), sslRequest)); err != nil {
		return "", err
	}
	answer := make([]byte, 1)
	if _, err := io.ReadFull(conn, answer); err != nil || answer[0] != 'S' {
		return "", fmt.Errorf("%s refused TLS: %q %w", host.name, answer, err)
	}
	client := tls.Client(conn, &tls.Config{ServerName: fleetPostgres, RootCAs: c.roots})
	startup := append(binary.BigEndian.AppendUint32(nil, 196608), "user\x00fleet\x00\x00"...)
	if _, err := client.Write(append(binary.BigEndian.AppendUint32(nil, uint32(4+len(startup))), startup...)); err != nil {
		return "", err
	}
	head := make([]byte, 5)
	if _, err := io.ReadFull(client, head); err != nil || head[0] != 'E' {
		return "", fmt.Errorf("%s postgres reply %q: %w", host.name, head, err)
	}
	body := make([]byte, binary.BigEndian.Uint32(head[1:])-4)
	if _, err := io.ReadFull(client, body); err != nil {
		return "", err
	}
	for field := range bytes.SplitSeq(body, []byte{0}) {
		if len(field) > 1 && field[0] == 'M' {
			return string(field[1:]), nil
		}
	}
	return "", fmt.Errorf("%s postgres reply has no message", host.name)
}

func (c fleetClient) serves(ctx context.Context, through *fleetProcess, want ...*fleetProcess) error {
	for _, name := range slices.Sorted(maps.Keys(fleetWeb)) {
		counts := map[string]int{}
		for range 6 * len(want) {
			status, body, err := c.get(ctx, through, name)
			if err != nil || status != http.StatusOK {
				return fmt.Errorf("%s via %s: HTTP %d %q, %w", name, through.name, status, body, err)
			}
			counts[body]++
		}
		for _, host := range want {
			if counts[host.name] != 6 {
				return fmt.Errorf("%s via %s spread %v, want 6 on each of %d hosts", name, through.name, counts, len(want))
			}
		}
	}
	answer, err := c.postgres(ctx, through)
	if err != nil || answer != through.name {
		return fmt.Errorf("postgres via %s answered %q, %w", through.name, answer, err)
	}
	return nil
}

func FleetEdgeJourney(root string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pem, err := os.ReadFile(filepath.Join(root, "ca.pem"))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("missing fleet root CA")
	}
	seed, secret := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	for _, step := range [][]string{{"link", "add", "fleet0", "type", "bridge"}, {"addr", "add", "10.77.0.1/24", "dev", "fleet0"}, {"link", "set", "fleet0", "up"}} {
		if err := fleetRun("ip", step...); err != nil {
			return err
		}
	}
	regions := []string{"gru", "gru", "sjc", "sjc", "fra", "fra"}
	if err := fleetNodeList(root, regions); err != nil {
		return err
	}
	hosts := []*fleetProcess{}
	defer func() {
		for _, host := range hosts {
			host.kill()
		}
	}()
	starts := 0
	start := func(index int, role string) error {
		starts++
		host, err := startFleetHost(root, self, index, regions[index], role, hex.EncodeToString(seed), hex.EncodeToString(secret), starts)
		if err != nil {
			return err
		}
		if index < len(hosts) {
			hosts[index] = host
		} else {
			hosts = append(hosts, host)
		}
		return nil
	}
	for index := range regions {
		role := "founder"
		if index%2 == 1 {
			role = "worker"
		}
		if err := start(index, role); err != nil {
			return err
		}
	}
	for _, host := range hosts {
		if err := host.awaitReady(ctx, root); err != nil {
			return err
		}
	}
	client := fleetClient{roots: roots, plain: &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}}
	signal := func(host *fleetProcess, sig syscall.Signal) error { return host.cmd.Process.Signal(sig) }
	for region := range 3 {
		founder, worker := hosts[2*region], hosts[2*region+1]
		for _, host := range []*fleetProcess{founder, worker} {
			if err := client.ready(ctx, host, http.StatusOK); err != nil {
				return err
			}
			if err := client.serves(ctx, host, host); err != nil {
				return err
			}
		}
		switch region {
		case 0:
			if err := client.write(ctx, worker, founder, 1); err != nil {
				return err
			}
			if err := founder.command(ctx, "malformed-proof"); err != nil {
				return err
			}
			if err := founder.command(ctx, "refresh"); err != nil {
				return err
			}
			if err := worker.command(ctx, "forge"); err != nil {
				return err
			}
			if err := client.serves(ctx, worker, worker); err != nil {
				return err
			}
			founder.kill()
			if err := client.ready(ctx, worker, http.StatusOK); err != nil {
				return err
			}
			if err := client.serves(ctx, worker, worker); err != nil {
				return err
			}
			worker.kill()
			if err := start(2*region+1, "alone"); err != nil {
				return err
			}
			worker = hosts[2*region+1]
			if err := worker.awaitReady(ctx, root); err != nil {
				return err
			}
			if err := client.ready(ctx, worker, http.StatusOK); err != nil {
				return err
			}
			if err := client.serves(ctx, worker, worker); err != nil {
				return err
			}
			worker.kill()
			if err := os.Remove(filepath.Join(root, "state-"+worker.name, "edge-inventory.json")); err != nil {
				return err
			}
			if err := start(2*region+1, "orphan"); err != nil {
				return err
			}
			worker = hosts[2*region+1]
			if err := worker.awaitReady(ctx, root); err != nil {
				return err
			}
			if err := client.ready(ctx, worker, http.StatusServiceUnavailable); err != nil {
				return err
			}
			if err := worker.query(ctx, "health", "health ok"); err != nil {
				return err
			}
			fmt.Printf("ok %s: SQL writes from the worker edge on :8080 reach the writer; a malformed proof label keeps the last good reference; forged, tampered and replayed inventories are refused; the worker serves after losing its manager and after a cold restart with the manager down; without any inventory it answers 503 and stays release-healthy\n", founder.name[3:6])
		case 1:
			if err := client.write(ctx, worker, founder, 1); err != nil {
				return err
			}
			if err := founder.command(ctx, "unready"); err != nil {
				return err
			}
			if err := founder.query(ctx, "health", "health edge not ready: backend not ready, backend not ready"); err != nil {
				return err
			}
			if err := client.serves(ctx, founder, worker); err != nil {
				return err
			}
			worker.kill()
			if status, body, err := client.get(ctx, founder, "dash.e2e.test"); err != nil || status != http.StatusOK || body != founder.name {
				return fmt.Errorf("an unready manager that lost its worker did not serve its running backend: %d %q, %v", status, body, err)
			}
			if err := client.write(ctx, founder, founder, 3); err != nil {
				return err
			}
			if err := start(2*region+1, "alone"); err != nil {
				return err
			}
			worker = hosts[2*region+1]
			if err := worker.awaitReady(ctx, root); err != nil {
				return err
			}
			if err := founder.command(ctx, "await-peer"); err != nil {
				return err
			}
			if err := client.serves(ctx, founder, worker); err != nil {
				return err
			}
			if err := client.write(ctx, worker, founder, 5); err != nil {
				return err
			}
			fmt.Printf("ok %s: an unready manager forwards to its worker and is release-unhealthy; after the worker is lost and cold-restarts it forwards again as soon as it re-advertises ready, and SQL writes from it reach the writer\n", founder.name[3:6])
		case 2:
			stopped := make(chan error, 1)
			go func() {
				if err := client.stalePeer(ctx, hosts[2], hosts[3]); err != nil {
					stopped <- err
					return
				}
				stopped <- client.stoppedPeer(ctx, hosts[2], hosts[3], signal)
			}()
			if err := founder.command(ctx, "unready"); err != nil {
				return err
			}
			if err := client.ready(ctx, founder, http.StatusServiceUnavailable); err != nil {
				return err
			}
			if err := client.serves(ctx, founder, worker); err != nil {
				return err
			}
			if echo, err := client.websocket(ctx, founder, "dash.e2e.test"); err != nil || echo != worker.name+" ping" {
				return fmt.Errorf("WebSocket through a peer edge: %q, %v", echo, err)
			}
			status, body, err := client.request(ctx, founder, http.MethodDelete, "https://dash.e2e.test/payload", http.Header{fleetSpoofHeader: {"1"}})
			if err != nil || status != http.StatusOK || body != worker.name+" 1" {
				return fmt.Errorf("a DELETE carrying a client marker through a peer: HTTP %d %q, %v", status, body, err)
			}
			if err := founder.query(ctx, "deletes", "deletes 0"); err != nil {
				return fmt.Errorf("a DELETE answered by the peer ran again locally: %w", err)
			}
			if err := founder.command(ctx, "await-peer"); err != nil {
				return err
			}
			if err := worker.command(ctx, "hang"); err != nil {
				return err
			}
			hung := make(chan error, 1)
			go func() {
				began := time.Now()
				status, _, err := client.get(ctx, founder, "dash.e2e.test")
				if took := time.Since(began); err != nil || status != http.StatusBadGateway || took > peerLayerBudget+time.Second {
					err = fmt.Errorf("a peer that never answers: HTTP %d after %s, %v, want main's 502 within %s", status, took, err, peerLayerBudget)
				}
				hung <- err
			}()
			streams := client.sameAsMainStreams(ctx, founder, worker, func() error {
				if err := worker.command(ctx, "await-inflight"); err != nil {
					return err
				}
				return worker.command(ctx, "mute")
			})
			if err := errors.Join(<-hung, streams); err != nil {
				return err
			}
			fmt.Println("ok fleet: same as main, local and peer HTTP/2 gRPC calls return their frame and success trailer after 31 seconds while the peer's announcements have stopped; client half-close preserves the complete backend reply")
			if err := worker.command(ctx, "unmute"); err != nil {
				return err
			}
			if err := founder.command(ctx, "await-peer"); err != nil {
				return err
			}
			if err := worker.command(ctx, "unhang"); err != nil {
				return err
			}
			if err := <-stopped; err != nil {
				return err
			}
			if err := worker.command(ctx, "unready"); err != nil {
				return err
			}
			if err := founder.command(ctx, "drain"); err != nil {
				return err
			}
			if err := founder.command(ctx, "await-no-peer"); err != nil {
				return err
			}
			if err := worker.command(ctx, "await-no-peer"); err != nil {
				return err
			}
			if err := client.ready(ctx, founder, http.StatusServiceUnavailable); err != nil {
				return err
			}
			if status, body, err := client.get(ctx, founder, "dash.e2e.test"); err != nil || status != http.StatusOK || body != founder.name {
				return fmt.Errorf("a draining host with no ready peer did not take main's local path: HTTP %d %q, %v", status, body, err)
			}
			if status, _, body, err := client.hop(ctx, founder, "dash.e2e.test", hex.EncodeToString(secret)); err != nil || status != http.StatusOK || body != founder.name {
				return fmt.Errorf("a peer hop to a draining host did not take main's local path: HTTP %d %q, %v", status, body, err)
			}
			if err := worker.command(ctx, "restart-dash"); err != nil {
				return err
			}
			if status, body, err := client.get(ctx, worker, "dash.e2e.test"); err != nil || status != http.StatusOK || body != worker.name {
				return fmt.Errorf("an unheld restarting backend did not get main's refused-dial wait: HTTP %d %q, %v", status, body, err)
			}
			if err := worker.command(ctx, "drop-proof"); err != nil {
				return err
			}
			if status, body, err := client.get(ctx, worker, "dash.e2e.test"); err != nil || status != http.StatusOK || body != worker.name {
				return fmt.Errorf("a host without a peer credential did not take main's local path: HTTP %d %q, %v", status, body, err)
			}
			if err := worker.command(ctx, "ready"); err != nil {
				return err
			}
			if err := worker.command(ctx, "stop-app"); err != nil {
				return err
			}
			if err := client.ready(ctx, worker, http.StatusServiceUnavailable); err != nil {
				return fmt.Errorf("a worker with no credential, no ready peer and no local backend: %w", err)
			}
			if err := worker.query(ctx, "health", "health edge not ready: backend unavailable"); err != nil {
				return err
			}
			if err := worker.command(ctx, "start-app"); err != nil {
				return err
			}
			if err := worker.command(ctx, "restore-proof"); err != nil {
				return err
			}
			if err := worker.command(ctx, "slow"); err != nil {
				return err
			}
			if status, body, err := client.get(ctx, worker, "dash.e2e.test"); err != nil || status != http.StatusOK || body != worker.name {
				return fmt.Errorf("a host whose readiness probe hangs did not take main's local path: HTTP %d %q, %v", status, body, err)
			}
			if status, body, err := client.do(ctx, founder, http.MethodGet, "https://"+netbirdHost+"/", nil); err != nil || status != http.StatusServiceUnavailable || !strings.Contains(body, "NetBird dashboard is preparing") {
				return fmt.Errorf("a draining host did not serve main's NetBird dashboard handler: HTTP %d %q, %v", status, body, err)
			}
			fmt.Printf("ok %s: with a ready peer an unready manager forwards HTTP and WebSockets, a client marker never causes a resend, a DELETE to a peer that never answers costs main's 502 and is not resent, a held port waits for its replacement and a peer that never answers costs main's 502 at %s; with no ready peer draining, hop, NetBird dashboard, hung readiness, missing credential and an unheld restart all take main's path, and a worker that can serve a route neither locally nor through a peer is not ready; in sjc a peer that falls silent or turns unready stops counting for a worker's readiness, health and new requests within its advertisement bound; a request-specific 503 or a request that outlives the header budget never excludes a healthy peer, while a peer edge that refuses connections is excluded until its next advertisement\n", founder.name[3:6], peerLayerBudget)
		}
	}
	return nil
}
