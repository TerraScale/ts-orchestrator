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
)

var fleetWeb = map[string]int{"dash.e2e.test": 18101, "auth.e2e.test": 18103}

var fleetServices = map[string]string{"dash.e2e.test": "ts-dashboard", "auth.e2e.test": "ts-auth"}

const fleetWriter = "api.e2e.test"

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
	var ready atomic.Bool
	ready.Store(true)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			if !ready.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			return
		}
		fmt.Fprint(w, name)
	})
	for _, port := range fleetWeb {
		listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			return err
		}
		go http.Serve(listener, app)
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
				conn.Write(postgresError("XX000", name))
			}()
		}
	}()
	state := filepath.Join(root, "state-"+name)
	if err := os.MkdirAll(filepath.Join(state, "edge-certs"), 0700); err != nil {
		return err
	}
	for _, host := range append(slices.Sorted(maps.Keys(fleetWeb)), fleetPostgres, fleetWriter) {
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
	entered := make(chan struct{}, 1)
	inner := public.local
	public.local = roundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Port() == strconv.Itoa(authPort) && r.URL.Path == "/payload" && handoff.Held(uint16(authPort)) {
			select {
			case entered <- struct{}{}:
			default:
			}
		}
		return inner.RoundTrip(r)
	})
	public.JoinMesh(node)
	web := maps.Clone(fleetWeb)
	web[fleetWriter] = 8080
	inventory := mesh.EdgeInventory{Web: web, Postgres: map[string]int{fleetPostgres: 15432}, Services: fleetServices, ProofRef: "fleet"}
	for host, port := range fleetWeb {
		inventory.Readiness = append(inventory.Readiness, mesh.EdgeRoute{Host: host, Port: port, Path: "/readyz"})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var source func() (mesh.EdgeInventory, bool)
	if role == "founder" {
		source = func() (mesh.EdgeInventory, bool) { return inventory, true }
		go func() {
			tick := time.NewTicker(time.Second)
			defer tick.Stop()
			for {
				if err := node.PublishEdgeInventory(state, inventory); err != nil {
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
		if ref != "fleet" {
			return errors.New("unexpected request proof reference")
		}
		return public.SetRequestProofSecret(secret)
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
		case "drain":
			public.Drain()
		case "await-peer":
			if err := fleetAwait(ctx, func() bool {
				return slices.ContainsFunc((*public.peerEdges.Load())(), func(peer mesh.WorkerPeer) bool { return len(peer.ReadyServices) == len(fleetWeb) })
			}); err != nil {
				return fmt.Errorf("%s never heard a ready peer: %w", name, err)
			}
		case "hold":
			handoff.Hold(uint16(authPort))
		case "release":
			select {
			case <-entered:
			case <-ctx.Done():
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
			fmt.Printf("ok %s: SQL writes from the worker edge on :8080 reach the writer; forged, tampered and replayed inventories are refused; the worker serves after losing its manager and after a cold restart with the manager down; without any inventory it answers 503 and stays release-healthy\n", founder.name[3:6])
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
			if status, _, err := client.get(ctx, founder, "dash.e2e.test"); err != nil || status == http.StatusOK {
				return fmt.Errorf("lost worker still answered through the manager: %d, %w", status, err)
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
			if err := founder.command(ctx, "unready"); err != nil {
				return err
			}
			if err := client.ready(ctx, founder, http.StatusServiceUnavailable); err != nil {
				return err
			}
			if err := client.serves(ctx, founder, worker); err != nil {
				return err
			}
			if err := signal(worker, syscall.SIGSTOP); err != nil {
				return err
			}
			began := time.Now()
			status, _, err := client.get(ctx, founder, "dash.e2e.test")
			if took := time.Since(began); err != nil || status == http.StatusOK || took > 5*time.Second {
				return fmt.Errorf("request to a stopped peer: HTTP %d after %s, %v", status, took, err)
			}
			if status, _, err := client.get(ctx, founder, "dash.e2e.test"); err != nil || status != http.StatusServiceUnavailable {
				return fmt.Errorf("a down peer was still a candidate: HTTP %d, %v", status, err)
			}
			if err := signal(worker, syscall.SIGCONT); err != nil {
				return err
			}
			if err := founder.command(ctx, "await-peer"); err != nil {
				return err
			}
			if err := client.serves(ctx, founder, worker); err != nil {
				return err
			}
			if err := signal(worker, syscall.SIGSTOP); err != nil {
				return err
			}
			if err := founder.command(ctx, "hold"); err != nil {
				return err
			}
			answered := make(chan error, 1)
			go func() {
				status, body, err := client.get(ctx, founder, "auth.e2e.test")
				if err == nil && (status != http.StatusOK || body != founder.name) {
					err = fmt.Errorf("held request answered HTTP %d %q", status, body)
				}
				answered <- err
			}()
			released := make(chan error, 1)
			go func() { released <- founder.command(ctx, "release") }()
			select {
			case err := <-answered:
				return fmt.Errorf("a held request was answered before its replacement: %v", err)
			case err := <-released:
				if err != nil {
					return err
				}
			}
			if err := <-answered; err != nil {
				return err
			}
			if err := signal(worker, syscall.SIGCONT); err != nil {
				return err
			}
			if err := founder.command(ctx, "await-peer"); err != nil {
				return err
			}
			if err := founder.command(ctx, "drain"); err != nil {
				return err
			}
			if err := client.ready(ctx, founder, http.StatusServiceUnavailable); err != nil {
				return err
			}
			if err := worker.command(ctx, "unready"); err != nil {
				return err
			}
			if err := client.ready(ctx, worker, http.StatusServiceUnavailable); err != nil {
				return err
			}
			status, body, err := client.get(ctx, worker, "dash.e2e.test")
			if err != nil || status != http.StatusServiceUnavailable || body != "" {
				return fmt.Errorf("no ready backend still answered: %d %q, %w", status, body, err)
			}
			fmt.Printf("ok %s: an unready manager is not ready itself but forwards to its peer; a stopped peer fails fast and is skipped until it re-advertises; a held stop-first port falls back from the stalled peer and waits for its replacement; drain and no ready backend answer 503\n", founder.name[3:6])
		}
	}
	return nil
}
