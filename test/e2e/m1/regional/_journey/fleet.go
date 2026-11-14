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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

var fleetWeb = map[string]int{"dash.e2e.test": 18101, "api.e2e.test": 18102, "auth.e2e.test": 18103}

var fleetServices = map[string]string{"dash.e2e.test": "ts-dashboard", "api.e2e.test": "api-front", "auth.e2e.test": "ts-auth"}

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
	for _, host := range append(slices.Sorted(maps.Keys(fleetWeb)), fleetPostgres) {
		cert, err := os.ReadFile(filepath.Join(root, "regional", "edge-certs", host))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(state, "edge-certs", host), cert, 0600); err != nil {
			return err
		}
	}
	public := New(state)
	public.JoinMesh(node)
	inventory := mesh.EdgeInventory{Web: fleetWeb, Postgres: map[string]int{fleetPostgres: 15432}, Services: fleetServices, ProofRef: "fleet"}
	for host, port := range fleetWeb {
		inventory.Readiness = append(inventory.Readiness, mesh.EdgeRoute{Host: host, Port: port, Path: "/readyz"})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := node.FollowEdgeInventory()
	if role == "founder" {
		source = func() (mesh.EdgeInventory, bool) { return inventory, true }
		go func() {
			tick := time.NewTicker(time.Second)
			defer tick.Stop()
			for {
				if err := node.PublishEdgeInventory(inventory); err != nil {
					fmt.Fprintln(os.Stderr, "fleet inventory publication:", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
				}
			}
		}()
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
		return public.Readiness(started).Ready && len(public.ReadyServices()) == len(fleetWeb) && peers != nil &&
			slices.ContainsFunc((*peers)(), func(peer mesh.WorkerPeer) bool { return len(peer.ReadyServices) == len(fleetWeb) })
	})
	if err != nil {
		return fmt.Errorf("%s never served with its peer: %w (%+v)", name, err, public.Readiness(ctx))
	}
	fmt.Println("ready")
	for commands.Scan() {
		switch commands.Text() {
		case "unready":
			ready.Store(false)
			if err := fleetAwait(started, func() bool { return len(public.ReadyServices()) == 0 }); err != nil {
				return fmt.Errorf("%s kept advertising unready services: %w", name, err)
			}
		case "drain":
			public.Drain()
		}
		fmt.Println("ok")
	}
	return nil
}

type fleetProcess struct {
	name, address string
	cmd           *exec.Cmd
	stdin         io.WriteCloser
	lines         chan string
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

func (p *fleetProcess) command(ctx context.Context, command string) error {
	if _, err := fmt.Fprintln(p.stdin, command); err != nil {
		return err
	}
	return p.expect(ctx, "ok")
}

func (p *fleetProcess) kill() {
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
}

func fleetRun(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}
	return nil
}

func startFleetHost(root, self string, index int, region, seed, secret string) (*fleetProcess, error) {
	p := &fleetProcess{name: fmt.Sprintf("ts-%s-%d", region, index%2+1), address: fmt.Sprintf("10.77.0.%d", 10+index), lines: make(chan string, 4)}
	log, err := os.Create(filepath.Join(root, p.name+".log"))
	if err != nil {
		return nil, err
	}
	peer, role := fmt.Sprintf("10.77.0.%d", 11+index), "founder"
	if index%2 == 1 {
		peer, role = fmt.Sprintf("10.77.0.%d", 9+index), "worker"
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
	veth := fmt.Sprintf("fv%d", index)
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

type fleetClient struct {
	roots *x509.CertPool
	plain *http.Client
}

func (c fleetClient) get(ctx context.Context, host *fleetProcess, name string) (int, string, error) {
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: c.roots}, DisableKeepAlives: true}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(host.address, "443"))
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+name+"/payload", nil)
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
	response.Body.Close()
	if response.StatusCode != want {
		return fmt.Errorf("%s /edge/ready: got %d, want %d", host.name, response.StatusCode, want)
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
	hosts := []*fleetProcess{}
	defer func() {
		for _, host := range hosts {
			host.kill()
		}
	}()
	for index, region := range []string{"gru", "gru", "sjc", "sjc", "fra", "fra"} {
		host, err := startFleetHost(root, self, index, region, hex.EncodeToString(seed), hex.EncodeToString(secret))
		if err != nil {
			return err
		}
		hosts = append(hosts, host)
	}
	for _, host := range hosts {
		if err := host.expect(ctx, "ready"); err != nil {
			log, _ := os.ReadFile(filepath.Join(root, host.name+".log"))
			return fmt.Errorf("%w: %s", err, log[max(0, len(log)-2000):])
		}
	}
	client := fleetClient{roots: roots, plain: &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}}
	for region := range 3 {
		founder, worker := hosts[2*region], hosts[2*region+1]
		for _, host := range []*fleetProcess{founder, worker} {
			if err := client.ready(ctx, host, http.StatusOK); err != nil {
				return err
			}
			if err := client.serves(ctx, host, founder, worker); err != nil {
				return err
			}
		}
		switch region {
		case 0, 1:
			lost, survivor := founder, worker
			if region == 1 {
				lost, survivor = worker, founder
			}
			lost.kill()
			if err := client.ready(ctx, survivor, http.StatusOK); err != nil {
				return err
			}
			if err := client.serves(ctx, survivor, survivor); err != nil {
				return err
			}
			fmt.Printf("ok %s: both hosts balance every endpoint 6/6 and serve Postgres; %s still serves everything after %s is lost\n", founder.name[3:6], survivor.name, lost.name)
		case 2:
			if err := founder.command(ctx, "unready"); err != nil {
				return err
			}
			if err := client.ready(ctx, founder, http.StatusOK); err != nil {
				return err
			}
			if err := client.serves(ctx, founder, worker); err != nil {
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
			fmt.Printf("ok %s: both hosts balance 6/6; an unready host forwards to its peer, drains to 503, and no ready backend answers 503\n", founder.name[3:6])
		}
	}
	return nil
}
