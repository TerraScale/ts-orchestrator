package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/plannedstop"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

var names = []string{"one", "two", "three"}

func address(i int) string { return fmt.Sprintf("10.79.0.%d", i+2) }

func node(work string, i int) error {
	ctx, cancel := plannedstop.NotifyContext(context.Background())
	defer cancel()
	routes := []string{}
	for j := range names {
		if j != i {
			routes = append(routes, "nats://"+address(j)+":6222")
		}
	}
	options := &server.Options{}
	err := options.ProcessConfigString(fmt.Sprintf(
		`server_name: %s
host: 0.0.0.0
port: 4223
jetstream { store_dir: %q }
cluster { name: fabric, host: 0.0.0.0, port: 6222, routes: [%s] }
accounts { SYS { users: [{user: monitor, password: fabric-monitor}] }, APP { jetstream: enabled, users: [{user: client, password: fabric-client}] } }
system_account: SYS
`,
		names[i], filepath.Join(work, names[i]), strings.Join(routes, ",")))
	if err != nil {
		return err
	}
	options.NoSigs = true
	options.SyncAlways = true
	s, err := server.NewServer(options)
	if err != nil {
		return err
	}
	go s.Start()
	defer s.Shutdown()
	if !s.ReadyForConnections(10 * time.Second) {
		return errors.New("embedded server did not start")
	}
	monitor, err := nats.Connect("nats://127.0.0.1:4223", nats.UserInfo("monitor", "fabric-monitor"))
	if err != nil {
		return err
	}
	defer monitor.Close()
	lifecycle := mesh.NewFabricLifecycle(s, monitor)
	var refusal atomic.Pointer[string]
	plannedstop.Register(ctx, func(ctx context.Context) error {
		err := lifecycle.PrepareStop(ctx)
		if err != nil {
			text := err.Error()
			refusal.Store(&text)
		}
		return err
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		health := lifecycle.Health(r.Context())
		text := ""
		if health != nil {
			text = health.Error()
		}
		last := refusal.Load()
		groups := server.RaftzStatus{}
		for _, account := range []string{"SYS", "APP"} {
			for name, values := range *s.Raftz(&server.RaftzOptions{AccountFilter: account}) {
				groups[name] = values
			}
		}
		_ = json.NewEncoder(w).Encode(struct {
			Groups  *server.RaftzStatus
			Health  string
			Refusal *string
		}{&groups, text, last})
	})
	mux.HandleFunc("/prepare", func(w http.ResponseWriter, r *http.Request) {
		if err := lifecycle.PrepareStop(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/abort", func(w http.ResponseWriter, r *http.Request) {
		lifecycle.AbortStop()
		w.WriteHeader(http.StatusNoContent)
	})
	web := &http.Server{Addr: address(i) + ":8090", Handler: mux, ReadHeaderTimeout: time.Second}
	webDone := make(chan error, 1)
	go func() { webDone <- web.ListenAndServe() }()
	select {
	case <-ctx.Done():
		s.Shutdown()
		s.WaitForShutdown()
		_ = web.Close()
		return nil
	case err := <-webDone:
		return err
	}
}

type process struct {
	cmd  *exec.Cmd
	done chan error
	log  *os.File
}

func start(work string, i int) (*process, error) {
	log, err := os.OpenFile(filepath.Join(work, names[i]+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	binary, err := os.Executable()
	if err != nil {
		log.Close()
		return nil, err
	}
	cmd := exec.Command("ip", "netns", "exec", fmt.Sprintf("fabric%d", i+1), binary, "node", work, fmt.Sprint(i))
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		log.Close()
		return nil, err
	}
	p := &process{cmd, make(chan error, 1), log}
	go func() { p.done <- cmd.Wait(); log.Close() }()
	return p, nil
}

type status struct {
	Groups  server.RaftzStatus
	Health  string
	Refusal *string
}

var client = &http.Client{Timeout: 1500 * time.Millisecond}

func readStatus(i int) (status, error) {
	var result status
	response, err := client.Get("http://" + address(i) + ":8090/status")
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	err = json.NewDecoder(response.Body).Decode(&result)
	return result, err
}

func post(i int, path string) error {
	response, err := client.Post("http://"+address(i)+":8090/"+path, "", nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(response.Body)
		return fmt.Errorf("%s: %s: %s", path, response.Status, body)
	}
	return nil
}

func await(ctx context.Context, name string, check func() bool) error {
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if check() {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: %w", name, ctx.Err())
		case <-tick.C:
		}
	}
}

func bounded(name string, duration time.Duration, check func() bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	return await(ctx, name, check)
}

func dial(i int, system bool) (*nats.Conn, error) {
	addresses := []string{"nats://" + address(i) + ":4223"}
	for j := range names {
		if j != i {
			addresses = append(addresses, "nats://"+address(j)+":4223")
		}
	}
	user, password := "client", "fabric-client"
	if system {
		user, password = "monitor", "fabric-monitor"
	}
	return nats.Connect(strings.Join(addresses, ","), nats.UserInfo(user, password), nats.MaxReconnects(-1),
		nats.ReconnectWait(100*time.Millisecond), nats.Timeout(time.Second), nats.DontRandomize())
}

func request(conn *nats.Conn, subject, preferred string) error {
	payload, _ := json.Marshal(server.JSApiLeaderStepdownRequest{Placement: &server.Placement{Preferred: preferred}})
	message, err := conn.Request(subject, payload, time.Second)
	if err != nil {
		return err
	}
	var reply struct {
		Success bool
		Error   *server.ApiError
	}
	if err := json.Unmarshal(message.Data, &reply); err != nil {
		return err
	}
	if reply.Error != nil {
		return fmt.Errorf("%s: %s", subject, reply.Error.Description)
	}
	if !reply.Success {
		return fmt.Errorf("%s: no success", subject)
	}
	return nil
}

func leadsAll(i int) bool {
	state, err := readStatus(i)
	if err != nil {
		return false
	}
	count := 0
	for _, account := range state.Groups {
		for _, group := range account {
			if group.State != "LEADER" {
				return false
			}
			count++
		}
	}
	return count == 3
}

func place(i int, app, system *nats.Conn) error {
	apis := []struct {
		conn    *nats.Conn
		subject string
		group   string
	}{
		{system, "$JS.API.META.LEADER.STEPDOWN", "_meta_"},
		{app, "$JS.API.STREAM.LEADER.STEPDOWN.KV_leases", "S-"},
		{app, "$JS.API.CONSUMER.LEADER.STEPDOWN.KV_leases.lease_audit", "C-"},
	}
	for _, api := range apis {
		state, err := readStatus(i)
		if err != nil {
			return err
		}
		already := false
		for _, account := range state.Groups {
			for name, group := range account {
				if strings.HasPrefix(name, api.group) && group.State == "LEADER" {
					already = true
				}
			}
		}
		if !already {
			if err := request(api.conn, api.subject, names[i]); err != nil {
				return err
			}
			if err := bounded("preferred "+api.group+" leader", 2*time.Second, func() bool {
				state, err := readStatus(i)
				if err != nil {
					return false
				}
				for _, account := range state.Groups {
					for name, group := range account {
						if strings.HasPrefix(name, api.group) && group.State == "LEADER" {
							return true
						}
					}
				}
				return false
			}); err != nil {
				return err
			}
		}
	}
	if !leadsAll(i) {
		return fmt.Errorf("%s does not lead all three groups", names[i])
	}
	return nil
}

type lease struct {
	mu       sync.Mutex
	last     time.Time
	maxGap   time.Duration
	lapses   int
	failures int
	writes   int
}

func holder(ctx context.Context, i int, result *lease, ready chan<- error) {
	conn, err := dial(i, false)
	if err != nil {
		ready <- err
		return
	}
	defer conn.Close()
	js, err := conn.JetStream(nats.MaxWait(500 * time.Millisecond))
	if err != nil {
		ready <- err
		return
	}
	kv, err := js.KeyValue("leases")
	if err != nil {
		ready <- err
		return
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	initial := true
	for {
		_, err := kv.Put("lease_"+names[i], []byte(time.Now().Format(time.RFC3339Nano)))
		result.mu.Lock()
		now := time.Now()
		if err == nil {
			if !result.last.IsZero() {
				gap := now.Sub(result.last)
				result.maxGap = max(result.maxGap, gap)
				if gap > 1500*time.Millisecond {
					result.lapses++
				}
			}
			result.last = now
			result.writes++
		} else {
			result.failures++
		}
		result.mu.Unlock()
		if initial {
			ready <- err
			if err != nil {
				return
			}
			initial = false
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func metrics(leases []*lease) (int, time.Duration, int) {
	lapses, failures := 0, 0
	var gap time.Duration
	for _, lease := range leases {
		lease.mu.Lock()
		lapses += lease.lapses
		failures += lease.failures
		gap = max(gap, lease.maxGap)
		lease.mu.Unlock()
	}
	return lapses, gap, failures
}

func run(work string) error {
	started := time.Now()
	processes := make([]*process, 3)
	defer func() {
		for i, p := range processes {
			if p != nil {
				state, err := readStatus(i)
				refusal := ""
				if state.Refusal != nil {
					refusal = *state.Refusal
				}
				fmt.Printf("final %s: health=%q refusal=%q error=%v\n", names[i], state.Health, refusal, err)
			}
		}
		for _, p := range processes {
			if p != nil {
				_ = p.cmd.Process.Kill()
			}
		}
	}()
	for i := range names {
		p, err := start(work, i)
		if err != nil {
			return err
		}
		processes[i] = p
	}
	healthy := func() bool {
		for i := range names {
			state, err := readStatus(i)
			if err != nil || state.Health != "" {
				return false
			}
			if len(state.Groups) == 0 {
				return false
			}
		}
		return true
	}
	if err := bounded("three current metadata members", 20*time.Second, healthy); err != nil {
		return err
	}
	app, err := dial(0, false)
	if err != nil {
		return err
	}
	defer app.Close()
	system, err := dial(0, true)
	if err != nil {
		return err
	}
	defer system.Close()
	js, err := app.JetStream()
	if err != nil {
		return err
	}
	if _, err := js.CreateKeyValue(&nats.KeyValueConfig{Bucket: "leases", Replicas: 3, TTL: 2 * time.Second}); err != nil {
		return fmt.Errorf("create KV: %w", err)
	}
	if _, err := js.AddConsumer("KV_leases", &nats.ConsumerConfig{Durable: "lease_audit", AckPolicy: nats.AckExplicitPolicy, Replicas: 3}); err != nil {
		return fmt.Errorf("create consumer: %w", err)
	}
	if err := bounded("three current stream and consumer members", 10*time.Second, healthy); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	leases := make([]*lease, 3)
	ready := make(chan error, 3)
	for i := range names {
		leases[i] = &lease{}
		go holder(ctx, i, leases[i], ready)
	}
	for range names {
		if err := <-ready; err != nil {
			return err
		}
	}
	if err := place(0, app, system); err != nil {
		return err
	}
	if err := post(0, "prepare"); err != nil {
		return err
	}
	state, err := readStatus(0)
	if err != nil {
		return err
	}
	for _, account := range state.Groups {
		for name, group := range account {
			if !group.Observer || group.State == "LEADER" {
				return fmt.Errorf("prepared group %s still eligible or leading", name)
			}
		}
	}
	if err := post(0, "abort"); err != nil {
		return err
	}
	state, err = readStatus(0)
	if err != nil {
		return err
	}
	for _, account := range state.Groups {
		for name, group := range account {
			if group.Observer {
				return fmt.Errorf("aborted group %s still an observer", name)
			}
		}
	}
	fmt.Println("ok aborted preparation restores every group's election eligibility")
	for i := range names {
		if err := place(i, app, system); err != nil {
			return err
		}
		stop := time.Now()
		if err := processes[i].cmd.Process.Signal(syscall.SIGTERM); err != nil {
			return err
		}
		if err := bounded("successor leaders", time.Until(stop.Add(2*time.Second)), func() bool {
			leaders := map[string]bool{}
			for j := range names {
				if i == j {
					continue
				}
				state, err := readStatus(j)
				if err != nil {
					return false
				}
				for _, account := range state.Groups {
					for name, group := range account {
						if group.State == "LEADER" {
							leaders[name] = true
						}
					}
				}
			}
			return len(leaders) == 3
		}); err != nil {
			return err
		}
		elected := time.Since(stop)
		select {
		case err := <-processes[i].done:
			if err != nil {
				return fmt.Errorf("planned stop of %s: %w", names[i], err)
			}
		case <-time.After(time.Until(stop.Add(5 * time.Second))):
			return fmt.Errorf("planned stop of %s exceeded handoff bound", names[i])
		}
		processes[i] = nil
		if err := bounded("all holders renewed after planned stop", 1500*time.Millisecond, func() bool {
			for _, lease := range leases {
				lease.mu.Lock()
				renewed := lease.last.After(stop)
				lease.mu.Unlock()
				if !renewed {
					return false
				}
			}
			return true
		}); err != nil {
			return err
		}
		lapses, gap, failures := metrics(leases)
		if lapses != 0 {
			return fmt.Errorf("planned %s: %d lease lapses, max gap %s", names[i], lapses, gap)
		}
		fmt.Printf("ok planned %s: all 3 successor leaders in %s, lease lapses=%d max_gap=%s publish_errors=%d\n",
			names[i], elected.Round(time.Millisecond), lapses, gap.Round(time.Millisecond), failures)
		processes[i], err = start(work, i)
		if err != nil {
			return err
		}
		if err := bounded("rejoined current members", 15*time.Second, healthy); err != nil {
			return err
		}
	}
	if err := place(0, app, system); err != nil {
		return err
	}
	killAt := time.Now()
	if err := processes[0].cmd.Process.Kill(); err != nil {
		return err
	}
	<-processes[0].done
	processes[0] = nil
	if err := bounded("kill baseline election and lease lapse", 15*time.Second, func() bool {
		lapses, _, _ := metrics(leases)
		return lapses > 0
	}); err != nil {
		return err
	}
	lapses, gap, failures := metrics(leases)
	if gap < 3*time.Second {
		return fmt.Errorf("kill baseline gap %s was not multi-second", gap)
	}
	fmt.Printf("ok kill baseline: recovery=%s lease_lapses=%d max_gap=%s publish_errors=%d\n",
		time.Since(killAt).Round(time.Millisecond), lapses, gap.Round(time.Millisecond), failures)
	processes[0], err = start(work, 0)
	if err != nil {
		return err
	}
	if err := bounded("baseline member rejoined", 15*time.Second, healthy); err != nil {
		return err
	}
	if err := processes[2].cmd.Process.Kill(); err != nil {
		return err
	}
	<-processes[2].done
	processes[2] = nil
	if err := bounded("down replica visible in health", 12*time.Second, func() bool {
		state, err := readStatus(1)
		return err == nil && strings.Contains(state.Health, "raft group") && strings.Contains(state.Health, "current replicas")
	}); err != nil {
		return err
	}
	if err := processes[1].cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	refusal := ""
	if err := bounded("quorum stop refusal", 5*time.Second, func() bool {
		state, err := readStatus(1)
		if err == nil && state.Refusal != nil {
			refusal = *state.Refusal
			return strings.Contains(refusal, "raft group") && strings.Contains(refusal, "quorum")
		}
		return false
	}); err != nil {
		return err
	}
	select {
	case err := <-processes[1].done:
		return fmt.Errorf("refused server exited: %v", err)
	default:
	}
	fmt.Printf("ok planned second stop refused while serving: %s\n", refusal)
	if err := processes[1].cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	select {
	case <-processes[1].done:
	case <-time.After(time.Second):
		return errors.New("second SIGTERM did not force stop")
	}
	processes[1] = nil
	fmt.Printf("ok second SIGTERM forces refused stop; fabric lane: %s\n", time.Since(started).Round(time.Millisecond))
	return nil
}

func main() {
	var err error
	if len(os.Args) == 4 && os.Args[1] == "node" {
		i := 0
		_, err = fmt.Sscan(os.Args[3], &i)
		if err == nil {
			err = node(os.Args[2], i)
		}
	} else if len(os.Args) == 2 {
		err = run(os.Args[1])
	} else {
		err = errors.New("usage: fabric WORK | fabric node WORK INDEX")
	}
	if err != nil {
		_, _ = io.WriteString(os.Stderr, "FAIL fabric: "+err.Error()+"\n")
		os.Exit(1)
	}
}
