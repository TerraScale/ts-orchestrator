package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/fsnotify/fsnotify"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}
func logStep(message string) { fmt.Println("ok:", message) }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	switch os.Args[1] {
	case "swarm":
		runSwarm(ctx, os.Args[2])
	case "region":
		runRegion(ctx, os.Args[2:])
	case "control":
		control(ctx, os.Args[2:])
	case "journey":
		journey(ctx, os.Args[2], os.Args[3], os.Args[4])
	default:
		panic("unknown rollout journey command")
	}
}

func runSwarm(ctx context.Context, root string) {
	child := exec.Command("/usr/local/bin/ts-orch", "single-host", "--state", root)
	output, err := child.StdoutPipe()
	must(err)
	child.Stderr = os.Stderr
	must(child.Start())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println(line)
			if strings.HasPrefix(line, "single-host manager ") && strings.Contains(line, " ready; advertise ") {
				close(ready)
			}
		}
		done <- child.Wait()
	}()
	select {
	case <-ready:
		fmt.Println("READY")
	case err := <-done:
		panic(fmt.Errorf("single-host exited before readiness: %v", err))
	case <-ctx.Done():
		_ = child.Process.Signal(syscall.SIGTERM)
		<-done
		return
	}
	select {
	case err := <-done:
		must(err)
	case <-ctx.Done():
		_ = child.Process.Signal(syscall.SIGTERM)
		<-done
	}
}

func relay(ctx context.Context, address, upstream string) {
	listener, err := net.Listen("tcp", address)
	must(err)
	go func() { <-ctx.Done(); listener.Close() }()
	go func() {
		for {
			downstream, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer downstream.Close()
				source, err := (&net.Dialer{}).DialContext(ctx, "tcp", upstream)
				if err != nil {
					return
				}
				defer source.Close()
				go func() { _, _ = io.Copy(source, downstream); source.Close() }()
				_, _ = io.Copy(downstream, source)
			}()
		}
	}()
}

func runRegion(ctx context.Context, args []string) {
	root, region, address, peerRegion, peerAddress, seedFile := args[0], args[1], args[2], args[3], args[4], args[5]
	seed, err := os.ReadFile(seedFile)
	must(err)
	ca, err := mesh.DeriveCA(seed)
	must(err)
	node, err := mesh.StartRegionalHost(mesh.RegionalHost{State: root, Region: region, Server: "single-host", CA: ca,
		TerraBaseToken: fmt.Sprintf("%x", seed), Seeds: map[string]string{peerRegion: "nats://" + peerAddress + ":6222"},
		ClusterAddress: address + ":6222", Address: func() (string, error) { return address, nil }})
	must(err)
	defer node.Close()
	go node.Run(ctx)
	releases, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: 4224, NoSigs: true, NoLog: true})
	must(err)
	go releases.Start()
	defer func() { releases.Shutdown(); releases.WaitForShutdown() }()
	require(releases.ReadyForConnections(10*time.Second), "release listener did not start")
	conn, err := nats.Connect(releases.ClientURL())
	must(err)
	defer conn.Close()
	handler := &releasepush.Handler{Health: func(ctx context.Context, name string) releasepush.HealthResult {
		return releasepush.HealthResult{Mesh: node.ReleaseHealth(ctx), Service: regionhealth.Serving(ctx, root, name)}
	}}
	must(handler.Serve(conn))
	relay(ctx, address+":14223", "127.0.0.1:4223")
	relay(ctx, address+":14222", "127.0.0.1:4224")
	fmt.Println("READY")
	<-ctx.Done()
}

func control(ctx context.Context, args []string) {
	root := args[0]
	client, conn, err := swarmruntime.DialSingleHost(root)
	must(err)
	defer conn.Close()
	var spec swarmruntime.ServiceSpec
	must(json.Unmarshal([]byte(args[1]), &spec))
	before, err := swarmruntime.ApplyServiceSpec(ctx, client, spec)
	must(err)
	if spec.Name != "e2e-lagging" {
		must(swarmruntime.CompleteServiceSpec(ctx, client, spec, before))
		_, err = swarmruntime.WaitServiceSpecExact(ctx, client, spec)
		must(err)
	}
}

type process struct {
	command *exec.Cmd
	done    chan error
}

func start(ctx context.Context, namespace, launcher, root, mode string, args ...string) *process {
	command := exec.CommandContext(ctx, "ip", append([]string{"netns", "exec", namespace, "unshare", "--mount", "--uts", "--propagation", "private", "bash", launcher, root, os.Args[0], mode}, args...)...)
	stdout, err := command.StdoutPipe()
	must(err)
	logfile, err := os.OpenFile(filepath.Join(root, mode+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	must(err)
	command.Stderr = logfile
	must(command.Start())
	ready := make(chan struct{})
	p := &process{command: command, done: make(chan error, 1)}
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Fprintln(logfile, line)
			if line == "READY" {
				close(ready)
			}
		}
		p.done <- command.Wait()
		logfile.Close()
	}()
	select {
	case <-ready:
		return p
	case err := <-p.done:
		detail, readErr := os.ReadFile(filepath.Join(root, mode+".log"))
		must(readErr)
		panic(fmt.Errorf("%s startup: %v: %s", mode, err, detail[max(0, len(detail)-4096):]))
	case <-ctx.Done():
		panic(ctx.Err())
	}
}
func (p *process) kill() { must(p.command.Process.Kill()); <-p.done }
func (p *process) stop() { _ = p.command.Process.Signal(syscall.SIGTERM); <-p.done }

func command(ctx context.Context, namespace, root string, spec any) {
	data, err := json.Marshal(spec)
	must(err)
	args := []string{"netns", "exec", namespace, os.Args[0], "control", root, string(data)}
	output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
	if err != nil {
		panic(fmt.Errorf("control apply: %w: %s", err, output))
	}
}

func health(ctx context.Context, conn *nats.Conn, name string) string {
	data, err := json.Marshal(releasepush.HealthRequest{Service: name})
	must(err)
	message, err := conn.RequestWithContext(ctx, releasepush.SubjectHealth, data)
	must(err)
	var reply releasepush.Reply
	must(json.Unmarshal(message.Data, &reply))
	return reply.Health
}

type state struct {
	Region  string                        `json:"region"`
	Ready   map[string]int64              `json:"ready"`
	Serving map[string]mesh.ServingResult `json:"serving"`
	Failed  map[string]int64              `json:"failed"`
	Excused map[string]int64              `json:"excused"`
}

func states(ctx context.Context, conn *nats.Conn) map[string]state {
	inbox := nats.NewInbox()
	replies := make(chan *nats.Msg, 2)
	sub, err := conn.ChanSubscribe(inbox, replies)
	must(err)
	defer sub.Unsubscribe()
	must(conn.PublishRequest(mesh.StateSubject, inbox, nil))
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	result := map[string]state{}
	for len(result) < 2 {
		select {
		case message := <-replies:
			var reply state
			must(json.Unmarshal(message.Data, &reply))
			result[reply.Region] = reply
		case <-deadline.C:
			panic("state replies exceeded the one-second rollout collection window")
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}
	return result
}

func observe(ctx context.Context, conn *nats.Conn, condition func(map[string]state) bool) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		if condition(states(ctx, conn)) {
			return
		}
		select {
		case <-ctx.Done():
			panic(ctx.Err())
		case <-tick.C:
		}
	}
}

type receipt struct {
	Generation int64               `json:"generation"`
	Bake       rollout.BakeVerdict `json:"bake"`
}

func evidence(ctx context.Context, root string, generation int64, condition func(receipt) bool) receipt {
	directory := filepath.Join(root, "mesh")
	watcher, err := fsnotify.NewWatcher()
	must(err)
	defer watcher.Close()
	must(watcher.Add(directory))
	path := filepath.Join(directory, fmt.Sprintf("bake-terrabase-%d.json", generation))
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			var record receipt
			must(json.Unmarshal(data, &record))
			if condition(record) {
				return record
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			panic(err)
		}
		select {
		case <-watcher.Events:
		case err := <-watcher.Errors:
			panic(err)
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}
}

func setHealth(ctx context.Context, address string, port int, code string) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://%s:%d/health", address, port), bytes.NewBufferString(code))
	must(err)
	response, err := http.DefaultClient.Do(request)
	must(err)
	defer response.Body.Close()
	require(response.StatusCode == http.StatusOK, "health control failed")
}

func journey(ctx context.Context, root, launcher, specFile string) {
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	must(err)
	seedFile := filepath.Join(root, "seed")
	must(os.WriteFile(seedFile, seed, 0600))
	regions := mesh.Regions()
	order := []string{regions[1], regions[0]}
	names := []string{"c21-first", "c21-second"}
	addresses := []string{"10.203.21.2", "10.203.21.3"}
	roots := []string{filepath.Join(root, "first"), filepath.Join(root, "second")}
	swarms := make([]*process, 2)
	nodes := make([]*process, 2)
	boot := func(i int) *process {
		return start(ctx, names[i], launcher, roots[i], "region", order[i], addresses[i], order[1-i], addresses[1-i], seedFile)
	}
	for i := range roots {
		socketReady(ctx, filepath.Join(roots[i], "run", "containerd.sock"))
		swarms[i] = start(ctx, names[i], launcher, roots[i], "swarm")
	}
	defer func() {
		for _, p := range swarms {
			if p != nil {
				p.stop()
			}
		}
	}()
	for i := range roots {
		nodes[i] = boot(i)
	}
	defer func() {
		for _, p := range nodes {
			if p != nil {
				p.stop()
			}
		}
	}()
	token, err := os.ReadFile(filepath.Join(roots[0], "mesh", "client.token"))
	must(err)
	conn, err := nats.Connect("nats://"+addresses[0]+":14223", nats.UserInfo("orch", strings.TrimSpace(string(token))))
	must(err)
	defer conn.Close()
	releases, err := nats.Connect("nats://" + addresses[0] + ":14222")
	must(err)
	defer releases.Close()
	data, err := os.ReadFile(specFile)
	must(err)
	var spec swarmruntime.ServiceSpec
	must(json.Unmarshal(data, &spec))
	spec.Name, spec.Args, spec.Port, spec.Regions, spec.Hostnames = "terrabase", []string{"--port", "18085"}, 18085, order, nil
	lagging := spec
	lagging.Name, lagging.Port, lagging.Args = "e2e-lagging", 18086, []string{"--port", "18086"}
	lagging.Regions = nil
	lagging.MilliCPU, lagging.MemoryMiB = 4000, 24576
	command(ctx, names[0], roots[0], lagging)
	apply := func(generation int64) {
		request := mesh.ApplyRequest{Name: spec.Name, Entry: mesh.Entry{Generation: generation, Spec: &spec}}
		data, err := json.Marshal(request)
		must(err)
		must(conn.PublishRequest(mesh.ApplySubject, nats.NewInbox(), data))
		must(conn.Flush())
	}
	generation := time.Now().UnixNano()
	apply(generation)
	initial := evidence(ctx, roots[0], generation, func(r receipt) bool { return !r.Bake.Started.IsZero() })
	require(initial.Bake.Finished.IsZero(), "interruption did not happen during the bake")
	require(states(ctx, conn)[order[1]].Ready[spec.Name] < generation, "later region advanced before the first bake")
	nodes[0].kill()
	nodes[0] = nil
	nodes[0] = boot(0)
	restarted := evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Started.After(initial.Bake.Started) })
	require(restarted.Bake.Finished.IsZero(), "restart did not start a fresh observation window")
	complete := evidence(ctx, roots[0], generation, func(r receipt) bool { return !r.Bake.Finished.IsZero() })
	require(complete.Bake.Reason == "", "restarted bake failed: "+complete.Bake.Reason)
	require(complete.Bake.Finished.Sub(complete.Bake.Started) >= rollout.BakeWindow, "restart shortened the bake window")
	next := evidence(ctx, roots[1], generation, func(r receipt) bool { return !r.Bake.Finished.IsZero() })
	require(next.Bake.Reason == "", "later region bake failed: "+next.Bake.Reason)
	observe(ctx, conn, func(s map[string]state) bool { return s[order[1]].Ready[spec.Name] == generation })
	logStep("abrupt agent exit restarts a full bake; the next region advances automatically")
	shortage := states(ctx, conn)[order[0]].Serving[lagging.Name]
	require(!shortage.At.IsZero() && !shortage.Serving, "B did not exhibit the intended replica shortage")
	require(health(ctx, releases, spec.Name) == "ok", "unrelated replica shortage blocked A")
	logStep("named service health passes while another service is short a replica")
	slow := spec
	slow.Name, slow.Port, slow.Args, slow.Regions = "e2e-slow", 18087, []string{"--port", "18087"}, nil
	command(ctx, names[0], roots[0], slow)
	must(exec.CommandContext(ctx, "ip", "netns", "exec", names[0], "iptables", "-A", "OUTPUT", "-o", "lo", "-p", "tcp", "--dport", "18087", "-j", "DROP").Run())
	defer exec.Command("ip", "netns", "exec", names[0], "iptables", "-D", "OUTPUT", "-o", "lo", "-p", "tcp", "--dport", "18087", "-j", "DROP").Run()
	observe(ctx, conn, func(s map[string]state) bool {
		return !s[order[0]].Serving[slow.Name].Serving && s[order[0]].Ready[spec.Name] == generation
	})
	logStep("a blackholed unrelated readiness endpoint leaves both state replies inside one second")
	setHealth(ctx, addresses[0], 18085, "503")
	require(health(ctx, releases, spec.Name) != "ok", "unready A passed named release health")
	observe(ctx, conn, func(s map[string]state) bool { return s[order[0]].Ready[spec.Name] < generation })
	logStep("a previously successful bake stops admitting regions when A stops serving")
	setHealth(ctx, addresses[0], 18085, "200")
	generation++
	apply(generation)
	evidence(ctx, roots[0], generation, func(r receipt) bool { return !r.Bake.Started.IsZero() })
	observe(ctx, conn, func(s map[string]state) bool {
		return s[order[0]].Serving[spec.Name].Generation == generation && s[order[0]].Serving[spec.Name].Serving
	})
	setHealth(ctx, addresses[0], 18085, "503")
	failed := evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Reason != "" })
	require(failed.Bake.Finished.IsZero(), "regression was not persisted before the terminal verdict")
	meshConnected := conn.StatusChanged(nats.CONNECTED)
	healthConnected := releases.StatusChanged(nats.CONNECTED)
	nodes[0].kill()
	nodes[0] = nil
	setHealth(ctx, addresses[0], 18085, "200")
	nodes[0] = boot(0)
	for _, connected := range []chan nats.Status{meshConnected, healthConnected} {
		select {
		case <-connected:
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}
	observe(ctx, conn, func(s map[string]state) bool { return s[order[0]].Failed[spec.Name] == generation })
	retained := evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Reason != "" })
	require(retained.Bake.Started.Equal(failed.Bake.Started), "restart erased a recorded regression")
	require(states(ctx, conn)[order[1]].Ready[spec.Name] < generation, "failed first bake admitted the next region")
	logStep("an observed regression remains failed across restart after readiness recovers")
	swarms[0].stop()
	swarms[0] = nil
	require(len(states(ctx, conn)) == 2, "mesh stopped with the swarm node")
	require(strings.Contains(health(ctx, releases, ""), "swarm node unreachable"), "unnamed binary health ignored the unavailable swarm node")
	logStep("unnamed orchestrator health fails while mesh is up and the swarm node is unavailable")
	fmt.Println("rollout journey passed")
}

func socketReady(ctx context.Context, path string) {
	watcher, err := fsnotify.NewWatcher()
	must(err)
	defer watcher.Close()
	must(watcher.Add(filepath.Dir(path)))
	for {
		info, err := os.Stat(path)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			panic(err)
		}
		select {
		case <-watcher.Events:
		case err := <-watcher.Errors:
			panic(err)
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}
}
