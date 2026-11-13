package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	"io"
	"math/big"
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

const revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type failure struct {
	Service    string
	Generation int64
	Region     string
	Reason     string
	ReplacedBy *struct {
		Generation int64
		Release    mesh.Deployment
	}
}

func prepareImage(ctx context.Context, root, specFile string) {
	ctx = namespaces.WithNamespace(ctx, "terrascale")
	client, err := containerd.New(filepath.Join(root, "run", "containerd.sock"))
	must(err)
	defer client.Close()
	ctx, release, err := client.WithLease(ctx)
	must(err)
	defer release(context.WithoutCancel(ctx))
	data, err := os.ReadFile(specFile)
	must(err)
	var spec swarmruntime.ServiceSpec
	must(json.Unmarshal(data, &spec))
	image, err := client.Pull(ctx, spec.Image, containerd.WithPullUnpack)
	must(err)
	store := client.ContentStore()
	manifest, err := images.Manifest(ctx, store, image.Target(), platforms.Default())
	must(err)
	config, err := content.ReadBlob(ctx, store, manifest.Config)
	must(err)
	var metadata imagespec.Image
	must(json.Unmarshal(config, &metadata))
	if metadata.Config.Labels == nil {
		metadata.Config.Labels = map[string]string{}
	}
	metadata.Config.Labels["org.opencontainers.image.revision"] = revision
	write := func(value any, media string) imagespec.Descriptor {
		data, err := json.Marshal(value)
		must(err)
		descriptor := imagespec.Descriptor{MediaType: media, Digest: digest.FromBytes(data), Size: int64(len(data))}
		must(content.WriteBlob(ctx, store, descriptor.Digest.String(), bytes.NewReader(data), descriptor))
		return descriptor
	}
	manifest.Config = write(metadata, manifest.Config.MediaType)
	target := write(manifest, imagespec.MediaTypeImageManifest)
	labels := map[string]string{"containerd.io/gc.ref.content.config": manifest.Config.Digest.String()}
	for i, layer := range manifest.Layers {
		labels[fmt.Sprintf("containerd.io/gc.ref.content.l.%d", i)] = layer.Digest.String()
	}
	_, err = store.Update(ctx, content.Info{Digest: target.Digest, Labels: labels}, "labels")
	must(err)
	spec.Image = "ghcr.io/terrascale/terrabase@" + target.Digest.String()
	_, err = client.ImageService().Create(ctx, images.Image{Name: spec.Image, Target: target})
	must(err)
	data, err = json.Marshal(spec)
	must(err)
	must(os.WriteFile(filepath.Join(root, "spec.json"), data, 0600))
}

func signedToken(key *rsa.PrivateKey, run string) string {
	encode := func(v any) string {
		data, err := json.Marshal(v)
		must(err)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	header := encode(map[string]string{"alg": "RS256", "kid": "journey"})
	claims := encode(map[string]any{
		"iss": "https://token.actions.githubusercontent.com", "aud": "ts-orch",
		"exp": time.Now().Add(time.Hour).Unix(), "nbf": time.Now().Add(-time.Minute).Unix(),
		"repository": "TerraScale/terrascale", "repository_owner": "TerraScale", "ref": "refs/heads/main",
		"sha": revision, "run_id": run, "run_attempt": "1", "event_name": "workflow_dispatch",
		"job_workflow_ref": "TerraScale/terrascale/.github/workflows/ci.yml@refs/heads/main",
	})
	signed := header + "." + claims
	sum := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	must(err)
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signedRelease(ctx context.Context, conn *nats.Conn, key *rsa.PrivateKey, image, run string) {
	data, err := json.Marshal(releasepush.AppRelease{Service: "terrabase", Image: image, Token: signedToken(key, run)})
	must(err)
	message, err := conn.RequestWithContext(ctx, releasepush.SubjectApp, data)
	must(err)
	var reply releasepush.Reply
	must(json.Unmarshal(message.Data, &reply))
	require(reply.State == "accepted", "signed release refused: "+reply.Error)
}

func unsignedRefused(ctx context.Context, conn *nats.Conn, spec swarmruntime.ServiceSpec, generation int64) {
	var output bytes.Buffer
	err := mesh.Apply(ctx, conn, spec, "", &output)
	require(err != nil && strings.Contains(err.Error(), fmt.Sprint(generation)) && strings.Contains(err.Error(), "signed release workflow"), "unsigned apply did not name the failed generation and signed release workflow")
	inbox := nats.NewInbox()
	replies := make(chan *nats.Msg, 3)
	sub, err := conn.ChanSubscribe(inbox, replies)
	must(err)
	defer sub.Unsubscribe()
	payload, err := json.Marshal(mesh.ApplyRequest{Name: spec.Name, Entry: mesh.Entry{Generation: time.Now().UnixNano(), Spec: &spec}})
	must(err)
	must(conn.PublishRequest(mesh.ApplySubject, inbox, payload))
	seen := map[string]bool{}
	for len(seen) < 3 {
		select {
		case message := <-replies:
			var reply mesh.Reply
			must(json.Unmarshal(message.Data, &reply))
			require(strings.Contains(reply.Error, fmt.Sprint(generation)) && strings.Contains(reply.Error, "signed release workflow"), "founder admitted an unsigned replacement: "+reply.Region+" "+reply.Error)
			seen[reply.Region] = true
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}

}

func newGeneration(s map[string]state, region string) int64 {
	var current struct {
		Generation int64
		Signed     *mesh.Entry
	}
	must(json.Unmarshal(s[region].Desired["terrabase"], &current))
	if current.Signed != nil && current.Signed.Generation > current.Generation {
		return current.Signed.Generation
	}
	return current.Generation
}

func readonly(p *process, path string) {
	output, err := exec.Command("nsenter", "-t", fmt.Sprint(p.command.Process.Pid), "-m", "mount", "--bind", path, path).CombinedOutput()
	require(err == nil, fmt.Sprintf("state bind mount: %v %s", err, output))
	output, err = exec.Command("nsenter", "-t", fmt.Sprint(p.command.Process.Pid), "-m", "mount", "-o", "remount,bind,ro", path).CombinedOutput()
	require(err == nil, fmt.Sprintf("read-only state: %v %s", err, output))
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	switch os.Args[1] {
	case "prepare":
		prepareImage(ctx, os.Args[2], os.Args[3])
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
	child := exec.Command(filepath.Join(root, "..", "ts-orch"), "single-host", "--state", root)
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

	public, err := os.ReadFile(filepath.Join(root, "..", "keys.json"))
	must(err)
	listener, err := net.Listen("tcp", "127.0.0.1:18088")
	must(err)
	jwks := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(public) })}
	go jwks.Serve(listener)
	defer jwks.Close()
	verifier := releasepush.NewVerifier()
	verifier.JWKSURL = "http://127.0.0.1:18088/keys"
	handler := &releasepush.Handler{Verifier: verifier, App: mesh.Release(root), Health: func(ctx context.Context, name string) releasepush.HealthResult {
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
	Desired map[string]json.RawMessage    `json:"desired"`
	Holds   map[string]failure            `json:"holds"`
}

func states(ctx context.Context, conn *nats.Conn) map[string]state {
	inbox := nats.NewInbox()
	replies := make(chan *nats.Msg, 3)
	sub, err := conn.ChanSubscribe(inbox, replies)
	must(err)
	defer sub.Unsubscribe()
	must(conn.PublishRequest(mesh.StateSubject, inbox, nil))
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	result := map[string]state{}
	for len(result) < 3 {
		select {
		case message := <-replies:
			require(len(message.Data) > 0, fmt.Sprintf("empty state reply from %s, headers %v", conn.ConnectedUrl(), message.Header))
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
	order := append(append([]string{}, regions[1:]...), regions[0])
	names := []string{"c21-first", "c21-second", "c21-third"}
	addresses := []string{"10.203.21.2", "10.203.21.3", "10.203.21.4"}
	roots := []string{filepath.Join(root, "first"), filepath.Join(root, "second"), filepath.Join(root, "third")}
	swarms := make([]*process, len(roots))
	nodes := make([]*process, len(roots))
	boot := func(i int) *process {
		return start(ctx, names[i], launcher, roots[i], "region", order[i], addresses[i], order[(i+1)%len(roots)], addresses[(i+1)%len(roots)], seedFile)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	public, err := json.Marshal(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "journey", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	must(err)
	must(os.WriteFile(filepath.Join(root, "keys.json"), public, 0600))

	for i := range roots {
		socketReady(ctx, filepath.Join(roots[i], "run", "containerd.sock"))
		output, err := exec.CommandContext(ctx, os.Args[0], "prepare", roots[i], specFile).CombinedOutput()
		require(err == nil, fmt.Sprintf("prepare image: %v %s", err, output))
		swarms[i] = start(ctx, names[i], launcher, roots[i], "swarm")
		data, err := os.ReadFile(filepath.Join(roots[i], "spec.json"))
		must(err)
		var baseline swarmruntime.ServiceSpec
		must(json.Unmarshal(data, &baseline))
		baseline.Name, baseline.Args, baseline.Port, baseline.Regions, baseline.Hostnames = "terrabase", []string{"--port", "18085"}, 18085, order, nil
		command(ctx, names[i], roots[i], baseline)

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
	conn, err := nats.Connect("nats://"+addresses[0]+":14223", nats.UserInfo("orch", strings.TrimSpace(string(token))), nats.IgnoreDiscoveredServers())
	must(err)
	defer conn.Close()
	releases, err := nats.Connect("nats://"+addresses[0]+":14222", nats.IgnoreDiscoveredServers())
	must(err)
	defer releases.Close()
	data, err := os.ReadFile(filepath.Join(roots[0], "spec.json"))
	must(err)
	var spec swarmruntime.ServiceSpec
	must(json.Unmarshal(data, &spec))
	spec.Name, spec.Args, spec.Port, spec.Regions, spec.Hostnames = "terrabase", []string{"--port", "18085"}, 18085, order, nil
	lagging := spec
	lagging.Name, lagging.Port, lagging.Args = "e2e-lagging", 18086, []string{"--port", "18086"}
	lagging.Regions = nil
	lagging.Replicas = 2
	lagging.MilliCPU, lagging.MemoryMiB = 4000, 24576
	command(ctx, names[0], roots[0], lagging)
	apply := func(generation int64) {
		request := mesh.ApplyRequest{Name: spec.Name, Entry: mesh.Entry{Generation: generation, Spec: &spec, HoldAfter: order[len(order)-1]}}
		data, err := json.Marshal(request)
		must(err)
		must(conn.PublishRequest(mesh.ApplySubject, nats.NewInbox(), data))
		must(conn.Flush())
	}
	initialApply := spec
	initialApply.Name, initialApply.Port, initialApply.Args, initialApply.Regions = "e2e-initial-apply", 18090, []string{"--port", "18090"}, []string{order[0]}
	initialDone := make(chan error, 1)
	go func() { var output bytes.Buffer; initialDone <- mesh.Apply(ctx, conn, initialApply, "", &output) }()
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
	select {
	case err := <-initialDone:
		must(err)
	case <-ctx.Done():
		panic(ctx.Err())
	}
	logStep("unsigned apply admits a new service without inventing a generation-zero hold")

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
	single := evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.FailedSamples == 1 })
	require(single.Bake.Reason == "" && single.Bake.HealthySince.IsZero(), "one failed sample held the bake")
	setHealth(ctx, addresses[0], 18085, "200")
	recovered := evidence(ctx, roots[0], generation, func(r receipt) bool { return !r.Bake.HealthySince.IsZero() && r.Bake.FailedSamples == 1 })
	require(recovered.Bake.Reason == "", "recovery held the bake")
	passed := evidence(ctx, roots[0], generation, func(r receipt) bool { return !r.Bake.Finished.IsZero() })
	require(passed.Bake.Reason == "" && passed.Bake.Finished.Sub(recovered.Bake.HealthySince) >= rollout.BakeWindow, "one bad sample did not require a full new window")
	evidence(ctx, roots[1], generation, func(r receipt) bool { return !r.Bake.Finished.IsZero() })
	logStep("one bad sample records count and reason, restarts the full window, and passes")
	generation++
	apply(generation)
	evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Samples >= 1 })
	setHealth(ctx, addresses[0], 18085, "503")
	failed := evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Reason != "" })
	require(failed.Bake.FailedSamples == 2 && strings.Contains(failed.Bake.Reason, "two consecutive"), "two failed samples did not hold the bake")
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
	must(conn.FlushWithContext(ctx))
	must(releases.FlushWithContext(ctx))
	require(conn.ConnectedUrl() == "nats://"+addresses[0]+":14223", "mesh client left its namespace relay")
	for range 19 {
		connected := conn.StatusChanged(nats.CONNECTED)
		healthy := releases.StatusChanged(nats.CONNECTED)
		nodes[0].kill()
		nodes[0] = boot(0)
		for _, event := range []chan nats.Status{connected, healthy} {
			select {
			case <-event:
			case <-ctx.Done():
				panic(ctx.Err())
			}
		}
		must(conn.FlushWithContext(ctx))
		must(releases.FlushWithContext(ctx))
		require(conn.ConnectedUrl() == "nats://"+addresses[0]+":14223", "reconnected mesh client left its namespace relay")
		require(states(ctx, conn)[order[0]].Failed[spec.Name] == generation, "repeated restart lost the persisted failure")
	}
	logStep("twenty observer restarts retain the failure and collect every region within one second")
	observe(ctx, conn, func(s map[string]state) bool {
		return s[order[0]].Failed[spec.Name] == generation
	})
	retained := evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Reason != "" })
	require(retained.Bake.Started.Equal(failed.Bake.Started), "restart erased a recorded regression")
	require(states(ctx, conn)[order[1]].Ready[spec.Name] < generation, "failed first bake admitted the next region")
	logStep("an observed regression remains failed across restart after readiness recovers")
	unsignedRefused(ctx, conn, spec, generation)
	var resumed bytes.Buffer
	resumeErr := mesh.Resume(ctx, conn, spec.Name, &resumed)
	require(resumeErr != nil && strings.Contains(resumeErr.Error(), fmt.Sprint(generation)) && strings.Contains(resumeErr.Error(), "signed release workflow"), "service resume cleared a failed bake")
	logStep("service resume refuses a failed bake even with a canary hold")
	logStep("persisted failure refuses local unsigned apply with held generation and release instructions")
	held := generation
	signedRelease(ctx, releases, key, spec.Image, "101")
	observe(ctx, conn, func(s map[string]state) bool { return newGeneration(s, order[0]) > held })
	generation = newGeneration(states(ctx, conn), order[0])
	evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Samples >= 1 })
	for _, state := range states(ctx, conn) {
		for _, failure := range state.Holds {
			if failure.Generation == held && failure.ReplacedBy != nil {
				release := failure.ReplacedBy.Release
				require(failure.ReplacedBy.Generation == generation && release.RunID == "101" && release.RunAttempt == 1 && release.Revision == revision, "signed replacement omitted release identity")
			}
		}
	}
	nodes[0].kill()
	nodes[0] = boot(0)
	evidence(ctx, roots[0], generation, func(r receipt) bool { return !r.Bake.Finished.IsZero() && r.Bake.Reason == "" })
	for i := 1; i < len(roots); i++ {
		evidence(ctx, roots[i], generation, func(r receipt) bool { return !r.Bake.Finished.IsZero() && r.Bake.Reason == "" })
	}
	observe(ctx, conn, func(s map[string]state) bool { return s[order[len(order)-1]].Ready[spec.Name] == generation })
	for _, root := range roots {
		data, err := os.ReadFile(filepath.Join(root, "mesh", "bake-holds.json"))
		must(err)
		ledger := map[string]failure{}
		must(json.Unmarshal(data, &ledger))
		replaced := false
		for _, failure := range ledger {
			if failure.Generation != held {
				continue
			}
			require(failure.ReplacedBy != nil, "founder did not durably record signed hold replacement")
			release := failure.ReplacedBy.Release
			require(failure.ReplacedBy.Generation == generation && release.RunID == "101" && release.RunAttempt == 1 && release.Revision == revision, "durable signed replacement identity differs")
			replaced = true
		}
		require(replaced, "founder omitted the failed generation from its durable ledger")
	}
	logStep("signed workflow replaces the held generation with run, attempt and revision; restart replays no stale failure and every target completes")
	signedRelease(ctx, releases, key, spec.Image, "102")
	previous := generation
	observe(ctx, conn, func(s map[string]state) bool { return newGeneration(s, order[0]) > previous })
	generation = newGeneration(states(ctx, conn), order[0])
	evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Samples >= 1 })
	setHealth(ctx, addresses[0], 18085, "503")
	evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.FailedSamples == 1 })
	readonly(nodes[0], filepath.Join(roots[0], "mesh"))
	observe(ctx, conn, func(s map[string]state) bool {
		for _, failure := range s[order[1]].Holds {
			if failure.Generation == generation && failure.Region == order[0] {
				return true
			}
		}
		return false
	})
	disk := evidence(ctx, roots[0], generation, func(r receipt) bool { return true })
	require(disk.Bake.Reason == "" && disk.Bake.FailedSamples == 1, "read-only disk unexpectedly saved the terminal failure")
	meshReconnected := conn.StatusChanged(nats.CONNECTED)
	healthReconnected := releases.StatusChanged(nats.CONNECTED)
	nodes[1].kill()
	nodes[1] = boot(1)
	nodes[0].kill()
	nodes[0] = nil
	setHealth(ctx, addresses[0], 18085, "200")
	nodes[0] = boot(0)
	for _, connected := range []chan nats.Status{meshReconnected, healthReconnected} {
		select {
		case <-connected:
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}
	observe(ctx, conn, func(s map[string]state) bool { return s[order[0]].Failed[spec.Name] == generation })
	require(states(ctx, conn)[order[1]].Ready[spec.Name] < generation, "published failure admitted the next region after observer restart")
	unsignedRefused(ctx, conn, spec, generation)
	logStep("read-only observer state cannot erase a peer-acknowledged failed verdict across observer restart")
	signedRelease(ctx, releases, key, spec.Image, "103")
	previous = generation
	observe(ctx, conn, func(s map[string]state) bool { return newGeneration(s, order[0]) > previous })
	generation = newGeneration(states(ctx, conn), order[0])
	evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Samples >= 1 })
	nodes[0].kill()
	nodes[0] = nil
	path := filepath.Join(roots[0], "mesh", fmt.Sprintf("bake-terrabase-%d.json", generation))
	data, err = os.ReadFile(path)
	must(err)
	var aged map[string]json.RawMessage
	must(json.Unmarshal(data, &aged))
	var agedBake rollout.BakeVerdict
	must(json.Unmarshal(aged["bake"], &agedBake))
	agedBake.FirstSample = time.Now().Add(-rollout.MaxBakeWindow - time.Second).UTC()
	aged["bake"], err = json.Marshal(agedBake)
	must(err)
	data, err = json.Marshal(aged)
	must(err)
	must(os.WriteFile(path, data, 0600))
	reconnect := conn.StatusChanged(nats.CONNECTED)
	nodes[0] = boot(0)
	select {
	case <-reconnect:
	case <-ctx.Done():
		panic(ctx.Err())
	}
	bounded := evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Reason != "" })
	require(strings.Contains(bounded.Bake.Reason, "total observation bound"), "restart extended the persisted total bound")
	require(states(ctx, conn)[order[1]].Ready[spec.Name] < generation, "total-bound failure admitted the next region")
	logStep("ten-minute total bound uses the persisted first sample and survives restart")
	pid, err := os.ReadFile(filepath.Join(roots[0], "containerd.pid"))
	must(err)
	runtimePID := strings.TrimSpace(string(pid))
	must(exec.Command("kill", "-TERM", runtimePID).Run())
	socketGone(ctx, filepath.Join(roots[0], "run", "containerd.sock"))
	require(len(states(ctx, conn)) == 3, "mesh stopped with containerd")
	response, err := http.Get("http://" + addresses[0] + ":18085/health")
	must(err)
	response.Body.Close()
	require(response.StatusCode == http.StatusOK, "shim task stopped with containerd")
	require(strings.Contains(health(ctx, releases, spec.Name), "container runtime unreachable"), "stopped runtime passed named health")
	require(strings.Contains(health(ctx, releases, ""), "container runtime unreachable"), "stopped runtime passed unnamed health")
	logStep("stopped runtime fails health while mesh, swarm agent and shim-owned service remain alive")
	swarms[0].stop()
	swarms[0] = nil
	require(len(states(ctx, conn)) == 3, "mesh stopped with the swarm node")
	require(health(ctx, releases, "") != "ok", "unnamed binary health ignored the unavailable swarm node")
	logStep("unnamed orchestrator health fails while mesh is up and the swarm node is unavailable")
	fmt.Println("rollout journey passed")
}

func socketGone(ctx context.Context, path string) {
	watcher, err := fsnotify.NewWatcher()
	must(err)
	defer watcher.Close()
	must(watcher.Add(filepath.Dir(path)))
	for {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return
		}
		select {
		case <-watcher.Events:
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}
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
