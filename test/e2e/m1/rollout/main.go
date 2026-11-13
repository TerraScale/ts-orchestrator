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
	metadata.Config.Cmd = []string{"--port", "8097"}
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
	for _, name := range []string{"app-canary", "install-canary", "invalid-canary", "nonce-canary"} {
		_, err = client.ImageService().Create(ctx, images.Image{Name: strings.Replace(spec.Image, "/terrabase@", "/"+name+"@", 1), Target: target})
		must(err)
	}
	data, err = json.Marshal(spec)
	must(err)
	must(os.WriteFile(filepath.Join(root, "spec.json"), data, 0600))
	metadata.Config.Labels["journey.image"] = "replacement"
	manifest.Config = write(metadata, manifest.Config.MediaType)
	replacement := write(manifest, imagespec.MediaTypeImageManifest)
	labels["containerd.io/gc.ref.content.config"] = manifest.Config.Digest.String()
	_, err = store.Update(ctx, content.Info{Digest: replacement.Digest, Labels: labels}, "labels")
	must(err)
	replacementName := "ghcr.io/terrascale/terrabase@" + replacement.Digest.String()
	_, err = client.ImageService().Create(ctx, images.Image{Name: replacementName, Target: replacement})
	must(err)
	must(os.WriteFile(filepath.Join(root, "replacement-image"), []byte(replacementName), 0600))
}

func signedToken(key *rsa.PrivateKey, run, service string) string {
	repository, workflow := "TerraScale/terrascale", "ci.yml"
	if service == "app-canary" {
		repository, workflow = "TerraScale/ts-orchestrator", "app-canary.yml"
	}
	encode := func(v any) string {
		data, err := json.Marshal(v)
		must(err)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	header := encode(map[string]string{"alg": "RS256", "kid": "journey"})
	claims := encode(map[string]any{
		"iss": "https://token.actions.githubusercontent.com", "aud": "ts-orch",
		"exp": time.Now().Add(time.Hour).Unix(), "nbf": time.Now().Add(-time.Minute).Unix(),
		"repository": repository, "repository_owner": "TerraScale", "ref": "refs/heads/main",
		"sha": revision, "run_id": run, "run_attempt": "1", "event_name": "workflow_dispatch",
		"job_workflow_ref": repository + "/.github/workflows/" + workflow + "@refs/heads/main",
	})
	signed := header + "." + claims
	sum := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	must(err)
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signedRelease(ctx context.Context, conn *nats.Conn, key *rsa.PrivateKey, image, run string) {
	reply := releaseReply(ctx, conn, key, "terrabase", image, run)
	require(reply.State == "accepted", "signed release refused: "+reply.Error)
}

func releaseReply(ctx context.Context, conn *nats.Conn, key *rsa.PrivateKey, service, image, run string) releasepush.Reply {
	data, err := json.Marshal(releasepush.AppRelease{Service: service, Image: image, Token: signedToken(key, run, service)})
	must(err)
	message, err := conn.RequestWithContext(ctx, releasepush.SubjectApp, data)
	must(err)
	var reply releasepush.Reply
	must(json.Unmarshal(message.Data, &reply))
	return reply
}

func serviceCLI(ctx context.Context, namespace, launcher, root string, args ...string) ([]byte, error) {
	command := []string{"netns", "exec", namespace, "unshare", "--mount", "--uts", "--propagation", "private", "bash", launcher, root, filepath.Join(root, "..", "ts-orch"), "service"}
	return exec.CommandContext(ctx, "ip", append(command, args...)...).CombinedOutput()
}

func unsignedRefused(ctx context.Context, namespace, launcher, root string, spec swarmruntime.ServiceSpec, generation int64) {
	data, err := json.Marshal(spec)
	must(err)
	path := filepath.Join(root, "apply.json")
	must(os.WriteFile(path, data, 0600))
	output, err := serviceCLI(ctx, namespace, launcher, root, "apply", "-f", path)
	require(err != nil && strings.Contains(string(output), fmt.Sprint(generation)) && strings.Contains(string(output), "release again"), "service apply did not name the failed generation and release instruction: "+string(output))
	output, err = serviceCLI(ctx, namespace, launcher, root, "resume", spec.Name)
	require(err != nil && strings.Contains(string(output), fmt.Sprint(generation)) && strings.Contains(string(output), "release again"), "service resume cleared a failed bake: "+string(output))
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
	case "clocks":
		clockCases(ctx, os.Args[2])
	case "clock":
		clockCase(ctx, os.Args[2], os.Args[3])
	case "sampler":
		hostSamplerCase(ctx, os.Args[2])
	case "prepare":
		prepareImage(ctx, os.Args[2], os.Args[3])
	case "swarm":
		runSwarm(ctx, os.Args[2])
	case "region":
		runRegion(ctx, os.Args[2:])
	case "inventory":
		client, conn, err := swarmruntime.DialSingleHost(os.Args[2])
		must(err)
		defer conn.Close()
		rows, err := swarmruntime.ListServiceSpecs(ctx, client)
		must(err)
		must(json.NewEncoder(os.Stdout).Encode(rows))
	case "control":
		control(ctx, os.Args[2:])
	case "journey", "install":
		journey(ctx, os.Args[2], os.Args[3], os.Args[4], os.Args[1] == "install")
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
	serverName, err := os.Hostname()
	must(err)
	node, err := mesh.StartRegionalHost(mesh.RegionalHost{State: root, Region: region, Server: serverName, CA: ca,
		TerraBaseToken: fmt.Sprintf("%x", seed), Seeds: map[string]string{peerRegion: "nats://" + peerAddress + ":6222"},
		ClusterAddress: address + ":6222", Address: func() (string, error) { return address, nil }})
	must(err)
	defer node.Close()
	if _, err := os.Stat(filepath.Join(root, "budget-full")); err == nil {
		fillMesh(root)
	}
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
	done    chan struct{}
	result  error
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
	p := &process{command: command, done: make(chan struct{})}
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Fprintln(logfile, line)
			if line == "READY" {
				close(ready)
			}
		}
		p.result = command.Wait()
		logfile.Close()
		close(p.done)
	}()
	select {
	case <-ready:
		return p
	case <-p.done:
		detail, readErr := os.ReadFile(filepath.Join(root, mode+".log"))
		must(readErr)
		panic(fmt.Errorf("%s startup: %v: %s", mode, p.result, detail[max(0, len(detail)-4096):]))
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

type admissionDecision struct {
	Generation int64
	At         time.Time
	Earlier    string
	Evidence   string
}

type state struct {
	Region       string                        `json:"region"`
	Ready        map[string]int64              `json:"ready"`
	Serving      map[string]mesh.ServingResult `json:"serving"`
	Failed       map[string]int64              `json:"failed"`
	Desired      map[string]json.RawMessage    `json:"desired"`
	Unsaved      map[string]int64              `json:"unsaved"`
	Admission    map[string]admissionDecision  `json:"admission"`
	BakeRequired map[string]bool               `json:"bakeRequired"`
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
			_ = exec.Command("pkill", "-QUIT", "-f", "^"+os.Args[0]+" region ").Run()
			panic(fmt.Sprintf("state replies exceeded the one-second rollout collection window: got %d regions", len(result)))
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
	Runtime struct {
		Tasks []swarmruntime.ServiceTaskEvidence
	} `json:"runtime"`
	Generation    int64               `json:"generation"`
	Interruptions int                 `json:"interruptions"`
	Bake          rollout.BakeVerdict `json:"bake"`
	Release       *mesh.Deployment    `json:"release"`
	ReplacedBy    *struct {
		Generation int64
		Release    mesh.Deployment
	} `json:"replacedBy"`
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

func journey(ctx context.Context, root, launcher, specFile string, installOnly bool) {
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

	baselineGeneration := time.Now().UnixNano()
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
		baseline.Generation = baselineGeneration
		command(ctx, names[i], roots[i], baseline)
		must(os.MkdirAll(filepath.Join(roots[i], "mesh"), 0700))
		local, err := json.Marshal(map[string]mesh.Entry{"terrabase": {Generation: baselineGeneration, Spec: &baseline}})
		must(err)
		must(os.WriteFile(filepath.Join(roots[i], "mesh", "desired.json"), local, 0600))

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
	apply := func(generation int64, hold string) {
		request := mesh.ApplyRequest{Name: spec.Name, Entry: mesh.Entry{Generation: generation, Spec: &spec, HoldAfter: hold, Deployment: &mesh.Deployment{Repository: "TerraScale/terrascale", RunID: "100", RunAttempt: 1, Revision: revision, Image: spec.Image}}}
		data, err := json.Marshal(request)
		must(err)
		must(conn.PublishRequest(mesh.ApplySubject, nats.NewInbox(), data))
		must(conn.Flush())
	}
	topologyReady(ctx, roots)
	if installOnly {
		nonceCases(ctx, conn, roots, order, names, launcher, spec)
		installCases(ctx, conn, nodes, boot, roots, order, names, launcher, spec)
		unsavedCase(ctx, conn, releases, key, nodes, boot, roots, order, addresses, spec)
		budgetCases(ctx, conn, releases, nodes, swarms, boot, roots, order, names, addresses, launcher, spec)
		fmt.Println("install and budget journey passed")
		return
	}
	management, err := os.ReadFile(filepath.Join(root, "management.json"))
	must(err)
	var initialApply swarmruntime.ServiceSpec
	must(json.Unmarshal(management, &initialApply))
	initialApply.Image, initialApply.Port, initialApply.Args, initialApply.Regions = spec.Image, 18090, []string{"--port", "18090"}, []string{order[0]}
	initialApply.Env, initialApply.Mounts, initialApply.Hostnames = nil, nil, nil
	initialApply.ReadyPath = spec.ReadyPath
	initialData, err := json.Marshal(initialApply)
	must(err)
	initialPath := filepath.Join(roots[0], "management.json")
	must(os.WriteFile(initialPath, initialData, 0600))
	for range 2 {
		output, err := serviceCLI(ctx, names[0], launcher, roots[0], "apply", "-f", initialPath)
		require(err == nil, fmt.Sprintf("management service plain apply: %v %s", err, output))
	}
	entries, err := os.ReadDir(filepath.Join(roots[0], "mesh"))
	must(err)
	require(len(entries) > 0, "management apply lost local state")
	logStep("management service declaration applied twice through service apply completes its bake")

	replacementImage, err := os.ReadFile(filepath.Join(roots[0], "replacement-image"))
	must(err)
	spec.Image = string(replacementImage)
	generation := time.Now().UnixNano()
	apply(generation, order[1])
	initial := evidence(ctx, roots[0], generation, func(r receipt) bool { return !r.Bake.Started.IsZero() })
	require(initial.Bake.Finished.IsZero(), "interruption did not happen during the bake")
	assertWaiting(ctx, conn, order[1], spec.Name, generation, order[0], "passed bake missing")
	assertRuntimeBefore(ctx, names[1], launcher, roots[1], spec.Name, generation)
	initialReconnected := conn.StatusChanged(nats.CONNECTED)
	nodes[0].kill()
	nodes[0] = nil
	nodes[0] = boot(0)
	select {
	case <-initialReconnected:
	case <-ctx.Done():
		panic(ctx.Err())
	}
	restarted := evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Started.After(initial.Bake.Started) })
	require(restarted.Bake.Finished.IsZero(), "restart did not start a fresh observation window")
	observe(ctx, conn, func(s map[string]state) bool {
		result := s[order[0]].Serving[spec.Name]
		return result.Serving && result.Generation == generation
	})
	assertWaiting(ctx, conn, order[1], spec.Name, generation, order[0], "passed bake missing")
	complete := evidence(ctx, roots[0], generation, func(r receipt) bool { return !r.Bake.Finished.IsZero() })
	require(complete.Bake.Reason == "", "restarted bake failed: "+complete.Bake.Reason)
	require(complete.Bake.Finished.Sub(complete.Bake.Started) >= rollout.BakeWindow, "restart shortened the bake window")
	evidence(ctx, roots[1], generation, func(r receipt) bool { return !r.Bake.Finished.IsZero() && r.Bake.Reason == "" })
	setHealth(ctx, addresses[0], 18085, "503")
	require(health(ctx, releases, spec.Name) != "ok", "unready A passed named release health")
	observe(ctx, conn, func(s map[string]state) bool { return s[order[0]].Ready[spec.Name] < generation })
	apply(generation, "")
	assertWaiting(ctx, conn, order[len(order)-1], spec.Name, generation, order[0], "fresh serving evidence missing")
	logStep("a previously successful bake stops admitting regions when A stops serving")
	setHealth(ctx, addresses[0], 18085, "200")
	next := evidence(ctx, roots[1], generation, func(r receipt) bool { return !r.Bake.Finished.IsZero() })
	require(next.Bake.Reason == "", "later region bake failed: "+next.Bake.Reason)
	observe(ctx, conn, func(s map[string]state) bool { return s[order[1]].Ready[spec.Name] == generation })
	require(len(initial.Runtime.Tasks) > 0 && initial.Runtime.Tasks[0].Image == spec.Image && initial.Runtime.Tasks[0].Generation == generation, "image change did not replace the task")
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
		observed, present := s[order[0]].Serving[slow.Name]
		return present && !observed.At.IsZero() && !observed.Serving && s[order[0]].Ready[spec.Name] == generation
	})
	logStep("a blackholed unrelated readiness endpoint leaves both state replies inside one second")
	generation++
	apply(generation, order[len(order)-1])
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
	apply(generation, order[len(order)-1])
	evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Samples >= 1 })
	setHealth(ctx, addresses[0], 18085, "503")
	two := evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.FailedSamples >= 2 })
	require(two.Bake.FailedSamples == 2 && two.Bake.Reason == "", "two failed samples held the bake")
	setHealth(ctx, addresses[0], 18085, "200")
	evidence(ctx, roots[0], generation, func(r receipt) bool { return !r.Bake.HealthySince.IsZero() })
	logStep("two consecutive failed samples do not fail a bake")
	setHealth(ctx, addresses[0], 18085, "503")
	failed := evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Reason != "" })
	lasting := false
	for probe, count := range failed.Bake.ConsecutiveFailures {
		lasting = lasting || count >= 3 && failed.Bake.Finished.Sub(failed.Bake.FailureSince[probe]) >= rollout.BakeFailureDuration
	}
	require(lasting && strings.Contains(failed.Bake.Reason, "15 seconds"), "lasting probe failure did not hold the bake")
	logStep("at least three consecutive failed samples spanning 15 seconds durably fail the bake")
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
	assertWaiting(ctx, conn, order[1], spec.Name, generation, order[0], "bake failed")
	assertRuntimeBefore(ctx, names[1], launcher, roots[1], spec.Name, generation)
	logStep("an observed regression remains failed across restart after readiness recovers")
	unsignedRefused(ctx, names[0], launcher, roots[0], spec, generation)
	logStep("service resume refuses a failed bake even with a canary hold")
	logStep("service apply refuses a held generation and names the release instruction")
	require(retained.Release != nil && retained.Release.RunID == "100" && retained.Release.RunAttempt == 1 && retained.Release.Repository == "TerraScale/terrascale" && retained.Release.Revision == revision && retained.Release.Image == spec.Image, "failed receipt omitted held signed release identity")
	signedRelease(ctx, releases, key, spec.Image, "100")
	observe(ctx, conn, func(s map[string]state) bool {
		reply := releaseReply(ctx, releases, key, spec.Name, spec.Image, "100")
		require(newGeneration(s, order[0]) == generation && s[order[0]].Failed[spec.Name] == generation, "replayed held release replaced its generation")
		if reply.State != "failed" {
			return false
		}
		require(strings.Count(reply.Error, "RunID:100") >= 2 && strings.Contains(reply.Error, "strictly newer"), "replay refusal omitted both release identities: "+reply.Error)
		return true
	})
	logStep("handler restart refuses replay of the same signed run and attempt and retains its hold")
	held := generation
	nodes[0].kill()
	olderHoldReceipt(roots[0], held)
	nodes[0] = boot(0)
	signedRelease(ctx, releases, key, spec.Image, "101")
	observe(ctx, conn, func(s map[string]state) bool { return newGeneration(s, order[0]) > held })
	generation = newGeneration(states(ctx, conn), order[0])
	evidence(ctx, roots[0], generation, func(r receipt) bool { return r.Bake.Samples >= 1 })
	nodes[0].kill()
	nodes[0] = boot(0)
	evidence(ctx, roots[0], generation, func(r receipt) bool { return !r.Bake.Finished.IsZero() && r.Bake.Reason == "" })
	for i := 1; i < len(roots); i++ {
		evidence(ctx, roots[i], generation, func(r receipt) bool { return !r.Bake.Finished.IsZero() && r.Bake.Reason == "" })
	}
	observe(ctx, conn, func(s map[string]state) bool { return s[order[len(order)-1]].Ready[spec.Name] == generation })
	replaced := evidence(ctx, roots[0], held, func(r receipt) bool { return r.ReplacedBy != nil })
	require(replaced.Release != nil && replaced.Release.RunID == "100", "older receipt release identity was not recovered and saved")
	logStep("older hold receipt recovers its own signed release identity before replacement")
	replacement := replaced.ReplacedBy
	require(replacement.Generation == generation && replacement.Release.Repository == "TerraScale/terrascale" && replacement.Release.RunID == "101" && replacement.Release.RunAttempt == 1 && replacement.Release.Revision == revision && replacement.Release.Image == spec.Image, "replacement journal omitted release identity")
	logStep("release journals the local held generation and deployment; restart retains it and every region completes")

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
