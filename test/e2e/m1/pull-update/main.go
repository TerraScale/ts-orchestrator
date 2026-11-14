package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/pullrelease"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/sigstore/sigstore-go/pkg/root"
)

const (
	asset      = releaseattest.AssetPrefix + runtime.GOARCH
	healthyFor = 2 * time.Second
	deadline   = 20 * time.Second
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func require(ok bool, format string, args ...any) {
	if !ok {
		panic(fmt.Sprintf(format, args...))
	}
}

func candidateMode() string {
	path, err := os.Executable()
	must(err)
	data, err := os.ReadFile(path)
	must(err)
	marker := bytes.LastIndex(data, []byte("\nCANDIDATE:"))
	if marker < 0 {
		return ""
	}
	return string(data[marker+len("\nCANDIDATE:"):])
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "release" && os.Args[2] == "preflight" {
		return
	}
	if len(os.Args) == 11 && os.Args[1] == "host" {
		runHost(os.Args[2:])
		return
	}
	require(len(os.Args) == 2, "usage: pull-update <ts-orch binary>")
	journey(os.Args[1])
}

func runHost(args []string) {
	dir, region, id, role, natsURL, githubURL, rootFile, listen, poll := args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8]
	ctx := context.Background()
	state := filepath.Join(dir, "state")
	must(os.MkdirAll(filepath.Join(state, "nats"), 0o700))
	h, err := releasepush.NewHandler(state)
	if err != nil {
		fmt.Fprintln(os.Stderr, "release handler:", err)
		os.Exit(5)
	}
	client := githubClient(githubURL)
	h.Verifier.JWKSURL = githubURL + "/jwks"
	h.Client, h.Source.Client = client, client
	data, err := os.ReadFile(rootFile)
	must(err)
	trusted, err := root.NewTrustedRootFromJSON(data)
	must(err)
	h.Attest = releaseattest.Verifier{Root: trusted}
	mode := candidateMode()
	h.Health = func(context.Context, string) releasepush.HealthResult {
		if mode == "unhealthy" {
			return releasepush.HealthResult{Service: errors.New("candidate is unhealthy")}
		}
		return releasepush.HealthResult{}
	}
	conn, err := nats.Connect(natsURL)
	must(err)
	must(h.ServePulled(conn, region, id))
	if probation, err := releasepush.Probe(state, os.Stdout); err == nil && probation != nil {
		require(probation.Served(), "%s must confirm its release", id)
	}
	if role == "manager" {
		port, err := strconv.Atoi(listen)
		must(err)
		auth, err := releasepush.NewAuth(h.Verifier)
		must(err)
		options, err := releasepush.Options(state, auth)
		must(err)
		options.Host, options.Port = "127.0.0.1", port
		listener, err := server.NewServer(options)
		must(err)
		go listener.Start()
		require(listener.ReadyForConnections(10*time.Second), "release listener must listen")
		inProcess, err := auth.Connect(listener)
		must(err)
		must(h.ServeNudge(inProcess))
		every, err := time.ParseDuration(poll)
		must(err)
		other := map[string]string{"manager": id, "worker": strings.TrimSuffix(id, "-m") + "-w"}
		updater := &pullrelease.Updater{Region: region, Self: id, State: state, Conn: conn,
			Hosts: func(context.Context) ([]pullrelease.Host, error) {
				return []pullrelease.Host{{ID: other["manager"], Name: other["manager"]}, {ID: other["worker"], Name: other["worker"]}}, nil
			},
			Health: func(ctx context.Context) error { return h.Health(ctx, "").Err() },
			Source: h.Source, Attest: h.Attest, Client: h.Client, Nudges: h.Nudges,
			Poll: every, HealthyFor: healthyFor, Deadline: deadline}
		go func() { _ = updater.Run(ctx) }()
	}
	must(conn.Publish("e2e.ready."+region+"."+id, []byte(h.Digest)))
	must(conn.Flush())
	<-h.Installed
	os.Exit(0)
}

type host struct {
	region, id, role, dir string
	args                  []string
	starts                atomic.Int32
	mu                    sync.Mutex
	cmd                   *exec.Cmd
}

func (h *host) supervise(ctx context.Context) {
	log, err := os.OpenFile(filepath.Join(h.dir, "host.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	must(err)
	defer log.Close()
	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, filepath.Join(h.dir, "bin", "terrascale-orchestrator"), h.args...)
		cmd.Stdout, cmd.Stderr = log, log
		h.mu.Lock()
		h.cmd = cmd
		err := cmd.Start()
		h.mu.Unlock()
		must(err)
		h.starts.Add(1)
		_ = cmd.Wait()
	}
}

func (h *host) kill() {
	h.mu.Lock()
	defer h.mu.Unlock()
	must(h.cmd.Process.Kill())
}

type lane struct {
	bin       string
	self      []byte
	revision  string
	github    *fakeGitHub
	sigstore  *testSigstore
	hosts     map[string]*host
	conns     map[string]*nats.Conn
	progress  map[string]chan pullrelease.Status
	last      map[string]pullrelease.Status
	ready     chan [2]string
	regionsGR string
}

func journey(bin string) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	self, err := os.Executable()
	must(err)
	selfBytes, err := os.ReadFile(self)
	must(err)
	revision := releasepush.Revision()
	require(regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(revision), "the journey binary needs a clean VCS revision, has %q", revision)
	work, err := os.MkdirTemp("", "pull-update-")
	must(err)
	defer os.RemoveAll(work)
	l := &lane{bin: bin, self: selfBytes, revision: revision, github: newGitHub(), sigstore: newSigstore(),
		hosts: map[string]*host{}, conns: map[string]*nats.Conn{}, progress: map[string]chan pullrelease.Status{},
		last: map[string]pullrelease.Status{}, ready: make(chan [2]string, 64)}
	defer func() {
		if failure := recover(); failure != nil {
			for id, h := range l.hosts {
				data, _ := os.ReadFile(filepath.Join(h.dir, "host.log"))
				lines := strings.Split(strings.TrimSpace(string(data)), "\n")
				fmt.Printf("--- %s (%d starts)\n%s\n", id, h.starts.Load(), strings.Join(lines[max(0, len(lines)-25):], "\n"))
			}
			panic(failure)
		}
	}()
	defer l.github.server.Close()
	rootFile := filepath.Join(work, "trusted-root.json")
	must(os.WriteFile(rootFile, l.sigstore.trustedRoot(), 0o600))
	polls := map[string]string{"gru": "1h", "sjc": "3s"}
	for _, region := range []string{"gru", "sjc"} {
		mesh, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoSigs: true, NoLog: true, ServerName: region})
		must(err)
		go mesh.Start()
		require(mesh.ReadyForConnections(10*time.Second), "%s mesh must listen", region)
		defer mesh.Shutdown()
		conn, err := nats.Connect(mesh.ClientURL())
		must(err)
		defer conn.Close()
		l.conns[region] = conn
		statuses := make(chan pullrelease.Status, 256)
		l.progress[region] = statuses
		_, err = conn.Subscribe(protocol.MeshPullProgressPrefix+region, func(m *nats.Msg) {
			var status pullrelease.Status
			must(json.Unmarshal(m.Data, &status))
			statuses <- status
		})
		must(err)
		_, err = conn.Subscribe("e2e.ready.>", func(m *nats.Msg) {
			l.ready <- [2]string{strings.TrimPrefix(m.Subject, "e2e.ready."), string(m.Data)}
		})
		must(err)
		must(conn.Flush())
		for _, role := range []string{"manager", "worker"} {
			id := region + "-" + role[:1]
			dir := filepath.Join(work, id)
			must(os.MkdirAll(filepath.Join(dir, "bin"), 0o700))
			must(os.WriteFile(filepath.Join(dir, "bin", "terrascale-orchestrator"), selfBytes, 0o755))
			port := "0"
			if role == "manager" {
				port = freePort()
				if region == "gru" {
					var pin bytes.Buffer
					must(releasepush.Pin([]string{"--state", filepath.Join(dir, "state")}, &pin))
					l.regionsGR = filepath.Join(work, "regions.json")
					regions, err := json.Marshal([]releasepush.Region{{Region: "gru", NATS: "tls://127.0.0.1:" + port, SPKISHA256: strings.TrimSpace(pin.String())}})
					must(err)
					must(os.WriteFile(l.regionsGR, regions, 0o600))
				}
			}
			l.hosts[id] = &host{region: region, id: id, role: role, dir: dir,
				args: []string{"host", dir, region, id, role, mesh.ClientURL(), l.github.server.URL, rootFile, port, polls[region]}}
		}
	}
	for _, h := range l.hosts {
		go h.supervise(ctx)
	}
	base := hex.EncodeToString(sha256Of(selfBytes))
	for range l.hosts {
		l.waitReady(ctx, "", base)
	}
	fmt.Println("cell up: gru and sjc, a manager and a worker each, on the base binary")

	r1 := l.publishGood("101", "c101")
	l.github.mint(revision, "101")
	require(strings.Contains(l.nudge(ctx), "gru: nudged"), "the first nudge must be accepted")
	require(strings.Contains(l.nudge(ctx), "gru: throttled"), "a second nudge within the spacing must be throttled")
	gru := l.waitStatus(ctx, "gru", "gru completes "+r1.tag+" after the nudge", complete(r1))
	sjc := l.waitStatus(ctx, "sjc", "sjc completes "+r1.tag+" by its poll alone", complete(r1))
	require(gru.Nudged == r1.tag && sjc.Nudged == "", "only gru was nudged: gru %q sjc %q", gru.Nudged, sjc.Nudged)
	l.requireVersions(ctx, r1.digest, "gru-m", "gru-w", "sjc-m", "sjc-w")
	fmt.Printf("nudge -> gru pulled %s; lost nudge -> sjc polled it; every host verified and on it\n%s\n%s\n", r1.tag, gru, sjc)

	wrongWorkflow := identity{workflow: "TerraScale/ts-orchestrator/.github/workflows/lint-cache.yml@refs/heads/main", ref: "refs/heads/main", trigger: "push"}
	wrongBranch := identity{workflow: "TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/feature", ref: "refs/heads/feature", trigger: "push"}
	c102, c103, c104, c105, c106 := l.candidate("c102"), l.candidate("c103"), l.candidate("c104"), l.candidate("c105"), l.candidate("c106")
	tampered := append(bytes.Clone(c105[:len(c105)-1]), c105[len(c105)-1]^1)
	other := strings.Repeat("e", 40)
	l.github.mu.Lock()
	l.github.compare[revision+"..."+other] = "diverged"
	l.github.mu.Unlock()
	refusals := []struct {
		name   string
		run    string
		sha    string
		binary []byte
		served []byte
		bundle []byte
		reason string
		direct bool
	}{
		{"wrong workflow", "102", revision, c102, c102, l.sigstore.bundle(wrongWorkflow, revision, "102", map[string][]byte{asset: c102}), "not signed by", true},
		{"wrong branch", "103", revision, c103, c103, l.sigstore.bundle(wrongBranch, revision, "103", map[string][]byte{asset: c103}), "not signed by", true},
		{"unattested", "104", revision, c104, c104, nil, "not found", false},
		{"tampered", "105", revision, c105, tampered, l.sigstore.bundle(mainIdentity, revision, "105", map[string][]byte{asset: c105}), "sha256 differs", false},
		{"not a descendant", "106", other, c106, c106, l.sigstore.bundle(mainIdentity, other, "106", map[string][]byte{asset: c106}), "does not descend", true},
	}
	for _, refusal := range refusals {
		release := l.github.publish(refusal.sha, refusal.run, asset, refusal.binary, refusal.served, refusal.bundle)
		status := l.waitStatus(ctx, "sjc", "sjc refuses the "+refusal.name+" release", func(s pullrelease.Status) bool {
			return s.Phase == pullrelease.PhaseRefused && s.Target != nil && s.Target.Tag() == release.tag
		})
		require(strings.Contains(status.Reason, refusal.reason), "%s: refusal %q lacks %q", refusal.name, status.Reason, refusal.reason)
		if refusal.direct {
			reply := l.ask(ctx, "gru", "gru-w", releasepush.PullRequest{Op: releasepush.PullInstall, Release: l.release(release)})
			require(reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalIntegrity && strings.Contains(reply.Refusal.Reason, refusal.reason),
				"%s: gru-w must refuse it itself, replied %+v", refusal.name, reply)
		}
		fmt.Printf("%s release %s refused: %s\n", refusal.name, release.tag, status.Reason)
	}
	l.requireVersions(ctx, r1.digest, "gru-m", "gru-w", "sjc-m", "sjc-w")
	fmt.Println("refused releases -> no host changed")

	managerStarts := l.hosts["sjc-m"].starts.Load()
	l.drainReady()
	r7 := l.publishGood("107", "unhealthy")
	status := l.waitStatus(ctx, "sjc", "sjc rolls back the unhealthy "+r7.tag, func(s pullrelease.Status) bool {
		return s.Phase == pullrelease.PhaseRolledBack && s.Target != nil && s.Target.Tag() == r7.tag
	})
	require(strings.Contains(status.Reason, "unhealthy") && len(status.Hosts) == 2 && status.Hosts[0].ID == "sjc-w" && status.Hosts[0].State == pullrelease.HostRolledBack,
		"the worker's gate must fail on health: %s", status)
	l.waitReady(ctx, "sjc.sjc-w", r1.digest)
	l.requireVersions(ctx, r1.digest, "sjc-m", "sjc-w")
	require(l.hosts["sjc-m"].starts.Load() == managerStarts, "the manager must not restart while its worker's release fails")
	fmt.Printf("unhealthy candidate -> rolled back to the previous binary; the manager never left it\n%s\n", status)

	workerStarts, gruStarts := l.hosts["gru-w"].starts.Load(), l.hosts["gru-m"].starts.Load()
	r8 := l.publishGood("108", "c108")
	l.github.mint(revision, "108")
	require(strings.Contains(l.nudge(ctx), "gru: nudged"), "the nudge for %s must be accepted", r8.tag)
	l.waitStatus(ctx, "gru", "gru gates its worker on "+r8.tag, func(s pullrelease.Status) bool {
		return s.Target != nil && s.Target.Tag() == r8.tag && len(s.Hosts) != 0 && s.Hosts[0].ID == "gru-w" && s.Hosts[0].State == pullrelease.HostGating
	})
	l.hosts["gru-m"].kill()
	gru = l.waitStatus(ctx, "gru", "gru resumes and completes "+r8.tag, complete(r8))
	l.waitStatus(ctx, "sjc", "sjc moves past the rolled-back release to "+r8.tag, complete(r8))
	l.requireVersions(ctx, r8.digest, "gru-m", "gru-w", "sjc-m", "sjc-w")
	require(l.hosts["gru-w"].starts.Load() == workerStarts+1, "the worker must install exactly once, started %d times", l.hosts["gru-w"].starts.Load()-workerStarts)
	require(l.hosts["gru-m"].starts.Load() == gruStarts+2, "the manager restarts once when killed and once for its own update, started %d times", l.hosts["gru-m"].starts.Load()-gruStarts)
	fmt.Printf("orchestrator killed mid-rollout -> resumed, worker installed once, manager updated itself last\n%s\n", gru)
}

func complete(release published) func(pullrelease.Status) bool {
	return func(s pullrelease.Status) bool {
		return s.Phase == pullrelease.PhaseComplete && s.Target != nil && s.Target.Tag() == release.tag
	}
}

func sha256Of(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func freePort() string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer listener.Close()
	return strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
}

func (l *lane) candidate(mode string) []byte {
	return append(bytes.Clone(l.self), []byte("\nCANDIDATE:"+mode)...)
}

func (l *lane) publishGood(run, mode string) published {
	binary := l.candidate(mode)
	return l.github.publish(l.revision, run, asset, binary, binary, l.sigstore.bundle(mainIdentity, l.revision, run, map[string][]byte{asset: binary}))
}

func (l *lane) release(p published) releaseattest.Release {
	return releaseattest.Release{SHA: p.sha, RunID: p.run, Bundle: releaseattest.AssetURL(p.sha, p.run, releaseattest.BundleAsset),
		Binaries: map[string]releaseattest.Artifact{runtime.GOARCH: {URL: releaseattest.AssetURL(p.sha, p.run, asset), SHA256: p.digest}}}
}

func (l *lane) nudge(ctx context.Context) string {
	command := exec.CommandContext(ctx, l.bin, "release", "nudge", "--regions", l.regionsGR)
	command.Env = append(os.Environ(), "ACTIONS_ID_TOKEN_REQUEST_URL="+l.github.server.URL+"/token?api-version=2.0", "ACTIONS_ID_TOKEN_REQUEST_TOKEN=e2e")
	output, err := command.CombinedOutput()
	require(err == nil, "release nudge: %v: %s", err, output)
	fmt.Print(string(output))
	return string(output)
}

func (l *lane) ask(ctx context.Context, region, id string, request releasepush.PullRequest) releasepush.Reply {
	data, err := json.Marshal(request)
	must(err)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	message, err := l.conns[region].RequestWithContext(ctx, releasepush.PullSubject(region, id), data)
	must(err)
	var reply releasepush.Reply
	must(json.Unmarshal(message.Data, &reply))
	return reply
}

func (l *lane) requireVersions(ctx context.Context, digest string, ids ...string) {
	for _, id := range ids {
		reply := l.ask(ctx, l.hosts[id].region, id, releasepush.PullRequest{Op: releasepush.PullStatus})
		require(reply.Version == l.revision && reply.SHA256 == digest && reply.Health == "ok",
			"%s must run %s and be healthy, runs %s %s (%s)", id, digest, reply.Version, reply.SHA256, reply.Health)
	}
}

func (l *lane) drainReady() {
	for {
		select {
		case <-l.ready:
		default:
			return
		}
	}
}

func (l *lane) waitReady(ctx context.Context, who, digest string) {
	for {
		select {
		case ready := <-l.ready:
			if (who == "" || ready[0] == who) && ready[1] == digest {
				return
			}
		case <-ctx.Done():
			panic(fmt.Sprintf("timed out waiting for %q to start on %s", who, digest))
		}
	}
}

func (l *lane) waitStatus(ctx context.Context, region, what string, done func(pullrelease.Status) bool) pullrelease.Status {
	for {
		select {
		case status := <-l.progress[region]:
			l.last[region] = status
			active := 0
			for _, host := range status.Hosts {
				if host.State == pullrelease.HostInstalling || host.State == pullrelease.HostGating {
					active++
				}
			}
			require(active <= 1, "%s: two hosts of one region are out of service at once:\n%s", region, status)
			if done(status) {
				return status
			}
		case <-ctx.Done():
			panic(fmt.Sprintf("timed out waiting until %s; last %s status:\n%s", what, region, l.last[region]))
		}
	}
}
