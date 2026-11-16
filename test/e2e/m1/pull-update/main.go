package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/pullrelease"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/sigstore/sigstore-go/pkg/root"
)

const (
	asset        = releaseattest.AssetPrefix + runtime.GOARCH
	healthyFor   = 2 * time.Second
	orchUser     = "orch"
	orchSecret   = "e2e-orch-secret"
	fabricUser   = "ts-orch"
	fabricSecret = "e2e-fabric-secret"
	deadline     = 20 * time.Second
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
	require(len(os.Args) == 3 && (os.Args[2] == "pull" || os.Args[2] == "push" || os.Args[2] == "degraded"), "usage: pull-update <ts-orch binary> pull|push|degraded")
	journey(os.Args[1], os.Args[2])
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
	h.PrepareStop = func(context.Context) error {
		if _, err := os.Stat(filepath.Join(dir, "refuse-stop")); err == nil {
			return errors.New("the region's raft quorum would be lost")
		}
		return nil
	}
	conn, err := nats.Connect(natsURL, nats.UserInfo(orchUser, orchSecret))
	must(err)
	fabric, err := nats.Connect(natsURL, nats.UserInfo(fabricUser, fabricSecret))
	must(err)
	must(h.ServeHostVersion(conn, region, id))
	must(h.ServePulled(conn, region, id))
	if role == "worker" {
		must(h.ServeWorker(conn, protocol.MeshWorkerReleasePrefix+region, id))
	}
	if probation, err := releasepush.Probe(state, os.Stdout); err == nil && probation != nil {
		require(probation.Served(), "%s must confirm its release", id)
	}
	var listener *server.Server
	if role == "manager" {
		h.Claim = func(ctx context.Context, release, sha string, digests map[string]string) error {
			return pullrelease.ClaimPush(ctx, fabric, region, pullrelease.PushClaim{Release: release, SHA: sha, Binaries: digests, Host: id})
		}
		h.Unclaim = func(ctx context.Context, release string) {
			must(pullrelease.ReleasePush(ctx, fabric, region, release))
		}
		h.HostReady = func(ctx context.Context, host, sha string, digests map[string]string) error {
			return releasepush.AwaitReady(ctx, conn, region, host, sha, digests)
		}
		h.Relay = func(ctx context.Context, request []byte) []releasepush.HostVersion {
			worker := &api.Node{ID: region + "-w", Role: api.NodeRoleWorker, Status: api.NodeStatus{State: api.NodeStatus_READY}}
			if _, err := os.Stat(filepath.Join(filepath.Dir(dir), region+"-w", "stopped")); err == nil {
				worker.Status.State = api.NodeStatus_DOWN
			}
			return releasepush.RelayWorkers(ctx, conn, protocol.MeshWorkerReleasePrefix+region, request, []*api.Node{worker})
		}
		if listen != "0" {
			port, err := strconv.Atoi(listen)
			must(err)
			auth, err := releasepush.NewAuth(h.Verifier)
			must(err)
			options, err := releasepush.Options(state, auth)
			must(err)
			options.Host, options.Port = "127.0.0.1", port
			listener, err = server.NewServer(options)
			must(err)
			go listener.Start()
			require(listener.ReadyForConnections(10*time.Second), "release listener must listen")
			inProcess, err := auth.Connect(listener)
			must(err)
			must(h.Serve(inProcess))
			if region == "gru" {
				var pin bytes.Buffer
				must(releasepush.Pin([]string{"--state", state}, &pin))
				regions, err := json.Marshal([]releasepush.Region{{Region: region, NATS: listener.ClientURL(), SPKISHA256: strings.TrimSpace(pin.String())}})
				must(err)
				path := filepath.Join(filepath.Dir(dir), "regions.json")
				must(os.WriteFile(path+".tmp", regions, 0o600))
				must(os.Rename(path+".tmp", path))
			}
		}
		every, err := time.ParseDuration(poll)
		must(err)
		updater := &pullrelease.Updater{Region: region, Self: id, State: state, Conn: conn, Fabric: fabric,
			Hosts: func(context.Context) ([]pullrelease.Host, error) {
				hosts := []pullrelease.Host{}
				for _, suffix := range []string{"-m", "-n", "-w"} {
					hosts = append(hosts, pullrelease.Host{ID: region + suffix, Name: region + suffix})
				}
				return hosts, nil
			},
			Health: func(ctx context.Context) error { return h.Health(ctx, "").Err() },
			Source: h.Source, Attest: h.Attest, Client: h.Client, Nudges: h.Nudges,
			Poll: every, HealthyFor: healthyFor, Deadline: deadline}
		go func() { _ = updater.Run(ctx) }()
	}
	must(conn.Publish("e2e.ready."+region+"."+id, []byte(h.Digest)))
	must(conn.Flush())
	<-h.Installed
	if listener != nil {
		listener.Shutdown()
		listener.WaitForShutdown()
	}
	must(conn.Publish("e2e.down."+region+"."+id, nil))
	must(conn.Flush())
	os.Exit(0)
}

type host struct {
	region, id, role, dir string
	args                  []string
	starts                atomic.Int32
	mu                    sync.Mutex
	cmd                   *exec.Cmd
	hold                  chan struct{}
}

func (h *host) supervise(ctx context.Context) {
	log, err := os.OpenFile(filepath.Join(h.dir, "host.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	must(err)
	defer log.Close()
	for ctx.Err() == nil {
		h.mu.Lock()
		hold := h.hold
		h.mu.Unlock()
		if hold != nil {
			select {
			case <-hold:
			case <-ctx.Done():
				return
			}
		}
		cmd := exec.CommandContext(ctx, filepath.Join(h.dir, "bin", "terrascale-orchestrator"), h.args...)
		cmd.Stdout, cmd.Stderr = log, log
		h.mu.Lock()
		h.cmd = cmd
		err := cmd.Start()
		h.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		must(err)
		h.starts.Add(1)
		_ = cmd.Wait()
	}
}

func (h *host) holdRestart() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hold = make(chan struct{})
}

func (h *host) releaseRestart() {
	h.mu.Lock()
	defer h.mu.Unlock()
	close(h.hold)
	h.hold = nil
}

func (h *host) kill() {
	h.mu.Lock()
	defer h.mu.Unlock()
	must(h.cmd.Process.Kill())
}

type outages struct {
	mu        sync.Mutex
	down      map[string]map[string]bool
	violation string
}

func (o *outages) mark(region, id string, down bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.down[region] == nil {
		o.down[region] = map[string]bool{}
	}
	if !down {
		delete(o.down[region], id)
		return
	}
	o.down[region][id] = true
	if len(o.down[region]) > 1 && o.violation == "" {
		hosts := []string{}
		for host := range o.down[region] {
			hosts = append(hosts, host)
		}
		slices.Sort(hosts)
		o.violation = fmt.Sprintf("%s: hosts %v are out of service at once", region, hosts)
	}
}

func (o *outages) check() {
	o.mu.Lock()
	defer o.mu.Unlock()
	require(o.violation == "", "%s", o.violation)
}

type lane struct {
	bin       string
	self      []byte
	revision  string
	github    *fakeGitHub
	sigstore  *testSigstore
	hosts     map[string]*host
	conn      *nats.Conn
	outages   *outages
	progress  map[string]chan pullrelease.Status
	last      map[string]pullrelease.Status
	ready     chan [2]string
	downs     chan string
	regionsGR string
}

func startMesh(work string) []*server.Server {
	var routes []*url.URL
	servers := []*server.Server{}
	configs := []*server.Options{}
	for i := range 4 {
		options := &server.Options{}
		must(options.ProcessConfigString(mesh.AccountsConfig))
		accounts := map[string]*server.Account{}
		for _, account := range options.Accounts {
			accounts[account.Name] = account
		}
		options.Users = []*server.User{{Username: orchUser, Password: orchSecret, Account: accounts[mesh.OrchAccount]},
			{Username: fabricUser, Password: fabricSecret, Account: accounts[mesh.FabricAccount]}}
		options.Host, options.Port, options.NoSigs, options.NoLog, options.ServerName = "127.0.0.1", -1, true, true, "mesh-"+strconv.Itoa(i)
		options.JetStream, options.StoreDir = i > 0, filepath.Join(work, "mesh", strconv.Itoa(i))
		options.Cluster = server.ClusterOpts{Name: "e2e-mesh", Host: "127.0.0.1", Port: -1, PinnedAccounts: []string{mesh.FabricAccount}}
		options.Routes = routes
		configs = append(configs, options.Clone())
		node, err := server.NewServer(options)
		must(err)
		go node.Start()
		servers = append(servers, node)
		require(node.ReadyForConnections(10*time.Second), "the mesh must listen")
		route, err := url.Parse("nats-route://" + node.ClusterAddr().String())
		must(err)
		routes = append(routes, route)
	}
	defer servers[0].WaitForShutdown()
	defer servers[0].Shutdown()
	for i, node := range servers[1:] {
		options := configs[i+1]
		options.Routes = routes[1:]
		must(node.ReloadOptions(options))
	}
	return servers[1:]
}

func journey(bin, part string) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
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
	var supervisors sync.WaitGroup
	defer func() {
		cancel()
		supervisors.Wait()
	}()
	l := &lane{bin: bin, self: selfBytes, revision: revision, github: newGitHub(), sigstore: newSigstore(),
		hosts: map[string]*host{}, outages: &outages{down: map[string]map[string]bool{}}, progress: map[string]chan pullrelease.Status{},
		last: map[string]pullrelease.Status{}, ready: make(chan [2]string, 1024), downs: make(chan string, 1024), regionsGR: filepath.Join(work, "regions.json")}
	defer func() {
		if failure := recover(); failure != nil {
			cancel()
			for _, h := range l.hosts {
				h.mu.Lock()
				if h.cmd != nil && h.cmd.Process != nil {
					_ = h.cmd.Process.Kill()
				}
				h.mu.Unlock()
			}
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
	meshes := startMesh(work)
	for _, mesh := range meshes {
		defer mesh.Shutdown()
	}
	l.conn, err = nats.Connect(meshes[0].ClientURL(), nats.UserInfo(orchUser, orchSecret))
	must(err)
	defer l.conn.Close()
	_, err = l.conn.Subscribe("e2e.>", func(m *nats.Msg) {
		parts := strings.Split(m.Subject, ".")
		l.outages.mark(parts[2], parts[3], parts[1] == "down")
		if parts[1] == "ready" {
			l.ready <- [2]string{parts[2] + "." + parts[3], string(m.Data)}
		} else {
			l.downs <- parts[2] + "." + parts[3]
		}
	})
	must(err)
	polls := map[string]string{"gru": "1h", "sjc": "3s"}
	for _, region := range []string{"gru", "sjc"} {
		statuses := make(chan pullrelease.Status, 256)
		l.progress[region] = statuses
		_, err = l.conn.Subscribe(protocol.MeshPullProgressPrefix+region, func(m *nats.Msg) {
			var status pullrelease.Status
			must(json.Unmarshal(m.Data, &status))
			statuses <- status
		})
		must(err)
		for _, suffix := range []string{"m", "n", "w"} {
			id, role := region+"-"+suffix, "manager"
			if suffix == "w" {
				role = "worker"
			}
			dir := filepath.Join(work, id)
			must(os.MkdirAll(filepath.Join(dir, "bin"), 0o700))
			must(os.WriteFile(filepath.Join(dir, "bin", "terrascale-orchestrator"), selfBytes, 0o755))
			port := "0"
			if suffix == "m" {
				port = "-1"
			}
			l.hosts[id] = &host{region: region, id: id, role: role, dir: dir,
				args: []string{"host", dir, region, id, role, meshes[0].ClientURL(), l.github.server.URL, rootFile, port, polls[region]}}
		}
	}
	must(l.conn.Flush())
	for _, h := range l.hosts {
		supervisors.Go(func() { h.supervise(ctx) })
	}
	base := hex.EncodeToString(sha256Of(selfBytes))
	for range l.hosts {
		l.waitReady(ctx, "", base)
	}
	for _, region := range []string{"gru", "sjc"} {
		owner := l.waitStatus(ctx, region, region+" elects one owner of its rollouts", func(s pullrelease.Status) bool { return s.Owner != "" })
		fmt.Printf("%s: %s owns the rollouts\n", region, owner.Owner)
	}
	fmt.Println("cell up: gru and sjc on one JetStream mesh, two managers and a worker each, on the base binary")

	if part == "push" {
		l.pushes(ctx)
		return
	}
	if part == "degraded" {
		l.degraded(ctx)
		return
	}
	l.pulls(ctx)
}

func (l *lane) pulls(ctx context.Context) {
	revision := l.revision
	older, base, before := strings.Repeat("1", 40), hex.EncodeToString(sha256Of(l.self)), l.starts()
	l.github.mu.Lock()
	l.github.compare[revision+"..."+older] = comparison{status: "behind", base: revision, mergeBase: older}
	l.github.mu.Unlock()
	c100 := l.candidate("c100")
	r0 := l.github.publish(older, "100", asset, c100, c100, l.sigstore.bundle(mainIdentity, older, "100", map[string][]byte{asset: c100}))
	newer := l.waitStatus(ctx, "sjc", "sjc finds every host already newer than "+r0.tag, func(s pullrelease.Status) bool {
		return s.Phase == pullrelease.PhaseNewer && s.Target != nil && s.Target.Tag() == r0.tag
	})
	require(!slices.Contains(newer.Bad, r0.tag) && len(newer.Hosts) == 3 && !slices.ContainsFunc(newer.Hosts, func(h pullrelease.HostProgress) bool {
		return h.State != pullrelease.HostNewer || h.Version != revision || h.Error != ""
	}), "an older release must leave every host on its newer release, unrefused and not marked bad:\n%s", newer)
	skipped := l.ask(ctx, "gru-w", releasepush.PullRequest{Op: releasepush.PullInstall, Release: l.release(r0)})
	require(skipped.State == releasepush.StateNewer && skipped.Version == revision && skipped.Refusal == nil && skipped.Error == "",
		"gru-w must skip the older release, replied %+v", skipped)
	l.requireVersions(ctx, base, l.region("gru", "sjc")...)
	require(maps.Equal(before, l.starts()), "no host may restart for an older release: %v -> %v", before, l.starts())
	fmt.Printf("older release %s -> every host already descends from it: nothing installed, not refused, not marked bad\n%s\n", r0.tag, newer)

	r1 := l.publishGood("101", "c101")
	l.github.mint(revision, "101")
	require(strings.Contains(l.nudge(ctx), "gru: nudged"), "the first nudge must be accepted")
	require(strings.Contains(l.nudge(ctx), "gru: throttled"), "a second nudge within the spacing must be throttled")
	gru := l.waitStatus(ctx, "gru", "gru completes "+r1.tag+" after the nudge", complete(r1))
	sjc := l.waitStatus(ctx, "sjc", "sjc completes "+r1.tag+" by its poll alone", complete(r1))
	require(gru.Nudged == r1.tag && sjc.Nudged == "", "only gru was nudged: gru %q sjc %q", gru.Nudged, sjc.Nudged)
	l.requireVersions(ctx, r1.digest, l.region("gru", "sjc")...)
	fmt.Printf("nudge -> gru pulled %s; lost nudge -> sjc polled it; every host verified and on it\n%s\n%s\n", r1.tag, gru, sjc)

	wrongWorkflow := identity{workflow: "TerraScale/ts-orchestrator/.github/workflows/lint-cache.yml@refs/heads/main", ref: "refs/heads/main", trigger: "push"}
	wrongBranch := identity{workflow: "TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/feature", ref: "refs/heads/feature", trigger: "push"}
	unlogged := mainIdentity
	unlogged.unlogged = true
	c102, c103, c104, c105, c106, c107, c108, c109 := l.candidate("c102"), l.candidate("c103"), l.candidate("c104"), l.candidate("c105"), l.candidate("c106"), l.candidate("c107"), l.candidate("c108"), l.candidate("c109")
	tampered := append(bytes.Clone(c105[:len(c105)-1]), c105[len(c105)-1]^1)
	diverged, forked, detached := strings.Repeat("e", 40), strings.Repeat("d", 40), strings.Repeat("b", 40)
	l.github.mu.Lock()
	l.github.compare[revision+"..."+diverged] = comparison{status: "diverged", base: revision, mergeBase: strings.Repeat("c", 40), commits: []string{diverged}}
	l.github.compare[revision+"..."+forked] = comparison{status: "ahead", base: revision, mergeBase: strings.Repeat("c", 40), commits: []string{strings.Repeat("a", 40), forked}}
	l.github.compare[revision+"..."+detached] = comparison{status: "ahead", base: revision, mergeBase: revision, commits: []string{strings.Repeat("a", 40), strings.Repeat("f", 40)}}
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
		{"not a descendant", "106", diverged, c106, c106, l.sigstore.bundle(mainIdentity, diverged, "106", map[string][]byte{asset: c106}), "does not descend", true},
		{"no certificate timestamp", "107", revision, c107, c107, l.sigstore.bundle(unlogged, revision, "107", map[string][]byte{asset: c107}), "SCT", true},
		{"ahead of another merge base", "108", forked, c108, c108, l.sigstore.bundle(mainIdentity, forked, "108", map[string][]byte{asset: c108}), "does not descend", true},
		{"comparison ends elsewhere", "109", detached, c109, c109, l.sigstore.bundle(mainIdentity, detached, "109", map[string][]byte{asset: c109}), "does not end at", true},
	}
	for _, refusal := range refusals {
		release := l.github.publish(refusal.sha, refusal.run, asset, refusal.binary, refusal.served, refusal.bundle)
		status := l.waitStatus(ctx, "sjc", "sjc refuses the "+refusal.name+" release", func(s pullrelease.Status) bool {
			return s.Phase == pullrelease.PhaseRefused && s.Target != nil && s.Target.Tag() == release.tag
		})
		require(strings.Contains(status.Reason, refusal.reason), "%s: refusal %q lacks %q", refusal.name, status.Reason, refusal.reason)
		if refusal.direct {
			reply := l.ask(ctx, "gru-w", releasepush.PullRequest{Op: releasepush.PullInstall, Release: l.release(release)})
			require(reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalIntegrity && strings.Contains(reply.Refusal.Reason, refusal.reason),
				"%s: gru-w must refuse it itself, replied %+v", refusal.name, reply)
		}
		fmt.Printf("%s release %s refused: %s\n", refusal.name, release.tag, status.Reason)
	}
	l.requireVersions(ctx, r1.digest, l.region("gru", "sjc")...)
	fmt.Println("refused releases -> no host changed")

	starts := l.starts()
	l.drainReady()
	r10 := l.publishGood("110", "unhealthy")
	gating := l.waitStatus(ctx, "sjc", "sjc gates its first host on the unhealthy "+r10.tag, gatingFirst(r10))
	failing := gating.Hosts[0].ID
	must(os.WriteFile(filepath.Join(l.hosts[failing].dir, "refuse-stop"), nil, 0o600))
	pending := l.waitStatus(ctx, "sjc", "sjc keeps "+r10.tag+" pending while "+failing+" refuses to stop", func(s pullrelease.Status) bool {
		return s.Phase == pullrelease.PhaseRollingBack && strings.Contains(s.Reason, "restoring the previous binary failed")
	})
	require(!slices.Contains(pending.Bad, r10.tag) && pending.Hosts[0].State == pullrelease.HostRestoring && strings.Contains(pending.Reason, "quorum"),
		"a refused restore must stay pending, not mark the release bad:\n%s", pending)
	still := l.ask(ctx, failing, releasepush.PullRequest{Op: releasepush.PullStatus})
	require(still.SHA256 == r10.digest, "%s must still run the failed candidate while its restore is refused, runs %s", failing, still.SHA256)
	fmt.Printf("restore refused by PrepareStop -> rollback pending, release not marked bad, %s still on it\n%s\n", failing, pending)
	must(os.Remove(filepath.Join(l.hosts[failing].dir, "refuse-stop")))
	status := l.waitStatus(ctx, "sjc", "sjc rolls back the unhealthy "+r10.tag, func(s pullrelease.Status) bool {
		return s.Phase == pullrelease.PhaseRolledBack && s.Target != nil && s.Target.Tag() == r10.tag
	})
	require(slices.Contains(status.Bad, r10.tag) && strings.Contains(status.Reason, "unhealthy") && status.Hosts[0].ID == failing && status.Hosts[0].State == pullrelease.HostRolledBack,
		"the failing host's gate must fail on health and be confirmed restored: %s", status)
	l.requireVersions(ctx, r1.digest, l.region("sjc")...)
	for _, id := range l.region("sjc") {
		want := starts[id]
		if id == failing {
			want += 3
		}
		require(l.hosts[id].starts.Load() == want, "%s started %d times, want %d", id, l.hosts[id].starts.Load()-starts[id], want-starts[id])
	}
	fmt.Printf("unhealthy candidate -> previous binary confirmed running, then marked bad; no other host restarted\n%s\n", status)

	r11 := l.publishGood("111", "unhealthy")
	gating = l.waitStatus(ctx, "sjc", "sjc gates its first host on the unhealthy "+r11.tag, gatingFirst(r11))
	stuck := gating.Hosts[0].ID
	must(os.WriteFile(filepath.Join(l.hosts[stuck].dir, "refuse-stop"), nil, 0o600))
	stalled := l.waitStatus(ctx, "sjc", "sjc stops holding the region once the rollback of "+r11.tag+" passes its bound", func(s pullrelease.Status) bool {
		return s.Phase == pullrelease.PhaseStalled && s.Target != nil && s.Target.Tag() == r11.tag
	})
	require(slices.Contains(stalled.Bad, r11.tag) && strings.HasPrefix(stalled.Reason, "critical: ") && strings.Contains(stalled.Reason, "quorum"),
		"a stalled rollback must report a critical status and mark the release bad:\n%s", stalled)
	still = l.ask(ctx, stuck, releasepush.PullRequest{Op: releasepush.PullStatus})
	require(still.SHA256 == r11.digest, "%s must still run %s when the rollback stalls, runs %s", stuck, r11.tag, still.SHA256)
	fmt.Printf("restore refused past the bound -> critical status, release marked bad, the region no longer held\n%s\n", stalled)
	must(os.Remove(filepath.Join(l.hosts[stuck].dir, "refuse-stop")))
	restored := l.ask(ctx, stuck, releasepush.PullRequest{Op: releasepush.PullRollback, Release: l.release(r11), Reason: "operator restores the stalled host"})
	require(restored.State == "restoring", "the operator's rollback of %s must restore its previous binary, replied %+v", stuck, restored)
	l.waitReady(ctx, "sjc."+stuck, r1.digest)
}

func (l *lane) pushes(ctx context.Context) {
	revision := l.revision
	r12 := l.publishGood("112", "c112")
	l.github.mint(revision, "112")
	require(strings.Contains(l.nudge(ctx), "gru: nudged"), "the nudge for %s must be accepted", r12.tag)
	first := l.waitStatus(ctx, "gru", "gru gates its first host on "+r12.tag, gatingFirst(r12))
	l.waitReady(ctx, "gru."+first.Hosts[0].ID, r12.digest)
	r13 := l.publishGood("113", "c113")
	reply := l.push(ctx, "113", l.candidate("c113"))
	require(reply.State == "installed" && len(reply.Workers) == 1 && reply.Workers[0].Error == "" && reply.Workers[0].Refusal == nil,
		"a push during a pull rollout must win, replied %+v", reply)
	preempted := l.waitStatus(ctx, "gru", "gru records that the push of "+r13.tag+" preempted "+r12.tag, func(s pullrelease.Status) bool {
		return s.Preempted == r12.tag
	})
	l.waitReady(ctx, "gru.gru-m", r13.digest)
	gru := l.waitStatus(ctx, "gru", "gru restarts its pull from the pushed "+r13.tag, complete(r13))
	l.waitStatus(ctx, "sjc", "sjc completes "+r13.tag, complete(r13))
	l.requireVersions(ctx, r13.digest, l.region("gru", "sjc")...)
	fmt.Printf("push during the pull rollout of %s -> the push installed, the pull recorded its preemption and restarted from the pushed release\n%s\n%s\n", r12.tag, preempted, gru)

	starts := l.starts()
	r14 := l.publishGood("114", "c114")
	l.github.mint(revision, "114")
	require(strings.Contains(l.nudge(ctx), "gru: nudged"), "the nudge for %s must be accepted", r14.tag)
	first = l.waitStatus(ctx, "gru", "gru gates its first host on "+r14.tag, gatingFirst(r14))
	l.waitReady(ctx, "gru."+first.Hosts[0].ID, r14.digest)
	owner := first.Owner
	l.hosts[owner].holdRestart()
	l.hosts[owner].kill()
	l.outages.mark("gru", owner, true)
	handover := l.waitStatus(ctx, "gru", "the other gru manager takes over "+r14.tag, func(s pullrelease.Status) bool {
		return s.Owner != owner && s.Target != nil && s.Target.Tag() == r14.tag
	})
	l.hosts[owner].releaseRestart()
	gru = l.waitStatus(ctx, "gru", "gru resumes and completes "+r14.tag, complete(r14))
	l.waitStatus(ctx, "sjc", "sjc completes "+r14.tag, complete(r14))
	l.requireVersions(ctx, r14.digest, l.region("gru", "sjc")...)
	for _, id := range l.region("gru") {
		want := starts[id] + 1
		if id == owner {
			want++
		}
		require(l.hosts[id].starts.Load() == want, "%s started %d times, want %d", id, l.hosts[id].starts.Load()-starts[id], want-starts[id])
	}
	fmt.Printf("owner %s killed mid-rollout -> %s took over the same rollout; every host installed once\n%s\n%s\n", owner, handover.Owner, handover, gru)

	r15 := l.publishGood("115", "c115")
	l.hosts["gru-w"].holdRestart()
	starts = l.starts()
	pushed := make(chan releasepush.Reply, 1)
	go func() { pushed <- l.push(ctx, "115", l.candidate("c115")) }()
	l.waitDown(ctx, "gru.gru-w")
	r16 := l.publishGood("116", "c116")
	l.github.mint(revision, "116")
	require(strings.Contains(l.nudge(ctx), "gru: nudged"), "the nudge for %s must be accepted", r16.tag)
	waiting := l.waitStatus(ctx, "gru", "gru waits for the push of "+r15.tag, func(s pullrelease.Status) bool {
		return s.Push != nil && strings.Contains(s.Reason, "release push "+r15.tag+" in progress")
	})
	require(waiting.Target != nil && waiting.Target.Tag() == r14.tag && waiting.Phase == pullrelease.PhaseComplete, "the pull must not start %s during the push:\n%s", r16.tag, waiting)
	manager := l.ask(ctx, "gru-m", releasepush.PullRequest{Op: releasepush.PullStatus})
	require(manager.SHA256 == r14.digest && manager.Health == "ok" && l.hosts["gru-m"].starts.Load() == starts["gru-m"],
		"gru-m must keep serving %s until its worker is ready, runs %s (%s)", r14.digest, manager.SHA256, manager.Health)
	fmt.Printf("push with its worker slow to come back -> the manager keeps running and the nudged pull waits\n%s\n", waiting)
	l.hosts["gru-w"].releaseRestart()
	reply = <-pushed
	require(reply.State == "installed" && len(reply.Workers) == 1 && reply.Workers[0].Error == "" && reply.Workers[0].Refusal == nil,
		"the push must install the worker, then gru-m, replied %+v", reply)
	l.waitReady(ctx, "gru.gru-m", r15.digest)
	gru = l.waitStatus(ctx, "gru", "gru pulls "+r16.tag+" once the push finished", complete(r16))
	l.waitStatus(ctx, "sjc", "sjc completes "+r16.tag, complete(r16))
	l.requireVersions(ctx, r16.digest, l.region("gru", "sjc")...)
	fmt.Printf("worker ready -> manager installed the push; its claim dropped and the pull rolled %s out\n%s\n", r16.tag, gru)

}

func (l *lane) degraded(ctx context.Context) {
	revision := l.revision
	worker := l.hosts["gru-w"]
	stopped := filepath.Join(worker.dir, "stopped")
	must(os.WriteFile(stopped, nil, 0o600))
	worker.holdRestart()
	worker.kill()
	r17 := l.publishGood("117", "c117")
	reply := l.push(ctx, "117", l.candidate("c117"))
	require(reply.State == "installed" && slices.Equal(reply.Degraded, []string{"gru-w"}) && len(reply.Workers) == 1 &&
		reply.Workers[0].Down && reply.Workers[0].Error == "no answer",
		"a push must install the manager past a stopped worker and report the region degraded, replied %+v", reply)
	l.waitReady(ctx, "gru.gru-m", r17.digest)
	metrics := l.releaseMetrics("gru-m")
	require(strings.Contains(metrics, "ts_orch_release_region_degraded 1") &&
		strings.Contains(metrics, `ts_orch_release_worker_skipped{host="gru-w",sha="`+revision+`",run="117"} 1`),
		"gru-m must export the skipped worker, exports:\n%s", metrics)
	fmt.Printf("worker host stopped -> the push installed gru-m anyway and the region reports degraded\n%s", metrics)
	must(os.Remove(stopped))
	worker.releaseRestart()
	l.waitReady(ctx, "gru.gru-w", hex.EncodeToString(sha256Of(l.self)))
	r18 := l.publishGood("118", "c118")
	reply = l.push(ctx, "118", l.candidate("c118"))
	require(reply.State == "installed" && len(reply.Degraded) == 0 && len(reply.Workers) == 1 && reply.Workers[0].Error == "" && reply.Workers[0].Refusal == nil,
		"the next push must reach the returned worker, replied %+v", reply)
	l.waitReady(ctx, "gru.gru-m", r18.digest)
	metrics = l.releaseMetrics("gru-m")
	require(strings.Contains(metrics, "ts_orch_release_region_degraded 0") && !strings.Contains(metrics, "ts_orch_release_worker_skipped"),
		"the push that reached every worker must clear the degraded report, exports:\n%s", metrics)
	l.requireVersions(ctx, r18.digest, "gru-m", "gru-w")
	fmt.Println("worker back -> the next push reached it and cleared the degraded report")
}

func (l *lane) releaseMetrics(id string) string {
	var metrics bytes.Buffer
	releasepush.WriteReleaseMetrics(&metrics, filepath.Join(l.hosts[id].dir, "state"))
	return metrics.String()
}

func (l *lane) waitDown(ctx context.Context, who string) {
	for {
		select {
		case down := <-l.downs:
			if down == who {
				return
			}
		case <-ctx.Done():
			panic(fmt.Sprintf("timed out waiting for %s to go down", who))
		}
	}
}

func gatingFirst(release published) func(pullrelease.Status) bool {
	return func(s pullrelease.Status) bool {
		return s.Target != nil && s.Target.Tag() == release.tag && len(s.Hosts) != 0 && s.Hosts[0].State == pullrelease.HostGating
	}
}

func (l *lane) region(regions ...string) []string {
	ids := []string{}
	for _, region := range regions {
		for _, suffix := range []string{"-m", "-n", "-w"} {
			ids = append(ids, region+suffix)
		}
	}
	return ids
}

func (l *lane) starts() map[string]int32 {
	starts := map[string]int32{}
	for id, h := range l.hosts {
		starts[id] = h.starts.Load()
	}
	return starts
}

func (l *lane) push(ctx context.Context, run string, binary []byte) releasepush.Reply {
	l.github.mint(l.revision, run)
	l.github.mu.Lock()
	token := l.github.token
	l.github.mu.Unlock()
	regions, err := releasepush.LoadRegions(l.regionsGR)
	must(err)
	conn, err := releasepush.Dial(regions[0], token)
	must(err)
	defer conn.Close()
	data, err := json.Marshal(releasepush.OrchRelease{SHA: l.revision, Token: token, Binaries: map[string]releasepush.Binary{
		runtime.GOARCH: {URL: releasepush.ReleaseURL(l.revision, run, runtime.GOARCH), SHA256: hex.EncodeToString(sha256Of(binary))}}})
	must(err)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	message, err := conn.RequestWithContext(ctx, releasepush.SubjectOrch, data)
	must(err)
	var reply releasepush.Reply
	must(json.Unmarshal(message.Data, &reply))
	return reply
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

func (l *lane) ask(ctx context.Context, id string, request releasepush.PullRequest) releasepush.Reply {
	data, err := json.Marshal(request)
	must(err)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	message, err := l.conn.RequestWithContext(ctx, releasepush.PullSubject(l.hosts[id].region, id), data)
	must(err)
	var reply releasepush.Reply
	must(json.Unmarshal(message.Data, &reply))
	return reply
}

func (l *lane) requireVersions(ctx context.Context, digest string, ids ...string) {
	for _, id := range ids {
		reply := l.ask(ctx, id, releasepush.PullRequest{Op: releasepush.PullStatus})
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
			l.outages.check()
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
