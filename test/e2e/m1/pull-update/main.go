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
	"net/http"
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
	"github.com/TerraScale/ts-orchestrator/internal/ocirelease"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/pullrelease"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/sigstore"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/sigstore/sigstore-go/pkg/root"
)

const (
	asset        = releaseattest.AssetPrefix + runtime.GOARCH
	healthyFor   = 2 * time.Second
	poll         = 3 * time.Second
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

func asRevision(binary []byte, from, to string) []byte {
	stamp := []byte("vcs.revision=" + from)
	require(bytes.Count(binary, stamp) > 0, "the journey binary carries no %s", stamp)
	return bytes.ReplaceAll(binary, stamp, []byte("vcs.revision="+to))
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "release" && os.Args[2] == "preflight" {
		return
	}
	if len(os.Args) == 13 && os.Args[1] == "host" {
		runHost(os.Args[2:])
		return
	}
	require(len(os.Args) == 3 && (os.Args[2] == "pull" || os.Args[2] == "handover" || os.Args[2] == "degraded"), "usage: pull-update <ts-orch binary> pull|handover|degraded")
	journey(os.Args[1], os.Args[2])
}

func runHost(args []string) {
	dir, region, id, role, natsURL, githubURL, rootFile, _, poll, registryURL, keyFile := args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10]
	ctx := context.Background()
	state := filepath.Join(dir, "state")
	must(os.MkdirAll(filepath.Join(state, "nats"), 0o700))
	h, err := releasepush.NewHandler(state)
	if err != nil {
		fmt.Fprintln(os.Stderr, "release handler:", err)
		os.Exit(5)
	}
	client := githubClient(githubURL, fmt.Sprintf("%s/%d", id, os.Getpid()))
	h.Verifier.JWKSURL = githubURL + "/jwks"
	regional := hostRegional(registryURL, keyFile, client.Transport)
	h.Client, h.Registry, h.Source.Client = &http.Client{Transport: regional}, regional.Registry, client
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
	if probation, err := releasepush.Probe(state, os.Stdout); err == nil && probation != nil {
		require(probation.Served(), "%s must confirm its release", id)
	}
	if role == "manager" {
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
			Source: h.Source, Channel: &ocirelease.Reader{Registry: h.Registry, Attest: h.Attest}, Attest: h.Attest, Client: h.Client,
			Poll: every, HealthyFor: healthyFor, Deadline: deadline, BakeFor: healthyFor}
		go func() { _ = updater.Run(ctx) }()
	}
	must(conn.Publish("e2e.ready."+region+"."+id, []byte(h.Digest)))
	must(conn.Flush())
	<-h.Installed

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
	bin        string
	self       []byte
	build      string
	revision   string
	github     *fakeGitHub
	offline    *offlineGitHub
	registries map[string]*regionRegistry
	first      channelRelease
	keyFile    string
	sigstore   *sigstore.Authority
	hosts      map[string]*host
	conn       *nats.Conn
	outages    *outages
	progress   map[string]chan pullrelease.Status
	last       map[string]pullrelease.Status
	ready      chan [2]string
	downs      chan string
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
	l := &lane{bin: bin, self: selfBytes, build: revision, revision: revision, github: newGitHub(), sigstore: sigstore.New(),
		hosts: map[string]*host{}, outages: &outages{down: map[string]map[string]bool{}}, progress: map[string]chan pullrelease.Status{},
		last: map[string]pullrelease.Status{}, ready: make(chan [2]string, 1024), downs: make(chan string, 1024)}
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
	githubURL, keyFile, registryURLs := l.github.server.URL, "-", map[string]string{"sjc": "-", "fra": "-", "gru": "-"}
	if part == "degraded" {
		l.offline, l.registries = newOfflineGitHub(), map[string]*regionRegistry{}
		defer l.offline.server.Close()
		key, path, certificate := principalKey(work)
		githubURL, keyFile, l.keyFile = l.offline.server.URL, path, path
		for region := range registryURLs {
			l.registries[region] = newRegionRegistry(&key.PublicKey, certificate)
			defer l.registries[region].server.Close()
			registryURLs[region] = l.registries[region].server.URL
		}
		l.first = l.channelRelease(100, "100", l.self, l.self)
		l.publishChannel(ctx, l.first)
	}
	rootFile := filepath.Join(work, "trusted-root.json")
	must(os.WriteFile(rootFile, l.sigstore.TrustedRoot(), 0o600))
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
	polls := map[string]string{"gru": poll.String(), "fra": poll.String(), "sjc": poll.String()}
	for _, region := range []string{"sjc", "fra", "gru"} {
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
				args: []string{"host", dir, region, id, role, meshes[0].ClientURL(), githubURL, rootFile, port, polls[region], registryURLs[region], keyFile}}
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
	for _, region := range []string{"sjc", "fra", "gru"} {
		owner := l.waitStatus(ctx, region, region+" elects one owner of its rollouts", func(s pullrelease.Status) bool { return s.Owner != "" })
		fmt.Printf("%s: %s owns the rollouts\n", region, owner.Owner)
	}
	fmt.Println("cell up: sjc, fra and gru on one JetStream mesh, two managers and a worker each, on the base binary")

	if part == "handover" {
		l.handover(ctx)
		return
	}
	if part == "degraded" {
		l.channel(ctx)
		return
	}
	l.pulls(ctx)
}

func (l *lane) pulls(ctx context.Context) {
	original := l.revision
	older, base, before := strings.Repeat("1", 40), hex.EncodeToString(sha256Of(l.self)), l.starts()
	l.github.mu.Lock()
	l.github.compare[older+"..."+original] = comparison{status: "ahead", aheadBy: 2, base: older, mergeBase: older}
	l.github.mu.Unlock()
	c100 := l.candidate("c100")
	r0 := l.github.publish(older, "100", asset, c100, c100, l.sigstore.Bundle(sigstore.MainIdentity, older, "100", map[string][]byte{asset: c100}))
	newer := l.waitStatus(ctx, "sjc", "sjc finds every host already newer than "+r0.tag, func(s pullrelease.Status) bool {
		return s.Phase == pullrelease.PhaseNewer && s.Target != nil && s.Target.Tag() == r0.tag
	})
	require(!slices.Contains(newer.Bad, r0.tag) && len(newer.Hosts) == 3 && !slices.ContainsFunc(newer.Hosts, func(h pullrelease.HostProgress) bool {
		return h.State != pullrelease.HostNewer || h.Version != original || h.Error != ""
	}), "an older release must leave every host on its newer release, unrefused and not marked bad:\n%s", newer)
	skipped := l.ask(ctx, "gru-w", releasepush.PullRequest{Op: releasepush.PullInstall, Release: l.release(r0)})
	require(skipped.State == releasepush.StateNewer && skipped.Version == original && skipped.Refusal == nil && skipped.Error == "",
		"gru-w must skip the older release, replied %+v", skipped)
	l.requireVersions(ctx, base, l.region("sjc", "fra", "gru")...)
	require(maps.Equal(before, l.starts()), "no host may restart for an older release: %v -> %v", before, l.starts())
	fmt.Printf("older release %s -> every host already descends from it: nothing installed, not refused, not marked bad\n%s\n", r0.tag, newer)

	revision := strings.Repeat("2", 40)
	lineage := revision + "..." + original
	l.github.mu.Lock()
	l.github.compare[lineage] = comparison{status: "behind", behindBy: 3, base: revision, mergeBase: original}
	l.github.mu.Unlock()
	l.revision = revision
	r1 := l.publishGood("101", "c101")
	sjc := l.waitStatus(ctx, "sjc", "sjc completes "+r1.tag, complete(r1))
	fra := l.waitStatus(ctx, "fra", "fra completes "+r1.tag, complete(r1))
	gru := l.waitStatus(ctx, "gru", "gru completes "+r1.tag, complete(r1))
	require(!fra.Done.Before(sjc.Done.Add(healthyFor)) && !gru.Done.Before(fra.Done.Add(healthyFor)), "a region bypassed its predecessor completion and bake")
	l.requireVersions(ctx, r1.digest, l.region("sjc", "fra", "gru")...)
	l.github.mu.Lock()
	compared, replied := l.github.compared[lineage], l.github.replied[lineage]
	l.github.mu.Unlock()
	require(replied > 1<<20 && compared >= 1 && compared <= len(l.hosts), "every host must check %s once against a comparison over 1 MiB: %d checks of %d bytes", lineage, compared, replied)
	fmt.Printf("attested release %s pulled in sjc, fra, gru order; predecessor completion and bake persisted across hosts; %d lineage checks for %d hosts, each reply %d bytes\n%s\n%s\n%s\n",
		r1.tag, compared, len(l.hosts), replied, sjc, fra, gru)

	wrongWorkflow := sigstore.Identity{Workflow: "TerraScale/ts-orchestrator/.github/workflows/lint-cache.yml@refs/heads/main", Ref: "refs/heads/main", Trigger: "push"}
	wrongBranch := sigstore.Identity{Workflow: "TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/feature", Ref: "refs/heads/feature", Trigger: "push"}
	unlogged := sigstore.MainIdentity
	unlogged.Unlogged = true
	c102, c103, c104, c105, c106, c107, c108, c109 := l.candidate("c102"), l.candidate("c103"), l.candidate("c104"), l.candidate("c105"), l.candidate("c106"), l.candidate("c107"), l.candidate("c108"), l.candidate("c109")
	tampered := append(bytes.Clone(c105[:len(c105)-1]), c105[len(c105)-1]^1)
	diverged, forked, detached := strings.Repeat("e", 40), strings.Repeat("d", 40), strings.Repeat("b", 40)
	l.github.mu.Lock()
	l.github.compare[diverged+"..."+revision] = comparison{status: "diverged", aheadBy: 1, behindBy: 1, base: diverged, mergeBase: strings.Repeat("c", 40)}
	l.github.compare[forked+"..."+revision] = comparison{status: "behind", behindBy: 2, base: forked, mergeBase: strings.Repeat("c", 40)}
	l.github.compare[detached+"..."+revision] = comparison{status: "behind", behindBy: 2, base: strings.Repeat("f", 40), mergeBase: revision}
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
		{"wrong workflow", "102", revision, c102, c102, l.sigstore.Bundle(wrongWorkflow, revision, "102", map[string][]byte{asset: c102}), "not signed by", true},
		{"wrong branch", "103", revision, c103, c103, l.sigstore.Bundle(wrongBranch, revision, "103", map[string][]byte{asset: c103}), "not signed by", true},
		{"unattested", "104", revision, c104, c104, nil, "not found", false},
		{"tampered", "105", revision, c105, tampered, l.sigstore.Bundle(sigstore.MainIdentity, revision, "105", map[string][]byte{asset: c105}), "sha256 differs", false},
		{"not a descendant", "106", diverged, c106, c106, l.sigstore.Bundle(sigstore.MainIdentity, diverged, "106", map[string][]byte{asset: c106}), "does not descend", true},
		{"no certificate timestamp", "107", revision, c107, c107, l.sigstore.Bundle(unlogged, revision, "107", map[string][]byte{asset: c107}), "SCT", true},
		{"ahead of another merge base", "108", forked, c108, c108, l.sigstore.Bundle(sigstore.MainIdentity, forked, "108", map[string][]byte{asset: c108}), "does not descend", true},
		{"comparison of another commit", "109", detached, c109, c109, l.sigstore.Bundle(sigstore.MainIdentity, detached, "109", map[string][]byte{asset: c109}), "GitHub resolved", true},
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
	l.requireVersions(ctx, r1.digest, l.region("sjc", "fra", "gru")...)
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
	listings, unchanged, shortest := l.github.listingGaps()
	require(unchanged > 0 && shortest >= poll, "an owner may list releases once per %s and repeat with its ETag: %d listings, %d unchanged, shortest gap %s", poll, listings, unchanged, shortest)
	fmt.Printf("release discovery: %d listings by the region owners, %d answered 304, at least %s apart in each process\n", listings, unchanged, shortest)
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
	return append(asRevision(l.self, l.build, l.revision), []byte("\nCANDIDATE:"+mode)...)
}

func (l *lane) publishGood(run, mode string) published {
	binary := l.candidate(mode)
	return l.github.publish(l.revision, run, asset, binary, binary, l.sigstore.Bundle(sigstore.MainIdentity, l.revision, run, map[string][]byte{asset: binary}))
}

func (l *lane) release(p published) releaseattest.Release {
	return releaseattest.Release{SHA: p.sha, RunID: p.run, Bundle: releaseattest.AssetURL(p.sha, p.run, releaseattest.BundleAsset),
		Binaries: map[string]releaseattest.Artifact{runtime.GOARCH: {URL: releaseattest.AssetURL(p.sha, p.run, asset), SHA256: p.digest}}}
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

func (l *lane) handover(ctx context.Context) {
	starts := l.starts()
	candidate := l.publishGood("114", "c114")
	first := l.waitStatus(ctx, "gru", "gru starts its ordered rollout", gatingFirst(candidate))
	l.waitReady(ctx, "gru."+first.Hosts[0].ID, candidate.digest)
	owner := first.Owner
	l.hosts[owner].holdRestart()
	l.hosts[owner].kill()
	l.outages.mark("gru", owner, true)
	handover := l.waitStatus(ctx, "gru", "the other manager takes over the same release", func(s pullrelease.Status) bool {
		return s.Owner != owner && s.Target != nil && s.Target.Tag() == candidate.tag
	})
	l.hosts[owner].releaseRestart()
	done := l.waitStatus(ctx, "gru", "gru completes the inherited rollout", complete(candidate))
	l.requireVersions(ctx, candidate.digest, l.region("sjc", "fra", "gru")...)
	for _, id := range l.region("gru") {
		want := starts[id] + 1
		if id == owner {
			want++
		}
		require(l.hosts[id].starts.Load() == want, "%s started %d times, want %d", id, l.hosts[id].starts.Load(), want)
	}
	fmt.Printf("owner %s killed: %s inherited the durable rollout; every host installed once\n%s\n", owner, handover.Owner, done)
}
