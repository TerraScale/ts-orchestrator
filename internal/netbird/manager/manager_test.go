package manager

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestAddressPlanRejectedBeforeManagerRequests(t *testing.T) {
	for _, cidr := range []string{"100.64.0.0/10", "10.251.0.0/16", "10.0.0.0/8"} {
		t.Run(cidr, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			api, err := NewAPI(server.URL, testPAT)
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			d := GRU()
			d.NetworkRange = cidr
			if _, err := Sync(t.Context(), api, d, true); err == nil || !strings.Contains(err.Error(), "address plan:") {
				t.Fatalf("expected address-plan rejection, got %v", err)
			}
			if calls.Load() != 0 {
				t.Fatal("invalid plan reached the manager")
			}
		})
	}
}

func TestSyncWarnsAboutSetupKeyWithoutChangingIt(t *testing.T) {
	f := newFakeManager(t)
	f.seedLegacy(t)
	f.setupKeys[0]["auto_groups"] = []string{}
	f.setupKeys[0]["state"] = "revoked"
	report, err := Sync(t.Context(), f.api(t), GRU(), false)
	if err != nil || len(report.Warnings) != 5 {
		t.Fatalf("warnings %v error %v", report.Warnings, err)
	}
}

func TestSyncIgnoresRevokedSetupKeysWithTheServerKeyName(t *testing.T) {
	f := newFakeManager(t)
	f.seedLegacy(t)
	f.setupKeys = append(f.setupKeys, map[string]any{"id": "sk0", "name": "gru-servers",
		"type": "reusable", "state": "revoked", "valid": false, "revoked": true, "auto_groups": f.setupKeys[0]["auto_groups"]})
	report, err := Sync(t.Context(), f.api(t), GRU(), false)
	if err != nil || len(report.Warnings) != 3 {
		t.Fatalf("warnings %v error %v", report.Warnings, err)
	}
}

func TestPruneDeletesReplacedRevisionsAndRestoresSlotNames(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	now := time.Now()
	old := now.Add(-2 * time.Hour)
	ancient := now.Add(-72 * time.Hour)
	servers := ids.servers
	// ctl-2: the replaced revision is offline under the slot name;
	// the new revision registered with a suffixed label.
	staleB := f.addPeer("ts-gru-2", "10.251.0.12", false, old, servers)
	liveB := f.addPeer("ts-gru-2", "10.251.0.12", true, now, servers)
	// db-1: the live revision registered under its OS hostname.
	staleM := f.addPeer("gru-1-db-1", "10.251.0.21", false, old, servers)
	liveM := f.addPeer("ip-10-251-0-21", "10.251.0.21", true, now, servers)
	// db-2 is down: keep its newest peer, delete an ancient one.
	keepM2 := f.addPeer("gru-1-db-2", "10.251.0.22", false, ancient.Add(time.Hour), servers)
	oldM2 := f.addPeer("gru-1-db-2-old", "10.251.0.22", false, ancient, servers)
	// An unattributed server peer, long offline, and a recent one.
	orphan := f.addPeer("scratch", "10.251.0.50", false, ancient, servers)
	recent := f.addPeer("scratch-2", "10.251.0.51", false, old, servers)
	// A disconnected peer outside the servers group is never touched.
	outside := f.addPeer("ts-gru-3", "10.251.0.13", false, ancient, ids.operators)
	api := f.api(t)
	d := GRU()

	plan, err := Prune(t.Context(), api, d, PruneOptions{Now: now}, false)
	if err != nil || len(f.mutations) != 0 {
		t.Fatalf("dry run: %v %v", f.mutations, err)
	}
	if len(plan.Changes) != 6 {
		t.Fatalf("plan: %v", plan.Changes)
	}
	if _, err := Prune(t.Context(), api, d, PruneOptions{Now: now}, true); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{staleB, staleM, oldM2, orphan} {
		if f.peer(id) != nil {
			t.Errorf("peer %s was not deleted", id)
		}
	}
	for _, id := range []string{ids.server1, liveB, liveM, keepM2, recent, outside, ids.tsOps} {
		if f.peer(id) == nil {
			t.Errorf("peer %s was deleted", id)
		}
	}
	if p := f.peer(liveB); p.Name != "ts-gru-2" || p.DNSLabel != "ts-gru-2.netbird.selfhosted" {
		t.Fatalf("ctl-2: %+v", p.apiPeer)
	}
	if p := f.peer(liveM); p.Name != "gru-1-db-1" || p.DNSLabel != "gru-1-db-1.netbird.selfhosted" || !p.SSHEnabled {
		t.Fatalf("db-1: %+v", p.apiPeer)
	}
	f.mutations = nil
	again, err := Prune(t.Context(), api, d, PruneOptions{Now: now}, true)
	if err != nil || len(again.Changes) != 0 || len(f.mutations) != 0 {
		t.Fatalf("second prune: %v %v", again.Changes, err)
	}
}

// TS-609 renamed gru-1's nodes: a connected server peer still named
// gru-1-ctl-2 takes its slot's node name.
func TestPruneRenamesAPeerAfterItsRenamedNode(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	live := f.addPeer("gru-1-ctl-2", "10.251.0.12", true, time.Now(), ids.servers)
	if _, err := Prune(t.Context(), f.api(t), GRU(), PruneOptions{}, true); err != nil {
		t.Fatal(err)
	}
	if p := f.peer(live); p.Name != "ts-gru-2" || p.DNSLabel != "ts-gru-2.netbird.selfhosted" {
		t.Fatalf("renamed node's peer: %+v", p.apiPeer)
	}
}

func TestPruneLeavesAmbiguousSlotsAlone(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	f.addPeer("other", "10.251.0.11", true, time.Now(), ids.servers)
	f.addPeer("ts-gru-1", "10.251.0.11", false, time.Now().Add(-48*time.Hour), ids.servers)
	report, err := Prune(t.Context(), f.api(t), GRU(), PruneOptions{}, true)
	if err != nil || len(report.Changes) != 0 || len(report.Warnings) != 1 {
		t.Fatalf("ambiguous slot: %v %v %v", report.Changes, report.Warnings, err)
	}
}

func TestPruneReportsDNSLabelHeldOutsideTheServersGroup(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	now := time.Now()
	f.addPeer("ts-gru-2", "203.0.113.9", true, now, ids.operators)
	live := f.addPeer("ip-10-251-0-12", "10.251.0.12", true, now, ids.servers)
	_, err := Prune(t.Context(), f.api(t), GRU(), PruneOptions{Now: now}, true)
	if err == nil || !strings.Contains(err.Error(), "another peer holds the DNS label ts-gru-2") {
		t.Fatalf("prune error = %v", err)
	}
	if f.peer(live).Name != "ts-gru-2" {
		t.Fatalf("live peer: %+v", f.peer(live).apiPeer)
	}
}

func TestPruneLeavesSlotWhoseNameIsHeldByAnotherConnectedPeerAlone(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	now := time.Now()
	stale := f.addPeer("ts-gru-2-old", "10.251.0.12", false, now.Add(-72*time.Hour), ids.servers)
	live := f.addPeer("ip-10-251-0-12", "10.251.0.12", true, now, ids.servers)
	squatter := f.addPeer("ts-gru-2", "10.251.0.99", true, now, ids.servers)
	api := f.api(t)
	for run := range 2 {
		report, err := Prune(t.Context(), api, GRU(), PruneOptions{Now: now}, true)
		if err != nil || len(report.Changes) != 0 || len(report.Warnings) != 1 || len(f.mutations) != 0 {
			t.Fatalf("prune %d: changes %v warnings %v mutations %v error %v", run, report.Changes, report.Warnings, f.mutations, err)
		}
	}
	for _, id := range []string{stale, live, squatter} {
		if f.peer(id) == nil {
			t.Errorf("peer %s was deleted", id)
		}
	}
	if f.peer(live).Name != "ip-10-251-0-12" || f.peer(squatter).Name != "ts-gru-2" {
		t.Fatal("a peer of the contested slot was renamed")
	}
}

func TestValidateRejectsSlotsOutsideThePrivateCellSubnetAndUnknownAliasRoles(t *testing.T) {
	for name, mutate := range map[string]func(*Desired){
		"slot outside the cell subnet":  func(d *Desired) { d.Slots[0].IP = "10.251.0.200" },
		"slot in another private range": func(d *Desired) { d.Slots[0].IP = "192.168.0.11" },
		"public slot in a public subnet": func(d *Desired) {
			d.Network.Resource.Address = "203.0.113.0/24"
			for i := range d.Slots {
				d.Slots[i].IP = "203.0.113." + strings.TrimPrefix(d.Slots[i].IP, "10.251.0.")
			}
		},
		"alias to an unknown role":           func(d *Desired) { d.RoleAliases["nats"] = "controllers" },
		"alias to an empty role":             func(d *Desired) { d.RoleAliases["nats"] = "" },
		"policy source by former group name": func(d *Desired) { d.Policies[0].Sources = []string{"gateway"} },
		"servers group by former name":       func(d *Desired) { d.ServersGroup = "ts-orch-servers" },
		"DNS disabled group by former name":  func(d *Desired) { d.DNSDisabledGroups = []string{"ts-orch-servers"} },
		"former name repeats a current name": func(d *Desired) { d.Groups[0].RenamedFrom = []string{d.Groups[1].Name} },
	} {
		d := GRU()
		mutate(&d)
		f := newFakeManager(t)
		if _, err := Sync(t.Context(), f.api(t), d, true); err == nil || len(f.mutations) != 0 {
			t.Errorf("%s: accepted or mutated manager: %v", name, err)
		}
	}
}

func TestAPIRefusesRedirectsAndHidesBodies(t *testing.T) {
	redirect := httptest.NewServer(http.RedirectHandler("https://attacker.invalid/api/groups", http.StatusFound))
	defer redirect.Close()
	api, err := NewAPI(redirect.URL, testPAT)
	if err != nil {
		t.Fatal(err)
	}
	var out []apiGroup
	var status *StatusError
	if err := api.do(t.Context(), "GET", "/groups", nil, &out); !errors.As(err, &status) || status.Status != http.StatusFound {
		t.Fatalf("redirect: %v", err)
	}
	f := newFakeManager(t)
	f.failStatus = http.StatusInternalServerError
	err = f.api(t).do(t.Context(), "GET", "/groups", nil, &out)
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), testPAT) {
		t.Fatalf("error leaked: %v", err)
	}
	for _, url := range []string{"http://netbird.terrascale.tech", "ftp://127.0.0.1", "https://x/api", "https://u:p@x", "https://x?q"} {
		if _, err := NewAPI(url, testPAT); err == nil {
			t.Errorf("accepted %s", url)
		}
	}
	for _, url := range []string{"http://127.0.0.1:8080", "http://[::1]:1", "https://netbird.terrascale.tech"} {
		if _, err := NewAPI(url, testPAT); err != nil {
			t.Errorf("refused %s: %v", url, err)
		}
	}
}

func TestAPIWrapsTransportErrorsWithoutTheToken(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + listener.Addr().String()
	listener.Close()
	api, err := NewAPI(closed, testPAT)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	leaks := func(err error) bool {
		text := err.Error()
		return strings.Contains(text, testPAT) || strings.Contains(text, testPAT[4:]) ||
			strings.Contains(text, "Authorization") || strings.Contains(text, "Token ")
	}
	err = api.do(t.Context(), "GET", "/groups", nil, nil)
	var transport *url.Error
	if !errors.As(err, &transport) || !errors.Is(err, syscall.ECONNREFUSED) || leaks(err) ||
		!strings.Contains(err.Error(), "NetBird API GET /groups") || strings.Contains(transport.URL, testPAT) {
		t.Fatalf("transport error: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err = api.do(ctx, "POST", "/groups", groupRequest{Name: "x"}, nil)
	if !errors.Is(err, context.Canceled) || leaks(err) {
		t.Fatalf("canceled error: %v", err)
	}
	for _, token := range []string{strings.Repeat("a", 40), "nbp_short", testPAT + "!", "Token " + testPAT} {
		if _, err := NewAPI("http://127.0.0.1:1", token); err == nil || strings.Contains(err.Error(), token) {
			t.Fatalf("NewAPI accepted or echoed a malformed PAT: %v", err)
		}
	}
}

func TestCLIReportOmitsSummaryWhenTheRunFailed(t *testing.T) {
	f := newFakeManager(t)
	f.seedLegacy(t)
	f.failStatus = http.StatusInternalServerError
	t.Setenv("NB_PAT", testPAT)
	var out bytes.Buffer
	for _, command := range [][]string{{"sync"}, {"sync", "--apply"}, {"prune-peers", "--apply"}} {
		out.Reset()
		err := runManualManagerCLI(t.Context(), append(command, "--management-url", f.server.URL), &out)
		if err == nil || strings.Contains(out.String(), "no changes") {
			t.Fatalf("%v on a failing manager: %q %v", command, out.String(), err)
		}
	}

}

func TestCLIReadsPATSafelyAndPrintsNoSecrets(t *testing.T) {
	f := newFakeManager(t)
	f.seedLegacy(t)
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	if err := os.WriteFile(patFile, []byte(testPAT+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runManualManagerCLI(t.Context(), []string{"inventory", "--pat-file", patFile, "--management-url", f.server.URL}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "SECRET") || !strings.Contains(out.String(), `"gru-servers"`) {
		t.Fatalf("inventory output: %s", out.String())
	}
	out.Reset()
	if err := runManualManagerCLI(t.Context(), []string{"sync", "--pat-file", patFile, "--management-url", f.server.URL}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "plan: rename group gru-servers") || !strings.Contains(out.String(), "rerun with --apply") ||
		len(f.mutations) != 0 {
		t.Fatalf("sync dry run output: %s", out.String())
	}
	t.Setenv("NB_PAT", testPAT)
	out.Reset()
	if err := runManualManagerCLI(t.Context(), []string{"prune-peers", "--apply", "--management-url", f.server.URL}, &out); err != nil ||
		!strings.Contains(out.String(), "no changes") {
		t.Fatalf("prune: %s %v", out.String(), err)
	}

	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte(testPAT), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(patFile, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{loose, link, dir} {
		if err := runManualManagerCLI(t.Context(), []string{"inventory", "--pat-file", path, "--management-url", f.server.URL}, &out); err == nil {
			t.Errorf("accepted PAT file %s", path)
		}
	}
	if err := runManualManagerCLI(t.Context(), []string{"prune-peers", "--offline-for", "5m"}, &out); err == nil {
		t.Fatal("accepted a too-short offline threshold")
	}
	if err := runManualManagerCLI(t.Context(), []string{"frobnicate", "--management-url", f.server.URL}, &out); err == nil ||
		!strings.Contains(err.Error(), `unknown netbird command "frobnicate"`) {
		t.Fatalf("unknown command error = %v", err)
	}
}

func TestLoopSkipsFollowersAndSurvivesFailuresAndPanics(t *testing.T) {
	f := newFakeManager(t)
	f.seedLegacy(t)
	var leader atomic.Bool
	var tokens atomic.Int32
	var logged []string
	loop := Loop{
		Leader: leader.Load,
		Token: func(context.Context) ([]byte, error) {
			switch tokens.Add(1) {
			case 1:
				return nil, errors.New("vault unavailable")
			case 2:
				panic("boom")
			}
			return []byte(testPAT), nil
		},
		ManagementURL: f.server.URL, Desired: GRU(), Interval: 5 * time.Millisecond,
		Logf:         func(format string, args ...any) { logged = append(logged, format) },
		initialDelay: time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	loop.Run(ctx)
	cancel()
	if tokens.Load() != 0 || len(f.mutations) != 0 {
		t.Fatal("a follower read the PAT or changed the manager")
	}
	leader.Store(true)
	loop = loop.withDefaults()
	warned := map[string]bool{}
	if err := loop.cycle(t.Context(), warned); err == nil || !strings.Contains(err.Error(), "vault") {
		t.Fatalf("token failure: %v", err)
	}
	if err := loop.cycle(t.Context(), warned); err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("panic was not recovered: %v", err)
	}
	if err := loop.cycle(t.Context(), warned); err != nil {
		t.Fatal(err)
	}
	if f.groupByName("gru-servers") == nil || len(f.zones) != 1 || len(logged) == 0 {
		t.Fatal("loop cycle did not reconcile after recovering")
	}
}

func TestLoopPrunesEvenWhenSyncRefuses(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	now := time.Now()
	// Duplicate admitted region groups refuse policy sync while peer cleanup continues.
	f.addGroup("sfo-servers")
	f.addGroup("sfo-servers")
	stale := f.addPeer("ts-gru-2", "10.251.0.12", false, now.Add(-2*time.Hour), ids.servers)
	f.addPeer("ts-gru-2", "10.251.0.12", true, now, ids.servers)
	loop := Loop{
		Leader:        func() bool { return true },
		Token:         func(context.Context) ([]byte, error) { return []byte(testPAT), nil },
		ManagementURL: f.server.URL, Desired: GRU(),
	}.withDefaults()
	err := loop.cycle(t.Context(), map[string]bool{})
	if err == nil || !strings.Contains(err.Error(), "sfo-servers") {
		t.Fatalf("sync refusal was not reported: %v", err)
	}
	if f.peer(stale) != nil {
		t.Fatal("a sync refusal stopped peer hygiene")
	}
}

func TestSyncWarnsAboutUnmanagedPoliciesAndBroadSetupKeysWithoutChangingThem(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	all := f.addGroup("All")
	f.policies = append(f.policies, f.policyFrom(f.id("pol"), policyRequest{Name: "Default", Enabled: true,
		SourcePostureChecks: []string{}, Rules: []ruleRequest{{Name: "Default", Enabled: true, Action: "accept",
			Bidirectional: true, Protocol: "all", Sources: []string{all}, Destinations: []string{all}}}}))
	f.setupKeys[0]["auto_groups"] = []string{ids.servers, ids.operators}
	if _, err := Sync(t.Context(), f.api(t), GRU(), true); err != nil {
		t.Fatal(err)
	}
	report, err := Sync(t.Context(), f.api(t), GRU(), true)
	if err != nil || len(report.Changes) != 0 {
		t.Fatalf("second sync: %v %v", report.Changes, err)
	}
	want := []string{"policy operators-to-gru-cell is not in the desired state of cell gru-1",
		"policy operators-to-forgejo is not in the desired state of cell gru-1",
		"policy operators-ping-to-forgejo is not in the desired state of cell gru-1",
		"policy Default is not in the desired state of cell gru-1",
		"setup key gru-servers must auto-assign only group gru-servers"}
	if !slices.Equal(report.Warnings, want) {
		t.Fatalf("warnings %q", report.Warnings)
	}
	if !slices.ContainsFunc(f.policies, func(p apiPolicy) bool { return p.Name == "Default" && p.Enabled }) ||
		len(f.setupKeys[0]["auto_groups"].([]string)) != 2 {
		t.Fatal("sync changed an unmanaged policy or the setup key")
	}
}

func TestRemovePeersDeletesOnlyDisconnectedServerPeersOfTheNamedSlots(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	old := time.Now().Add(-time.Hour)
	// ctl-1's live peer (ids.server1) is connected; its replaced
	// revision is not. db-1 is down and matches only by name; db-2
	// registered under its hostname; a slot-named peer outside the servers
	// group is no server.
	staleA := f.addPeer("ts-gru-1-old", "10.251.0.11", false, old, ids.servers)
	member1 := f.addPeer("gru-1-db-1", "10.251.0.99", false, old, ids.servers)
	member2 := f.addPeer("ip-10-251-0-22", "10.251.0.22", false, old, ids.servers)
	scratch := f.addPeer("scratch", "10.251.0.50", false, old, ids.servers)
	outside := f.addPeer("gru-1-db-1", "203.0.113.9", false, old, ids.operators)
	api, d := f.api(t), GRU()

	if _, err := Remove(t.Context(), api, d, []string{"controller-z"}, false); err == nil {
		t.Fatal("accepted an unknown slot")
	}
	plan, err := Remove(t.Context(), api, d, []string{"ts-gru-1", "db-1"}, false)
	if err != nil || len(plan.Changes) != 2 || len(plan.Warnings) != 1 || len(f.mutations) != 0 {
		t.Fatalf("dry run: %v %v %v %v", plan.Changes, plan.Warnings, f.mutations, err)
	}
	if _, err := Remove(t.Context(), api, d, []string{"ts-gru-1", "db-1"}, true); err != nil {
		t.Fatal(err)
	}
	for id, kept := range map[string]bool{staleA: false, member1: false, ids.server1: true, member2: true,
		scratch: true, outside: true, ids.tsOps: true} {
		if (f.peer(id) != nil) != kept {
			t.Errorf("peer %s kept=%t, want %t", id, f.peer(id) != nil, kept)
		}
	}
	report, err := Remove(t.Context(), api, d, nil, true)
	if err != nil || len(report.Changes) != 2 || f.peer(member2) != nil || f.peer(scratch) != nil ||
		f.peer(ids.server1) == nil || f.peer(outside) == nil {
		t.Fatalf("remove all: %v %v", report.Changes, err)
	}
}

func TestSetupKeyCommandWritesTheKeyOnlyToANewOwnerOnlyFile(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	t.Setenv("NB_PAT", testPAT)
	out := filepath.Join(t.TempDir(), "servers.key")
	var stdout bytes.Buffer
	run := func(args ...string) error {
		stdout.Reset()
		return runManualManagerCLI(t.Context(), append(append([]string{"setup-key"}, args...), "--management-url", f.server.URL), &stdout)
	}
	if err := run("--out", out); err != nil || len(f.mutations) != 0 ||
		!strings.Contains(stdout.String(), "plan: create setup-key gru-servers") ||
		!strings.Contains(stdout.String(), "warning: setup key gru-servers (sk1) is still valid") {
		t.Fatalf("dry run: %q %v %v", stdout.String(), f.mutations, err)
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("dry run created the key file: %v", err)
	}
	if err := run("--out", out, "--apply"); err != nil {
		t.Fatalf("apply: %q %v", stdout.String(), err)
	}
	wire, err := os.ReadFile(out)
	info, statErr := os.Stat(out)
	if err != nil || statErr != nil || string(wire) != "NEW-SECRET-SETUP-KEY\n" || info.Mode().Perm() != 0o600 ||
		strings.Contains(stdout.String(), "NEW-SECRET") {
		t.Fatalf("key file %q %v %v, output %q", wire, info, err, stdout.String())
	}
	key := f.setupKeys[len(f.setupKeys)-1]
	if key["name"] != "gru-servers" || key["type"] != "reusable" || key["expires_in"] != 0 || key["usage_limit"] != 0 ||
		key["ephemeral"] != false || !slices.Equal(key["auto_groups"].([]string), []string{ids.servers}) {
		t.Fatalf("created key %v", key)
	}
	// An existing file is refused before any key is created.
	f.mutations = nil
	if err := run("--out", out, "--apply"); err == nil || len(f.mutations) != 0 {
		t.Fatalf("existing file: %v %v", f.mutations, err)
	}
	// Another region's key auto-assigns only its own servers group.
	if err := run("--out", filepath.Join(t.TempDir(), "sfo.key"), "--servers-group", "sfo-servers", "--apply"); err != nil {
		t.Fatalf("other servers group: %q %v", stdout.String(), err)
	}
	if key := f.setupKeys[len(f.setupKeys)-1]; key["name"] != "sfo-servers" || !slices.Equal(key["auto_groups"].([]string), []string{f.groupByName("sfo-servers").ID}) {
		t.Fatalf("created key %v", key)
	}
	if err := run("--out", filepath.Join(t.TempDir(), "x.key"), "--servers-group", "nobody", "--apply"); err == nil {
		t.Fatal("created a key for an unknown group")
	}
	for _, args := range [][]string{{"setup-key"}, {"remove-peers"}, {"remove-peers", "--all", "--slot", "db-1"}} {
		if err := runManualManagerCLI(t.Context(), args, &stdout); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}
