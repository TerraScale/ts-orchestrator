package manager

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGRUDesiredStateIsConsistentWithTheImageInput(t *testing.T) {
	d := GRU()
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	subnet := netip.MustParsePrefix(d.Network.Resource.Address)
	for _, slot := range d.Slots {
		if !subnet.Contains(netip.MustParseAddr(slot.IP)) {
			t.Fatalf("slot %s is outside the cell subnet", slot.Name)
		}
	}
	var input struct {
		PeerNames map[string]string `json:"peer_names"`
	}
	wire, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "image", "inputs", "netbird-gru.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(wire, &input); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"10.251.0.11": "gru-controller-a", "10.251.0.12": "gru-controller-b",
		"10.251.0.13": "gru-controller-c", "10.251.0.21": "gru-member-1", "10.251.0.22": "gru-member-2"}
	if got := d.PeerNames(); !mapsEqual(got, want) || !mapsEqual(input.PeerNames, want) {
		t.Fatalf("slot peer names: desired %v, image input %v", got, input.PeerNames)
	}
	var records []string
	for _, r := range d.Records() {
		records = append(records, r.Name+"="+r.Content)
	}
	wantRecords := []string{
		"controller-a.gru.ts.internal=10.251.0.11", "controller-b.gru.ts.internal=10.251.0.12",
		"controller-c.gru.ts.internal=10.251.0.13", "member-1.gru.ts.internal=10.251.0.21",
		"member-2.gru.ts.internal=10.251.0.22", "nats.gru.ts.internal=10.251.0.11",
		"nats.gru.ts.internal=10.251.0.12", "nats.gru.ts.internal=10.251.0.13",
		"terrabase.gru.ts.internal=10.251.0.21", "terrabase.gru.ts.internal=10.251.0.22",
	}
	if !slices.Equal(records, wantRecords) {
		t.Fatalf("records %v", records)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestSyncRenamesLegacyObjectsInPlaceAndConverges(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	api := f.api(t)
	d := GRU()

	plan, err := Sync(t.Context(), api, d, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.mutations) != 0 {
		t.Fatalf("dry run mutated the manager: %v", f.mutations)
	}
	var lines []string
	for _, change := range plan.Changes {
		lines = append(lines, change.String())
	}
	text := strings.Join(lines, "\n")
	for _, want := range []string{
		"rename group ts-ops-gateway (from gateway)", "rename group gru-servers (from ts-orch-servers)",
		"rename network resource gru-cell-private-subnet (from gru-cell, description)",
		"rename policy operators-to-ts-ops-ping (from operators-ping-to-forgejo, rule name, description, rule description, one-way)",
		"update account settings acct (dns_domain nb.ts.internal)",
		"update dns settings disabled_management_groups (gru-servers)",
		"create dns zone gru-cell (gru.ts.internal)", "create dns record nats.gru.ts.internal A 10.251.0.13",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("plan lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "SECRET") || len(plan.Warnings) != 0 {
		t.Fatalf("unexpected plan output: %s %v", text, plan.Warnings)
	}

	if _, err := Sync(t.Context(), api, d, true); err != nil {
		t.Fatal(err)
	}
	for id, name := range map[string]string{ids.operators: "operators", ids.gateway: "ts-ops-gateway", ids.servers: "gru-servers"} {
		if group := f.group(id); group == nil || group.Name != name || len(group.Peers) != 1 {
			t.Fatalf("group %s lost its ID or members: %+v", name, group)
		}
	}
	if len(f.groups) != 3 {
		t.Fatalf("sync created groups: %+v", f.groups)
	}
	resource := f.networks[0].resources[0]
	if resource.ID != ids.resource || resource.Name != "gru-cell-private-subnet" || resource.Address != "10.251.0.0/25" {
		t.Fatalf("resource: %+v", resource)
	}
	if len(f.policies) != 4 {
		t.Fatalf("policies: %d", len(f.policies))
	}
	for _, policy := range f.policies {
		if len(policy.Rules) != 1 || policy.Rules[0].Name != policy.Name || policy.Rules[0].Bidirectional ||
			policy.Rules[0].Description != policy.Description {
			t.Fatalf("policy %+v", policy)
		}
	}
	ping := f.policies[slices.IndexFunc(f.policies, func(p apiPolicy) bool { return p.ID == ids.ping })]
	if ping.Name != "operators-to-ts-ops-ping" || ping.Rules[0].Protocol != "icmp" || ping.Rules[0].Destinations[0].ID != ids.gateway {
		t.Fatalf("ping policy %+v", ping)
	}
	if got := rawString(f.account, "dns_domain"); got != "nb.ts.internal" || string(f.account["lazy_connection_enabled"]) != "true" ||
		string(f.account["extra"]) != `{"user_approval_required":false}` {
		t.Fatalf("account settings were not merged: %v", f.account)
	}
	if !slices.Equal(f.dnsGroups, []string{ids.servers}) {
		t.Fatalf("dns settings %v", f.dnsGroups)
	}
	if len(f.zones) != 1 || len(f.zones[0].records) != 10 || !slices.Equal(f.zones[0].DistributionGroups, []string{ids.operators}) {
		t.Fatalf("zone %+v", f.zones)
	}

	f.mutations = nil
	again, err := Sync(t.Context(), api, d, true)
	if err != nil || len(again.Changes) != 0 || len(f.mutations) != 0 {
		t.Fatalf("second sync was not a no-op: %v %v %v", again.Changes, f.mutations, err)
	}

	// The zone is fully owned: extra records go, wrong TTLs are corrected.
	zone := f.zones[0]
	zone.records = append(zone.records, apiRecord{ID: "stray", Name: "old.gru.ts.internal", Type: "A", Content: "10.251.0.99", TTL: 300})
	zone.records[0].TTL = 60
	report, err := Sync(t.Context(), api, d, true)
	if err != nil || len(report.Changes) != 2 || len(zone.records) != 10 {
		t.Fatalf("record reconciliation: %v %v records=%d", report.Changes, err, len(zone.records))
	}
}

func TestSyncRefusesUnexpectedNetworkShapeWithoutChanges(t *testing.T) {
	for name, mutate := range map[string]func(*fakeManager, legacyIDs){
		"wider subnet": func(f *fakeManager, _ legacyIDs) { f.networks[0].resources[0].Address = "10.251.0.0/24" },
		"other router": func(f *fakeManager, ids legacyIDs) { f.networks[0].routers[0].Peer = ids.server1 },
		"second router": func(f *fakeManager, ids legacyIDs) {
			f.networks[0].routers = append(f.networks[0].routers, apiRouter{ID: "x", PeerGroups: []string{ids.gateway}})
		},
		"ambiguous group": func(f *fakeManager, _ legacyIDs) { f.addGroup("gateway") },
		"router peer outside gateway": func(f *fakeManager, ids legacyIDs) {
			f.group(ids.gateway).Peers = []groupMinimum{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeManager(t)
			ids := f.seedLegacy(t)
			mutate(f, ids)
			if _, err := Sync(t.Context(), f.api(t), GRU(), true); err == nil {
				t.Fatal("sync accepted an unexpected shape")
			}
			if len(f.mutations) != 0 {
				t.Fatalf("refused sync mutated the manager: %v", f.mutations)
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
	if err != nil || len(report.Warnings) != 2 {
		t.Fatalf("warnings %v error %v", report.Warnings, err)
	}
}

func TestSyncIgnoresRevokedSetupKeysWithTheServerKeyName(t *testing.T) {
	f := newFakeManager(t)
	f.seedLegacy(t)
	f.setupKeys = append(f.setupKeys, map[string]any{"id": "sk0", "name": "gru-ts-orch-servers",
		"type": "reusable", "state": "revoked", "valid": false, "revoked": true, "auto_groups": f.setupKeys[0]["auto_groups"]})
	report, err := Sync(t.Context(), f.api(t), GRU(), false)
	if err != nil || len(report.Warnings) != 0 {
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
	// controller-b: the replaced revision is offline under the slot name;
	// the new revision registered with a suffixed label.
	staleB := f.addPeer("gru-controller-b", "10.251.0.12", false, old, servers)
	liveB := f.addPeer("gru-controller-b", "10.251.0.12", true, now, servers)
	// member-1: the live revision registered under its OS hostname.
	staleM := f.addPeer("gru-member-1", "10.251.0.21", false, old, servers)
	liveM := f.addPeer("ip-10-251-0-21", "10.251.0.21", true, now, servers)
	// member-2 is down: keep its newest peer, delete an ancient one.
	keepM2 := f.addPeer("gru-member-2", "10.251.0.22", false, ancient.Add(time.Hour), servers)
	oldM2 := f.addPeer("gru-member-2-old", "10.251.0.22", false, ancient, servers)
	// An unattributed server peer, long offline, and a recent one.
	orphan := f.addPeer("scratch", "10.251.0.50", false, ancient, servers)
	recent := f.addPeer("scratch-2", "10.251.0.51", false, old, servers)
	// A disconnected peer outside the servers group is never touched.
	outside := f.addPeer("gru-controller-c", "10.251.0.13", false, ancient, ids.operators)
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
	if p := f.peer(liveB); p.Name != "gru-controller-b" || p.DNSLabel != "gru-controller-b.netbird.selfhosted" {
		t.Fatalf("controller-b: %+v", p.apiPeer)
	}
	if p := f.peer(liveM); p.Name != "gru-member-1" || p.DNSLabel != "gru-member-1.netbird.selfhosted" || !p.SSHEnabled {
		t.Fatalf("member-1: %+v", p.apiPeer)
	}
	f.mutations = nil
	again, err := Prune(t.Context(), api, d, PruneOptions{Now: now}, true)
	if err != nil || len(again.Changes) != 0 || len(f.mutations) != 0 {
		t.Fatalf("second prune: %v %v", again.Changes, err)
	}
}

func TestPruneLeavesAmbiguousSlotsAlone(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	f.addPeer("other", "10.251.0.11", true, time.Now(), ids.servers)
	f.addPeer("gru-controller-a", "10.251.0.11", false, time.Now().Add(-48*time.Hour), ids.servers)
	report, err := Prune(t.Context(), f.api(t), GRU(), PruneOptions{}, true)
	if err != nil || len(report.Changes) != 0 || len(report.Warnings) != 1 {
		t.Fatalf("ambiguous slot: %v %v %v", report.Changes, report.Warnings, err)
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

func TestCLIReadsPATSafelyAndPrintsNoSecrets(t *testing.T) {
	f := newFakeManager(t)
	f.seedLegacy(t)
	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	if err := os.WriteFile(patFile, []byte(testPAT+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Run(t.Context(), []string{"inventory", "--pat-file", patFile, "--management-url", f.server.URL}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "SECRET") || !strings.Contains(out.String(), `"gru-ts-orch-servers"`) {
		t.Fatalf("inventory output: %s", out.String())
	}
	out.Reset()
	if err := Run(t.Context(), []string{"sync", "--pat-file", patFile, "--management-url", f.server.URL}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "plan: rename group gru-servers") || !strings.Contains(out.String(), "rerun with --apply") ||
		len(f.mutations) != 0 {
		t.Fatalf("sync dry run output: %s", out.String())
	}
	t.Setenv("NB_PAT", testPAT)
	out.Reset()
	if err := Run(t.Context(), []string{"prune-peers", "--apply", "--management-url", f.server.URL}, &out); err != nil ||
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
		if _, err := readToken(path); err == nil {
			t.Errorf("accepted PAT file %s", path)
		}
	}
	if err := Run(t.Context(), []string{"prune-peers", "--offline-for", "5m"}, &out); err == nil {
		t.Fatal("accepted a too-short offline threshold")
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
