package manager

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	want := map[string]string{"10.251.0.11": "gru-1-ctl-1", "10.251.0.12": "gru-1-ctl-2",
		"10.251.0.13": "gru-1-ctl-3", "10.251.0.21": "gru-1-db-1", "10.251.0.22": "gru-1-db-2"}
	if got := d.PeerNames(); !mapsEqual(got, want) || !mapsEqual(input.PeerNames, want) {
		t.Fatalf("slot peer names: desired %v, image input %v", got, input.PeerNames)
	}
	var records []string
	for _, r := range d.Records() {
		records = append(records, r.Name+"="+r.Content)
	}
	wantRecords := []string{
		"ctl-1.gru.ts.internal=10.251.0.11", "ctl-2.gru.ts.internal=10.251.0.12",
		"ctl-3.gru.ts.internal=10.251.0.13", "db-1.gru.ts.internal=10.251.0.21",
		"db-2.gru.ts.internal=10.251.0.22", "nats.gru.ts.internal=10.251.0.11",
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
		"update dns settings disabled_management_groups (gru-servers,sfo-servers)",
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
	if len(f.groups) != len(d.Groups) {
		t.Fatalf("sync created groups: %+v", f.groups)
	}
	resource := f.networks[0].resources[0]
	if resource.ID != ids.resource || resource.Name != "gru-cell-private-subnet" || resource.Address != "10.251.0.0/25" {
		t.Fatalf("resource: %+v", resource)
	}
	if len(f.policies) != len(d.Policies) {
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
	sfo := f.groups[slices.IndexFunc(f.groups, func(g apiGroup) bool { return g.Name == "sfo-servers" })]
	if !slices.Equal(f.dnsGroups, []string{ids.servers, sfo.ID}) {
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

func TestSyncBootstrapsFreshAccountBeforeTheRouterJoinsTheGateway(t *testing.T) {
	f := newFakeManager(t)
	tsOps := f.addPeer("ts-ops", "10.250.10.155", true, time.Now())
	api := f.api(t)
	d := GRU()

	text := func(report Report) string {
		var lines []string
		for _, change := range report.Changes {
			lines = append(lines, change.String())
		}
		return strings.Join(lines, "\n")
	}
	plan, err := Sync(t.Context(), api, d, false)
	if err != nil {
		t.Fatalf("fresh account dry run refused: %v", err)
	}
	planned := text(plan)
	for _, want := range []string{"create group operators", "create group ts-ops-gateway", "create group gru-servers",
		"create group ops-automation", "create policy operators-to-gru-servers-ssh", "create policy operators-to-ts-ops-ping",
		"create policy ops-automation-to-gru-servers-ssh"} {
		if !strings.Contains(planned, want) {
			t.Errorf("plan lacks %q:\n%s", want, planned)
		}
	}
	if strings.Contains(planned, "network") || strings.Contains(planned, "operators-to-gru-cell-ops-ports") {
		t.Fatalf("deferred network objects were planned:\n%s", planned)
	}
	warnings := strings.Join(plan.Warnings, "\n")
	if !strings.Contains(warnings, "network gru-cell deferred: add peer ts-ops to group ts-ops-gateway") ||
		!strings.Contains(warnings, "policy operators-to-gru-cell-ops-ports deferred") {
		t.Fatalf("warnings %v", plan.Warnings)
	}

	if _, err := Sync(t.Context(), api, d, true); err != nil {
		t.Fatal(err)
	}
	if len(f.groups) != len(d.Groups) || len(f.networks) != 0 || len(f.policies) != len(d.Policies)-1 {
		t.Fatalf("first sync: groups %d networks %d policies %d", len(f.groups), len(f.networks), len(f.policies))
	}

	gateway := f.groupByName("ts-ops-gateway")
	gateway.Peers = append(gateway.Peers, groupMinimum{ID: tsOps, Name: "ts-ops"})
	report, err := Sync(t.Context(), api, d, true)
	if err != nil {
		t.Fatal(err)
	}
	applied := text(report)
	for _, want := range []string{"create network gru-cell", "create network resource gru-cell-private-subnet",
		"create network router gru-cell/ts-ops", "create policy operators-to-gru-cell-ops-ports"} {
		if !strings.Contains(applied, want) {
			t.Errorf("second sync lacks %q:\n%s", want, applied)
		}
	}
	if strings.Contains(strings.Join(report.Warnings, "\n"), "deferred") {
		t.Fatalf("second sync still deferred: %v", report.Warnings)
	}
	if len(f.networks) != 1 || len(f.networks[0].resources) != 1 || len(f.networks[0].routers) != 1 ||
		f.networks[0].routers[0].Peer != tsOps || len(f.policies) != len(d.Policies) {
		t.Fatalf("network %+v policies %d", f.networks, len(f.policies))
	}
	f.mutations = nil
	again, err := Sync(t.Context(), api, d, true)
	if err != nil || len(again.Changes) != 0 || len(f.mutations) != 0 {
		t.Fatalf("third sync was not a no-op: %v %v %v", again.Changes, f.mutations, err)
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
	f.setupKeys = append(f.setupKeys, map[string]any{"id": "sk0", "name": "gru-servers",
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
	// ctl-2: the replaced revision is offline under the slot name;
	// the new revision registered with a suffixed label.
	staleB := f.addPeer("gru-1-ctl-2", "10.251.0.12", false, old, servers)
	liveB := f.addPeer("gru-1-ctl-2", "10.251.0.12", true, now, servers)
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
	outside := f.addPeer("gru-1-ctl-3", "10.251.0.13", false, ancient, ids.operators)
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
	if p := f.peer(liveB); p.Name != "gru-1-ctl-2" || p.DNSLabel != "gru-1-ctl-2.netbird.selfhosted" {
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

func TestPruneLeavesAmbiguousSlotsAlone(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	f.addPeer("other", "10.251.0.11", true, time.Now(), ids.servers)
	f.addPeer("gru-1-ctl-1", "10.251.0.11", false, time.Now().Add(-48*time.Hour), ids.servers)
	report, err := Prune(t.Context(), f.api(t), GRU(), PruneOptions{}, true)
	if err != nil || len(report.Changes) != 0 || len(report.Warnings) != 1 {
		t.Fatalf("ambiguous slot: %v %v %v", report.Changes, report.Warnings, err)
	}
}

func TestPruneReportsDNSLabelHeldOutsideTheServersGroup(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	now := time.Now()
	f.addPeer("gru-1-ctl-2", "203.0.113.9", true, now, ids.operators)
	live := f.addPeer("ip-10-251-0-12", "10.251.0.12", true, now, ids.servers)
	_, err := Prune(t.Context(), f.api(t), GRU(), PruneOptions{Now: now}, true)
	if err == nil || !strings.Contains(err.Error(), "another peer holds the DNS label gru-1-ctl-2") {
		t.Fatalf("prune error = %v", err)
	}
	if f.peer(live).Name != "gru-1-ctl-2" {
		t.Fatalf("live peer: %+v", f.peer(live).apiPeer)
	}
}

func TestPruneLeavesSlotWhoseNameIsHeldByAnotherConnectedPeerAlone(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	now := time.Now()
	stale := f.addPeer("gru-1-ctl-2-old", "10.251.0.12", false, now.Add(-72*time.Hour), ids.servers)
	live := f.addPeer("ip-10-251-0-12", "10.251.0.12", true, now, ids.servers)
	squatter := f.addPeer("gru-1-ctl-2", "10.251.0.99", true, now, ids.servers)
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
	if f.peer(live).Name != "ip-10-251-0-12" || f.peer(squatter).Name != "gru-1-ctl-2" {
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
		if err := d.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoopWithoutCallbacksNeitherPanicsNorActs(t *testing.T) {
	var loop Loop
	loop = loop.withDefaults()
	if loop.Leader() {
		t.Fatal("a loop without a leadership check acts as the leader")
	}
	loop.Logf("ignored %d", 1)
	// Run on a zero Loop must not dereference the nil callbacks.
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	Loop{initialDelay: time.Millisecond, Interval: time.Millisecond}.Run(ctx)
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
		err := Run(t.Context(), append(command, "--management-url", f.server.URL), &out)
		if err == nil || strings.Contains(out.String(), "no changes") {
			t.Fatalf("%v on a failing manager: %q %v", command, out.String(), err)
		}
	}

	partial := Report{Changes: []Change{{"create", "group", "operators", ""}}, Warnings: []string{"w"}}
	out.Reset()
	writeReport(&out, partial, true, errors.New("boom"))
	if out.String() != "applied: create group operators\nwarning: w\n" {
		t.Fatalf("partial report: %q", out.String())
	}
	out.Reset()
	writeReport(&out, Report{}, true, errors.New("boom"))
	if out.String() != "" {
		t.Fatalf("failed empty report: %q", out.String())
	}
	out.Reset()
	writeReport(&out, Report{}, true, nil)
	if out.String() != "no changes\n" {
		t.Fatalf("empty report: %q", out.String())
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
	if strings.Contains(out.String(), "SECRET") || !strings.Contains(out.String(), `"gru-servers"`) {
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
	if err := Run(t.Context(), []string{"frobnicate", "--management-url", f.server.URL}, &out); err == nil ||
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
	// A routing-peer reinstall enrolled before the old peer was removed: two
	// ts-ops peers in the gateway group make sync refuse the existing network.
	f.addPeer("ts-ops", "10.250.10.155", true, now, ids.gateway)
	stale := f.addPeer("gru-1-ctl-2", "10.251.0.12", false, now.Add(-2*time.Hour), ids.servers)
	f.addPeer("gru-1-ctl-2", "10.251.0.12", true, now, ids.servers)
	loop := Loop{
		Leader:        func() bool { return true },
		Token:         func(context.Context) ([]byte, error) { return []byte(testPAT), nil },
		ManagementURL: f.server.URL, Desired: GRU(),
	}.withDefaults()
	err := loop.cycle(t.Context(), map[string]bool{})
	if err == nil || !strings.Contains(err.Error(), "refusing NetBird network sync") {
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
	want := []string{"policy Default is not in the desired state of cell gru-1",
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
	staleA := f.addPeer("gru-1-ctl-1-old", "10.251.0.11", false, old, ids.servers)
	member1 := f.addPeer("gru-1-db-1", "10.251.0.99", false, old, ids.servers)
	member2 := f.addPeer("ip-10-251-0-22", "10.251.0.22", false, old, ids.servers)
	scratch := f.addPeer("scratch", "10.251.0.50", false, old, ids.servers)
	outside := f.addPeer("gru-1-db-1", "203.0.113.9", false, old, ids.operators)
	api, d := f.api(t), GRU()

	if _, err := Remove(t.Context(), api, d, []string{"controller-z"}, false); err == nil {
		t.Fatal("accepted an unknown slot")
	}
	plan, err := Remove(t.Context(), api, d, []string{"ctl-1", "db-1"}, false)
	if err != nil || len(plan.Changes) != 2 || len(plan.Warnings) != 1 || len(f.mutations) != 0 {
		t.Fatalf("dry run: %v %v %v %v", plan.Changes, plan.Warnings, f.mutations, err)
	}
	if _, err := Remove(t.Context(), api, d, []string{"ctl-1", "db-1"}, true); err != nil {
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
		return Run(t.Context(), append(append([]string{"setup-key"}, args...), "--management-url", f.server.URL), &stdout)
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
	if err := run("--out", filepath.Join(t.TempDir(), "sfo.key"), "--servers-group", "ts-ops-gateway", "--apply"); err != nil {
		t.Fatalf("other servers group: %q %v", stdout.String(), err)
	}
	if key := f.setupKeys[len(f.setupKeys)-1]; key["name"] != "ts-ops-gateway" || !slices.Equal(key["auto_groups"].([]string), []string{ids.gateway}) {
		t.Fatalf("created key %v", key)
	}
	if err := run("--out", filepath.Join(t.TempDir(), "x.key"), "--servers-group", "nobody", "--apply"); err == nil {
		t.Fatal("created a key for an unknown group")
	}
	for _, args := range [][]string{{"setup-key"}, {"remove-peers"}, {"remove-peers", "--all", "--slot", "db-1"}} {
		if err := Run(t.Context(), args, &stdout); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}
