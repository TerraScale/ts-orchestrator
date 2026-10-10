package regionview

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlink"
)

// A hostile or broken peer controls everything in its summary reply. Its
// topology lists must arrive bounded, it must not speak for another region,
// and region names must not widen the request subject.
func TestRemoteSummaryFromHostilePeerIsBounded(t *testing.T) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	ctx := t.Context()

	const flood = 5000
	names := make([]string, flood)
	hostile := Summary{Version: summaryVersion, Region: "sfo", Local: true,
		Versions: make([]Version, 100), Members: make([]Member, flood), Hosts: make([]Host, flood), Nodes: make([]Node, 100),
		Decisions: []decisionlog.Decision{{ID: "forged", Region: "gru"}}}
	for index := range flood {
		names[index] = "n" + strconv.Itoa(index)
		hostile.Members[index] = Member{Name: names[index], Role: "controller", Ready: true}
		hostile.Hosts[index] = Host{Name: names[index]}
		if index < len(hostile.Nodes) {
			hostile.Nodes[index] = Node{Name: names[index], Services: make([]Service, 100), Backends: make([]Backend, 100),
				Fence: names[:100]}
		}
		if index < len(hostile.Versions) {
			hostile.Versions[index] = Version{Version: names[index], Members: names[:100]}
		}
	}
	hostile.Quorum.Missing = names
	hostile.ObservedAt = time.Now().UTC()
	forged := hostile
	forged.Region = "gru"
	// Prepare the flood before the request deadline: the link timeout tests
	// delivery, not how quickly a loaded race-test host marshals the fixture.
	hostileWire, err := json.Marshal(hostile)
	if err != nil {
		t.Fatal(err)
	}
	forgedWire, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	var seenMu sync.Mutex
	var seen []string
	if _, err := conn.Subscribe(">", func(message *nats.Msg) {
		if strings.HasPrefix(message.Subject, "_INBOX.") {
			return
		}
		seenMu.Lock()
		seen = append(seen, message.Subject)
		seenMu.Unlock()
		data := hostileWire
		if strings.HasPrefix(message.Subject, "ts.orch.v1.mia.") {
			data = forgedWire
		}
		if message.Reply != "" {
			if err := message.Respond(data); err != nil {
				t.Errorf("hostile peer response: %v", err)
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	links, err := regionlink.New("gru", nil, []string{"SFO", "MIA", "sfo.>", "*", "fra.obs"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if regions := links.Regions(); !slices.Equal(regions, []string{"gru", "mia", "sfo"}) {
		t.Fatalf("regions = %v, injected tokens must be dropped", regions)
	}
	if err := links.Link("sfo.>", conn); err == nil {
		t.Fatal("a wildcard region must not link")
	}
	_ = links.Link("sfo", conn)
	_ = links.Link("mia", conn)
	local := &Provider{Cell: "gru", Cluster: staticCluster{cluster(member("c1", "v1", true))}, Links: links}
	sfo := local.Probe(ctx, "sfo")
	if sfo.Reach != decisionlog.RegionOK || sfo.Local || len(sfo.Decisions) != 0 {
		t.Fatalf("sfo reach=%s local=%v decisions=%d", sfo.Reach, sfo.Local, len(sfo.Decisions))
	}
	if len(sfo.Members) > maxTopologyMembers || len(sfo.Hosts) > maxTopologyHosts ||
		len(sfo.Quorum.Missing) > maxTopologyMembers || len(sfo.Versions) != maxTopologyMembers ||
		len(sfo.Versions[0].Members) != maxTopologyMembers || len(sfo.Members) != maxTopologyMembers {
		t.Fatalf("unbounded peer lists: members=%d hosts=%d missing=%d versions=%d", len(sfo.Members), len(sfo.Hosts),
			len(sfo.Quorum.Missing), len(sfo.Versions))
	}
	if len(sfo.Nodes) != maxTopologyMembers || len(sfo.Nodes[0].Services) != maxNodeServices ||
		len(sfo.Nodes[0].Backends) != maxNodeBackends || len(sfo.Nodes[0].Fence) != maxNodeBackends {
		t.Fatalf("unbounded peer nodes: nodes=%d", len(sfo.Nodes))
	}
	if mia := local.Probe(ctx, "mia"); mia.Reach != decisionlog.RegionError || len(mia.Members) != 0 {
		t.Fatalf("a summary naming another region must be rejected: %s", mia.Reach)
	}
	seenMu.Lock()
	defer seenMu.Unlock()
	if len(seen) < 2 {
		t.Fatalf("requests seen = %v", seen)
	}
	for _, subject := range seen {
		if subject != "ts.orch.v1.sfo.obs.region" && subject != "ts.orch.v1.mia.obs.region" {
			t.Errorf("unexpected request subject %q", subject)
		}
	}
}
