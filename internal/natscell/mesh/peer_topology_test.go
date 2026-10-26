package mesh

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func TestTopologyRejectsTruncationAndSurvivesRestartWithoutTrustingFile(t *testing.T) {
	regions := Regions()[:2]
	cfg := config{dir: t.TempDir(), peersDir: t.TempDir(), region: regions[0], server: "home",
		address: func() (string, error) { return "10.200.0.1", nil }}
	p, err := newPeers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	up := map[string]peer{regions[0]: {"home", "10.200.0.1"}, regions[1]: {"remote", "10.200.0.2"}}
	if err := p.admit(up, regions); err != nil {
		t.Fatal(err)
	}
	if err := p.track("app", regions); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(cfg.peersDir, "app", "peers")
	complete, _ := os.ReadFile(file)
	for range peersMissedRounds + 1 {
		_ = p.observe(map[string]peer{regions[0]: up[regions[0]]})
	}
	if got, _ := os.ReadFile(file); !bytes.Equal(got, complete) || p.rejected["app"] != 1 {
		t.Fatalf("truncated proposal replaced admitted membership: %q", got)
	}
	// A future writer/file corruption must not poison the oracle after a restart.
	if err := os.WriteFile(file, []byte("home "+regions[0]+" 10.200.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	restarted, err := newPeers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(restarted.regions, regions[1]) {
		t.Fatal("cancellation membership lost an unavailable admitted region on restart")
	}
	n := &Node{cfg: cfg, peers: restarted, desired: map[string]desiredState{"app": stateFor(Entry{Generation: 1,
		Spec: &swarmruntime.ServiceSpec{Name: "app", Regions: regions}})}}
	n.publishTopologyDesired()
	n.attestPeers(t.Context())
	if report := n.localAttestations()["app"]; report.Mismatch != 1 || report.Expected != 2 {
		t.Fatalf("missing peer not detected: %+v", report)
	}
	data, _ := os.ReadFile(filepath.Join(cfg.peersDir, "app", "topology.json"))
	var manifest peerTopology
	if err := protocol.DecodeStrict(data, &manifest, maxWire); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Peers) != 2 || manifest.Generation != 1 {
		t.Fatalf("oracle followed damaged file: %+v", manifest)
	}
	if info, _ := os.Stat(filepath.Join(cfg.peersDir, "app", "topology.json")); info.Mode().Perm() != 0644 {
		t.Fatal("manifest not readable by task")
	}
	if err := os.WriteFile(file, []byte("wrong "+regions[1]+" 10.200.0.99\nextra "+Regions()[2]+" 10.200.0.98\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := restarted.track("app", regions); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(file); !bytes.Equal(got, complete) {
		t.Fatal("file identity overrode durable admission")
	}
	// An admitted placement update, unlike a missed ping, authorizes a drain.
	n.desired["app"] = stateFor(Entry{Generation: 2, Spec: &swarmruntime.ServiceSpec{Name: "app", Regions: regions[:1]}})
	n.publishTopologyDesired()
	if err := restarted.track("app", regions[:1]); err != nil {
		t.Fatal(err)
	}
	n.attestPeers(t.Context())
	if got := n.localAttestations()["app"]; got.Mismatch != 0 || got.Expected != 1 || got.Rejected != 0 {
		t.Fatalf("authorized drain: %+v", got)
	}
}

func TestPeerMetricsFailClosedForMissingAndStaleReports(t *testing.T) {
	regions := Regions()[:2]
	n := &Node{peers: &peers{}, desired: map[string]desiredState{"app": stateFor(Entry{Generation: 1,
		Spec: &swarmruntime.ServiceSpec{Name: "app", Regions: regions}})},
		peerReports: map[string]map[string]PeerAttestation{regions[0]: {"app": {Expected: 2, CheckedAt: time.Now().Add(-time.Minute)}}}}
	n.publishTopologyDesired()
	var out bytes.Buffer
	n.writePeerMetrics(&out)
	if !strings.Contains(out.String(), `ts_orch_peer_topology_mismatch{region="`+regions[1]+`",service="app"} 1`) || !strings.Contains(out.String(), "ts_orch_peer_topology_age_seconds") {
		t.Fatalf("missing observation appears healthy: %s", &out)
	}
}

func TestExportedPeerMismatchReadsOnlyTheTopologyGauge(t *testing.T) {
	gauge := "# HELP terrabase_peer_topology_mismatch One when admitted topology differs.\n# TYPE terrabase_peer_topology_mismatch gauge\nterrabase_peer_topology_mismatch{otel_scope_name=\"TerraScale.TerraBase\"} %s\n"
	// A production exposition passed 2 MiB with thousands of per-database series.
	var bulk strings.Builder
	for i := 0; bulk.Len() < 3<<20; i++ {
		fmt.Fprintf(&bulk, "terrabase_replication_cdc_backlog{database=\"%026d\",peer_region=\"sjc\"} %d\n", i, i)
	}
	for _, test := range []struct {
		name string
		body string
		want int
	}{
		{"agrees beyond 2 MiB", bulk.String() + fmt.Sprintf(gauge, "0") + "terrabase_peer_topology_mismatch_total 3\n", 0},
		{"mismatch", fmt.Sprintf(gauge, "1"), 1},
		{"absent", bulk.String(), 1},
		{"two samples", fmt.Sprintf(gauge, "0") + "terrabase_peer_topology_mismatch{otel_scope_name=\"other\"} 0\n", 1},
		{"malformed", "terrabase_peer_topology_mismatch zero\n", 1},
		{"overlong line", strings.Repeat("x", 2<<20) + "\n" + fmt.Sprintf(gauge, "0"), 1},
	} {
		if got := exportedPeerMismatch(strings.NewReader(test.body)); got != test.want {
			t.Errorf("%s: mismatch %d, want %d", test.name, got, test.want)
		}
	}
}
