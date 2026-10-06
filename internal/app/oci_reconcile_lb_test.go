package app

import (
	"encoding/json/v2"
	"errors"
	"slices"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

const publicLBID = "ocid1.loadbalancer.oc1.sa-saopaulo-1.public"

func terraBaseSeats(peers string) map[string]WorkloadProfile {
	return map[string]WorkloadProfile{terrabase.Role: {Env: map[string]string{
		"TERRABASE_REGION": "gru-1", "TERRABASE_PEER_PORT": "9443", "TERRABASE_CLIENT_PORT": "9465", "TERRABASE_PEERS": peers}}}
}

func publishedBackends(t *testing.T, store ociresource.Store) (uint64, []string) {
	t.Helper()
	records, err := store.List(t.Context(), "GRU", lb.Kind)
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	var spec lb.Spec
	if err := json.Unmarshal(records[0].Spec, &spec); err != nil {
		t.Fatal(err)
	}
	var backends []string
	for _, backend := range spec.Backends {
		if spec.LoadBalancerID != publicLBID || spec.BackendSet != "terrabase" || backend.Drain {
			t.Fatalf("spec=%+v", spec)
		}
		backends = append(backends, backend.IP)
	}
	return records[0].Generation, backends
}

func TestPublicLBConfigDecodesAndValidates(t *testing.T) {
	var cfg ControllerConfig
	wire := `{"oci_reconcile":{"enabled":true,"public_lb":{"name":"public-terrabase","load_balancer_id":"` + publicLBID +
		`","backend_set":"terrabase","seats":["gru-1-db-1"]}}}`
	if err := json.Unmarshal([]byte(wire), &cfg, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	public := *cfg.OciReconcile.PublicLB
	if key, err := public.key("GRU"); err != nil || key.String() != "GRU/lb-backends/public-terrabase" {
		t.Fatalf("key=%v err=%v", key, err)
	}
	for _, bad := range []OciReconcileLBConfig{
		{Name: "Public", LoadBalancerID: publicLBID, BackendSet: "terrabase"},
		{Name: "public-terrabase", LoadBalancerID: "ocid1.networkloadbalancer.oc1..n", BackendSet: "terrabase"},
		{Name: "public-terrabase", LoadBalancerID: publicLBID},
		{Name: "public-terrabase", LoadBalancerID: publicLBID, BackendSet: "terrabase", Seats: []string{"gru-1-db-1", "gru-1-db-1"}},
		{Name: "public-terrabase", LoadBalancerID: publicLBID, BackendSet: "terrabase", Seats: []string{""}},
	} {
		if _, err := bad.key("GRU"); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func TestPublicLBSpecIsTheSignedSeats(t *testing.T) {
	public := OciReconcileLBConfig{Name: "public-terrabase", LoadBalancerID: publicLBID, BackendSet: "terrabase"}
	profiles := terraBaseSeats("gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443")
	spec, err := public.spec(profiles)
	if err != nil {
		t.Fatal(err)
	}
	want := []lb.Backend{{IP: "10.251.0.21", Port: 9465}, {IP: "10.251.0.22", Port: 9465}}
	if !slices.Equal(spec.Backends, want) || spec.AllowEmpty {
		t.Fatalf("spec=%+v", spec)
	}
	public.Seats = []string{"gru-1-db-1"}
	if spec, err = public.spec(profiles); err != nil || !slices.Equal(spec.Backends, want[:1]) {
		t.Fatalf("seats: spec=%+v err=%v", spec, err)
	}

	noClient := terraBaseSeats("gru-1-db-1=10.251.0.21:9443")
	delete(noClient[terrabase.Role].Env, "TERRABASE_CLIENT_PORT")
	for name, profiles := range map[string]map[string]WorkloadProfile{
		"no terrabase profile":  {},
		"listed seat not peer":  terraBaseSeats("gru-1-db-2=10.251.0.22:9443"),
		"malformed peers":       terraBaseSeats("gru-1-db-1=10.251.0.21"),
		"client listener off":   noClient,
		"peer off its own port": terraBaseSeats("gru-1-db-1=10.251.0.21:9999"),
	} {
		if spec, err := public.spec(profiles); err == nil {
			t.Fatalf("%s: spec=%+v", name, spec)
		}
	}
}

// The pass fences before it publishes, follows a profile change with a new
// generation, and keeps the last published set when the profile yields an
// unusable one.
func TestPublicLBPassFollowsTheProfile(t *testing.T) {
	public := OciReconcileLBConfig{Name: "public-terrabase", LoadBalancerID: publicLBID, BackendSet: "terrabase"}
	key, err := public.key("GRU")
	if err != nil {
		t.Fatal(err)
	}
	store := ociresource.NewMemoryStore()
	profiles := terraBaseSeats("gru-1-db-1=10.251.0.21:9443")
	current := func() map[string]WorkloadProfile { return profiles }

	if err := publicLBPass(store, reconcileTestFencer{fenced: true}, key, public, current).Run(t.Context(), 1); !errors.Is(err, ociresource.ErrFenced) {
		t.Fatalf("fenced pass err=%v", err)
	}
	if records, _ := store.List(t.Context(), "GRU", lb.Kind); len(records) != 0 {
		t.Fatal("a fenced pass published")
	}
	pass := publicLBPass(store, reconcileTestFencer{}, key, public, current)
	for range 2 {
		if err := pass.Run(t.Context(), 1); err != nil {
			t.Fatal(err)
		}
	}
	if generation, backends := publishedBackends(t, store); generation != 1 || !slices.Equal(backends, []string{"10.251.0.21"}) {
		t.Fatalf("generation=%d backends=%v", generation, backends)
	}

	profiles = terraBaseSeats("gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443")
	if err := pass.Run(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if generation, backends := publishedBackends(t, store); generation != 2 || !slices.Equal(backends, []string{"10.251.0.21", "10.251.0.22"}) {
		t.Fatalf("generation=%d backends=%v", generation, backends)
	}

	profiles = map[string]WorkloadProfile{}
	if err := pass.Run(t.Context(), 1); err == nil {
		t.Fatal("published without a terrabase profile")
	}
	if generation, backends := publishedBackends(t, store); generation != 2 || len(backends) != 2 {
		t.Fatalf("the previous set did not stay: generation=%d backends=%v", generation, backends)
	}
}
