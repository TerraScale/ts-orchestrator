package region

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/lb"
)

const (
	sfoPlan  = "../../deploy/oci-region/sfo-1-plan.json"
	homePlan = "../../deploy/oci-region/plan.json"
)

var (
	sfoLive = Live{AvailabilityDomain: "YDvv:US-SANJOSE-1-AD-1",
		ServiceID:   "ocid1.service.oc1.us-sanjose-1.aaaaaaaa7w72lnqlnse4zc5vubcjv6mhsooz3jlaazcbzq7hnzih26qqiw6a",
		ServiceCIDR: "all-sjc-services-in-oracle-services-network"}
	fraLive = Live{AvailabilityDomain: "YDvv:EU-FRANKFURT-1-AD-1",
		ServiceID:   "ocid1.service.oc1.eu-frankfurt-1.aaaaaaaafra",
		ServiceCIDR: "all-fra-services-in-oracle-services-network"}
)

func load(t *testing.T, path string) map[string]any {
	t.Helper()
	plan, err := ociregion.LoadPlan(path)
	if err != nil {
		t.Fatal(err)
	}
	delete(plan, "_source_path")
	return plan
}

func TestNetworkFollowsTheCatalog(t *testing.T) {
	for cell, want := range map[string]string{"GRU": "10.251.0.0/24", "SFO": "10.252.0.0/24", "FRA": "10.253.0.0/24"} {
		if got, err := Network(cell); err != nil || got != want {
			t.Fatalf("%s: %q %v", cell, got, err)
		}
	}
	if _, err := Network("XYZ"); err == nil {
		t.Fatal("a cell outside the catalog has a network")
	}
}

// Deriving fra from sfo-1 and sfo back from fra must give sfo-1's reviewed
// plan: every field is either derived or kept, none hand-edited.
func TestDeriveRoundTripsTheReviewedPlan(t *testing.T) {
	sfo := load(t, sfoPlan)
	fra, err := Derive(load(t, sfoPlan), "fra", "eu-frankfurt-1", fraLive)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fra-1-plan.json")
	if err := writePlan(path, fra); err != nil {
		t.Fatal(err)
	}
	fra = load(t, path)
	purpose := fra["purpose"]
	delete(fra, "purpose") // names its template
	data, _ := json.Marshal(fra)
	text := string(data)
	for _, gone := range []string{"sfo-1", "ts-sfo", "10.252.", "all-sjc", "us-sanjose-1"} {
		if strings.Contains(text, gone) {
			t.Fatalf("fra plan still names %q", gone)
		}
	}
	public := fra["public_api"].(map[string]any)
	if fra["cell"] != "FRA" || fra["network_cidr"] != "10.253.0.0/24" || fra["subnet_cidr"] != "10.253.0.0/25" ||
		public["subnet_cidr"] != "10.253.0.128/26" || !reflect.DeepEqual(public["terrabase_members"], []any{"ts-fra-1", "ts-fra-2", "ts-fra-3"}) ||
		fra["preview_compartment_names"].(map[string]any)["control"] != "fra-1-control" ||
		fra["hosts"].([]any)[2].(map[string]any)["private_ip"] != "10.253.0.13" ||
		!reflect.DeepEqual(fra["existing_forgejo"], sfo["existing_forgejo"]) || !reflect.DeepEqual(public["origin_pull"], sfo["public_api"].(map[string]any)["origin_pull"]) {
		t.Fatalf("fra plan: %s", text)
	}
	fra["purpose"] = purpose
	back, err := Derive(fra, "sfo", "us-sanjose-1", sfoLive)
	if err != nil {
		t.Fatal(err)
	}
	back["purpose"] = sfo["purpose"]
	want, _ := json.Marshal(sfo, json.Deterministic(true))
	got, _ := json.Marshal(back, json.Deterministic(true))
	if string(got) != string(want) {
		t.Fatalf("round trip differs\nwant %s\n got %s", want, got)
	}
}

func TestDeriveRefuses(t *testing.T) {
	gru := load(t, "../../deploy/oci-region/plan.json")
	for name, run := range map[string]func() error{
		"home region":       func() error { _, err := Derive(load(t, sfoPlan), "gru", "sa-saopaulo-1", fraLive); return err },
		"wrong OCI region":  func() error { _, err := Derive(load(t, sfoPlan), "fra", "us-sanjose-1", fraLive); return err },
		"not in catalog":    func() error { _, err := Derive(load(t, sfoPlan), "nrt", "ap-tokyo-1", fraLive); return err },
		"same region":       func() error { _, err := Derive(load(t, sfoPlan), "sfo", "us-sanjose-1", sfoLive); return err },
		"home template":     func() error { _, err := Derive(gru, "fra", "eu-frankfurt-1", fraLive); return err },
		"no live lookup":    func() error { _, err := Derive(load(t, sfoPlan), "fra", "eu-frankfurt-1", Live{}); return err },
		"existing out file": func() error { return writePlan("/dev/null/x", map[string]any{}) },
	} {
		if run() == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestRegionProfileKeepsOnlyDefaultInTheRegion(t *testing.T) {
	dir := t.TempDir()
	for input, want := range map[string]string{
		"[DEFAULT]\nuser=u\nregion=sa-saopaulo-1\nkey_file=~/.oci/k.pem\n[OTHER]\nregion=x\n": "[DEFAULT]\nuser=u\nregion=eu-frankfurt-1\nkey_file=~/.oci/k.pem\n",
		"[OTHER]\nuser=o\n[DEFAULT]\nuser=u":                                                  "[DEFAULT]\nuser=u\nregion=eu-frankfurt-1\n",
	} {
		path := filepath.Join(dir, "config")
		if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := regionProfile(path, "eu-frankfurt-1"); err != nil || string(got) != want {
			t.Fatalf("%q: %q %v", input, got, err)
		}
	}
	path := filepath.Join(dir, "none")
	_ = os.WriteFile(path, []byte("[OTHER]\nregion=x\n"), 0o600)
	if _, err := regionProfile(path, "eu-frankfurt-1"); err == nil {
		t.Fatal("a config without DEFAULT gave a profile")
	}
}

// creation runs region create against a fake ts-orch that plays each
// command's file effects.
type creation struct {
	*Creation
	calls    []string
	failOn   string
	verified int
	verifyOK bool
}

func newCreation(t *testing.T) *creation {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(filepath.Join(home, ".oci"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".oci", "config"), []byte("[DEFAULT]\nuser=u\nregion=sa-saopaulo-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("CF_API_TOKEN", "token")
	t.Setenv("NB_PAT", "pat")
	base := filepath.Join(dir, "attempt-base.json")
	if err := os.WriteFile(base, []byte(`{"validity_days":364,"trust":{"root_public":"/k/root.pub","root_private":"/k/root.key"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)
	c := &creation{}
	c.Creation = &Creation{Label: "fra", OCIRegion: "eu-frankfurt-1", State: filepath.Join(dir, "state"), Template: sfoPlan,
		AttemptBase: base, HomeOperator: "/var/lib/terrascale-operator/operator.json", HomePlan: homePlan, Wait: time.Minute, Out: &bytes.Buffer{},
		Now:    func() time.Time { clock = clock.Add(time.Minute); return clock },
		Lookup: func(_ context.Context, tenancy, region string) (Live, error) { return fraLive, nil },
		Verify: func(_ context.Context, bound string, wait time.Duration) error {
			c.verified++
			if !c.verifyOK {
				return errors.New("2 of 4 region checks fail")
			}
			return nil
		}}
	c.Run = func(_ context.Context, sudo bool, args ...string) (string, error) {
		call := strings.Join(args, " ")
		if sudo {
			call = "sudo " + call
		}
		c.calls = append(c.calls, call)
		if c.failOn != "" && strings.HasPrefix(call, c.failOn) {
			return "", errors.New("exit status 1")
		}
		flag := func(name string) string { return args[slices.Index(args, name)+1] }
		switch {
		case strings.HasPrefix(call, "oci-region foundation"):
			plan := load(t, flag("--plan"))
			ids := plan["resource_ids"].(map[string]any)
			ids["vcn"], ids["vault"] = "ocid1.vcn.oc1.eu-frankfurt-1.aaaavcn", "ocid1.vault.oc1.eu-frankfurt-1.aaaavault"
			ids["key"], ids["control_compartment"] = "ocid1.key.oc1.eu-frankfurt-1.aaaakey", "ocid1.compartment.oc1..aaaacontrol"
			return "", writePlan(flag("--out"), plan)
		case strings.HasPrefix(call, "vault put"):
			return `{"secret":"fra-1-netbird-setup-key","id":"ocid1.vaultsecret.oc1.eu-frankfurt-1.aaaanb","created":true}` + "\n", nil
		case strings.HasPrefix(call, "oci-region public-api apply"):
			return "plan done\n" + `{"network_load_balancer":"ocid1.loadbalancer.oc1.eu-frankfurt-1.aaaalb","public_subnet":"ocid1.subnet.oc1.eu-frankfurt-1.aaaapub","public_ip":"192.0.2.1"}` + "\n", nil
		case strings.HasPrefix(call, "sudo atlas add-region"):
			return `{"status":"planned"}`, os.WriteFile(flag("--out"), []byte("{}"), 0o600)
		}
		return "", nil
	}
	return c
}

func TestCreateRunsEveryStepOnceAndResumes(t *testing.T) {
	c := newCreation(t)
	c.failOn = "oci-region dns"
	if err := c.Create(t.Context()); err == nil {
		t.Fatal("a failed dns step passed")
	}
	c.failOn = ""
	if err := c.Create(t.Context()); err == nil || c.verified != 1 {
		t.Fatalf("verification did not gate the run: %v, %d", err, c.verified)
	}
	c.verifyOK = true
	if err := c.Create(t.Context()); err != nil {
		t.Fatal(err)
	}
	state := c.State
	want := []string{
		"oci-region foundation --plan " + state + "/plan.json --out " + state + "/bound-plan.json --apply",
		"netbird sync --apply",
		"netbird setup-key --servers-group fra-servers --out " + state + "/netbird-setup-key --apply",
		"vault put --vault-id ocid1.vault.oc1.eu-frankfurt-1.aaaavault --key-id ocid1.key.oc1.eu-frankfurt-1.aaaakey --compartment-id ocid1.compartment.oc1..aaaacontrol --name fra-1-netbird-setup-key --file " + state + "/netbird-setup-key",
		"netbird image-input --plan " + state + "/bound-plan.json --setup-key-secret-id ocid1.vaultsecret.oc1.eu-frankfurt-1.aaaanb --out " + state + "/netbird.json",
		"ts-auth secrets --plan " + state + "/bound-plan.json",
		"oci-region attempt --config " + state + "/attempt.json up",
		"oci-region public-api cert --plan " + state + "/bound-plan.json --apply",
		"oci-region public-api apply --plan " + state + "/bound-plan.json --member-ca " + state + "/attempt/material/terrabase-member-ca.pem --cell-ca " + state + "/attempt/material/ca.pem",
		"oci-region peer --pair-intent " + state + "/peer-intent.json --left-plan " + state + "/bound-plan.json --right-plan " + homePlan +
			" --out " + state + "/peer-bound-intent.json --apply",
		"oci-region dns --plan " + state + "/bound-plan.json --apply",
		"oci-region dns --plan " + state + "/bound-plan.json --apply",
		"sudo atlas add-region --config /var/lib/terrascale-operator/operator.json --cell fra-1 --out " + state + "/atlas.candidate.json",
		"release sign-spec --candidate " + state + "/atlas.candidate.json --root --root-key /k/root.pub --signing-key /k/root.key --out " + state + "/atlas.signed.json",
		"sudo apply --config /var/lib/terrascale-operator/operator.json -f " + state + "/atlas.signed.json",
	}
	if !slices.Equal(c.calls, want) {
		t.Fatalf("calls:\n%s", strings.Join(c.calls, "\n"))
	}
	bound := load(t, filepath.Join(state, "bound-plan.json"))
	ids := bound["resource_ids"].(map[string]any)
	if ids["network_load_balancer"] != "ocid1.loadbalancer.oc1.eu-frankfurt-1.aaaalb" || ids["vcn"] != "ocid1.vcn.oc1.eu-frankfurt-1.aaaavcn" || ids["public_ip"] != nil {
		t.Fatalf("bound IDs: %v", ids)
	}
	var config map[string]any
	data, _ := os.ReadFile(filepath.Join(state, "attempt.json"))
	if err := json.Unmarshal(data, &config); err != nil || !entityid.Valid(config["deployment_id"].(string)) || config["prefix"] != "fra-1" ||
		config["base_plan"] != state+"/bound-plan.json" || config["validity_days"] != 364.0 ||
		config["image"].(map[string]any)["netbird_config"] != state+"/netbird.json" {
		t.Fatalf("attempt config: %s", data)
	}
	if profile, _ := os.ReadFile(filepath.Join(state, "oci-config")); !strings.Contains(string(profile), "region=eu-frankfurt-1") {
		t.Fatalf("attempt OCI profile: %s", profile)
	}
	report := c.Out.(*bytes.Buffer).String()
	if !strings.Contains(report, "| dns | 1m0s |") || !strings.Contains(report, "| total |") {
		t.Fatalf("report: %s", report)
	}
	// Done is done: a fourth run runs nothing.
	c.calls = nil
	if err := c.Create(t.Context()); err != nil || len(c.calls) != 0 || c.verified != 2 {
		t.Fatalf("rerun: %v %v %d", err, c.calls, c.verified)
	}
}

// The peer step pins both plans in a draft pair intent once and peers the
// region with the global home; a plan changed since is refused.
func TestCreatePeersWithTheHome(t *testing.T) {
	// After edge, which rewrites bound-plan.json with the load balancer's
	// IDs: the intent pins the final plan.
	if i := slices.Index(Steps, "peer"); i < 1 || Steps[i-1] != "edge" {
		t.Fatalf("steps %v", Steps)
	}
	c := newCreation(t)
	c.failOn = "oci-region dns" // stop right after peer
	if err := c.Create(t.Context()); err == nil {
		t.Fatal("a failed dns step passed")
	}
	state, bound := c.State, filepath.Join(c.State, "bound-plan.json")
	call := "oci-region peer --pair-intent " + state + "/peer-intent.json --left-plan " + bound + " --right-plan " + homePlan +
		" --out " + state + "/peer-bound-intent.json --apply"
	if !slices.Contains(c.calls, call) {
		t.Fatalf("calls:\n%s", strings.Join(c.calls, "\n"))
	}
	written, err := os.ReadFile(filepath.Join(state, "peer-intent.json"))
	if err != nil {
		t.Fatal(err)
	}
	var intent map[string]any
	if err := json.Unmarshal(written, &intent); err != nil {
		t.Fatal(err)
	}
	cells := intent["cells"].(map[string]any)
	for cell, path := range map[string]string{"FRA": bound, "GRU": homePlan} {
		sum, _ := ociregion.SHA256(path)
		row := cells[cell].(map[string]any)
		if row["plan_sha256"] != sum || row["monthly_cross_region_egress_gb"] != 10.0 || row["drg_id"] != nil || len(row) != 10 {
			t.Fatalf("%s row %v", cell, row)
		}
	}
	if !reflect.DeepEqual(intent["allowed_tcp_ports"], []any{7422.0, 9443.0}) || intent["realm"] != "oc1" ||
		intent["tenancy_id"] != load(t, homePlan)["tenancy_id"] || len(cells) != 2 {
		t.Fatalf("intent %s", written)
	}
	// A rerun reuses the intent.
	c.calls = nil
	if err := c.peer(t.Context(), "fra-1"); err != nil || !slices.Equal(c.calls, []string{call}) {
		t.Fatalf("rerun: %v %v", err, c.calls)
	}
	if again, _ := os.ReadFile(filepath.Join(state, "peer-intent.json")); !bytes.Equal(again, written) {
		t.Fatal("rerun rewrote the intent")
	}
	// A plan changed since is refused before the runner.
	plan := load(t, bound)
	plan["resource_ids"].(map[string]any)["subnet"] = "ocid1.subnet.oc1.eu-frankfurt-1.aaaachanged"
	if err := writePlan(bound, plan); err != nil {
		t.Fatal(err)
	}
	c.calls = nil
	if err := c.peer(t.Context(), "fra-1"); err == nil || !strings.Contains(err.Error(), "delete it") || len(c.calls) != 0 {
		t.Fatalf("stale intent: %v %v", err, c.calls)
	}
}

func TestCreateRefusesBeforeSpending(t *testing.T) {
	c := newCreation(t)
	t.Setenv("CF_API_TOKEN", "")
	if err := c.Create(t.Context()); err == nil || len(c.calls) != 0 {
		t.Fatal("ran without the Cloudflare token")
	}
	t.Setenv("CF_API_TOKEN", "token")
	for _, plan := range []string{"", sfoPlan} {
		c.HomePlan = plan
		if err := c.Create(t.Context()); err == nil || !strings.Contains(err.Error(), "home") || len(c.calls) != 0 {
			t.Fatalf("ran with --home-plan %q: %v", plan, err)
		}
	}
	c.HomePlan = homePlan
	c.Label, c.OCIRegion = "gru", "sa-saopaulo-1"
	if err := c.Create(t.Context()); err == nil || len(c.calls) != 0 {
		t.Fatal("created the home region")
	}
	c.Label, c.OCIRegion = "fra", "eu-frankfurt-1"
	if err := os.WriteFile(c.AttemptBase, []byte(`{"workdir":"/elsewhere"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(t.Context()); err == nil || !strings.Contains(err.Error(), "workdir") {
		t.Fatalf("attempt base overriding the region's workdir: %v", err)
	}
}

type fakeLB struct {
	backends  map[string][]lb.Backend
	unhealthy map[string]map[string]bool
}

func (f fakeLB) ListBackends(_ context.Context, _, set string) ([]lb.Backend, error) {
	return f.backends[set], nil
}
func (f fakeLB) UnhealthyBackends(_ context.Context, _, set string) (map[string]bool, error) {
	return f.unhealthy[set], nil
}
func (fakeLB) GetLoadBalancer(context.Context, string) (lb.LoadBalancer, error) { panic("read only") }
func (fakeLB) CreateBackend(context.Context, string, string, lb.Backend) (string, error) {
	panic("read only")
}
func (fakeLB) UpdateBackend(context.Context, string, string, lb.Backend) (string, error) {
	panic("read only")
}
func (fakeLB) DeleteBackend(context.Context, string, string, string) (string, error) {
	panic("read only")
}
func (fakeLB) UpdateTags(context.Context, string, string, ociresource.Tags) (string, error) {
	panic("read only")
}
func (fakeLB) WaitWorkRequest(context.Context, string) error { panic("read only") }

func TestVerifierPassesOnlyAServingRegion(t *testing.T) {
	var issuer, region, health string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			fmt.Fprintf(w, `{"status":"ok","version":"1","region":%q}`, region)
		case "/auth/terrascale/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":"x"}`, issuer)
		case "/atlas/v1/discovery":
			fmt.Fprintf(w, `{"v":1,"regions":[{"id":"gru-1","health":"ok"},{"id":"fra-1","health":%q}]}`, health)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	healthy := []lb.Backend{{IP: "10.253.0.11", Port: 9465}, {IP: "10.253.0.12", Port: 9465}}
	balancer := fakeLB{backends: map[string][]lb.Backend{"terrabase": healthy, "ts-auth": healthy},
		unhealthy: map[string]map[string]bool{}}
	v := Verifier{HTTP: server.Client(), Cell: "fra-1", API: server.URL, Auth: server.URL + "/auth", Atlas: server.URL + "/atlas",
		LB: balancer, LoadBalancerID: "lb", BackendSets: []string{"terrabase", "ts-auth"}}
	failing := func() []string {
		var names []string
		for _, check := range v.Checks(t.Context()) {
			if !check.OK {
				names = append(names, check.Name)
			}
		}
		return names
	}
	issuer, region, health = server.URL+"/auth/terrascale", "fra-1", "ok"
	if got := failing(); len(got) != 0 {
		t.Fatalf("serving region fails %v", got)
	}
	for name, breakIt := range map[string]func(){
		"api":           func() { region = "gru-1" },
		"auth":          func() { issuer = "https://gru.auth.terrascale.tech/terrascale" },
		"atlas":         func() { health = "unknown" },
		"load balancer": func() { balancer.unhealthy["ts-auth"] = map[string]bool{"10.253.0.12:8080": true} },
	} {
		breakIt()
		if got := failing(); !slices.Equal(got, []string{name}) {
			t.Fatalf("broken %s: failing %v", name, got)
		}
		issuer, region, health = server.URL+"/auth/terrascale", "fra-1", "ok"
		clear(balancer.unhealthy)
	}
	v.BackendSets = append(v.BackendSets, "ts-orch")
	if got := failing(); !slices.Equal(got, []string{"load balancer"}) {
		t.Fatalf("an empty backend set passed: %v", got)
	}
	v.LoadBalancerID = ""
	if checks, err := v.Until(t.Context(), 0, time.Millisecond); err == nil {
		t.Fatalf("unbound load balancer passed: %v", checks)
	}
	var out bytes.Buffer
	if err := Print(&out, v.Checks(t.Context())); err != nil || !strings.Contains(out.String(), "| load balancer | FAIL |") {
		t.Fatal(out.String(), err)
	}
}

func TestRunRefusesBadArguments(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{
		{"plan", "fra"}, {"plan", "fra", "--out", "x"}, {"create", "fra", "eu-frankfurt-1"}, {"verify", "--plan", "x"},
		{"verify", "fra"}, {"nope", "fra", "x"},
	} {
		if err := Run(t.Context(), args, &out, &out); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
	if err := Run(t.Context(), []string{"--help"}, &out, &out); err != nil || !strings.Contains(out.String(), "create  LABEL OCI_REGION") {
		t.Fatal(out.String(), err)
	}
}
