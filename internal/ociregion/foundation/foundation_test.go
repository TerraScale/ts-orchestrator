package foundation

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/publicapi"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
)

const (
	sfo  = "us-sanjose-1"
	home = "sa-saopaulo-1"
)

// fakeOCI is a stateful tenancy that answers both the foundation's commands
// and inspect-foundation's reads, so a bound plan is checked against what
// the foundation created.
type fakeOCI struct {
	mu        sync.Mutex
	seq       int
	rows      map[string]*row
	order     []string
	nsgRules  map[string][]any
	retention map[string][]any
	writes    []string
	args      [][]string
	failOn    string
	// peer serves the private peering's actions; see peer_test.go.
	peer func(region string, c sdkcli.Command) (any, bool, error)
}

type row struct {
	kind, region string
	data         Object
}

// kinds are each resource's OCID kind, whether it is global (IAM) and the
// state it is created in.
var kinds = map[string]struct {
	ocid   string
	global bool
	state  string
}{
	"compartment": {"compartment", true, "ACTIVE"}, "dynamic-group": {"dynamicgroup", true, "ACTIVE"}, "policy": {"policy", true, "ACTIVE"},
	"vcn": {"vcn", false, "AVAILABLE"}, "service-gateway": {"servicegateway", false, "AVAILABLE"}, "route-table": {"routetable", false, "AVAILABLE"},
	"security-list": {"securitylist", false, "AVAILABLE"}, "subnet": {"subnet", false, "AVAILABLE"}, "nsg": {"networksecuritygroup", false, "AVAILABLE"},
	"vault": {"vault", false, "CREATING"}, "key": {"key", false, "CREATING"}, "bucket": {"bucket", false, ""},
	"drg": {"drg", false, "AVAILABLE"}, "remote-peering-connection": {"remotepeeringconnection", false, "AVAILABLE"},
	"drg-route-distribution": {"drgroutedistribution", false, "AVAILABLE"}, "drg-route-table": {"drgroutetable", false, "AVAILABLE"},
	"drg-attachment": {"drgattachment", false, "ATTACHED"},
}

func newFake() *fakeOCI {
	return &fakeOCI{rows: map[string]*row{}, nsgRules: map[string][]any{}, retention: map[string][]any{}}
}

type client struct {
	f      *fakeOCI
	region string
}

// Call prints a route table's or security list's ETag beside its data, as
// the oci CLI does.
func (c client) Call(_ context.Context, args ...string) (map[string]any, error) {
	v, err := c.f.handle(c.region, args)
	r := map[string]any{"data": v}
	if m, ok := v.(Object); ok && m["etag"] != nil {
		r["etag"] = m["etag"]
	}
	return r, err
}
func (c client) Head(context.Context, ...string) error { return errors.New("unexpected head") }

// dependency serves the inspection engine's oci reads; IAM reads name no
// region.
func (f *fakeOCI) dependency(name string, args []any, kwargs Object) (any, error) {
	if name != "oci" {
		return nil, fmt.Errorf("unexpected dependency %s", name)
	}
	words := make([]string, len(args))
	for i, a := range args {
		words[i] = fmt.Sprint(a)
	}
	region, _ := kwargs["region"].(string)
	if region == "" {
		region = home
	}
	v, err := f.handle(region, words)
	if err != nil {
		return nil, err
	}
	// The engine compares typed plan values with decoded responses.
	wire, _ := json.Marshal(v)
	return decode(wire), nil
}

func decode(wire []byte) any {
	var v any
	if err := json.Unmarshal(wire, &v); err != nil {
		panic(err)
	}
	return v
}
func clone(v any) any { wire, _ := json.Marshal(v); return decode(wire) }

func (f *fakeOCI) add(kind, region string, data Object) string {
	f.seq++
	k := kinds[kind]
	if k.global {
		region = ""
	}
	id := fmt.Sprintf("ocid1.%s.oc1.%s.fake%d", k.ocid, region, f.seq)
	data["id"] = id
	if _, ok := data["lifecycle-state"]; !ok && k.state != "" {
		data["lifecycle-state"] = k.state
	}
	f.rows[id] = &row{kind, region, data}
	f.order = append(f.order, id)
	return id
}

func (f *fakeOCI) find(kind, region string, match func(Object) bool) []*row {
	var r []*row
	for _, id := range f.order {
		x := f.rows[id]
		if x.kind == kind && (x.region == "" || x.region == region) && match(x.data) {
			r = append(r, x)
		}
	}
	return r
}

func (f *fakeOCI) bucket(region, name string) (*row, error) {
	if b := f.find("bucket", region, func(o Object) bool { return o["name"] == name }); len(b) == 1 {
		return b[0], nil
	}
	return nil, errors.New("404 BucketNotFound")
}

func (f *fakeOCI) handle(region string, args []string) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, err := sdkcli.Parse(args)
	if err != nil {
		return nil, err
	}
	words := strings.Fields(c.Path)
	verb, flags := words[len(words)-1], c.Flags
	if verb != "get" && verb != "list" {
		f.writes = append(f.writes, region+" "+c.Path)
		f.args = append(f.args, args)
		if c.Path == f.failOn {
			f.failOn = ""
			return nil, errors.New("connection reset")
		}
		if words[0] == "iam" && region != home {
			return nil, errors.New("403 NotAllowed: IAM writes are accepted only in the home region")
		}
	}
	if f.peer != nil {
		if v, ok, err := f.peer(region, c); ok {
			return v, err
		}
	}
	switch c.Path {
	case "os ns get":
		return "fakens", nil
	case "os bucket get":
		b, err := f.bucket(region, flags["bucket-name"])
		if err != nil {
			return nil, err
		}
		return clone(b.data), nil
	case "network nsg rules add":
		var rules []any
		if err := json.Unmarshal([]byte(flags["security-rules"]), &rules); err != nil {
			return nil, err
		}
		for _, r := range kebab(rules).([]any) {
			f.seq++
			r.(Object)["id"] = fmt.Sprintf("rule%d", f.seq)
			f.nsgRules[flags["nsg-id"]] = append(f.nsgRules[flags["nsg-id"]], r)
		}
		return Object{}, nil
	case "network nsg rules list":
		return clone(append([]any{}, f.nsgRules[flags["nsg-id"]]...)), nil
	case "network nsg rules remove":
		var ids []string
		if err := json.Unmarshal([]byte(flags["security-rule-ids"]), &ids); err != nil {
			return nil, err
		}
		f.nsgRules[flags["nsg-id"]] = slices.DeleteFunc(f.nsgRules[flags["nsg-id"]], func(r any) bool {
			return slices.Contains(ids, text(r.(Object)["id"]))
		})
		return Object{}, nil
	case "os retention-rule create":
		var amount int
		fmt.Sscan(flags["time-amount"], &amount)
		f.retention[flags["bucket-name"]] = append(f.retention[flags["bucket-name"]],
			Object{"display-name": flags["display-name"], "duration": Object{"time-amount": amount, "time-unit": flags["time-unit"]}})
		return Object{}, nil
	case "os retention-rule list":
		return clone(append([]any{}, f.retention[flags["bucket-name"]]...)), nil
	}
	kind := words[len(words)-2]
	switch verb {
	case "create":
		data := Object{}
		for name, value := range flags {
			switch {
			case name == "wait-for-state" || name == "endpoint" || name == "namespace-name":
			case value == "true" || value == "false":
				data[name] = value == "true"
			case strings.HasPrefix(value, "[") || strings.HasPrefix(value, "{"):
				data[name] = kebab(decode([]byte(value)))
			default:
				data[name] = value
			}
		}
		switch kind {
		case "subnet":
			data["prohibit-internet-ingress"] = data["prohibit-public-ip-on-vnic"]
		case "vault":
			f.seq++
			data["management-endpoint"] = fmt.Sprintf("https://v%d-management.kms.%s.oraclecloud.com", f.seq, region)
		case "key":
			vault := f.find("vault", region, func(o Object) bool { return o["management-endpoint"] == flags["endpoint"] })
			data["vault-id"] = vault[0].data["id"]
		case "bucket":
			if _, err := f.bucket(region, flags["name"]); err == nil {
				return nil, errors.New("409 BucketAlreadyExists")
			}
		case "route-table", "security-list":
			data["etag"] = "1"
		case "drg-route-distribution", "drg-route-table", "drg-attachment":
			data["compartment-id"] = f.rows[flags["drg-id"]].data["compartment-id"]
			if kind == "drg-route-table" {
				data["import-drg-route-distribution-id"] = data["import-route-distribution-id"]
				delete(data, "import-route-distribution-id")
			}
			if kind == "drg-attachment" {
				data["is-cross-tenancy"] = false
			}
		case "remote-peering-connection":
			data["peering-status"], data["is-cross-tenancy-peering"] = "NEW", false
		}
		id := f.add(kind, region, data)
		if kind == "remote-peering-connection" {
			// OCI attaches a new RPC to its DRG's default RPC route table.
			f.add("drg-attachment", region, Object{"compartment-id": data["compartment-id"], "drg-id": data["drg-id"],
				"network-details": Object{"type": "REMOTE_PEERING_CONNECTION", "id": id}, "is-cross-tenancy": false,
				"drg-route-table-id": "ocid1.drgroutetable.oc1." + region + ".default"})
		}
		return clone(f.rows[id].data), nil
	case "get":
		for name, id := range flags {
			if !strings.HasSuffix(name, "-id") && name != "rt-id" {
				continue
			}
			r := f.rows[id]
			if r == nil || r.kind != kind || (r.region != "" && r.region != region) {
				return nil, fmt.Errorf("404 NotAuthorizedOrNotFound: %s", id)
			}
			v := clone(r.data)
			// A vault and its key read back CREATING once, then ready.
			switch r.data["lifecycle-state"] {
			case "CREATING":
				r.data["lifecycle-state"] = map[string]string{"vault": "ACTIVE", "key": "ENABLED"}[kind]
			}
			return v, nil
		}
		return nil, fmt.Errorf("no id for %s", c.Path)
	case "list":
		var endpointVault any
		if endpoint := flags["endpoint"]; endpoint != "" {
			endpointVault = f.find("vault", region, func(o Object) bool { return o["management-endpoint"] == endpoint })[0].data["id"]
		}
		r := []any{}
		attachment := flags["attachment-type"]
		for _, x := range f.find(kind, region, func(o Object) bool {
			return (flags["compartment-id"] == "" || o["compartment-id"] == flags["compartment-id"]) && (flags["vcn-id"] == "" || o["vcn-id"] == flags["vcn-id"]) &&
				(endpointVault == nil || o["vault-id"] == endpointVault) && (flags["drg-id"] == "" || o["drg-id"] == flags["drg-id"]) &&
				(attachment == "" || attachment == "ALL" || obj(o["network-details"])["type"] == attachment)
		}) {
			r = append(r, clone(x.data))
		}
		return r, nil
	}
	return nil, fmt.Errorf("unexpected OCI command %s", c.Path)
}

func kebab(v any) any {
	wire, err := sdkcli.Render(v)
	if err != nil {
		panic(err)
	}
	return decode(wire)
}

func loadPlan(t *testing.T) Object {
	t.Helper()
	plan, err := ociregion.LoadPlan(filepath.Join("..", "..", "..", "deploy", "oci-region", "sfo-1-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func allowWrite(context.Context, bool) (func(), error) { return func() {}, nil }
func allowGuard(context.Context) error                 { return nil }

func run(t *testing.T, f *fakeOCI, apply bool, out string, plans ...Object) (string, error) {
	t.Helper()
	plan := loadPlan(t)
	if len(plans) != 0 {
		plan = plans[0]
	}
	var log bytes.Buffer
	foundation := &Foundation{Region: client{f, sfo}, Home: client{f, home}, Apply: apply, Out: &log,
		BeforeWrite: allowWrite, Guard: allowGuard, Checkpoint: func(context.Context, string, string) error { return nil },
		Pause: func(context.Context, time.Duration) error { return nil },
		Check: (&ociregion.Engine{Context: t.Context(), Dependency: f.dependency}).CheckFoundation}
	err := foundation.Run(t.Context(), plan, out)
	return log.String(), err
}

// creates are the writes a first apply of sfo-1's plan makes, each once.
var creates = []string{
	"iam compartment create", "iam compartment create", "iam compartment create",
	"network vcn create", "network service-gateway create", "network route-table create", "network security-list create",
	"network subnet create", "network nsg create", "network nsg rules add", "network nsg create", "network nsg rules add",
	"kms management vault create", "kms management key create",
	"iam dynamic-group create", "iam dynamic-group create", "iam policy create", "iam policy create", "iam policy create", "iam policy create",
	"os bucket create", "os retention-rule create", "os bucket create", "os bucket create", "os retention-rule create", "os bucket create",
}

func paths(writes []string) []string {
	r := []string{}
	for _, w := range writes {
		r = append(r, strings.SplitN(w, " ", 2)[1])
	}
	return r
}

func TestDryRunMakesNoWrite(t *testing.T) {
	f := newFake()
	out := filepath.Join(t.TempDir(), "bound.json")
	log, err := run(t, f, false, out)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("dry run wrote %v", f.writes)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry run wrote the bound plan: %v", err)
	}
	for _, want := range []string{"plan: create compartment sfo-1-control", "plan: create VCN sfo-1-vcn", "plan: create HSM key sfo-1-key",
		"plan: create policy sfo-1-netbird-enrollment", "plan: create retention rule ledger-retention on bucket sfo-1-ledger",
		fmt.Sprintf("%d changes planned", len(creates))} {
		if !strings.Contains(log, want) {
			t.Fatalf("dry run output lacks %q:\n%s", want, log)
		}
	}
}

func TestApplyCreatesEveryResourceOnceAndUncheckpointedRerunIsRefused(t *testing.T) {
	f := newFake()
	out := filepath.Join(t.TempDir(), "bound.json")
	if _, err := run(t, f, true, out); err != nil {
		t.Fatal(err)
	}
	if got := paths(f.writes); !slices.Equal(got, creates) {
		t.Fatalf("first apply wrote\n%v\nwant\n%v", got, creates)
	}
	// The in-binary SDK creators accept every command exactly as sent.
	for _, args := range f.args {
		if err := publicapi.DecodeCreate(args); err != nil {
			t.Fatal(err)
		}
	}
	// The bound plan is a valid plan whose IDs pass inspect-foundation's
	// live checks against what was created.
	bound, err := ociregion.LoadPlan(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&ociregion.Engine{Context: t.Context(), Dependency: f.dependency}).CheckFoundation(bound); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"control_compartment", "vcn", "subnet", "workload_network_security_group", "key", "controller_policy", "host_dynamic_group"} {
		if id, _ := bound["resource_ids"].(Object)[key].(string); !strings.HasPrefix(id, "ocid1.") {
			t.Fatalf("bound plan lacks %s: %v", key, bound["resource_ids"])
		}
	}
	netbird := f.find("policy", home, func(o Object) bool { return o["name"] == "sfo-1-netbird-enrollment" })
	if len(netbird) != 1 || !strings.Contains(fmt.Sprint(netbird[0].data["statements"]), "target.secret.name = 'sfo-1-netbird-setup-key'") {
		t.Fatalf("NetBird enrollment policy: %v", netbird)
	}
	usage := f.find("policy", home, func(o Object) bool { return o["name"] == "sfo-1-controller-usage" })
	if len(usage) != 1 || usage[0].data["compartment-id"] != loadPlan(t)["tenancy_id"] ||
		!slices.Equal(clone(usage[0].data["statements"]).([]any), []any{"Allow dynamic-group sfo-1-controllers to read usage-report in tenancy"}) {
		t.Fatalf("usage policy is not a tenancy-root statement for the controllers: %v", usage)
	}
	before, _ := os.ReadFile(out)
	f.writes = nil
	log, err := run(t, f, true, out)
	if err == nil || !strings.Contains(err.Error(), "refusing adoption") || len(f.writes) != 0 {
		t.Fatalf("rerun: err %v, writes %v, output:\n%s", err, f.writes, log)
	}
	if after, _ := os.ReadFile(out); !bytes.Equal(before, after) {
		t.Fatal("rerun changed the bound plan")
	}
	if log, err := run(t, f, false, out); err == nil || !strings.Contains(err.Error(), "refusing adoption") {
		t.Fatalf("dry run after apply: %v\n%s", err, log)
	}
}

func TestIAMWritesGoToTheHomeRegion(t *testing.T) {
	f := newFake()
	if _, err := run(t, f, true, filepath.Join(t.TempDir(), "bound.json")); err != nil {
		t.Fatal(err)
	}
	for _, w := range f.writes {
		region, path, _ := strings.Cut(w, " ")
		if want := map[bool]string{true: home, false: sfo}[strings.HasPrefix(path, "iam ")]; region != want {
			t.Fatalf("%s went to %s, want %s", path, region, want)
		}
	}
}

func TestInterruptedRunRequiresAuthenticatedCheckpointsToResume(t *testing.T) {
	for _, step := range []string{"network subnet create", "kms management key create", "iam policy create", "os retention-rule create"} {
		t.Run(step, func(t *testing.T) {
			f := newFake()
			f.failOn = step
			out := filepath.Join(t.TempDir(), "bound.json")
			if _, err := run(t, f, true, out); err == nil {
				t.Fatal("interrupted run succeeded")
			}
			if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("interrupted run wrote the bound plan")
			}
			before := len(f.writes)
			if _, err := run(t, f, true, out); err == nil || !strings.Contains(err.Error(), "refusing adoption") {
				t.Fatalf("uncheckpointed restart: %v", err)
			}
			if len(f.writes) != before {
				t.Fatalf("uncheckpointed restart issued new writes: %v", f.writes[before:])
			}
		})
	}
}

func TestDifferingResourcesAreRefusedNotAdopted(t *testing.T) {
	plan := loadPlan(t)
	parent := plan["parent_compartment_id"]
	seed := func(f *fakeOCI) string {
		var network string
		for _, name := range []string{"sfo-1-control", "sfo-1-network", "sfo-1-workload"} {
			id := f.add("compartment", "", Object{"name": name, "compartment-id": parent, "freeform-tags": Object{"terrascale.owner": "ts-orch", "terrascale.cell": "sfo-1"}})
			if name == "sfo-1-network" {
				network = id
			}
		}
		return network
	}
	for name, test := range map[string]struct {
		setup func(*fakeOCI)
		want  string
	}{
		"VCN with another CIDR": {func(f *fakeOCI) {
			f.add("vcn", sfo, Object{"display-name": "sfo-1-vcn", "compartment-id": seed(f), "cidr-block": "10.9.0.0/24", "freeform-tags": Object{"terrascale.owner": "ts-orch", "terrascale.cell": "sfo-1"}})
		}, "VCN sfo-1-vcn exists but differs from the plan"},
		"bucket in another compartment": {func(f *fakeOCI) {
			seed(f)
			f.add("bucket", sfo, Object{"name": "sfo-1-ledger", "compartment-id": "ocid1.compartment.oc1..elsewhere"})
		}, "create bucket sfo-1-ledger: 409 BucketAlreadyExists"},
		"dynamic group matching other instances": {func(f *fakeOCI) {
			f.add("dynamic-group", "", Object{"name": "sfo-1-controllers", "compartment-id": plan["tenancy_id"], "matching-rule": "ANY {instance.compartment.id = 'x'}", "freeform-tags": Object{"terrascale.owner": "ts-orch", "terrascale.cell": "sfo-1"}})
		}, "dynamic group sfo-1-controllers exists but differs from the plan"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake()
			test.setup(f)
			approved := loadPlan(t)
			// These fixture IDs stand for an authenticated journal; tags alone
			// cannot move the shape-validation scenarios past discovery.
			for id, row := range f.rows {
				key := map[string]string{"sfo-1-control": "control_compartment", "sfo-1-network": "network_compartment", "sfo-1-workload": "workload_compartment", "sfo-1-vcn": "vcn", "sfo-1-controllers": "controller_dynamic_group"}[text(row.data["name"])]
				if row.kind == "vcn" {
					key = "vcn"
				}
				if key != "" {
					obj(approved["resource_ids"])[key] = id
				}
			}
			rows := len(f.rows)
			out := filepath.Join(t.TempDir(), "bound.json")
			if _, err := run(t, f, true, out, approved); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err %v, want %q", err, test.want)
			}
			if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("refused run wrote the bound plan")
			}
			for _, w := range f.writes {
				if strings.HasSuffix(w, "network vcn create") && name == "VCN with another CIDR" {
					t.Fatal("refused VCN was replaced")
				}
			}
			if name == "VCN with another CIDR" && len(f.rows) != rows {
				t.Fatalf("refused run created %d resources", len(f.rows)-rows)
			}
		})
	}
}

func TestADifferentBoundPlanIsNeverOverwritten(t *testing.T) {
	out := filepath.Join(t.TempDir(), "bound.json")
	if err := os.WriteFile(out, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, newFake(), true, out); err == nil || !strings.Contains(err.Error(), "never overwritten") {
		t.Fatalf("err %v", err)
	}
	if wire, _ := os.ReadFile(out); string(wire) != "{}\n" {
		t.Fatal("bound plan overwritten")
	}
}
