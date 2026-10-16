package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/bucket"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/nsg"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/routetable"
)

func TestOciReconcileConfigDefaultsOffAndValidates(t *testing.T) {
	var cfg ControllerConfig
	if err := json.Unmarshal([]byte(`{"candidate_id":"a"}`), &cfg, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if cfg.OciReconcile != nil {
		t.Fatal("OCI reconcile is on by default")
	}
	wire := `{"oci_reconcile":{"enabled":true,"interval_seconds":120,"tag_mode":"defined",` +
		`"public_nlb":{"name":"public-api","nlb_id":"ocid1.networkloadbalancer.oc1..n","backend_set":"terrabase-https","port":9465}}}`
	if err := json.Unmarshal([]byte(wire), &cfg, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if cfg.OciReconcile.Desired != nil {
		t.Fatal("desired specs are published by default")
	}
	if interval, err := cfg.OciReconcile.interval(); err != nil || interval != 2*time.Minute {
		t.Fatalf("interval=%v err=%v", interval, err)
	}
	ownership, err := cfg.OciReconcile.ownership("cell-gru")
	if err != nil || ownership.Mode != ociresource.TagModeDefined || ownership.Namespace != "" {
		t.Fatalf("ownership=%+v err=%v", ownership, err)
	}
	for _, seconds := range []int{1, 29, 3601} {
		if _, err := (OciReconcileConfig{IntervalSeconds: seconds}).interval(); err == nil {
			t.Fatalf("accepted interval %d", seconds)
		}
	}
	if _, err := (OciReconcileConfig{TagMode: "adopt-anything"}).ownership("cell-gru"); err == nil {
		t.Fatal("accepted an unknown tag mode")
	}
	if _, err := (OciReconcileConfig{}).ownership("Cell_GRU"); err == nil {
		t.Fatal("accepted an owner that is not a token")
	}
}

type reconcileTestFencer struct{ fenced bool }

func (f reconcileTestFencer) Current() authority.Snapshot {
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Leader: true, Ready: true, Epoch: 1}
}

func (f reconcileTestFencer) Guard(context.Context, uint64) error {
	if f.fenced {
		return errors.New("lost leadership")
	}
	return nil
}

const reconcileTestNSG = "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.members"

func desiredTestConfig(t *testing.T, wire string) OciDesiredConfig {
	t.Helper()
	var cfg ControllerConfig
	if err := json.Unmarshal([]byte(`{"oci_reconcile":{"enabled":true,"desired":`+wire+`}}`), &cfg,
		json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	return *cfg.OciReconcile.Desired
}

func TestOciDesiredConfigIsBoundToTheSignedRegionAndDefaultsToReport(t *testing.T) {
	region := oci.RegionConfig{Region: oci.RegionGRU, NetworkSecurityGroupIDs: []string{reconcileTestNSG}}
	desired := desiredTestConfig(t, `{"nsg_rules":{"members":{"spec":{"nsgId":"`+reconcileTestNSG+`","rules":[`+
		`{"direction":"INGRESS","protocol":"6","peer":"10.0.0.0/16","portMin":4222,"portMax":4222}]}}},`+
		`"buckets":{"backups":{"policy":"enforce","spec":{"namespace":"tenancy","bucket":"backups","versioning":"Enabled"}}}}`)
	sets, delay, err := desiredSets(desired, "GRU", region)
	if err != nil || len(sets) != 2 || delay != time.Hour {
		t.Fatalf("sets=%+v delay=%v err=%v", sets, delay, err)
	}
	if sets[0].kind != nsg.Kind || sets[0].entries[0].Policy != ociresource.PolicyReport ||
		sets[1].kind != bucket.Kind || sets[1].entries[0].Policy != ociresource.PolicyEnforce {
		t.Fatalf("sets=%+v", sets)
	}

	// An NSG the signed region configuration does not admit is refused.
	other := region
	other.NetworkSecurityGroupIDs = []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.other"}
	if _, _, err := desiredSets(desired, "GRU", other); err == nil {
		t.Fatal("accepted an NSG outside the signed region configuration")
	}
	for name, wire := range map[string]string{
		"policy":      `{"buckets":{"b":{"policy":"adopt","spec":{"namespace":"tenancy","bucket":"b"}}}}`,
		"spec":        `{"buckets":{"b":{"spec":{"namespace":"tenancy","bucket":"b","versioning":"Disabled"}}}}`,
		"name":        `{"buckets":{"Bad_Name":{"spec":{"namespace":"tenancy","bucket":"b"}}}}`,
		"prune delay": `{"prune":true,"prune_delay_seconds":-1}`,
		"long delay":  `{"prune":true,"prune_delay_seconds":700000}`,
	} {
		if _, _, err := desiredSets(desiredTestConfig(t, wire), "GRU", region); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOciDesiredPassPublishesFencedAndFeedsInsights(t *testing.T) {
	region := oci.RegionConfig{Region: oci.RegionGRU, NetworkSecurityGroupIDs: []string{reconcileTestNSG}}
	desired := desiredTestConfig(t, `{"route_tables":{"private":{"spec":{"routeTableId":"ocid1.routetable.oc1..r",`+
		`"routes":[{"destination":"0.0.0.0/0","networkEntityId":"ocid1.natgateway.oc1..n"}]}}}}`)
	sets, delay, err := desiredSets(desired, "GRU", region)
	if err != nil {
		t.Fatal(err)
	}
	store := ociresource.NewMemoryStore()
	fenced := desiredPass("GRU", store, reconcileTestFencer{fenced: true}, sets, false, delay)
	if err := fenced.Run(t.Context(), 1); !errors.Is(err, ociresource.ErrFenced) {
		t.Fatalf("fenced pass err=%v", err)
	}
	if records, _ := store.List(t.Context(), "GRU", routetable.Kind); len(records) != 0 {
		t.Fatal("a fenced pass published")
	}
	if err := desiredPass("GRU", store, reconcileTestFencer{}, sets, false, delay).Run(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	records, _ := store.List(t.Context(), "GRU", routetable.Kind)
	if len(records) != 1 || records[0].Policy != ociresource.PolicyReport || records[0].Generation != 1 {
		t.Fatalf("records=%+v", records)
	}

	key := records[0].Key
	if err := store.PutStatus(t.Context(), ociresource.Status{Key: key, Policy: ociresource.PolicyReport, Found: true,
		Drift: []ociresource.Change{{Op: "add-route", Detail: "x"}}}); err != nil {
		t.Fatal(err)
	}
	runtime := &ociReconcileRuntime{store: store, cell: "GRU"}
	resources, err := runtime.resources().OCIResources(t.Context())
	if err != nil || len(resources) != 1 || resources[0].Key != "GRU/route-table-rules/private" ||
		resources[0].Drift[0] != "add-route x" || resources[0].Policy != "report" {
		t.Fatalf("resources=%+v err=%v", resources, err)
	}
	var off *ociReconcileRuntime
	if off.resources() != nil {
		t.Fatal("a disabled reconcile exposes a provider")
	}
}

// A cell spec oci_desired section replaces the signed config's desired
// resources on running controllers: the reconcile pass publishes whichever
// is in force. The signed list is generation 0 for the root rule, and the
// section must pass the signed region config.
func TestOciDesiredFollowsTheCellSpec(t *testing.T) {
	region := oci.RegionConfig{Region: oci.RegionGRU, NetworkSecurityGroupIDs: []string{reconcileTestNSG}}
	signed := desiredTestConfig(t, `{"prune":true,"buckets":{"backups":{"policy":"enforce","spec":`+
		`{"namespace":"tenancy","bucket":"backups","versioning":"Enabled"}},"logs":{"spec":{"namespace":"tenancy","bucket":"logs"}}}}`)
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true},
		Controller: ControllerConfig{OciReconcile: &OciReconcileConfig{Enabled: true, Desired: &signed}}}
	registry, err := newSpecRegistry(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	section := desiredTestConfig(t, `{"route_tables":{"private":{"spec":{"routeTableId":"ocid1.routetable.oc1..r",`+
		`"routes":[{"destination":"0.0.0.0/0","networkEntityId":"ocid1.natgateway.oc1..n"}]}}}}`)
	spec := cellspec.Spec{Schema: cellspec.Schema, Generation: 1, RequiresBinary: 7, OCIDesired: &section}
	if err := registry.validate(spec); err == nil || !strings.Contains(err.Error(), "signed region config") {
		t.Fatalf("section before the region config is known: %v", err)
	}
	registry.ociRegion = &region
	if err := registry.validate(spec); err != nil {
		t.Fatal(err)
	}
	foreign := desiredTestConfig(t, `{"nsg_rules":{"m":{"spec":{"nsgId":"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.other",`+
		`"rules":[{"direction":"INGRESS","protocol":"6","peer":"10.0.0.0/16","portMin":4222,"portMax":4222}]}}}}`)
	if err := registry.validate(cellspec.Spec{Schema: cellspec.Schema, Generation: 1, RequiresBinary: 7,
		OCIDesired: &foreign}); err == nil {
		t.Fatal("section naming an NSG the signed region config does not admit")
	}
	off, err := newSpecRegistry(Config{NATS: natscell.Config{Cell: "gru", Lab: true}}, "")
	if err != nil {
		t.Fatal(err)
	}
	off.ociRegion = &region
	if err := off.validate(spec); err == nil || !strings.Contains(err.Error(), "OCI reconcile") {
		t.Fatalf("section without OCI reconcile: %v", err)
	}

	// The signed list is what a section amends: restating it is ordinary,
	// and so is a list that prunes nothing, but a pruning list that drops
	// one of its entries needs a root.
	current := registry.current
	pruning := section
	pruning.Prune = true
	for name, test := range map[string]struct {
		section *OciDesiredConfig
		root    []string
	}{
		"restate":      {section: &signed},
		"no prune":     {section: &section},
		"prune others": {section: &pruning, root: []string{"oci_desired buckets backups pruned", "oci_desired buckets logs pruned"}},
	} {
		next := cellspec.Spec{Schema: cellspec.Schema, Generation: 1, RequiresBinary: 7, OCIDesired: test.section}
		if changes := cellspec.AuthorityChanges(registry.withSigned(current), registry.withSigned(next), nil); !slices.Equal(changes, test.root) {
			t.Errorf("%s: root changes = %v", name, changes)
		}
	}

	store := ociresource.NewMemoryStore()
	pass := currentDesiredPass("GRU", region, store, reconcileTestFencer{}, registry.ociDesired)
	if err := pass.Run(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if records, _ := store.List(t.Context(), "GRU", bucket.Kind); len(records) != 2 {
		t.Fatalf("signed buckets = %+v", records)
	}
	registry.adopt(spec, 1)
	if err := pass.Run(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if records, _ := store.List(t.Context(), "GRU", routetable.Kind); len(records) != 1 || records[0].Key.Name != "private" {
		t.Fatalf("spec route tables = %+v", records)
	}
}
