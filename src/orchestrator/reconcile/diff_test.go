package reconcile

import (
	"reflect"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

func gruBucket() Resource {
	return Resource{
		Ref: estate.ResourceRef{Kind: estate.ResourceBucket, Region: "gru", Name: "backups"},
		Attributes: []Attribute{
			{Name: "bucket.purpose", Value: "database-backup"},
			{Name: "bucket.versioning", Value: "true"},
			{Name: "bucket.lifecycle-rule", Value: "expire-history|delete|35"},
		},
	}
}

func TestDeclaredRendersTheAttributeContract(t *testing.T) {
	declared, err := Declared(estate.Default())
	if err != nil {
		t.Fatalf("declared rendering failed: %v", err)
	}
	kinds := map[estate.ResourceKind]bool{}
	for _, resource := range declared.Resources {
		if len(resource.Attributes) == 0 {
			t.Fatalf("resource %s rendered without attributes", RefKey(resource.Ref))
		}
		kinds[resource.Ref.Kind] = true
	}
	for _, kind := range []estate.ResourceKind{
		estate.ResourceCompute, estate.ResourceNetwork, estate.ResourceSubnet,
		estate.ResourceNSG, estate.ResourceBucket, estate.ResourceVaultKey,
		estate.ResourceCertificate, estate.ResourceDNS, estate.ResourceCacheRule,
		estate.ResourceSnippetRule, estate.ResourceWorkerRoute, estate.ResourceKVMap,
		estate.ResourceWAFRule, estate.ResourceRateRule, estate.ResourceCapabilityKey,
	} {
		if !kinds[kind] {
			t.Fatalf("declared state is missing kind %s", kind)
		}
	}
}

func TestDiffCreateUpdateDelete(t *testing.T) {
	declared := State{Resources: []Resource{gruBucket()}}

	// Missing resource: create with the declared attributes.
	plan, err := Diff(declared, State{})
	if err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != ActionCreate {
		t.Fatalf("diff of an empty observation = %+v, want one create", plan.Actions)
	}
	if !reflect.DeepEqual(plan.Actions[0].Attributes, normalizeAttributes(gruBucket().Attributes)) {
		t.Fatalf("create action attributes = %+v", plan.Actions[0].Attributes)
	}

	// Different lifecycle rule: update with the changed attribute only.
	changed := gruBucket()
	changed.Attributes[2].Value = "expire-history|delete|7"
	plan, err = Diff(declared, State{Resources: []Resource{changed}})
	if err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != ActionUpdate {
		t.Fatalf("diff of a changed bucket = %+v, want one update", plan.Actions)
	}
	want := []Change{{Name: "bucket.lifecycle-rule", Declared: "expire-history|delete|35", Observed: "expire-history|delete|7"}}
	if !reflect.DeepEqual(plan.Actions[0].Changes, want) {
		t.Fatalf("update changes = %+v, want %+v", plan.Actions[0].Changes, want)
	}

	// Undeclared resource: delete with the observed attributes.
	extra := Resource{
		Ref:        estate.ResourceRef{Kind: estate.ResourceBucket, Region: "gru", Name: "clicked-in-console"},
		Attributes: []Attribute{{Name: "bucket.purpose", Value: "unknown"}},
	}
	plan, err = Diff(declared, State{Resources: []Resource{gruBucket(), extra}})
	if err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != ActionDelete || plan.Actions[0].Ref.Name != "clicked-in-console" {
		t.Fatalf("diff with an extra bucket = %+v, want one delete", plan.Actions)
	}

	// Matching observation: converged.
	plan, err = Diff(declared, State{Resources: []Resource{gruBucket()}})
	if err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	if !plan.Empty() {
		t.Fatalf("matching observation produced %+v", plan.Actions)
	}
}

func TestDiffMultisetOrderIrrelevant(t *testing.T) {
	declared := State{Resources: []Resource{{
		Ref: estate.ResourceRef{Kind: estate.ResourceNSG, Region: "gru", Name: "members"},
		Attributes: []Attribute{
			{Name: "nsg.rule", Value: "ingress|tcp|0.0.0.0/0|443-443"},
			{Name: "nsg.rule", Value: "egress|tcp|0.0.0.0/0|443-443"},
		},
	}}}
	observed := State{Resources: []Resource{{
		Ref: estate.ResourceRef{Kind: estate.ResourceNSG, Region: "gru", Name: "members"},
		Attributes: []Attribute{
			{Name: "nsg.rule", Value: "egress|tcp|0.0.0.0/0|443-443"},
			{Name: "nsg.rule", Value: "ingress|tcp|0.0.0.0/0|443-443"},
		},
	}}}
	plan, err := Diff(declared, observed)
	if err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	if !plan.Empty() {
		t.Fatalf("rule order changed the plan: %+v", plan.Actions)
	}
}

func TestDiffScopedToOwnedKinds(t *testing.T) {
	declared, err := Declared(estate.Default())
	if err != nil {
		t.Fatalf("declared rendering failed: %v", err)
	}
	plan, err := Diff(declared, State{}, estate.ResourceBucket)
	if err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	if plan.Empty() {
		t.Fatal("scoped diff found no bucket drift")
	}
	for _, action := range plan.Actions {
		if action.Ref.Kind != estate.ResourceBucket {
			t.Fatalf("scoped diff planned %s, want buckets only", RefKey(action.Ref))
		}
	}
}

func TestDiffRejectsDuplicateObservations(t *testing.T) {
	duplicated := State{Resources: []Resource{gruBucket(), gruBucket()}}
	if _, err := Diff(State{Resources: []Resource{gruBucket()}}, duplicated); err == nil {
		t.Fatal("duplicate observed resources must fail the diff")
	}
}
