package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
)

func TestLiveControlChecksPinAuthenticatedLeaseAndPreserveInventory(t *testing.T) {
	r, nc, kv, lease, plan := mutationTestRuntime(t)
	declared := plan.Checks
	declared[0].AuthorityTerm = 0
	declared[0].AuthorityCandidateID, declared[0].AuthorityLeaseID = "", ""
	original, err := json.Marshal(declared)
	if err != nil {
		t.Fatal(err)
	}
	request := ControlActionRequest{Action: ControlAction{Kind: ControlActionPromoteR3, Region: "gru", ExpectedEpoch: 1, TargetEpoch: 2}}
	var retained []ControlStoreCheck
	r.config.ResolveChecks = func(ctx context.Context, got ControlActionRequest, checks []ControlStoreCheck) ([]ControlStoreCheck, error) {
		if !reflect.DeepEqual(got, request) {
			t.Fatal("resolver lost the action identity")
		}
		conn, err := openControlNATS(ctx, r.config.Stores[checks[0].Store])
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		entry, err := readControlLeaseFromLeader(ctx, conn, checks[0].LeaseKey)
		if err != nil {
			return nil, err
		}
		var observed authority.RegionalAuthorityLeaseDocument
		if err := json.Unmarshal(entry.Data, &observed); err != nil {
			return nil, err
		}
		checks[0].AuthorityTerm, checks[0].AuthorityCandidateID, checks[0].AuthorityLeaseID = uint64(observed.Epoch), observed.CandidateId, observed.LeaseId
		retained = checks
		return checks, nil
	}
	resolved, err := r.resolveCheckIdentities(t.Context(), request, declared)
	if err != nil {
		t.Fatal(err)
	}
	if resolved[0].AuthorityTerm != uint64(lease.Epoch) || resolved[0].AuthorityLeaseID != lease.LeaseId || resolved[0].AuthorityCandidateID != lease.CandidateId {
		t.Fatalf("live election identity = %+v", resolved[0])
	}
	retained[0].Streams[0].Servers[0] = "unadmitted"
	retained[0].AuthorityLeaseID = "forged"
	if resolved[0].Streams[0].Servers[0] != "controlMutation-0" || resolved[0].AuthorityLeaseID != lease.LeaseId {
		t.Fatal("resolver retained mutable action inventory or lease pins")
	}
	after, err := json.Marshal(declared)
	if err != nil || string(original) != string(after) {
		t.Fatal("resolution mutated the owner declaration")
	}
	plan.Checks = resolved
	pins, err := r.controlMutationPins(plan)
	if err != nil {
		t.Fatal(err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkControlMutation(t.Context(), js, "target", pins); err != nil {
		t.Fatal(err)
	}
	lease.Epoch++
	lease.LeaseId = "replacement-election"
	putControlMutationTestLease(t, t.Context(), kv, lease)
	if err := checkControlMutation(t.Context(), js, "target", pins); !errors.Is(err, ErrControlRuntimeUnavailable) {
		t.Fatalf("action adopted a later election mid-mutation: %v", err)
	}
	next, err := r.resolveCheckIdentities(t.Context(), request, declared)
	if err != nil || next[0].AuthorityLeaseID != lease.LeaseId {
		t.Fatalf("next action did not resolve replacement election: %+v, %v", next, err)
	}
	resolver := r.config.ResolveChecks
	for name, edit := range map[string]func(*ControlStoreCheck){
		"store":         func(c *ControlStoreCheck) { c.Store = "source" },
		"region":        func(c *ControlStoreCheck) { c.Region = "sfo" },
		"authority":     func(c *ControlStoreCheck) { c.AuthorityID = "sfo-regional" },
		"lease key":     func(c *ControlStoreCheck) { c.LeaseKey = "authority.regional" },
		"members":       func(c *ControlStoreCheck) { c.Members = []string{"other"} },
		"streams":       func(c *ControlStoreCheck) { c.Streams[0].Name = "OTHER" },
		"servers":       func(c *ControlStoreCheck) { c.Streams[0].Servers[0] = "other" },
		"replicas":      func(c *ControlStoreCheck) { c.Streams[0].Replicas = 1 },
		"mirrors":       func(c *ControlStoreCheck) { c.Mirrors = []ControlMirrorPlan{{Name: "other"}} },
		"candidate":     func(c *ControlStoreCheck) { c.AuthorityCandidateID = "global-controller-sfo-one" },
		"missing lease": func(c *ControlStoreCheck) { c.AuthorityLeaseID = "" },
		"forged lease":  func(c *ControlStoreCheck) { c.AuthorityLeaseID = "not-live" },
		"future term":   func(c *ControlStoreCheck) { c.AuthorityTerm++ },
	} {
		t.Run(name, func(t *testing.T) {
			r.config.ResolveChecks = func(ctx context.Context, request ControlActionRequest, checks []ControlStoreCheck) ([]ControlStoreCheck, error) {
				resolved, err := resolver(ctx, request, checks)
				if err == nil {
					edit(&resolved[0])
				}
				return resolved, err
			}
			if _, err := r.resolveCheckIdentities(t.Context(), request, declared); err == nil {
				t.Fatal("resolver widened inventory or forged authority")
			}
		})
	}
}

func TestLiveControlPlanRequiresResolverAndCompleteInventory(t *testing.T) {
	r := &NATSControlRuntime{config: NATSControlRuntimeConfig{Stores: map[string]ControlNATSStore{"regional": {}}}, members: map[string]ControlRuntimeMember{"one": {MemberID: "one", Region: "gru", Instance: "one", Store: "regional", ServerName: "gru-one"}}}
	plan := ControlRuntimeActionPlan{Kind: ControlActionVerifyCandidate, Region: "gru", ExpectedEpoch: 1, TargetEpoch: 2, Checks: []ControlStoreCheck{{Store: "regional", Region: "gru", AuthorityID: "gru-regional", LeaseKey: "authority.regional", Members: []string{"one"}, Streams: []ControlStreamAssignment{{Name: "KV_ORCH_LEADERS", Replicas: 1, Servers: []string{"gru-one"}}, {Name: "KV_ORCH_RUNTIME", Replicas: 1, Servers: []string{"gru-one"}}}}}}
	if err := r.validatePlan(plan); err == nil {
		t.Fatal("unresolved election accepted without a resolver")
	}
	r.config.ResolveChecks = func(context.Context, ControlActionRequest, []ControlStoreCheck) ([]ControlStoreCheck, error) {
		t.Fatal("declaration validation invoked live resolver")
		return nil, nil
	}
	if err := r.validatePlan(plan); err != nil {
		t.Fatalf("unresolved live declaration rejected: %v", err)
	}
	plan.Checks[0].Streams[1].Name = "unrelated"
	if err := r.validatePlan(plan); err == nil {
		t.Fatal("live declaration bypassed signed membership inventory")
	}
}
