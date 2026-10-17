package rootoci

import (
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// These are selector-shape checks, not accepted-birth or provider fixtures.
func TestPoolRetirementDiscoveryIsDescriptive(t *testing.T) {
	selector := PoolRetirementSelector{Cell: "GRU", InstanceID: "ocid1.instance.oc1..original"}
	payload, err := json.Marshal(selector)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{}
	request := wireRequest{Operation: OperationPreparePoolRetirement, Payload: payload}
	if !service.validRequest(request) || !request.Operation.observationOnly() || request.Operation.ReadOnly() {
		t.Fatal("cleanup discovery must be readonly without gaining startup admission")
	}
	if errors.Is(outcomeError(request.Operation), ErrOutcomeUnknown) {
		t.Fatal("readonly discovery failure claimed possible provider effects")
	}
	for _, raw := range []string{
		`{"cell":"GRU","instance_id":""}`,
		`{"cell":"","instance_id":"original"}`,
		`{"cell":"GRU","instance_id":"original","removal_operation_id":"invented"}`,
	} {
		request.Payload = []byte(raw)
		if service.validRequest(request) {
			t.Fatalf("discovery accepted invalid selectors: %s", raw)
		}
	}
}

func TestPoolRetirementPreparationKeepsOriginalSelectors(t *testing.T) {
	selector := PoolRetirementSelector{Cell: "GRU", InstanceID: "ocid1.instance.oc1..original"}
	original := PoolRetirementPreparation{Node: "ts-gru-4", CurrentGrantSHA256: strings.Repeat("c", 64), CurrentGeneration: 2, Retirement: PoolRetirementExpectation{
		Child: PoolChildExpectation{Cell: selector.Cell, OperationID: entityid.Derive("original-birth"), ReservationID: entityid.Derive("original-birth"),
			RecipeSHA256: strings.Repeat("a", 64), PoolID: "ocid1.instancepool.oc1..original", ConfigurationID: "ocid1.instanceconfiguration.oc1..original",
			GrantSHA256: strings.Repeat("b", 64), Generation: 1, Epoch: 2}, InstanceID: selector.InstanceID}}
	if !validPoolRetirementPreparation(original, selector) {
		t.Fatal("original descriptive selectors rejected")
	}
	payload, err := json.Marshal(original.Retirement)
	if err != nil {
		t.Fatal(err)
	}
	if (&Service{}).validRequest(wireRequest{Operation: OperationRetirePoolChild, Payload: payload}) {
		t.Fatal("discovery without a separately chosen action became a retirement request")
	}
	for _, tc := range []struct {
		name   string
		change func(*PoolRetirementPreparation)
	}{
		{"another_cell", func(p *PoolRetirementPreparation) { p.Retirement.Child.Cell = "FRA" }},
		{"another_instance", func(p *PoolRetirementPreparation) { p.Retirement.InstanceID = "another" }},
		{"another_reservation", func(p *PoolRetirementPreparation) { p.Retirement.Child.ReservationID = entityid.Derive("another") }},
		{"missing_original_grant", func(p *PoolRetirementPreparation) { p.Retirement.Child.GrantSHA256 = "" }},
		{"missing_original_generation", func(p *PoolRetirementPreparation) { p.Retirement.Child.Generation = 0 }},
		{"missing_original_epoch", func(p *PoolRetirementPreparation) { p.Retirement.Child.Epoch = 0 }},
		{"missing_original_pool", func(p *PoolRetirementPreparation) { p.Retirement.Child.PoolID = "" }},
		{"missing_original_configuration", func(p *PoolRetirementPreparation) { p.Retirement.Child.ConfigurationID = "" }},
		{"action_in_discovery", func(p *PoolRetirementPreparation) { p.Retirement.RemovalOperationID = entityid.Derive("removal") }},
		{"drain_in_discovery", func(p *PoolRetirementPreparation) { p.Retirement.DrainSHA256 = strings.Repeat("c", 64) }},
		{"missing_current_grant", func(p *PoolRetirementPreparation) { p.CurrentGrantSHA256 = "" }},
		{"malformed_current_grant", func(p *PoolRetirementPreparation) { p.CurrentGrantSHA256 = strings.Repeat("C", 64) }},
		{"missing_current_generation", func(p *PoolRetirementPreparation) { p.CurrentGeneration = 0 }},
		{"foreign_node", func(p *PoolRetirementPreparation) { p.Node = "ts-fra-4" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := original
			tc.change(&changed)
			if validPoolRetirementPreparation(changed, selector) {
				t.Fatal("conflicting preparation accepted")
			}
		})
	}
}
