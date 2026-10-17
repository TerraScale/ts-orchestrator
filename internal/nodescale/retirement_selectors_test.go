package nodescale

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// These are inert request selectors. No synthetic view grants ROOT authority.
func TestOriginalPoolRetirementPreservesPreparedPurchase(t *testing.T) {
	prepared := rootoci.PoolRetirementPreparation{Node: "ts-gru-4", Retirement: rootoci.PoolRetirementExpectation{
		InstanceID: "ocid1.instance.original", Child: rootoci.PoolChildExpectation{Cell: "GRU", OperationID: entityid.New(), PoolID: "ocid1.instancepool.original",
			ConfigurationID: "ocid1.instanceconfiguration.original", RecipeSHA256: strings.Repeat("c", 64),
			GrantSHA256: strings.Repeat("a", 64), Generation: 1, Epoch: 3}}}
	prepared.Retirement.Child.ReservationID = prepared.Retirement.Child.OperationID
	removal := entityid.New()
	original, err := originalPoolRetirement(prepared, prepared.Retirement.InstanceID, removal)
	if err != nil {
		t.Fatal(err)
	}
	if original.Child.GrantSHA256 != prepared.Retirement.Child.GrantSHA256 || original.Child.Generation != prepared.Retirement.Child.Generation || original.Child.Epoch != prepared.Retirement.Child.Epoch || original.RemovalOperationID != removal {
		t.Fatal("retirement request replaced original purchase or birth epoch")
	}
	if original.DrainSHA256 != "" {
		t.Fatal("observational preparation supplied a digest before protected capture")
	}
	want := prepared.Retirement
	want.RemovalOperationID = removal
	before, err := protocol.EncodeJSON(want)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(original)
	if err != nil || !bytes.Equal(before, wire) {
		t.Fatal("preparation changed beyond the chosen removal operation", err)
	}
	if prepared.Retirement.RemovalOperationID != "" {
		t.Fatal("constructing a request mutated the action-free preparation")
	}
	for name, mutate := range map[string]func(*rootoci.PoolRetirementExpectation){
		"missing original grant":      func(r *rootoci.PoolRetirementExpectation) { r.Child.GrantSHA256 = "" },
		"invalid original grant":      func(r *rootoci.PoolRetirementExpectation) { r.Child.GrantSHA256 = strings.Repeat("x", 64) },
		"missing original generation": func(r *rootoci.PoolRetirementExpectation) { r.Child.Generation = 0 },
		"missing birth epoch":         func(r *rootoci.PoolRetirementExpectation) { r.Child.Epoch = 0 },
		"foreign instance":            func(r *rootoci.PoolRetirementExpectation) { r.InstanceID = "ocid1.instance.foreign" },
		"existing removal":            func(r *rootoci.PoolRetirementExpectation) { r.RemovalOperationID = entityid.New() },
		"existing drain":              func(r *rootoci.PoolRetirementExpectation) { r.DrainSHA256 = strings.Repeat("d", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := prepared
			mutate(&changed.Retirement)
			if _, err := originalPoolRetirement(changed, prepared.Retirement.InstanceID, removal); !errors.Is(err, ErrCapacityPending) {
				t.Fatal("missing original purchase lineage acquired retirement selectors", err)
			}
		})
	}
}
