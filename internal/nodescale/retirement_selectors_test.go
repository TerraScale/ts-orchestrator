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
func TestOriginalPoolRetirementPreservesPurchaseAcrossCurrentGrantChange(t *testing.T) {
	birth := rootoci.PoolChildView{Cell: "GRU", OperationID: entityid.New(), InstanceID: "ocid1.instance.original", PoolID: "ocid1.instancepool.original",
		ConfigurationID: "ocid1.instanceconfiguration.original", RecipeSHA256: strings.Repeat("c", 64),
		GrantSHA256: strings.Repeat("b", 64), Generation: 12, Epoch: 3,
		OriginalBirthGrantSHA256: strings.Repeat("a", 64), OriginalBirthGeneration: 1}
	birth.ReservationID = birth.OperationID
	removal := entityid.New()
	original, err := originalPoolRetirement(birth, birth.InstanceID, removal)
	if err != nil {
		t.Fatal(err)
	}
	if original.Child.GrantSHA256 != birth.OriginalBirthGrantSHA256 || original.Child.Generation != birth.OriginalBirthGeneration || original.Child.Epoch != birth.Epoch {
		t.Fatal("retirement request replaced original purchase or birth epoch")
	}
	if original.DrainSHA256 != "" {
		t.Fatal("observational preparation supplied a digest before protected capture")
	}
	before, err := protocol.EncodeJSON(original)
	if err != nil {
		t.Fatal(err)
	}
	birth.GrantSHA256, birth.Generation = strings.Repeat("d", 64), 13
	after, err := originalPoolRetirement(birth, birth.InstanceID, removal)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(after)
	if err != nil || !bytes.Equal(before, wire) {
		t.Fatal("compatible current grant changed original outgoing retirement selectors", err)
	}
	for name, mutate := range map[string]func(*rootoci.PoolChildView){
		"missing original grant":      func(view *rootoci.PoolChildView) { view.OriginalBirthGrantSHA256 = "" },
		"invalid original grant":      func(view *rootoci.PoolChildView) { view.OriginalBirthGrantSHA256 = strings.Repeat("x", 64) },
		"missing original generation": func(view *rootoci.PoolChildView) { view.OriginalBirthGeneration = 0 },
		"missing birth epoch":         func(view *rootoci.PoolChildView) { view.Epoch = 0 },
		"foreign instance":            func(view *rootoci.PoolChildView) { view.InstanceID = "ocid1.instance.foreign" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := birth
			mutate(&changed)
			if _, err := originalPoolRetirement(changed, birth.InstanceID, removal); !errors.Is(err, ErrCapacityPending) {
				t.Fatal("missing original purchase lineage acquired retirement selectors", err)
			}
		})
	}
}
