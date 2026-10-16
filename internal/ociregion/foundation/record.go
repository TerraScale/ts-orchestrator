package foundation

import (
	"fmt"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// Record projects a verified foundation's non-secret provider references.
// It is not an authority or admission proof; the owning durable operation
// supplies its authenticated identity and generation separately.
type Record struct {
	Cell        string             `json:"cell"`
	Region      string             `json:"region"`
	HomeRegion  string             `json:"home_region"`
	ResourceIDs map[string]string  `json:"resource_ids"`
	Vault       vaultsecret.Target `json:"vault"`
	Buckets     map[string]string  `json:"buckets"`
}

// RecordFromPlan projects an inspected bound plan. The caller must obtain the
// plan from the authenticated operation store; names and tags do not authorize it.
func RecordFromPlan(plan Object, homeRegion string) (Record, error) {
	bound, err := ociregion.ValidatePlan(plan)
	if err != nil {
		return Record{}, err
	}
	if !catalog.IsOCIRegion(homeRegion) {
		return Record{}, fmt.Errorf("foundation home region %q is not in the catalog", homeRegion)
	}
	ids := obj(bound["resource_ids"])
	record := Record{Cell: text(bound["cell"]), Region: text(bound["region"]), HomeRegion: homeRegion, ResourceIDs: map[string]string{}, Buckets: map[string]string{}}
	for _, key := range []string{"control_compartment", "network_compartment", "workload_compartment", "vcn", "subnet", "network_security_group", "vault", "key"} {
		if text(ids[key]) == "" {
			return Record{}, fmt.Errorf("foundation record lacks verified %s", key)
		}
	}
	for key, value := range ids {
		if id := text(value); id != "" {
			record.ResourceIDs[key] = id
		}
	}
	for role, value := range obj(bound["foundation_buckets"]) {
		record.Buckets[role] = text(value)
	}
	record.Vault = vaultsecret.Target{CompartmentID: text(ids["control_compartment"]), VaultID: text(ids["vault"]), KeyID: text(ids["key"])}
	return record, nil
}
