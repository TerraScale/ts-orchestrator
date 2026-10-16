package region

import (
	"context"
	"errors"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// FoundationResolver exposes only foundations still covered by authenticated
// scope. It grants neither host admission nor permission to found a cluster.
type FoundationResolver struct {
	Footprint Footprint
	Store     FoundationStore
}

func (r FoundationResolver) Resolve(ctx context.Context, cell string) (FoundationRecord, error) {
	if r.Footprint == nil || r.Store == nil {
		return FoundationRecord{}, errors.New("foundation discovery requires authenticated footprint and durable store")
	}
	footprint, err := r.Footprint.AuthorizedRegions(ctx)
	if err != nil {
		return FoundationRecord{}, err
	}
	if err := validateFootprint(footprint); err != nil {
		return FoundationRecord{}, err
	}
	for _, intent := range footprint.Regions {
		if intent.Plan["cell"] != cell {
			continue
		}
		record, _, err := r.Store.Load(ctx, cell)
		if err != nil {
			return FoundationRecord{}, err
		}
		digest, err := FoundationIntentDigest(intent)
		if err != nil {
			return FoundationRecord{}, err
		}
		if record.IntentDigest != digest || record.Generation != intent.Generation || record.TenancyID != footprint.TenancyID ||
			record.ParentCompartmentID != footprint.ParentCompartmentID || record.SharedCompartmentID != footprint.SharedCompartmentID || record.Stage != "reconciled" {
			return FoundationRecord{}, errors.New("authorized regional foundation is not reconciled at its current generation")
		}
		return record, nil
	}
	return FoundationRecord{}, errors.New("region is outside authenticated foundation footprint")
}

func (r FoundationRecord) VaultTarget() (vaultsecret.Target, error) {
	if err := r.validate(); err != nil || r.Stage != "reconciled" {
		return vaultsecret.Target{}, errors.New("Vault delivery requires a reconciled foundation record")
	}
	target := vaultsecret.Target{CompartmentID: r.ResourceIDs["control_compartment"], VaultID: r.ResourceIDs["vault"], KeyID: r.ResourceIDs["key"]}
	for kind, id := range map[string]string{"compartment": target.CompartmentID, "vault": target.VaultID, "key": target.KeyID} {
		parts := strings.Split(id, ".")
		if len(parts) < 5 || parts[0] != "ocid1" || parts[1] != kind || parts[2] != "oc1" || kind != "compartment" && parts[3] != r.OCIRegion {
			return vaultsecret.Target{}, errors.New("foundation Vault target has invalid resource scope")
		}
		for _, c := range id {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
				return vaultsecret.Target{}, errors.New("foundation Vault target has invalid resource identity")
			}
		}
	}
	return target, nil
}

func (r FoundationResolver) BootstrapMaterial(ctx context.Context, cell string) (VerifiedBootstrapMaterial, error) {
	reader, ok := r.Footprint.(interface {
		AuthorizedBootstrapMaterial(context.Context, string) (VerifiedBootstrapMaterial, error)
	})
	if !ok {
		return VerifiedBootstrapMaterial{}, errors.New("foundation scope does not authorize bootstrap material discovery")
	}
	return reader.AuthorizedBootstrapMaterial(ctx, cell)
}
