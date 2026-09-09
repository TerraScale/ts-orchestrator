package databaseadmission

import (
	"context"
	"reflect"

	"terrascale.tech/orchestrator/src/orchestrator/keylease"
)

var databaseKeyPurposes = [...]string{"data", "backup", "checkpoint"}

func purposeTargets(r Record, purpose string) []keylease.ProvisionTarget {
	targets := []keylease.ProvisionTarget{}
	seen := map[string]bool{}
	for _, target := range r.Targets {
		if seen[target.Region] {
			continue
		}
		seen[target.Region] = true
		provision := target.Provision
		provision.Binding.Purpose = purpose
		targets = append(targets, provision)
	}
	return targets
}

// Each purpose gets an independent random DEK; all selected Regions share only
// that purpose's material. Persist each completed set before starting the next.
func (p *Pipeline) provisionKeys(ctx context.Context, r *Record) error {
	for _, purpose := range databaseKeyPurposes {
		targets := purposeTargets(*r, purpose)
		count := 0
		for _, entry := range r.Wrapped {
			if entry.Binding.Purpose == purpose {
				count++
			}
		}
		if count == len(targets) {
			continue
		}
		if count != 0 {
			return ErrInvalid
		}
		if err := p.config.CheckAuthority(ctx); err != nil {
			return err
		}
		// A policy can be revoked while a previous purpose is being
		// provisioned. Recheck the immutable request at each provider effect;
		// one authorization at reconcile entry is not sufficient for retries or
		// multi-purpose issuance.
		if err := p.config.Authorize(ctx, r.Request); err != nil {
			return err
		}
		if err := p.config.ProvisionKeys(ctx, p.config.CatalogPath, targets); err != nil {
			return err
		}
		catalog, err := keylease.ReadCatalog(p.config.CatalogPath)
		if err != nil {
			return err
		}
		for _, target := range targets {
			found := false
			for _, entry := range catalog.Entries {
				if entry.Binding == target.Binding {
					r.Wrapped = append(r.Wrapped, entry)
					found = true
					break
				}
			}
			if !found {
				return ErrInvalid
			}
		}
		if len(r.Wrapped) == len(r.Request.Regions)*len(databaseKeyPurposes) {
			r.State = "keys_provisioned"
		}
		if err := p.save(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

func wrappedPreserved(old, next []keylease.Entry) bool {
	if len(next) < len(old) {
		return false
	}
	return reflect.DeepEqual(old, next[:len(old)]) || len(old) == 0
}
