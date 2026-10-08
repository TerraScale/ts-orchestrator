// Package disasterrecovery prepares the cross-region bootstrap copies. It
// never re-founds a controller or changes a running cell's desired state.
package disasterrecovery

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// Config pins the two existing control compartments and their regional keys.
// Bucket names are derived, so an operator cannot select a serving bucket as
// a read-only replication destination.
type Config struct {
	Version   int    `json:"version"`
	Namespace string `json:"namespace"`
	GRU       Region `json:"gru"`
	SFO       Region `json:"sfo"`
}

type Region struct {
	CompartmentID string            `json:"compartment_id"`
	VaultID       string            `json:"vault_id"`
	KeyID         string            `json:"key_id"`
	BucketIDs     map[string]string `json:"bucket_ids,omitempty"` // Reviewed destination bucket name -> OCID.
	PolicyIDs     map[string]string `json:"policy_ids,omitempty"` // Reviewed source policy name -> opaque ID.
}

var namespacePattern = regexp.MustCompile(`^[a-z0-9]{1,64}$`)
var ocidPattern = regexp.MustCompile(`^ocid1\.[a-z]+\.oc1\.[a-z0-9-]*\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)
var policyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func (config Config) Validate() error {
	if config.Version != 1 || !namespacePattern.MatchString(config.Namespace) {
		return errors.New("disaster recovery config requires version 1 and an Object Storage namespace")
	}
	seenIDs := make(map[string]string)
	for cell, region := range map[string]Region{catalog.GRU: config.GRU, catalog.SFO: config.SFO} {
		if !validOCID(region.CompartmentID, "compartment", "") ||
			!validOCID(region.VaultID, "vault", catalog.OCIRegion(cell)) ||
			!validOCID(region.KeyID, "key", catalog.OCIRegion(cell)) {
			return fmt.Errorf("%s requires a control compartment and its regional Vault and key OCIDs", cell)
		}
		other := "sfo"
		if cell == catalog.SFO {
			other = "gru"
		}
		prefix := strings.ToLower(cell) + "-1-dr-" + other + "-1-"
		for name, id := range region.BucketIDs {
			if (name != prefix+"backup" && name != prefix+"backup-seed" && name != prefix+"head" && name != prefix+"head-seed") ||
				!validOCID(id, "bucket", catalog.OCIRegion(cell)) {
				return fmt.Errorf("%s has an unexpected destination bucket name or OCID: %s", cell, name)
			}
			if previous, ok := seenIDs[id]; ok {
				return fmt.Errorf("bucket %s shares its OCID with %s", name, previous)
			}
			seenIDs[id] = name
		}
		prefix = "TS-641-" + strings.ToLower(cell) + "-1-"
		for name, id := range region.PolicyIDs {
			// The SDK treats replication policy IDs as opaque strings, not OCIDs.
			if (name != prefix+"backup" && name != prefix+"head") || !policyIDPattern.MatchString(id) {
				return fmt.Errorf("%s has an unexpected replication policy name or ID: %s", cell, name)
			}
			if previous, ok := seenIDs[id]; ok {
				return fmt.Errorf("policy %s shares its ID with %s", name, previous)
			}
			seenIDs[id] = name
		}
	}
	if config.GRU.CompartmentID == config.SFO.CompartmentID {
		return errors.New("GRU and SFO control compartments must differ")
	}
	return nil
}

func validOCID(id, kind, region string) bool {
	if !ocidPattern.MatchString(id) {
		return false
	}
	parts := strings.Split(id, ".")
	return parts[1] == kind && parts[3] == region
}
