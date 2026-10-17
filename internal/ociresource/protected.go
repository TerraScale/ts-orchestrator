package ociresource

import (
	"encoding/hex"
	"errors"
)

// ResourceSource identifies the exact accepted config and root-signed amendment
// used by the root domain. These digests record provenance; they grant no rights.
type ResourceSource struct {
	ControllerConfigSHA256 string `json:"controllerConfigSha256"`
	CellSpecSHA256         string `json:"cellSpecSha256,omitempty"`
	CellSpecGeneration     uint64 `json:"cellSpecGeneration,omitzero"`
	GrantSHA256            string `json:"grantSha256"`
}

func (s ResourceSource) Validate() error {
	digest := func(value string) bool {
		wire, err := hex.DecodeString(value)
		return err == nil && len(wire) == 32 && hex.EncodeToString(wire) == value
	}
	if !digest(s.ControllerConfigSHA256) || !digest(s.GrantSHA256) ||
		(s.CellSpecSHA256 == "") != (s.CellSpecGeneration == 0) || s.CellSpecSHA256 != "" && !digest(s.CellSpecSHA256) {
		return errors.New("OCI resource source lacks exact accepted config, signed spec or grant identity")
	}
	return nil
}

// ProtectedResource keeps the original convergence and its signed provenance in
// the foundation's existing protected CAS object, separate from unsigned KV.
type ProtectedResource struct {
	Revision      uint64          `json:"revision"`
	Source        ResourceSource  `json:"source"`
	RemovalSource *ResourceSource `json:"removalSource,omitempty"`
	Desired       Desired         `json:"desired"`
}

// ProtectedJournal shares the foundation record's existing finite byte bound.
// Resource revisions advance only after that whole protected object commits.
type ProtectedJournal struct {
	Revision  uint64                       `json:"revision"`
	Source    ResourceSource               `json:"source"`
	Resources map[string]ProtectedResource `json:"resources"`
}

func (j ProtectedJournal) Validate(cell string) error {
	if j.Revision == 0 {
		return errors.New("protected OCI resource journal has no committed revision")
	}
	if err := j.Source.Validate(); err != nil {
		return err
	}
	for key, resource := range j.Resources {
		if key != resource.Desired.Key.String() || resource.Desired.Key.Region != cell ||
			resource.Revision == 0 || resource.Revision > j.Revision {
			return errors.New("protected OCI resource journal has an invalid key, region or revision")
		}
		if err := resource.Desired.Validate(); err != nil {
			return err
		}
		if err := resource.Source.Validate(); err != nil {
			return err
		}
		if (resource.Desired.Tombstone == nil) != (resource.RemovalSource == nil) {
			return errors.New("protected OCI tombstone lacks its signed removal source")
		}
		if resource.RemovalSource != nil {
			if err := resource.RemovalSource.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}
