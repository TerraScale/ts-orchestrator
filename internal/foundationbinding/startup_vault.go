package foundationbinding

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// VerifiedStartupVault observes only the signed host-publication destination.
// Exact pins never become logical bindings or receive creation provenance.
type VerifiedStartupVault struct {
	factory                 *ociclient.Factory
	authority               Authority
	wire                    []byte
	expires                 time.Time
	leaseExpiresAt          time.Time
	operationID, leaseID    string
	epoch                   uint64
	compartment, vault, key string
}

func (v VerifiedStartupVault) CompartmentOCID() string { return v.compartment }
func (v VerifiedStartupVault) VaultOCID() string       { return v.vault }
func (v VerifiedStartupVault) KMSKeyOCID() string      { return v.key }
func (v VerifiedStartupVault) ExpiresAt() time.Time    { return v.expires }

// Revalidate preserves the original operation, fencing epoch, lease and deadline.
func (v VerifiedStartupVault) Revalidate(ctx context.Context) error {
	if v.factory == nil || !time.Now().Before(v.expires) {
		return errors.New("startup vault observation expired or unverified")
	}
	current, err := VerifyStartupVault(ctx, v.factory, v.authority, v.wire, v.expires)
	if err != nil {
		return err
	}
	if current.operationID != v.operationID || current.epoch != v.epoch || current.leaseID != v.leaseID || !current.leaseExpiresAt.Equal(v.leaseExpiresAt) ||
		current.compartment != v.compartment || current.vault != v.vault || current.key != v.key {
		return errors.New("startup vault operation or target changed after verification")
	}
	return nil
}

// VerifyStartupVault authenticates original signed pins and the retained regional
// operation before fresh OCI reads. deadline is the original bootstrap anchor cap.
// Target roles in Authority.Keys also require genuine birth when exactly pinned.
func VerifyStartupVault(ctx context.Context, factory *ociclient.Factory, authority Authority, grantWire []byte, deadline time.Time) (VerifiedStartupVault, error) {
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	if deadline.IsZero() || !time.Now().Before(deadline) {
		return VerifiedStartupVault{}, errors.New("startup vault authority expired")
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if factory == nil || !catalog.IsCell(authority.Cell) || !canonicalDigest(authority.GrantSHA256) || authority.Generation == 0 ||
		!entityid.Valid(authority.InstallationID) || !resourceID(authority.TenancyID, "tenancy", "") ||
		authority.Namespace == "" || authority.Bucket == "" || authority.Prefix == "" || strings.ContainsAny(authority.Prefix, "\\\r\n\x00") || strings.ContainsAny(authority.Namespace+authority.Bucket, "/\\\r\n\x00") ||
		authority.Scope.Domain != "terrascale.foundation.scope" || authority.Scope.Cell != "GRU" || authority.Scope.Role != "foundation" {
		return VerifiedStartupVault{}, errors.New("foundation binding authority is incomplete or outside its root scope")
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy != authority.TenancyID {
		return VerifiedStartupVault{}, errors.New("foundation binding tenancy differs from authenticated OCI identity")
	}
	if digest(grantWire) != authority.GrantSHA256 {
		return VerifiedStartupVault{}, errors.New("foundation grant differs from root-pinned exact wire")
	}
	envelope, err := trust.DecodeEnvelope(grantWire)
	if err != nil {
		return VerifiedStartupVault{}, err
	}
	payload, err := trust.VerifyCurrent(envelope, authority.Scope, authority.Roots, time.Now(), authority.Policy)
	if err != nil {
		return VerifiedStartupVault{}, err
	}
	grantCtx, grantCancel := context.WithDeadline(ctx, envelope.ExpiresAt)
	defer grantCancel()
	ctx = grantCtx
	if err := verifyCurrentGrant(ctx, factory, authority, grantWire); err != nil {
		return VerifiedStartupVault{}, err
	}
	var approved grant
	if err := json.Unmarshal(payload, &approved, json.RejectUnknownMembers(true)); err != nil {
		return VerifiedStartupVault{}, fmt.Errorf("foundation grant schema: %w", err)
	}
	if (approved.SchemaVersion != 2 && approved.SchemaVersion != 3) || approved.Generation != authority.Generation || approved.InstallationID != authority.InstallationID || approved.TenancyID != tenancy ||
		!resourceID(approved.ParentCompartmentID, "compartment", "") || !resourceID(approved.SharedCompartmentID, "compartment", "") ||
		approved.MonthlyLimitMinor <= 0 || approved.Currency != "USD" && approved.Currency != "BRL" || approved.CleanupOwner == "" || len(approved.CleanupOwner) > 128 ||
		len(approved.Regions) == 0 || len(approved.Regions) > catalog.Len {
		return VerifiedStartupVault{}, errors.New("foundation grant lacks current bound scope or spend authority")
	}
	var selected intent
	var selectedDigest string
	seen := map[string]bool{}
	for _, raw := range approved.Regions {
		var region intent
		if err := json.Unmarshal(raw, &region, json.RejectUnknownMembers(true)); err != nil {
			return VerifiedStartupVault{}, fmt.Errorf("foundation region intent schema: %w", err)
		}
		cell, _ := region.Plan["cell"].(string)
		if !catalog.IsCell(cell) || seen[cell] || region.Generation != approved.Generation || region.Plan["region"] != catalog.OCIRegion(cell) ||
			region.Plan["tenancy_id"] != tenancy || region.Plan["parent_compartment_id"] != approved.ParentCompartmentID || region.Plan["shared_compartment_id"] != approved.SharedCompartmentID {
			return VerifiedStartupVault{}, errors.New("foundation region intent differs from signed scope or repeats a cell")
		}
		if _, ok := region.Plan["resource_ids"].(map[string]any); !ok {
			return VerifiedStartupVault{}, errors.New("foundation region intent lacks resource roles")
		}
		seen[cell] = true
		if cell == authority.Cell {
			selected = region
			wire, err := json.Marshal(region, json.Deterministic(true))
			if err != nil {
				return VerifiedStartupVault{}, err
			}
			// Decode optional signed documents before canonicalizing their maps.
			var canonical map[string]any
			if err := json.Unmarshal(wire, &canonical); err != nil {
				return VerifiedStartupVault{}, err
			}
			wire, err = json.Marshal(canonical, json.Deterministic(true))
			if err != nil {
				return VerifiedStartupVault{}, err
			}
			selectedDigest = digest(wire)
		}
	}
	if !seen[authority.Cell] {
		return VerifiedStartupVault{}, errors.New("foundation cell is outside the signed grant")
	}
	requested := map[string]bool{}
	pins := selected.Plan["resource_ids"].(map[string]any)
	// False retains an exact dependency without making it logically resolvable.
	for _, role := range []string{"control_compartment", "vault", "key"} {
		pin, exists := pins[role]
		if exists && pin != nil {
			value, ok := pin.(string)
			if !ok {
				return VerifiedStartupVault{}, errors.New("startup vault role is not a signed resource identity")
			}
			if strings.HasPrefix(value, "foundation:") {
				cell, key, err := Parse(value)
				if err != nil || cell != authority.Cell || key != role {
					return VerifiedStartupVault{}, errors.New("startup vault role has an invalid reference")
				}
				continue
			}
		}
	}
	current, err := loadRecord(ctx, factory, authority)
	if err != nil {
		return VerifiedStartupVault{}, err
	}
	for _, role := range []string{"control_compartment", "vault", "key"} {
		requested[role] = pins[role] != current.ResourceIDs[role] || slices.Contains(authority.Keys, role)
	}
	if err := validateRecord(current, approved, authority, selectedDigest, selected.Plan, requested); err != nil {
		return VerifiedStartupVault{}, err
	}
	expires := envelope.ExpiresAt
	if deadline.Before(expires) {
		expires = deadline
	}
	if current.Stage == "foundation" && current.ExpiresAt.Before(expires) {
		expires = current.ExpiresAt
	}
	if !time.Now().Before(expires) {
		return VerifiedStartupVault{}, errors.New("startup vault authority expired")
	}
	observedCtx, observedCancel := context.WithDeadline(ctx, expires)
	defer observedCancel()
	current.ResourceIDs = map[string]string{"control_compartment": current.ResourceIDs["control_compartment"], "vault": current.ResourceIDs["vault"], "key": current.ResourceIDs["key"]}
	// A canonical logical role still needs birth evidence; observe checks its ID.
	plan := maps.Clone(selected.Plan)
	concretePins := maps.Clone(pins)
	for role := range requested {
		if value, _ := concretePins[role].(string); strings.HasPrefix(value, "foundation:") {
			delete(concretePins, role)
		}
	}
	plan["resource_ids"] = concretePins
	if err := observe(observedCtx, factory, plan, current); err != nil {
		return VerifiedStartupVault{}, err
	}
	// SDK waits cannot seal an operation superseded while resources were read.
	if err := verifyCurrentGrant(observedCtx, factory, authority, grantWire); err != nil {
		return VerifiedStartupVault{}, err
	}
	retained, err := loadRecord(observedCtx, factory, authority)
	if err != nil {
		return VerifiedStartupVault{}, err
	}
	if err := validateRecord(retained, approved, authority, selectedDigest, selected.Plan, requested); err != nil {
		return VerifiedStartupVault{}, err
	}
	if retained.OperationID != current.OperationID || retained.Epoch != current.Epoch || retained.LeaseID != current.LeaseID || !retained.ExpiresAt.Equal(current.ExpiresAt) ||
		retained.ResourceIDs["control_compartment"] != current.ResourceIDs["control_compartment"] || retained.ResourceIDs["vault"] != current.ResourceIDs["vault"] || retained.ResourceIDs["key"] != current.ResourceIDs["key"] {
		return VerifiedStartupVault{}, errors.New("startup vault operation changed during SDK observations")
	}
	if err := observedCtx.Err(); err != nil {
		return VerifiedStartupVault{}, err
	}
	if !time.Now().Before(expires) {
		return VerifiedStartupVault{}, errors.New("startup vault observation exceeded authority deadline")
	}
	authority.Keys = slices.Clone(authority.Keys)
	authority.Roots = maps.Clone(authority.Roots)
	for key, public := range authority.Roots {
		authority.Roots[key] = ed25519.PublicKey(bytes.Clone(public))
	}
	return VerifiedStartupVault{factory: factory, authority: authority, wire: bytes.Clone(grantWire), expires: expires,
		operationID: current.OperationID, epoch: current.Epoch, leaseID: current.LeaseID, leaseExpiresAt: current.ExpiresAt,
		compartment: current.ResourceIDs["control_compartment"], vault: current.ResourceIDs["vault"], key: current.ResourceIDs["key"]}, nil
}
