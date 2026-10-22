package region

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// FoundationResourceReference names one immutable resource role in the signed
// foundation grant; observations and caller-selected OCIDs cannot authorize it.
func FoundationResourceReference(cell, key string) (string, error) {
	return foundationbinding.Reference(cell, key)
}

// ResourceBindings independently verifies the grant, protected creation journal
// and exact current SDK resources before exposing any logical authorization.
func (r FoundationResolver) ResourceBindings(ctx context.Context, cell string) (foundationbinding.VerifiedBindings, error) {
	return r.ResourceBindingsFor(ctx, cell)
}

// ResourceBindingsFor narrows observation to already-created signed roles when
// a finite bootstrap allocation is needed before the whole region exists.
func (r FoundationResolver) ResourceBindingsFor(ctx context.Context, cell string, keys ...string) (foundationbinding.VerifiedBindings, error) {
	reader, ok := r.Footprint.(*SignedFootprint)
	if !ok {
		return foundationbinding.VerifiedBindings{}, errors.New("logical resource bindings require an independently authenticated signed foundation")
	}
	wire, err := reader.readGrant(ctx)
	if err != nil {
		return foundationbinding.VerifiedBindings{}, err
	}
	return reader.resourceBindingsFor(ctx, cell, wire, keys...)
}

func (r FoundationResolver) ResolveResource(ctx context.Context, reference string) (string, error) {
	cell, _, err := foundationbinding.Parse(reference)
	if err != nil {
		return "", err
	}
	bindings, err := r.ResourceBindings(ctx, cell)
	if err != nil {
		return "", err
	}
	return bindings.Resolve(reference)
}

func (s *SignedFootprint) resourceBindings(ctx context.Context, cell string, wire []byte) (foundationbinding.VerifiedBindings, error) {
	return s.resourceBindingsFor(ctx, cell, wire)
}

func (s *SignedFootprint) resourceBindingsFor(ctx context.Context, cell string, wire []byte, keys ...string) (foundationbinding.VerifiedBindings, error) {
	if s.factory == nil {
		return foundationbinding.VerifiedBindings{}, errors.New("logical resource binding requires the authenticated production OCI factory")
	}
	if _, _, err := s.verifyGrant(wire); err != nil {
		return foundationbinding.VerifiedBindings{}, err
	}
	return foundationbinding.Verify(ctx, s.factory, foundationbinding.Authority{Scope: s.scope, Roots: s.roots,
		Policy: bootstrap.BootstrapAnchorTrustPolicy(), GrantSHA256: s.home.GrantSHA256, Generation: s.home.GrantGeneration,
		InstallationID: s.home.InstallationID, TenancyID: s.tenancy, Namespace: s.storage.Namespace,
		Bucket: s.storage.HeadBucket, Prefix: s.storage.Prefix, Cell: cell, Keys: keys}, wire)
}

func (s *SignedFootprint) boundStartup(ctx context.Context, startup BootstrapStartupIntent, plan map[string]any, wire []byte, originalAdmission bool) (BootstrapStartupIntent, map[string]any, *bootstrap.VerifiedStartupTemplate, error) {
	if _, _, err := s.verifyGrant(wire); err != nil {
		return BootstrapStartupIntent{}, nil, nil, err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return BootstrapStartupIntent{}, nil, nil, err
	}
	var version struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	if err := json.Unmarshal(envelope.Payload, &version); err != nil {
		return BootstrapStartupIntent{}, nil, nil, err
	}
	// Historical exact-only grants retain their existing offline authorizer.
	if version.SchemaVersion == 1 {
		return startup, plan, nil, nil
	}
	cell, _ := plan["cell"].(string)
	keys, err := startup.FoundationReferenceKeys(cell)
	if err != nil {
		return BootstrapStartupIntent{}, nil, nil, err
	}
	verify, roots := bootstrap.VerifyBoundRegionalStartupTemplate, s.roots
	if originalAdmission {
		// Original startup admission is bound to the independent genesis, never to transported terminal roots.
		verify, roots = bootstrap.VerifyBoundOriginalStartupTemplate, s.independentGenesis
	}
	verified, err := verify(ctx, s.factory, wire, roots, s.bootstrapAnchor, oci.Region(cell), time.Now())
	if err != nil {
		return BootstrapStartupIntent{}, nil, nil, err
	}
	original, err := json.Marshal(startup, json.Deterministic(true))
	if err != nil {
		return BootstrapStartupIntent{}, nil, nil, err
	}
	originalDigest := sha256.Sum256(original)
	if verified.TemplateDigest() != hex.EncodeToString(originalDigest[:]) {
		return BootstrapStartupIntent{}, nil, nil, errors.New("regional startup differs from original signed template")
	}
	ctx, cancel := context.WithDeadline(ctx, verified.ExpiresAt())
	defer cancel()
	bound := maps.Clone(plan)
	ids, _ := plan["resource_ids"].(map[string]any)
	ids = maps.Clone(ids)
	target := verified.VaultTarget()
	for role, id := range map[string]string{"control_compartment": target.CompartmentOCID, "vault": target.VaultOCID, "key": target.KMSKeyOCID} {
		ids[role] = id
	}
	// Target roles use the same finite birth/observation bridge as bootstrap.
	keys = slices.DeleteFunc(keys, func(role string) bool { return role == "control_compartment" || role == "vault" || role == "key" })
	if len(keys) != 0 {
		bindings, err := s.resourceBindingsFor(ctx, cell, wire, keys...)
		if err != nil {
			return BootstrapStartupIntent{}, nil, nil, err
		}
		for _, role := range keys {
			reference, err := FoundationResourceReference(cell, role)
			if err != nil {
				return BootstrapStartupIntent{}, nil, nil, err
			}
			id, err := bindings.Resolve(reference)
			if err != nil {
				return BootstrapStartupIntent{}, nil, nil, err
			}
			ids[role] = id
		}
	}
	if err := verified.VerifyCurrentContext(ctx, time.Now()); err != nil {
		return BootstrapStartupIntent{}, nil, nil, err
	}
	bound["resource_ids"] = ids
	return verified.Template(), bound, &verified, nil
}
