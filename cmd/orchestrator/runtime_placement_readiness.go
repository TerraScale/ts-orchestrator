package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"maps"
	"slices"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type productionReadinessKeyFile struct {
	KeyID         string `json:"key_id"`
	PublicKeyFile string `json:"public_key_file"`
}

func loadProductionReadinessKeys(files map[string]productionReadinessKeyFile) (map[string]databaseadmission.ReadinessKey, error) {
	if len(files) == 0 || len(files) > 128 {
		return nil, errors.New("runtime readiness: pinned member signing keys required")
	}
	keys := map[string]databaseadmission.ReadinessKey{}
	for identity, file := range files {
		if _, err := placementpublisher.HostSubject(identity); err != nil {
			return nil, err
		}
		if file.KeyID == "" {
			return nil, errors.New("runtime readiness: signing key ID required")
		}
		public, err := bootstrapcredentials.ReadFile(file.PublicKeyFile, false, ed25519.PublicKeySize)
		if err != nil || len(public) != ed25519.PublicKeySize {
			return nil, errors.New("runtime readiness: exact raw Ed25519 public key required")
		}
		keys[identity] = databaseadmission.ReadinessKey{KeyID: file.KeyID, PublicKey: public}
	}
	return keys, nil
}
func newProductionReadiness(keys map[string]databaseadmission.ReadinessKey, session globalWorkerSession, identities []productionPlacementTarget) (*databaseadmission.ReadinessConfig, error) {
	if len(keys) == 0 || len(keys) != len(identities) {
		return nil, errors.New("runtime readiness: every admitted member requires a pinned signing key")
	}
	pinned := maps.Clone(keys)
	targets := map[string]placementpublisher.ReadinessTarget{}
	for _, identity := range identities {
		key, ok := pinned[identity.ServerIdentity]
		if !ok || key.KeyID == "" || len(key.PublicKey) != ed25519.PublicKeySize || targets[identity.ServerIdentity] != nil {
			return nil, errors.New("runtime readiness: invalid pinned member set")
		}
		key.PublicKey = slices.Clone(key.PublicKey)
		pinned[identity.ServerIdentity] = key
		target, err := placementpublisher.NewRemoteTarget(session.Connection, identity.ServerIdentity, identity.Principal, 10*time.Second)
		if err != nil {
			return nil, err
		}
		targets[identity.ServerIdentity] = target
	}
	return &databaseadmission.ReadinessConfig{Keys: pinned, Collect: collectProductionReadiness(targets, session.CheckEffectAuthority)}, nil
}
func collectProductionReadiness(targets map[string]placementpublisher.ReadinessTarget, check func(context.Context) error) func(context.Context, databaseadmission.Record, string) ([]databaseadmission.SignedReadiness, error) {
	return func(ctx context.Context, record databaseadmission.Record, nonce string) ([]databaseadmission.SignedReadiness, error) {
		if check == nil || len(record.Targets) == 0 {
			return nil, databaseadmission.ErrInvalid
		}
		request := &pb.PlacementControlServiceReadinessRequest{Tenant: record.Request.TenantID, Project: record.Request.ProjectID, Database: record.DatabaseID, OperationId: databaseadmission.PlacementOperationID(record.Request), Nonce: nonce}
		if err := tbep.ValidateReadinessRequest(request); err != nil {
			return nil, err
		}
		receipts := make([]databaseadmission.SignedReadiness, 0, len(record.Targets))
		staged := map[string]bool{}
		for _, target := range record.PlacementTargets {
			if target.Proposed {
				staged[target.ServerIdentity] = true
			}
		}
		seen := map[string]bool{}
		for _, host := range record.Targets {
			target := targets[host.ServerIdentity]
			if target == nil || seen[host.ServerIdentity] || !host.Installed {
				return nil, databaseadmission.ErrInvalid
			}
			seen[host.ServerIdentity] = true
			if err := check(ctx); err != nil {
				return nil, err
			}
			response, err := target.Readiness(ctx, request)
			if err != nil {
				return nil, err
			}
			if err := tbep.ValidateReadinessEnvelope(response); err != nil {
				return nil, err
			}
			var signed databaseadmission.SignedReadiness
			if json.Unmarshal(response.SignedReceipt, &signed, json.RejectUnknownMembers(true)) != nil {
				return nil, databaseadmission.ErrInvalid
			}
			receipts = append(receipts, signed)
		}
		if err := check(ctx); err != nil {
			return nil, err
		}
		return receipts, nil
	}
}
