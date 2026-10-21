package materialsource

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"os"
	"path/filepath"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type seedCheckpoint struct {
	StartupSHA256  string                                       `json:"startupSha256"`
	SourceSHA256   string                                       `json:"sourceSha256"`
	GrantSHA256    string                                       `json:"grantSha256"`
	TemplateSHA256 string                                       `json:"templateSha256"`
	InstanceID     string                                       `json:"instanceId"`
	Records        bootstrapstart.ExternalSeedCompletionRecords `json:"records"`
}

// PrepareSeedLedger keeps the source key inside the recovered source and
// produces the exact existing slot history before admission can install it.
func (source *ColdStartMaterial) PrepareSeedLedger(ctx context.Context, roots trust.Keyring, anchor bootstrap.VerifiedBootstrapAnchor, authority bootstrap.DerivedStartupAuthority, founder bootstrapstart.VerifiedSourceFounder) (bootstrap.SlotState, error) {
	if source == nil || source.link != nil || !founder.IsVerified() || source.verifySource(ctx) != nil || founder.GrantDigest() != digestWire(source.grant.FoundationGrantWire()) || founder.TemplateDigest() != authority.TemplateDigest() {
		return bootstrap.SlotState{}, ErrMaterialSource
	}
	metadata, err := os.ReadFile(filepath.Join(source.directory, "material.json"))
	if err != nil || !bytes.Equal(metadata, authority.MaterialRecord()) {
		return bootstrap.SlotState{}, ErrMaterialSource
	}
	key, err := os.ReadFile(filepath.Join(source.directory, "founder-ledger.key"))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return bootstrap.SlotState{}, ErrMaterialSource
	}
	defer clear(key)
	checkpoint := func(ctx context.Context, proposed *bootstrapstart.ExternalSeedCompletionRecords) (bootstrapstart.ExternalSeedCompletionRecords, error) {
		state, etag, err := source.read(ctx)
		if err != nil || state.Reference != source.state.Reference || !bytes.Equal(state.Startup[authority.Manifest().SeedSlot], authority.Wire()) {
			return bootstrapstart.ExternalSeedCompletionRecords{}, ErrMaterialSource
		}
		expected := seedCheckpoint{StartupSHA256: authority.Digest(), SourceSHA256: state.Reference.SHA256, GrantSHA256: founder.GrantDigest(), TemplateSHA256: founder.TemplateDigest(), InstanceID: founder.InstanceID()}
		decode := func(wire []byte) (bootstrapstart.ExternalSeedCompletionRecords, error) {
			var stored seedCheckpoint
			if json.Unmarshal(wire, &stored, json.RejectUnknownMembers(true)) != nil || stored.StartupSHA256 != expected.StartupSHA256 || stored.SourceSHA256 != expected.SourceSHA256 || stored.GrantSHA256 != expected.GrantSHA256 || stored.TemplateSHA256 != expected.TemplateSHA256 || stored.InstanceID != expected.InstanceID || len(stored.Records.ReceiptWire) == 0 || len(stored.Records.ResultWire) == 0 || len(stored.Records.CompletedHeadWire) == 0 {
				return bootstrapstart.ExternalSeedCompletionRecords{}, ErrMaterialSource
			}
			return stored.Records, nil
		}
		if len(state.SeedCompletion) > 0 {
			source.state, source.etag = state, etag
			return decode(state.SeedCompletion)
		}
		if proposed == nil {
			return bootstrapstart.ExternalSeedCompletionRecords{}, nil
		}
		expected.Records = *proposed
		wire, err := json.Marshal(expected, json.Deterministic(true))
		if err != nil || len(wire) > 256<<10 {
			return bootstrapstart.ExternalSeedCompletionRecords{}, ErrMaterialSource
		}
		if _, err := decode(wire); err != nil {
			return bootstrapstart.ExternalSeedCompletionRecords{}, err
		}
		state.SeedCompletion = wire
		if _, err := source.write(ctx, state, etag); err != nil {
			// A concurrent founder may have durably pinned a different fresh
			// observation. Read its exact winning bytes rather than resigning.
			current, currentETag, readErr := source.read(ctx)
			if readErr != nil || current.Reference != state.Reference || !bytes.Equal(current.Startup[authority.Manifest().SeedSlot], authority.Wire()) {
				return bootstrapstart.ExternalSeedCompletionRecords{}, ErrMaterialSource
			}
			records, decodeErr := decode(current.SeedCompletion)
			if decodeErr != nil {
				return bootstrapstart.ExternalSeedCompletionRecords{}, err
			}
			source.state, source.etag = current, currentETag
			return records, nil
		}
		current, currentETag, err := source.read(ctx)
		if err != nil || current.Reference != state.Reference || !bytes.Equal(current.SeedCompletion, wire) {
			return bootstrapstart.ExternalSeedCompletionRecords{}, ErrMaterialSource
		}
		source.state, source.etag = current, currentETag
		return decode(current.SeedCompletion)
	}
	return bootstrapstart.EnsureDerivedSeed(ctx, roots, anchor, authority, founder, ed25519.PrivateKey(key), checkpoint)
}
