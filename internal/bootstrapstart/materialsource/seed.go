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
	StartupSHA256  string                            `json:"startupSha256"`
	SourceSHA256   string                            `json:"sourceSha256"`
	GrantSHA256    string                            `json:"grantSha256"`
	TemplateSHA256 string                            `json:"templateSha256"`
	InstanceID     string                            `json:"instanceId"`
	Records        bootstrapstart.DerivedSeedRecords `json:"records"`
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
	checkpoint := func(ctx context.Context, proposed *bootstrapstart.DerivedSeedRecords) (bootstrapstart.DerivedSeedRecords, error) {
		state, etag, err := source.read(ctx)
		if err != nil || state.Reference != source.state.Reference || !bytes.Equal(state.Startup[authority.Manifest().SeedSlot], authority.Wire()) {
			return bootstrapstart.DerivedSeedRecords{}, ErrMaterialSource
		}
		expected := seedCheckpoint{StartupSHA256: authority.Digest(), SourceSHA256: state.Reference.SHA256, GrantSHA256: founder.GrantDigest(), TemplateSHA256: founder.TemplateDigest(), InstanceID: founder.InstanceID()}
		decode := func(wire []byte) (bootstrapstart.DerivedSeedRecords, error) {
			var stored seedCheckpoint
			if json.Unmarshal(wire, &stored, json.RejectUnknownMembers(true)) != nil || stored.StartupSHA256 != expected.StartupSHA256 || stored.SourceSHA256 != expected.SourceSHA256 || stored.GrantSHA256 != expected.GrantSHA256 || stored.TemplateSHA256 != expected.TemplateSHA256 || stored.InstanceID != expected.InstanceID || len(stored.Records.Reservation.IntentWire) == 0 || len(stored.Records.Reservation.InitialHeadWire) == 0 || (len(stored.Records.Completion.ReceiptWire) == 0) != (len(stored.Records.Completion.ResultWire) == 0) || (len(stored.Records.Completion.ResultWire) == 0) != (len(stored.Records.Completion.CompletedHeadWire) == 0) {
				return bootstrapstart.DerivedSeedRecords{}, ErrMaterialSource
			}
			return stored.Records, nil
		}
		if len(state.SeedCompletion) > 0 {
			source.state, source.etag = state, etag
			stored, err := decode(state.SeedCompletion)
			if err != nil || proposed == nil || len(stored.Completion.ResultWire) > 0 || len(proposed.Completion.ResultWire) == 0 {
				return stored, err
			}
			if !bytes.Equal(stored.Reservation.IntentWire, proposed.Reservation.IntentWire) || !bytes.Equal(stored.Reservation.InitialHeadWire, proposed.Reservation.InitialHeadWire) {
				return bootstrapstart.DerivedSeedRecords{}, ErrMaterialSource
			}
		}
		if proposed == nil {
			return bootstrapstart.DerivedSeedRecords{}, nil
		}
		expected.Records = *proposed
		wire, err := json.Marshal(expected, json.Deterministic(true))
		if err != nil || len(wire) > 256<<10 {
			return bootstrapstart.DerivedSeedRecords{}, ErrMaterialSource
		}
		if _, err := decode(wire); err != nil {
			return bootstrapstart.DerivedSeedRecords{}, err
		}
		state.SeedCompletion = wire
		if _, err := source.write(ctx, state, etag); err != nil {
			// A concurrent founder may have pinned the reservation or completed
			// observation. Read its exact winning bytes rather than resigning.
			current, currentETag, readErr := source.read(ctx)
			if readErr != nil || current.Reference != state.Reference || !bytes.Equal(current.Startup[authority.Manifest().SeedSlot], authority.Wire()) {
				return bootstrapstart.DerivedSeedRecords{}, ErrMaterialSource
			}
			records, decodeErr := decode(current.SeedCompletion)
			if decodeErr != nil {
				return bootstrapstart.DerivedSeedRecords{}, err
			}
			source.state, source.etag = current, currentETag
			return records, nil
		}
		current, currentETag, err := source.read(ctx)
		if err != nil || current.Reference != state.Reference || !bytes.Equal(current.SeedCompletion, wire) {
			return bootstrapstart.DerivedSeedRecords{}, ErrMaterialSource
		}
		source.state, source.etag = current, currentETag
		return decode(current.SeedCompletion)
	}
	return bootstrapstart.EnsureDerivedSeed(ctx, roots, anchor, authority, founder, ed25519.PrivateKey(key), checkpoint)
}
