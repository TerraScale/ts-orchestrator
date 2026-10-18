package materialsource

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
)

// PrepareOriginalSeed retains the private ledger key inside the original
// archive and checkpoints the winning signed completion before installation.
func (v *VerifiedOriginalSourceArchive) PrepareOriginalSeed(ctx context.Context, authority bootstrap.DerivedStartupAuthority) (bootstrap.SlotState, error) {
	if v == nil || ctx == nil || ctx.Err() != nil || !authority.IsVerified() || v.VerifyCurrent(ctx) != nil {
		return bootstrap.SlotState{}, ErrMaterialSource
	}
	launch, err := authority.OriginalLaunch()
	if err != nil || launch.InstanceOCID != v.inputs.scope.InstanceID || authority.SourceSHA256() != v.state.Reference.SHA256 ||
		authority.Template().GrantDigest() != v.inputs.scope.GrantSHA256 || len(v.state.Startup) != 3 ||
		!bytes.Equal(v.state.Startup[authority.Manifest().SeedSlot], authority.Wire()) {
		return bootstrap.SlotState{}, ErrMaterialSource
	}
	template, err := v.actor.OriginalStartupTemplate(ctx)
	if err != nil || template.TemplateDigest() != authority.TemplateDigest() || authority.VerifyCurrent(ctx, time.Now()) != nil {
		return bootstrap.SlotState{}, ErrMaterialSource
	}
	clients, actorCtx, guarded, guard, err := v.originalStartupSession(ctx, template)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	body, _, err := readOriginalVault(guarded, clients, v.state)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	defer clear(body)
	archive, _, err := decodeOriginalCandidate(v.directory, v.inputs, v.state, body)
	if err != nil {
		return bootstrap.SlotState{}, err
	}
	defer clearArchive(archive)
	key := archive.Files["founder-ledger.key"]
	if len(key) != ed25519.PrivateKeySize || authority.VerifyLedgerKey(ed25519.PrivateKey(key).Public().(ed25519.PublicKey)) != nil {
		return bootstrap.SlotState{}, ErrMaterialSource
	}
	checkpoint := func(check context.Context, proposed *bootstrapstart.ExternalSeedCompletionRecords) (bootstrapstart.ExternalSeedCompletionRecords, error) {
		deny := func() (bootstrapstart.ExternalSeedCompletionRecords, error) {
			return bootstrapstart.ExternalSeedCompletionRecords{}, ErrMaterialSource
		}
		if err := check.Err(); err != nil {
			return bootstrapstart.ExternalSeedCompletionRecords{}, err
		}
		readback := originalPublicationCheckpointContext(check, actorCtx)
		if err := v.actor.Guard(readback); err != nil {
			return bootstrapstart.ExternalSeedCompletionRecords{}, err
		}
		if err := authority.VerifyCurrent(readback, time.Now()); err != nil {
			return bootstrapstart.ExternalSeedCompletionRecords{}, err
		}
		state, etag, err := readOriginalState(readback, clients.objects, v.inputs)
		if err != nil || !immutableOriginalState(v.state, state) || state.Reference != v.state.Reference || len(state.Startup) != 3 || !bytes.Equal(state.Startup[authority.Manifest().SeedSlot], authority.Wire()) {
			return deny()
		}
		expected := seedCheckpoint{StartupSHA256: authority.Digest(), SourceSHA256: state.Reference.SHA256, GrantSHA256: template.GrantDigest(), TemplateSHA256: template.TemplateDigest(), InstanceID: launch.InstanceOCID}
		decode := func(wire []byte) (bootstrapstart.ExternalSeedCompletionRecords, error) {
			var saved seedCheckpoint
			if json.Unmarshal(wire, &saved, json.RejectUnknownMembers(true)) != nil || saved.StartupSHA256 != expected.StartupSHA256 || saved.SourceSHA256 != expected.SourceSHA256 || saved.GrantSHA256 != expected.GrantSHA256 || saved.TemplateSHA256 != expected.TemplateSHA256 || saved.InstanceID != expected.InstanceID ||
				len(saved.Records.ReceiptWire) == 0 || len(saved.Records.ResultWire) == 0 || len(saved.Records.CompletedHeadWire) == 0 {
				return deny()
			}
			return saved.Records, nil
		}
		if len(state.SeedCompletion) != 0 {
			records, err := decode(state.SeedCompletion)
			if err != nil {
				return bootstrapstart.ExternalSeedCompletionRecords{}, err
			}
			v.state, v.etag = state, etag
			return records, nil
		}
		if err := guard(check); err != nil {
			return bootstrapstart.ExternalSeedCompletionRecords{}, err
		}
		if etag != v.etag {
			return deny()
		}
		if proposed == nil {
			return bootstrapstart.ExternalSeedCompletionRecords{}, nil
		}
		expected.Records = *proposed
		wire, err := json.Marshal(expected, json.Deterministic(true))
		if err != nil || len(wire) > 256<<10 {
			return deny()
		}
		if _, err := decode(wire); err != nil {
			return bootstrapstart.ExternalSeedCompletionRecords{}, err
		}
		state.SeedCompletion = wire
		dispatch := originalPublicationContext{Context: check, values: guarded}
		observed, writeErr := writeOriginalState(dispatch, readback, clients.objects, v.inputs, state, etag)
		if writeErr == nil {
			v.state, v.etag = state, observed
			return decode(wire)
		}
		// Only the superseded source revision is dropped for independent CAS
		// recovery. Actor, caller guards and the dispatch lifetime remain active.
		current, currentETag, readErr := readOriginalState(readback, clients.objects, v.inputs)
		if readErr != nil || !immutableOriginalState(v.state, current) || current.Reference != state.Reference || len(current.Startup) != 3 || !bytes.Equal(current.Startup[authority.Manifest().SeedSlot], authority.Wire()) {
			return bootstrapstart.ExternalSeedCompletionRecords{}, writeErr
		}
		records, decodeErr := decode(current.SeedCompletion)
		if decodeErr != nil {
			return bootstrapstart.ExternalSeedCompletionRecords{}, writeErr
		}
		v.state, v.etag = current, currentETag
		return records, nil
	}
	return bootstrapstart.EnsureOriginalSeed(guarded, authority, ed25519.PrivateKey(key), checkpoint)
}
