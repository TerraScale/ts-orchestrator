package materialsource

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// Startup siblings are one append after complete publication. Seed completion
// is a separate append after those exact signed siblings have been acknowledged.
func validOriginalStartupState(state originalSourceState, in originalSourceInputs) bool {
	if len(state.Startup) == 0 {
		return len(state.SeedCompletion) == 0
	}
	if len(state.Startup) != 3 || len(in.config.Slots) != 3 || state.Publication == nil || state.Publication.Result == nil || len(state.SeedCompletion) > 256<<10 {
		return false
	}
	record, _, err := originalPublicationRecord(state, in)
	if err != nil {
		return false
	}
	public, err := base64.StdEncoding.Strict().DecodeString(record.Public.LedgerSignerPublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return false
	}
	id, err := trust.KeyID(ed25519.PublicKey(public))
	if err != nil {
		return false
	}
	stripped := state
	stripped.Startup, stripped.SeedCompletion = nil, nil
	sourceWire, err := json.Marshal(stripped, json.Deterministic(true))
	if err != nil {
		return false
	}
	slots := make([]string, len(in.config.Slots))
	for i, slot := range in.config.Slots {
		slots[i] = slot.Name
	}
	var selected bootstrap.DerivedStartupBinding
	for _, slot := range in.config.Slots {
		wire := state.Startup[slot.Name]
		if len(wire) == 0 || len(wire) > bootstrap.MaxManifestBytes {
			return false
		}
		envelope, err := trust.DecodeEnvelope(wire)
		var binding bootstrap.DerivedStartupBinding
		if err != nil || json.Unmarshal(envelope.Payload, &binding, json.RejectUnknownMembers(true)) != nil || binding.SchemaVersion != 2 || binding.GrantSHA256 != in.scope.GrantSHA256 || !validDigest(binding.TemplateSHA256) ||
			binding.SourceSHA256 != state.Reference.SHA256 || binding.OriginalLaunch == nil || binding.OriginalLaunch.InstanceOCID != in.scope.InstanceID || binding.OriginalSource == nil || binding.OriginalSource.StateSHA256 != digestWire(sourceWire) ||
			binding.Link == nil || !bytes.Equal(binding.MaterialRecord, originalInventoryRecordWire(state.OriginalAdmissionInventory)) || !slices.Equal(binding.Manifest.ControllerSlots, slots) || !slices.Contains(slots, binding.Manifest.SeedSlot) || binding.Manifest.OCIRegion != in.config.Region || binding.Manifest.ClusterID != in.config.ClusterID || binding.Manifest.Slot != slot.Name || binding.Manifest.DeploymentID != in.config.DeploymentID || binding.Manifest.Environment != in.config.Environment || string(binding.Manifest.Cell) != in.scope.Cell ||
			len(binding.Manifest.ControllerConfig) == 0 || len(binding.Manifest.ControllerConfig) > bootstrap.MaxControllerConfigBytes || digestWire(binding.Manifest.ControllerConfig) != binding.Manifest.ControllerConfigSHA256 {
			return false
		}
		if _, err := bootstrap.OriginalLaunchCreateKey(*binding.OriginalLaunch); err != nil {
			return false
		}
		if _, err := trust.VerifyHistorical(envelope, bootstrap.DerivedStartupScope(binding.Manifest), trust.Keyring{id: ed25519.PublicKey(public)}, bootstrap.ManifestTrustPolicy()); err != nil {
			return false
		}
		if selected.TemplateSHA256 != "" && (selected.TemplateSHA256 != binding.TemplateSHA256 || selected.Manifest.SeedSlot != binding.Manifest.SeedSlot || *selected.OriginalLaunch != *binding.OriginalLaunch || !sameOriginalLinkEvidence(selected.Link, binding.Link)) {
			return false
		}
		selected = binding
	}
	if len(state.SeedCompletion) == 0 {
		return true
	}
	var checkpoint seedCheckpoint
	return json.Unmarshal(state.SeedCompletion, &checkpoint, json.RejectUnknownMembers(true)) == nil && checkpoint.StartupSHA256 == digestWire(state.Startup[selected.Manifest.SeedSlot]) &&
		checkpoint.SourceSHA256 == state.Reference.SHA256 && checkpoint.GrantSHA256 == in.scope.GrantSHA256 && checkpoint.TemplateSHA256 == selected.TemplateSHA256 && checkpoint.InstanceID == in.scope.InstanceID &&
		len(checkpoint.Records.ReceiptWire) != 0 && len(checkpoint.Records.ResultWire) != 0 && len(checkpoint.Records.CompletedHeadWire) != 0
}

func immutableOriginalStartup(prior, next originalSourceState) bool {
	if len(prior.Startup) == 0 {
		if len(next.Startup) != 0 && (prior.Publication == nil || prior.Publication.Result == nil) {
			return false
		}
	} else {
		before, err := json.Marshal(prior.Startup, json.Deterministic(true))
		after, other := json.Marshal(next.Startup, json.Deterministic(true))
		if err != nil || other != nil || !bytes.Equal(before, after) {
			return false
		}
	}
	if len(prior.SeedCompletion) != 0 {
		return bytes.Equal(prior.SeedCompletion, next.SeedCompletion)
	}
	return len(next.SeedCompletion) == 0 || len(prior.Startup) == 3
}

// OriginalStartup returns existing sealed bootstrap proofs, never a converted
// ordinary founder or a public record treated as authority.
func (v *VerifiedOriginalSourceArchive) OriginalStartup(ctx context.Context, now time.Time) (bootstrap.VerifiedStartupTemplate, bootstrapmaterial.Record, bootstrap.VerifiedStartupLink, error) {
	var template bootstrap.VerifiedStartupTemplate
	var record bootstrapmaterial.Record
	var link bootstrap.VerifiedStartupLink
	if v == nil || ctx == nil || ctx.Err() != nil || now.IsZero() {
		return template, record, link, ErrMaterialSource
	}
	if err := v.PublishRegionalMaterial(ctx, now); err != nil {
		return template, record, link, err
	}
	template, err := v.actor.OriginalStartupTemplate(ctx)
	if err != nil {
		return template, record, link, err
	}
	record, _, err = originalPublicationRecord(v.state, v.inputs)
	if err != nil {
		return bootstrap.VerifiedStartupTemplate{}, bootstrapmaterial.Record{}, link, err
	}
	link, err = v.originalStartupLink(ctx, template, now)
	if err != nil {
		return bootstrap.VerifiedStartupTemplate{}, bootstrapmaterial.Record{}, bootstrap.VerifiedStartupLink{}, err
	}
	if err := v.VerifyCurrent(ctx); err != nil {
		return bootstrap.VerifiedStartupTemplate{}, bootstrapmaterial.Record{}, bootstrap.VerifiedStartupLink{}, err
	}
	return template, cloneRecord(record), link, nil
}

// OriginalStartupReferences returns DATA only, from the exact completed
// publication, after rechecking current original archive custody.
func (v VerifiedOriginalSourceArchive) OriginalStartupReferences(ctx context.Context) ([]bootstrap.SecretReference, error) {
	if v.VerifyCurrent(ctx) != nil || v.state.Publication == nil || v.state.Publication.Result == nil {
		return nil, ErrMaterialSource
	}
	refs := make([]bootstrap.SecretReference, len(v.state.Publication.Result.References))
	for i, ref := range v.state.Publication.Result.References {
		refs[i] = ref.Reference
	}
	return refs, nil
}

func (v *VerifiedOriginalSourceArchive) originalStartupSession(ctx context.Context, template bootstrap.VerifiedStartupTemplate) (originalSourceClients, context.Context, context.Context, func(context.Context) error, error) {
	clients, actorCtx, err := originalClients(ctx, v.actor)
	if err != nil {
		return clients, nil, nil, nil, err
	}
	guard := func(dispatch context.Context) error {
		if err := dispatch.Err(); err != nil {
			return err
		}
		check := originalPublicationCheckpointContext(dispatch, ctx)
		if err := v.actor.Guard(check); err != nil {
			return err
		}
		if err := template.VerifyCurrentContext(check, time.Now()); err != nil {
			return err
		}
		state, etag, err := readOriginalState(check, clients.objects, v.inputs)
		if err != nil || etag != v.etag || !sameOriginalState(state, v.state) {
			return errors.Join(ErrMaterialSource, err)
		}
		return ociclient.LimitAdmission(dispatch, v.inputs.scope.Deadline)
	}
	guarded := ociclient.WithRequestGuard(ociclient.WithAuthority(actorCtx, guard), guard)
	return clients, actorCtx, guarded, guard, nil
}

// BindOriginalStartup pins all three signed renderer outputs in one source CAS
// before returning the independently verified authority for this original slot.
func (v *VerifiedOriginalSourceArchive) BindOriginalStartup(ctx context.Context, template bootstrap.VerifiedStartupTemplate, link bootstrap.VerifiedStartupLink, configs map[string][]byte, now time.Time) (bootstrap.DerivedStartupAuthority, error) {
	deny := func() (bootstrap.DerivedStartupAuthority, error) {
		return bootstrap.DerivedStartupAuthority{}, ErrMaterialSource
	}
	if v == nil || ctx == nil || ctx.Err() != nil || now.IsZero() || !template.IsVerified() || !link.IsVerified() || len(configs) != 3 || v.VerifyCurrent(ctx) != nil {
		return deny()
	}
	_, unlock, err := lockOriginalDirectory(v.directory)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	defer unlock()
	launch, err := template.OriginalLaunch()
	if err != nil || launch.InstanceOCID != v.inputs.scope.InstanceID || template.GrantDigest() != v.inputs.scope.GrantSHA256 || template.PlanDigest() != v.inputs.scope.PlanSHA256 {
		return deny()
	}
	clients, actorCtx, guarded, guard, err := v.originalStartupSession(ctx, template)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	if err := guard(ctx); err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	checkedLink, err := bootstrap.VerifyStartupLink(guarded, template, clients.objects, link.Evidence(), now)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	baseGuard := guard
	guard = func(dispatch context.Context) error {
		if err := baseGuard(dispatch); err != nil {
			return err
		}
		return checkedLink.VerifyCurrent(originalPublicationCheckpointContext(dispatch, ctx), time.Now())
	}
	guarded = ociclient.WithRequestGuard(ociclient.WithAuthority(actorCtx, guard), guard)
	refs, err := v.OriginalStartupReferences(ctx)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	for _, ref := range checkedLink.References() {
		index := slices.IndexFunc(refs, func(existing bootstrap.SecretReference) bool { return existing.TargetFile == ref.TargetFile })
		if index < 0 {
			refs = append(refs, ref)
		} else if ref.TargetFile == "cell.jwt" && v.inputs.config.Cell == "gru" {
			refs[index] = ref
		} else {
			return deny()
		}
	}
	body, _, err := readOriginalVault(guarded, clients, v.state)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	defer clear(body)
	archive, record, err := decodeOriginalCandidate(v.directory, v.inputs, v.state, body)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	defer clearArchive(archive)
	key := archive.Files["founder-ledger.key"]
	if len(key) != ed25519.PrivateKeySize {
		return deny()
	}
	stateWire, err := json.Marshal(v.state, json.Deterministic(true))
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	sourceBinding, err := bootstrap.OriginalSourceBindingFor(stateWire)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	issued := record.IssuedAt
	if template.IssuedAt().After(issued) {
		issued = template.IssuedAt()
	}
	expires := minOriginalTime(template.ExpiresAt(), record.ExpiresAt)
	expires = minOriginalTime(expires, issued.Add(bootstrap.MaxManifestLifetime))
	next := v.state
	next.Startup = make(map[string][]byte, 3)
	for _, slot := range v.inputs.config.Slots {
		config := configs[slot.Name]
		if len(config) == 0 || len(config) > bootstrap.MaxControllerConfigBytes {
			return deny()
		}
		manifest, err := template.ManifestFor(slot.Name, refs)
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		manifest.ControllerConfig, manifest.ControllerConfigSHA256 = bytes.Clone(config), digestWire(config)
		if err := template.ValidateProjection(manifest); err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		binding := bootstrap.DerivedStartupBinding{SchemaVersion: 2, GrantSHA256: template.GrantDigest(), TemplateSHA256: template.TemplateDigest(), SourceSHA256: v.state.Reference.SHA256, MaterialRecord: archive.Files["material.json"], Manifest: manifest, Link: new(checkedLink.Evidence()), OriginalLaunch: new(launch), OriginalSource: new(sourceBinding)}
		payload, err := trust.EncodePayload(binding)
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		envelope, err := trust.Sign(payload, bootstrap.DerivedStartupScope(manifest), issued, expires, ed25519.PrivateKey(key))
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		if prior := v.state.Startup[slot.Name]; len(prior) != 0 && !bytes.Equal(prior, wire) {
			return deny()
		}
		next.Startup[slot.Name] = wire
	}
	if err := checkedLink.VerifyCurrent(ctx, time.Now()); err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	if len(v.state.Startup) == 0 {
		etag, err := writeOriginalState(guarded, actorCtx, clients.objects, v.inputs, next, v.etag)
		if err != nil {
			return bootstrap.DerivedStartupAuthority{}, err
		}
		v.state, v.etag = next, etag
	}
	wire := v.state.Startup[template.Template().SeedSlot]
	return bootstrap.VerifyDerivedStartupAuthority(guarded, template, clients.objects, wire, time.Now())
}

func originalInventoryRecordWire(wire []byte) []byte {
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return nil
	}
	var inventory bootstrap.RegionalSourceInventory
	if json.Unmarshal(envelope.Payload, &inventory, json.RejectUnknownMembers(true)) != nil {
		return nil
	}
	return inventory.MaterialRecord
}

func sameOriginalLinkEvidence(a, b *bootstrap.RegionalLinkEvidence) bool {
	x, err := json.Marshal(a, json.Deterministic(true))
	y, other := json.Marshal(b, json.Deterministic(true))
	return err == nil && other == nil && bytes.Equal(x, y)
}
