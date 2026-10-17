package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
)

const (
	nativeHistoryBucket   = "TS_NATIVE_RELEASES"
	nativeGoodLimit       = 10
	nativeHistoryMaxBytes = 768 << 10
	nativePayloadOverhead = 4096
	nativeBlobBytes       = 256 << 10
	nativePrepareKind     = "native.release.prepare"
	nativeObserveKind     = "native.release.observe"
)

// Provenance retains public signed material, never resolved Vault values.
type nativeProfileProvenance struct {
	Spec          []byte `json:"spec,omitempty"`
	Manifest      []byte `json:"manifest,omitempty"`
	Config        []byte `json:"config,omitempty"`
	MaterialChain []byte `json:"material_chain,omitempty"`
	Identity      []byte `json:"identity,omitempty"`
}

type nativeReleaseBinding struct {
	Intent        delivery.Intent         `json:"intent"`
	Fingerprint   string                  `json:"fingerprint"`
	Artifact      delivery.ArtifactRecord `json:"artifact"`
	Profile       WorkloadProfile         `json:"-"`
	ProfileDigest string                  `json:"profile_digest"`
	Provenance    nativeProfileProvenance `json:"-"`
	ProfileRecord string                  `json:"profile_record"`
	Deadline      time.Time               `json:"deadline,omitzero"`
}

type nativeGoodRelease struct {
	Binding nativeReleaseBinding `json:"binding"`
	Nodes   []string             `json:"nodes"`
	GoodAt  time.Time            `json:"good_at"`
}

// Pending and Recovery are exact operation bindings, not a digest lookup API.
type nativeReleaseHistory struct {
	Schema   int                   `json:"schema"`
	Good     []nativeGoodRelease   `json:"good,omitempty"`
	Pending  *nativeReleaseBinding `json:"pending,omitempty"`
	Previous *nativeGoodRelease    `json:"previous,omitempty"`
	Recovery *nativeReleaseBinding `json:"recovery,omitempty"`
	Rejected string                `json:"rejected,omitempty"`
}

// The role CAS contains references; immutable records share full signed proof
// across artifacts and keep a maximum-length material chain out of one reply.
// shortcut: proof metadata is append-only; add fenced reference collection before long-lived fleet use.
type nativeStoredProfile struct {
	Schema     int             `json:"schema"`
	Profile    WorkloadProfile `json:"profile"`
	Provenance struct {
		Spec          []string `json:"spec,omitempty"`
		Manifest      []string `json:"manifest,omitempty"`
		Config        []string `json:"config,omitempty"`
		MaterialChain []string `json:"material_chain,omitempty"`
		Identity      []string `json:"identity,omitempty"`
	} `json:"provenance"`
}

func nativeBindings(state *nativeReleaseHistory) []*nativeReleaseBinding {
	bindings := []*nativeReleaseBinding{state.Pending, state.Recovery}
	if state.Previous != nil {
		bindings = append(bindings, &state.Previous.Binding)
	}
	for i := range state.Good {
		bindings = append(bindings, &state.Good[i].Binding)
	}
	return slices.DeleteFunc(bindings, func(b *nativeReleaseBinding) bool { return b == nil })
}

func nativeValueFits(wire []byte, maxPayload int64) bool {
	return len(wire) <= nativeHistoryMaxBytes && int64((len(wire)+2)/3*4+nativePayloadOverhead) <= maxPayload
}

func encodeNativeHistory(state nativeReleaseHistory, maxPayload int64) ([]byte, map[string][]byte, error) {
	state.Good = slices.Clone(state.Good)
	if state.Pending != nil {
		state.Pending = new(*state.Pending)
	}
	if state.Recovery != nil {
		state.Recovery = new(*state.Recovery)
	}
	if state.Previous != nil {
		state.Previous = new(*state.Previous)
	}
	records := map[string][]byte{}
	for _, b := range nativeBindings(&state) {
		reference, stored, err := encodeNativeProfile(b.Profile, b.Provenance, maxPayload)
		if err != nil {
			return nil, nil, err
		}
		b.ProfileRecord = reference
		maps.Copy(records, stored)
	}
	wire, err := json.Marshal(state, json.Deterministic(true))
	if err != nil {
		return nil, nil, err
	}
	if !nativeValueFits(wire, maxPayload) {
		return nil, nil, fmt.Errorf("%w: native history index exceeds broker payload bound", delivery.ErrInvalid)
	}
	return wire, records, nil
}

func encodeNativeProfile(profile WorkloadProfile, provenance nativeProfileProvenance, maxPayload int64) (string, map[string][]byte, error) {
	records := map[string][]byte{}
	stored := nativeStoredProfile{Schema: 1, Profile: profile}
	for _, field := range []struct {
		data []byte
		refs *[]string
		max  int
	}{
		{provenance.Spec, &stored.Provenance.Spec, cellspec.MaxSignedBytes},
		{provenance.Manifest, &stored.Provenance.Manifest, bootstrapstart.MaxControllerManifestMetadataBytes},
		{provenance.Config, &stored.Provenance.Config, bootstrap.MaxControllerConfigBytes},
		{provenance.MaterialChain, &stored.Provenance.MaterialChain, bootstrap.MaxMaterialGenerations * (bootstrap.MaxMaterialGenerationBytes + 16<<10)},
		{provenance.Identity, &stored.Provenance.Identity, bootstrapstart.MaxAcceptedIdentityBytes},
	} {
		if len(field.data) > field.max {
			return "", nil, fmt.Errorf("%w: native provenance exceeds its signed input bound", delivery.ErrInvalid)
		}
		for offset := 0; offset < len(field.data); offset += nativeBlobBytes {
			chunk := field.data[offset:min(offset+nativeBlobBytes, len(field.data))]
			if !nativeValueFits(chunk, maxPayload) {
				return "", nil, fmt.Errorf("%w: native provenance chunk exceeds broker payload bound", delivery.ErrInvalid)
			}
			key := "blob." + controllerSHA256(chunk)
			records[key] = chunk
			*field.refs = append(*field.refs, key)
		}
	}
	wire, err := json.Marshal(stored, json.Deterministic(true))
	if err != nil {
		return "", nil, err
	}
	if !nativeValueFits(wire, maxPayload) {
		return "", nil, fmt.Errorf("%w: native profile record exceeds broker payload bound", delivery.ErrInvalid)
	}
	reference := "profile." + controllerSHA256(wire)
	records[reference] = wire
	return reference, records, nil
}

// Only authoritative reads retry through a short leader election; no effect
// or ambiguous publish is retried here.
func nativeLeaderGet(ctx context.Context, js jetstream.JetStream, bucket, key string) (*nats.RawStreamMsg, error) {
	legacy, err := js.Conn().JetStream()
	if err != nil {
		return nil, err
	}
	return nativeReadRetry(ctx, func(attempt context.Context) (*nats.RawStreamMsg, error) {
		return legacy.GetLastMsg("KV_"+bucket, "$KV."+bucket+"."+key, nats.Context(attempt))
	})
}

func nativeReadRetry(ctx context.Context, read func(context.Context) (*nats.RawStreamMsg, error)) (*nats.RawStreamMsg, error) {
	readCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for {
		attempt, done := context.WithTimeout(readCtx, 500*time.Millisecond)
		msg, err := read(attempt)
		done()
		api, isAPI := errors.AsType[*nats.APIError](err)
		retry := errors.Is(err, nats.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrJetStreamNotEnabled) || isAPI && api.ErrorCode == nats.JSErrCodeJetStreamNotAvailable
		if err == nil || !retry || readCtx.Err() != nil {
			return msg, err
		}
		select {
		case <-readCtx.Done():
			return nil, err
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (h *nativeHistory) immutable(ctx context.Context, key string) ([]byte, error) {
	kind, digest, ok := strings.Cut(key, ".")
	if !ok || kind != "blob" && kind != "profile" || len(digest) != 64 || !lowerHexString(digest) {
		return nil, errors.New("invalid native immutable record reference")
	}
	msg, err := nativeLeaderGet(ctx, h.js, nativeHistoryBucket, key)
	if err != nil {
		return nil, err
	}
	if msg.Subject != "$KV."+nativeHistoryBucket+"."+key || msg.Header.Get("KV-Operation") != "" || msg.Header.Get(jetstream.MarkerReasonHeader) != "" || !nativeValueFits(msg.Data, h.js.Conn().MaxPayload()) || controllerSHA256(msg.Data) != digest {
		return nil, errors.New("invalid native immutable record")
	}
	return msg.Data, nil
}

func (h *nativeHistory) hydrate(ctx context.Context, b *nativeReleaseBinding) error {
	profile, provenance, err := h.readProfile(ctx, b.ProfileRecord)
	if err != nil {
		return err
	}
	b.Profile, b.Provenance = profile, provenance
	return nil
}

func (h *nativeHistory) readProfile(ctx context.Context, reference string) (WorkloadProfile, nativeProfileProvenance, error) {
	wire, err := h.immutable(ctx, reference)
	if err != nil {
		return WorkloadProfile{}, nativeProfileProvenance{}, err
	}
	var stored nativeStoredProfile
	if err := json.Unmarshal(wire, &stored, json.RejectUnknownMembers(true)); err != nil {
		return WorkloadProfile{}, nativeProfileProvenance{}, err
	}
	if stored.Schema != 1 {
		return WorkloadProfile{}, nativeProfileProvenance{}, errors.New("invalid native profile schema")
	}
	profile := stored.Profile
	var provenance nativeProfileProvenance
	for _, field := range []struct {
		refs []string
		data *[]byte
		max  int
	}{
		{stored.Provenance.Spec, &provenance.Spec, cellspec.MaxSignedBytes},
		{stored.Provenance.Manifest, &provenance.Manifest, bootstrapstart.MaxControllerManifestMetadataBytes},
		{stored.Provenance.Config, &provenance.Config, bootstrap.MaxControllerConfigBytes},
		{stored.Provenance.MaterialChain, &provenance.MaterialChain, bootstrap.MaxMaterialGenerations * (bootstrap.MaxMaterialGenerationBytes + 16<<10)},
		{stored.Provenance.Identity, &provenance.Identity, bootstrapstart.MaxAcceptedIdentityBytes},
	} {
		if len(field.refs) > (field.max+nativeBlobBytes-1)/nativeBlobBytes {
			return WorkloadProfile{}, nativeProfileProvenance{}, errors.New("native provenance has too many chunks")
		}
		for i, key := range field.refs {
			if !strings.HasPrefix(key, "blob.") {
				return WorkloadProfile{}, nativeProfileProvenance{}, errors.New("invalid native provenance chunk reference")
			}
			chunk, err := h.immutable(ctx, key)
			if err != nil {
				return WorkloadProfile{}, nativeProfileProvenance{}, err
			}
			if len(chunk) == 0 || len(chunk) > nativeBlobBytes || i < len(field.refs)-1 && len(chunk) != nativeBlobBytes || len(*field.data)+len(chunk) > field.max {
				return WorkloadProfile{}, nativeProfileProvenance{}, errors.New("invalid native provenance chunk size")
			}
			*field.data = append(*field.data, chunk...)
		}
	}
	return profile, provenance, nil
}

type nativeHistory struct {
	effects    sync.Mutex
	gates      sync.Mutex
	fences     *releaseFence
	canary     canaryGate
	kv         jetstream.KeyValue
	js         jetstream.JetStream
	services   *specRegistry
	deliveries *delivery.Service
	hosts      *host.Controller
	fencer     authority.Fencer
	cfg        Config
}

func openNativeHistory(ctx context.Context, js jetstream.JetStream, replicas int) (jetstream.KeyValue, error) {
	// Leader GET replies base64-encode values inside JSON, including metadata.
	maxValue := min(int64(nativeHistoryMaxBytes), (js.Conn().MaxPayload()-nativePayloadOverhead)*3/4)
	if maxValue <= 0 {
		return nil, errors.New("broker payload is too small for native history")
	}
	return js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: nativeHistoryBucket,
		Storage: jetstream.FileStorage, Replicas: replicas, History: 1, MaxValueSize: int32(maxValue)})
}

func nativeProfileDigest(profile WorkloadProfile) string {
	wire, _ := json.Marshal(profile, json.Deterministic(true))
	return controllerSHA256(wire)
}

func cloneNativeProfile(profile WorkloadProfile) WorkloadProfile {
	profile.Args, profile.Env, profile.Secrets = slices.Clone(profile.Args), maps.Clone(profile.Env), maps.Clone(profile.Secrets)
	return profile
}

func nativeBinding(intent delivery.Intent, artifact delivery.ArtifactRecord, profile WorkloadProfile,
	provenance nativeProfileProvenance,
) (nativeReleaseBinding, error) {
	fingerprint, err := intent.Fingerprint()
	if err != nil {
		return nativeReleaseBinding{}, err
	}
	return nativeReleaseBinding{Intent: intent, Fingerprint: fingerprint, Artifact: artifact,
		Profile: cloneNativeProfile(profile), ProfileDigest: nativeProfileDigest(profile), Provenance: provenance}, nil
}

// load uses the stream leader; a follower's direct KV read cannot authorize effects.
func (h *nativeHistory) load(ctx context.Context, role string) (nativeReleaseHistory, uint64, error) {
	subject := "$KV." + nativeHistoryBucket + "." + role
	msg, err := nativeLeaderGet(ctx, h.js, nativeHistoryBucket, role)
	if errors.Is(err, nats.ErrMsgNotFound) {
		return nativeReleaseHistory{Schema: 1}, 0, nil
	}
	if err != nil {
		return nativeReleaseHistory{}, 0, err
	}
	if msg.Subject != subject || msg.Sequence == 0 || msg.Header.Get("KV-Operation") != "" || msg.Header.Get(jetstream.MarkerReasonHeader) != "" {
		return nativeReleaseHistory{}, 0, errors.New("invalid native release history marker")
	}
	if !nativeValueFits(msg.Data, h.js.Conn().MaxPayload()) {
		return nativeReleaseHistory{}, 0, errors.New("native history exceeds broker payload bound")
	}
	var state nativeReleaseHistory
	if err := json.Unmarshal(msg.Data, &state, json.RejectUnknownMembers(true)); err != nil {
		return state, 0, err
	}
	if state.Schema != 1 || len(state.Good) > nativeGoodLimit {
		return state, 0, errors.New("invalid native release history")
	}
	bindings := []*nativeReleaseBinding{state.Pending, state.Recovery}
	if state.Previous != nil {
		bindings = append(bindings, &state.Previous.Binding)
	}
	for i := range state.Good {
		good := &state.Good[i]
		if good.GoodAt.IsZero() || good.GoodAt.After(time.Now()) || len(good.Nodes) == 0 || !slices.IsSorted(good.Nodes) || len(slices.Compact(slices.Clone(good.Nodes))) != len(good.Nodes) {
			return state, 0, errors.New("invalid native good observation")
		}
		bindings = append(bindings, &good.Binding)
	}
	profiles := map[string]nativeReleaseBinding{}
	for _, b := range bindings {
		if b == nil {
			continue
		}
		if saved, ok := profiles[b.ProfileRecord]; ok {
			b.Profile, b.Provenance = cloneNativeProfile(saved.Profile), saved.Provenance
		} else {
			if err := h.hydrate(ctx, b); err != nil {
				return state, 0, err
			}
			profiles[b.ProfileRecord] = *b
		}
		fp, err := b.Intent.Fingerprint()
		if err != nil || fp != b.Fingerprint || b.Intent.Role != role || b.Intent.Cell != h.services.cell ||
			b.Intent.Source != b.Artifact.Source || b.Intent.ManifestDigest != b.Artifact.ManifestDigest ||
			b.Intent.ArtifactDigest != b.Artifact.Digest || b.Intent.Cell != b.Artifact.Cell || b.Intent.Role != b.Artifact.Role || b.Intent.Environment != b.Artifact.Environment ||
			b.ProfileDigest != nativeProfileDigest(b.Profile) || b.Intent.ConfigDigest != delivery.ConfigDigestOf(b.Profile.Args, b.Profile.Env, b.Profile.Secrets) {
			return state, 0, errors.New("invalid native intent/profile binding")
		}
	}
	return state, msg.Sequence, nil
}

func (h *nativeHistory) save(ctx context.Context, epoch uint64, role string, state nativeReleaseHistory, revision uint64) error {
	if err := h.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	wire, records, err := encodeNativeHistory(state, h.js.Conn().MaxPayload())
	if err != nil {
		return err
	}
	// Every newly selected reference touches object metadata before its CAS.
	for _, b := range []*nativeReleaseBinding{state.Pending, state.Recovery} {
		if b != nil {
			if err := h.deliveries.RetainArtifact(ctx, b.Artifact); err != nil {
				return err
			}
		}
	}
	if state.Previous != nil {
		if err := h.deliveries.RetainArtifact(ctx, state.Previous.Binding.Artifact); err != nil {
			return err
		}
	}
	if err := h.writeProfileRecords(ctx, epoch, records); err != nil {
		return err
	}
	if err := h.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	if revision == 0 {
		_, err = h.kv.Create(ctx, role, wire)
	} else {
		_, err = h.kv.Update(ctx, role, wire, revision)
	}
	return err
}

func (h *nativeHistory) writeProfileRecords(ctx context.Context, epoch uint64, records map[string][]byte) error {
	for key, value := range records {
		if err := h.fencer.Guard(ctx, epoch); err != nil {
			return err
		}
		// An existing content address must contain exactly the same bytes.
		if _, err := h.kv.Create(ctx, key, value); errors.Is(err, jetstream.ErrKeyExists) {
			held, err := h.immutable(ctx, key)
			if err != nil {
				return err
			}
			if !bytes.Equal(held, value) {
				return errors.New("native immutable record content changed")
			}
		} else if err != nil {
			return err
		}
	}
	return nil
}

func (h *nativeHistory) currentProvenance(ctx context.Context, role string, profile WorkloadProfile) (nativeProfileProvenance, error) {
	r := h.services
	if r.roots == nil {
		return nativeProfileProvenance{}, errors.New("native release requires signed workload profile provenance")
	}
	if r.kv != nil {
		msg, err := nativeLeaderGet(ctx, h.js, cellSpecBucket, cellSpecKey)
		if err != nil && !errors.Is(err, nats.ErrMsgNotFound) {
			return nativeProfileProvenance{}, err
		}
		if err == nil {
			if msg.Header.Get("KV-Operation") != "" {
				return nativeProfileProvenance{}, errors.New("cell spec was removed")
			}
			verified, err := r.verify(msg.Data, nil)
			if err != nil {
				return nativeProfileProvenance{}, err
			}
			for _, service := range verified.Spec.Services {
				if service.Role == role {
					if nativeProfileDigest(service.Profile) != nativeProfileDigest(profile) {
						return nativeProfileProvenance{}, errors.New("profile changed during native release preparation")
					}
					return nativeProfileProvenance{Spec: bytes.Clone(msg.Data)}, nil
				}
			}
		}
	}
	initial, err := bootstrapstart.NewMarkerStore().ReadInitialFormation()
	if err != nil {
		return nativeProfileProvenance{}, err
	}
	manifest, err := readInstalledControllerFile(controllerConfigDirectory, controllerManifestFilename, 0, 0, 0o644, bootstrapstart.MaxControllerManifestMetadataBytes)
	if err != nil || controllerSHA256(manifest) != initial.ManifestSHA256 {
		return nativeProfileProvenance{}, errors.New("native profile manifest is not the accepted install")
	}
	config, err := h.cfg.signedWire()
	if err != nil {
		return nativeProfileProvenance{}, err
	}
	uid, gid, err := controllerServiceIdentity()
	if err != nil {
		return nativeProfileProvenance{}, err
	}
	accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return nativeProfileProvenance{}, err
	}
	p := nativeProfileProvenance{Manifest: manifest, Config: config}
	p.Identity, err = bootstrapstart.EncodeAcceptedIdentity(accepted)
	if err != nil {
		return nativeProfileProvenance{}, err
	}
	p.MaterialChain, err = readInstalledControllerFile(bootstrapstart.MaterialDirectory, bootstrapstart.MaterialGenerationsFile,
		uid, gid, 0o600, bootstrap.MaxMaterialGenerations*(bootstrap.MaxMaterialGenerationBytes+16<<10))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nativeProfileProvenance{}, err
	}
	if err := h.verifyProfile(role, profile, p); err != nil {
		return nativeProfileProvenance{}, err
	}
	return p, nil
}

func (h *nativeHistory) verifyProfile(role string, profile WorkloadProfile, p nativeProfileProvenance) error {
	r := h.services
	if r.roots == nil {
		return errors.New("native profile trust roots are unavailable")
	}
	var signed WorkloadProfile
	if len(p.Spec) != 0 {
		if len(p.Manifest)+len(p.Config)+len(p.MaterialChain)+len(p.Identity) != 0 {
			return errors.New("ambiguous native profile provenance")
		}
		verified, err := cellspec.VerifyHistorical(p.Spec, r.roots.current(), r.identity)
		if err != nil {
			return err
		}
		found := false
		for _, s := range verified.Spec.Services {
			if s.Role == role {
				signed, found = s.Profile, true
			}
		}
		if !found {
			return errors.New("signed cell spec does not contain the retained role")
		}
	} else {
		envelope, err := trust.DecodeEnvelope(p.Manifest)
		if err != nil {
			return err
		}
		manifest, err := bootstrap.ManifestPayload(envelope.Payload)
		if err != nil {
			return err
		}
		if manifest.DeploymentID != r.identity.DeploymentID || strings.ToLower(string(manifest.Cell)) != r.identity.Cell || manifest.Environment != r.identity.Environment {
			return errors.New("retained controller manifest belongs to another deployment")
		}
		identity, err := bootstrapstart.DecodeAcceptedIdentity(p.Identity)
		if err != nil {
			return err
		}
		if identity.DeploymentID != manifest.DeploymentID || identity.Cell != string(manifest.Cell) || identity.Slot != manifest.Slot {
			return errors.New("retained accepted identity belongs to another controller")
		}
		acceptance, err := identity.AcceptanceSHA256()
		if err != nil {
			return err
		}
		_, err = bootstrap.VerifyHistoricalManifest(envelope, r.roots.current(), bootstrap.ManifestExpectation{
			DeploymentID: r.identity.DeploymentID, Cell: manifest.Cell, Environment: r.identity.Environment,
			ClusterID: manifest.ClusterID, Slot: manifest.Slot, ImageOCID: manifest.ImageOCID,
			StorageDomain: manifest.StorageDomain, ControllerSlots: manifest.ControllerSlots}, bootstrap.ManifestTrustPolicy())
		if err != nil {
			return err
		}
		want := manifest.ControllerConfigSHA256
		if len(p.MaterialChain) != 0 {
			chain, err := bootstrap.DecodeMaterialGenerationChain(p.MaterialChain)
			if err != nil {
				return err
			}
			verified, err := bootstrap.VerifyAdoptedMaterialGenerationChain(chain, r.roots.current(), bootstrap.MaterialGenerationExpectation{
				DeploymentID: manifest.DeploymentID, Environment: manifest.Environment, ClusterID: manifest.ClusterID,
				Cell: manifest.Cell, ControllerSlots: manifest.ControllerSlots})
			if err != nil {
				return err
			}
			for _, pin := range verified[len(verified)-1].Generation().ControllerConfigs {
				if pin.Slot == manifest.Slot {
					if pin.AcceptanceSHA256 != acceptance {
						return errors.New("retained material/config acceptance mismatch")
					}
					want = pin.SHA256
				}
			}
		}
		cfg, err := ValidateLoadedControllerConfig(manifest, p.Config, want, "")
		if err != nil {
			return err
		}
		signed = cfg.Controller.Workloads[role]
	}
	if nativeProfileDigest(signed) != nativeProfileDigest(profile) {
		return errors.New("retained profile differs from signed provenance")
	}
	current := r.profiles()
	approved, ok := current[role]
	if !ok {
		return errors.New("retained native role is no longer approved")
	}
	if role == terrabase.Role && approved.Env[terrabase.EnvPeers] != profile.Env[terrabase.EnvPeers] {
		return errors.New("retained TerraBase membership differs from current authority")
	}
	current[role] = profile
	return validateWorkloadProfiles(r.cell, current)
}

// nativeReady requires one exact current-session proof per committed expected
// node. HostStatus.Verified certifies the controller's session rechecks.
func nativeReady(statuses []host.HostStatus, desired []host.Desired, intent delivery.Intent, now time.Time) ([]string, error) {
	expected := map[string]host.Desired{}
	for _, d := range desired {
		if d.Cell != intent.Cell || d.Role != intent.Role || d.Environment != intent.Environment || d.Withdrawn {
			continue
		}
		if _, duplicate := expected[d.Node]; duplicate {
			return nil, errors.New("duplicate expected native node")
		}
		if d.Digest != intent.ArtifactDigest || d.Generation != intent.Generation && workload.ReleaseOf(d.Generation) != intent.Generation ||
			delivery.ConfigDigestOf(d.Args, d.Env, d.Secrets) != intent.ConfigDigest {
			return nil, nil
		}
		expected[d.Node] = d
	}
	if len(expected) != intent.DesiredReplicas || len(expected) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	for _, status := range statuses {
		r := status.Registration
		d, ok := expected[r.Node]
		if !ok {
			continue
		}
		if seen[r.Node] {
			return nil, errors.New("duplicate native host status")
		}
		seen[r.Node] = true
		if !status.Verified || status.Retired || !status.SessionExpiresAt.After(now) || r.Cell != intent.Cell || r.Environment != intent.Environment || !slices.Contains(r.Roles, intent.Role) {
			return nil, nil
		}
		matches := 0
		for _, report := range status.Reports {
			if report.Role != intent.Role {
				continue
			}
			matches++
			if matches > 1 {
				return nil, errors.New("duplicate native report")
			}
			if report.Cell != intent.Cell || report.Node != d.Node || report.Environment != intent.Environment || report.Digest != d.Digest || report.Generation != d.Generation ||
				report.SessionID == "" || report.Epoch == 0 || report.ObservedAt.IsZero() || report.ObservedAt.After(now) || now.Sub(report.ObservedAt) >= host.ReportMaxAge {
				return nil, nil
			}
			if report.State == "failed" {
				return nil, fmt.Errorf("%w: %s replica %s failed: %s", errBadRelease, intent.Role, report.Node, report.Error)
			}
			if report.State != "running" {
				return nil, nil
			}
		}
		if matches != 1 {
			return nil, nil
		}
	}
	if len(seen) != len(expected) {
		return nil, nil
	}
	return slices.Sorted(maps.Keys(expected)), nil
}

func (h *nativeHistory) ready(ctx context.Context, intent delivery.Intent) ([]string, error) {
	proofs, err := h.proofs(ctx, intent)
	return slices.Sorted(maps.Keys(proofs)), err
}

func (h *nativeHistory) proofs(ctx context.Context, intent delivery.Intent) (map[string]host.Report, error) {
	if h.hosts == nil {
		return nil, errors.New("native release observer is not ready")
	}
	return observeNativeProofs(ctx, h.deliveries, h.hosts, intent)
}

type nativeStatusReader interface {
	ListDesired(context.Context, string) ([]host.Desired, error)
	ListHosts(context.Context) ([]host.HostStatus, error)
}

func observeNativeProofs(ctx context.Context, deliveries *delivery.Service, hosts nativeStatusReader, intent delivery.Intent) (map[string]host.Report, error) {
	if hosts == nil {
		return nil, errors.New("native release observer is not ready")
	}
	receipt, err := deliveries.StatusFor(ctx, intent)
	if errors.Is(err, delivery.ErrPending) {
		return nil, nil
	}
	if err != nil || receipt.Status != "accepted" {
		return nil, err
	}
	desired, err := hosts.ListDesired(ctx, intent.Role)
	if err != nil {
		return nil, err
	}
	statuses, err := hosts.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	nodes, err := nativeReady(statuses, desired, intent, time.Now())
	if err != nil || len(nodes) == 0 {
		return nil, err
	}
	confirmed, err := hosts.ListDesired(ctx, intent.Role)
	if err != nil {
		return nil, err
	}
	left, _ := json.Marshal(desired, json.Deterministic(true))
	right, _ := json.Marshal(confirmed, json.Deterministic(true))
	if !bytes.Equal(left, right) {
		return nil, errors.New("native desired changed during good observation")
	}
	proofs := make(map[string]host.Report, len(nodes))
	for _, status := range statuses {
		if slices.Contains(nodes, status.Registration.Node) {
			for _, report := range status.Reports {
				if report.Role == intent.Role {
					proofs[report.Node] = report
				}
			}
		}
	}
	return proofs, nil
}

// A second current-session report must span the deployer's fixed poll, so
// a process that reports running once and immediately exits cannot be good.
func nativeProofsAdvance(first, second map[string]host.Report) bool {
	if len(first) == 0 || len(first) != len(second) {
		return false
	}
	for node, old := range first {
		next, ok := second[node]
		if !ok || next.SessionID != old.SessionID || next.Epoch != old.Epoch || next.Generation != old.Generation || next.Digest != old.Digest || next.ObservedAt.Sub(old.ObservedAt) < time.Second {
			return false
		}
	}
	return true
}

func addNativeGood(state *nativeReleaseHistory, good nativeGoodRelease) {
	state.Good = slices.DeleteFunc(state.Good, func(old nativeGoodRelease) bool {
		return old.Binding.Artifact.Digest == good.Binding.Artifact.Digest && old.Binding.ProfileDigest == good.Binding.ProfileDigest
	})
	state.Good = append([]nativeGoodRelease{good}, state.Good...)
	state.Good = state.Good[:min(len(state.Good), nativeGoodLimit)]
}

func (h *nativeHistory) observeBinding(ctx context.Context, state *nativeReleaseHistory, binding nativeReleaseBinding) (bool, error) {
	if err := h.verifyProfile(binding.Intent.Role, binding.Profile, binding.Provenance); err != nil {
		return false, err
	}
	if err := h.refuseKnownBad(ctx, binding.Artifact); err != nil {
		return false, err
	}
	if bad, err := h.badProfile(ctx, binding); err != nil {
		return false, err
	} else if bad {
		return false, errors.New("native artifact/profile is known bad")
	}
	first, err := h.proofs(ctx, binding.Intent)
	if err != nil || len(first) == 0 {
		return false, err
	}
	nodes := slices.Sorted(maps.Keys(first))
	if len(state.Good) != 0 && state.Good[0].Binding.Fingerprint == binding.Fingerprint && slices.Equal(state.Good[0].Nodes, nodes) {
		return false, nil
	}
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-time.After(time.Second):
	}
	second, err := h.proofs(ctx, binding.Intent)
	if err != nil || !nativeProofsAdvance(first, second) {
		return false, err
	}
	if err := h.deliveries.RetainArtifact(ctx, binding.Artifact); err != nil {
		return false, err
	}
	addNativeGood(state, nativeGoodRelease{Binding: binding, Nodes: nodes, GoodAt: time.Now().UTC()})
	return true, nil
}

// baseline initializes history from an accepted exact signed serving release;
// an artifact digest inferred from a running report is never sufficient.
func (h *nativeHistory) baseline(ctx context.Context, role string, state *nativeReleaseHistory) (*nativeGoodRelease, error) {
	desired, err := h.hosts.ListDesired(ctx, role)
	if err != nil {
		return nil, err
	}
	active := slices.DeleteFunc(slices.Clone(desired), func(d host.Desired) bool { return d.Withdrawn })
	if len(active) == 0 {
		return nil, nil
	}
	for _, good := range state.Good {
		if nodes, err := h.ready(ctx, good.Binding.Intent); err != nil {
			return nil, err
		} else if len(nodes) != 0 {
			if err := h.refuseKnownBad(ctx, good.Binding.Artifact); err != nil {
				return nil, err
			}
			if err := h.verifyProfile(role, good.Binding.Profile, good.Binding.Provenance); err != nil {
				return nil, err
			}
			return &good, nil
		}
	}
	profile, ok := h.services.profiles()[role]
	if !ok {
		return nil, errors.New("serving native baseline has no signed profile")
	}
	provenance, err := h.currentProvenance(ctx, role, profile)
	if err != nil {
		return nil, err
	}
	first := active[0]
	generation := first.Generation
	if release := workload.ReleaseOf(generation); release > 0 {
		generation = release
	}
	query := delivery.Intent{Cell: first.Cell, Role: role, Environment: first.Environment, Generation: generation,
		ArtifactDigest: first.Digest, ConfigDigest: delivery.ConfigDigestOf(profile.Args, profile.Env, profile.Secrets)}
	intent, err := h.deliveries.AcceptedIntent(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("serving native baseline is not an exact accepted signed profile: %w", err)
	}
	artifact, err := h.deliveries.ResolveAdmittedArtifact(ctx, first.Digest, role, first.Environment)
	if err != nil {
		return nil, err
	}
	binding, err := nativeBinding(intent, artifact, profile, provenance)
	if err != nil {
		return nil, err
	}
	if h.fences != nil {
		if !h.gates.TryLock() {
			return nil, delivery.ErrConflict
		}
		defer h.gates.Unlock()
		if err := h.fences.sequence(ctx, intent, h.selectedCanaryGate(*state, binding)); err != nil {
			return nil, err
		}
	}
	changed, err := h.observeBinding(ctx, state, binding)
	if err != nil {
		return nil, err
	}
	if !changed {
		return nil, errors.New("serving native baseline lacks complete fresh verified proofs")
	}
	return &state.Good[0], nil
}

type nativePrepareRequest struct {
	Intent     delivery.Intent `json:"intent"`
	RecoveryOf string          `json:"recovery_of,omitempty"`
	ResumeOf   string          `json:"resume_of,omitempty"`
	Deadline   time.Time       `json:"deadline,omitzero"`
}

type nativePrepareReply struct {
	Intent   delivery.Intent       `json:"intent"`
	Previous *nativeRollbackTarget `json:"previous,omitempty"`
	previous *nativeGoodRelease
	Ready    bool   `json:"ready,omitzero"`
	Error    string `json:"error,omitempty"`
}

// Only the recovery identity crosses RPC; retained signed config stays private.
type nativeRollbackTarget struct {
	Artifact     delivery.ArtifactRecord `json:"artifact"`
	ConfigDigest string                  `json:"config_digest"`
	Replicas     int                     `json:"replicas"`
}

func encodeNativeReply(reply nativePrepareReply, maxPayload int64) ([]byte, error) {
	wire, err := json.Marshal(reply)
	if err != nil {
		return nil, err
	}
	if len(wire) > maxRegistrationBytes || int64(len(wire)+nativePayloadOverhead) > maxPayload {
		return nil, errors.New("native release reply exceeds broker payload bound")
	}
	return wire, nil
}

func nativeTarget(good *nativeGoodRelease) *nativeRollbackTarget {
	if good == nil {
		return nil
	}
	return &nativeRollbackTarget{Artifact: good.Binding.Artifact, ConfigDigest: good.Binding.Intent.ConfigDigest, Replicas: good.Binding.Intent.DesiredReplicas}
}

func nativeForwardAllowed(state nativeReleaseHistory, binding nativeReleaseBinding) error {
	if slices.ContainsFunc(state.Good, func(g nativeGoodRelease) bool { return g.Binding.Fingerprint == binding.Fingerprint }) {
		return nil
	}
	if state.Recovery != nil && state.Recovery.Fingerprint == binding.Fingerprint && binding.Deadline.IsZero() {
		return nil
	}
	if binding.Deadline.IsZero() || !time.Now().Before(binding.Deadline) {
		return fmt.Errorf("%w: native selected release deadline expired: %w", delivery.ErrInvalid, context.DeadlineExceeded)
	}
	return nil
}

// Reserve both promotion and recovery index growth before selecting forward
// work. Proof bytes are immutable and are never duplicated by either phase.
func (h *nativeHistory) checkForwardCapacity(state nativeReleaseHistory) error {
	if state.Pending == nil || state.Recovery != nil {
		return nil
	}
	promoted := state
	promoted.Good = slices.Clone(state.Good)
	nodes := make([]string, state.Pending.Intent.DesiredReplicas)
	for i := range nodes {
		nodes[i] = strings.Repeat("n", 128)
	}
	addNativeGood(&promoted, nativeGoodRelease{Binding: *state.Pending, Nodes: nodes, GoodAt: time.Now().UTC()})
	if state.Previous != nil {
		recovery := state.Previous.Binding
		recovery.Intent.OperationID = strings.Repeat("0", 26)
		recovery.Intent.AuthorityEpoch, recovery.Intent.Generation = ^uint64(0), ^uint64(0)
		recovery.Fingerprint = strings.Repeat("f", 64)
		promoted.Recovery, promoted.Rejected = &recovery, state.Pending.Fingerprint
	}
	_, _, err := encodeNativeHistory(promoted, h.js.Conn().MaxPayload())
	return err
}

func (h *nativeHistory) prepare(ctx context.Context, request nativePrepareRequest) (nativePrepareReply, error) {
	h.effects.Lock()
	defer h.effects.Unlock()
	i := request.Intent
	if !slices.Contains(serviceReleaseRoles, i.Role) || i.Cell != h.services.cell {
		return nativePrepareReply{}, delivery.ErrInvalid
	}
	if err := h.fencer.Guard(ctx, i.AuthorityEpoch); err != nil {
		return nativePrepareReply{}, err
	}
	// Spec/root adoption cannot interleave with selecting and persisting a profile.
	h.services.launches.RLock()
	defer h.services.launches.RUnlock()
	state, revision, err := h.load(ctx, i.Role)
	if err != nil {
		return nativePrepareReply{}, err
	}
	fp, err := i.Fingerprint()
	if err != nil {
		return nativePrepareReply{}, err
	}
	if request.RecoveryOf != "" {
		if state.Pending == nil || state.Pending.Intent.OperationID != request.RecoveryOf || state.Previous == nil {
			return nativePrepareReply{}, delivery.ErrConflict
		}
		target := state.Previous.Binding
		if err := h.refuseKnownBad(ctx, target.Artifact); err != nil {
			return nativePrepareReply{}, err
		}
		if i.Source != target.Intent.Source || i.ArtifactDigest != target.Intent.ArtifactDigest || i.ManifestDigest != target.Intent.ManifestDigest ||
			i.ConfigDigest != target.Intent.ConfigDigest || i.Environment != target.Intent.Environment || i.DesiredReplicas != target.Intent.DesiredReplicas || i.Generation <= state.Pending.Intent.Generation {
			return nativePrepareReply{}, delivery.ErrConflict
		}
		if state.Recovery != nil && state.Recovery.Fingerprint != fp && request.ResumeOf != state.Recovery.Intent.OperationID {
			return nativePrepareReply{}, delivery.ErrConflict
		}
		if err := h.verifyProfile(i.Role, target.Profile, target.Provenance); err != nil {
			return nativePrepareReply{}, err
		}
		binding, err := nativeBinding(i, target.Artifact, target.Profile, target.Provenance)
		if err != nil {
			return nativePrepareReply{}, err
		}
		state.Recovery = &binding
		state.Rejected = state.Pending.Fingerprint
		if bad, err := h.badProfile(ctx, binding); err != nil {
			return nativePrepareReply{}, err
		} else if bad {
			return nativePrepareReply{}, errors.New("native recovery artifact/profile is known bad")
		}
	} else if state.Pending != nil && state.Pending.Fingerprint == fp {
		if state.Recovery != nil || state.Rejected == fp {
			return nativePrepareReply{}, delivery.ErrConflict
		}
		if err := nativeForwardAllowed(state, *state.Pending); err != nil {
			return nativePrepareReply{}, err
		}
		if err := h.verifyProfile(i.Role, state.Pending.Profile, state.Pending.Provenance); err != nil {
			return nativePrepareReply{}, err
		}
		if err := h.checkForwardCapacity(state); err != nil {
			return nativePrepareReply{}, err
		}
		if err := h.prepareGate(ctx, i, state); err != nil {
			return nativePrepareReply{}, err
		}
		return nativePrepareReply{Intent: i, Previous: nativeTarget(state.Previous), previous: state.Previous}, nil
	} else if request.ResumeOf != "" {
		if state.Pending == nil || state.Pending.Intent.OperationID != request.ResumeOf || state.Recovery != nil || state.Rejected != "" {
			return nativePrepareReply{}, delivery.ErrConflict
		}
		old := state.Pending
		if err := nativeForwardAllowed(state, *old); err != nil {
			return nativePrepareReply{}, err
		}
		if i.Source != old.Intent.Source || i.ArtifactDigest != old.Intent.ArtifactDigest || i.ConfigDigest != old.Intent.ConfigDigest || i.ManifestDigest != old.Intent.ManifestDigest ||
			i.Environment != old.Intent.Environment || i.DesiredReplicas != old.Intent.DesiredReplicas || i.Generation < old.Intent.Generation {
			return nativePrepareReply{}, delivery.ErrConflict
		}
		if receipt, err := h.deliveries.StatusFor(ctx, old.Intent); err != nil && !errors.Is(err, delivery.ErrPending) {
			return nativePrepareReply{}, err
		} else if err == nil && receipt.Status == "accepted" {
			return nativePrepareReply{}, delivery.ErrConflict
		}
		if err := h.verifyProfile(i.Role, old.Profile, old.Provenance); err != nil {
			return nativePrepareReply{}, err
		}
		binding, err := nativeBinding(i, old.Artifact, old.Profile, old.Provenance)
		if err != nil {
			return nativePrepareReply{}, err
		}
		binding.Deadline = old.Deadline
		state.Pending = &binding
	} else {
		if request.Deadline.IsZero() || !time.Now().Before(request.Deadline) {
			return nativePrepareReply{}, fmt.Errorf("%w: native forward deadline expired: %w", delivery.ErrInvalid, context.DeadlineExceeded)
		}
		if request.Deadline.After(time.Now().Add(rollout.ObservationBudget)) {
			return nativePrepareReply{}, fmt.Errorf("%w: native forward deadline exceeds observation budget", delivery.ErrInvalid)
		}
		if state.Pending != nil {
			current := state.Pending
			if state.Recovery != nil {
				current = state.Recovery
			}
			if !slices.ContainsFunc(state.Good, func(g nativeGoodRelease) bool { return g.Binding.Fingerprint == current.Fingerprint }) {
				receipt, err := h.deliveries.StatusFor(ctx, state.Pending.Intent)
				if err != nil || !unchanged(receipt) {
					return nativePrepareReply{}, delivery.ErrConflict
				}
			}
		}
		previous, err := h.baseline(ctx, i.Role, &state)
		if err != nil {
			return nativePrepareReply{}, err
		}
		profile, ok := h.services.profiles()[i.Role]
		if !ok || i.ConfigDigest != delivery.ConfigDigestOf(profile.Args, profile.Env, profile.Secrets) {
			return nativePrepareReply{}, errors.New("new native intent differs from current signed profile")
		}
		provenance, err := h.currentProvenance(ctx, i.Role, profile)
		if err != nil {
			return nativePrepareReply{}, err
		}
		if err := h.verifyProfile(i.Role, profile, provenance); err != nil {
			return nativePrepareReply{}, err
		}
		artifact, err := h.deliveries.ResolveAdmittedArtifact(ctx, i.ArtifactDigest, i.Role, i.Environment)
		if err != nil {
			return nativePrepareReply{}, err
		}
		if err := h.refuseKnownBad(ctx, artifact); err != nil {
			return nativePrepareReply{}, err
		}
		binding, err := nativeBinding(i, artifact, profile, provenance)
		if err != nil {
			return nativePrepareReply{}, err
		}
		bad, err := h.badProfile(ctx, binding)
		if err != nil {
			return nativePrepareReply{}, err
		}
		if bad {
			return nativePrepareReply{}, errors.New("native artifact/profile is known bad")
		}
		binding.Deadline = request.Deadline.UTC()
		state.Pending, state.Previous, state.Recovery, state.Rejected = &binding, previous, nil, ""
	}
	if request.RecoveryOf == "" {
		if err := nativeForwardAllowed(state, *state.Pending); err != nil {
			return nativePrepareReply{}, err
		}
		if err := h.checkForwardCapacity(state); err != nil {
			return nativePrepareReply{}, err
		}
	}
	if _, err := encodeNativeReply(nativePrepareReply{Intent: i, Previous: nativeTarget(state.Previous)}, h.js.Conn().MaxPayload()); err != nil {
		return nativePrepareReply{}, err
	}
	if err := h.save(ctx, i.AuthorityEpoch, i.Role, state, revision); err != nil {
		return nativePrepareReply{}, err
	}
	if err := h.prepareGate(ctx, i, state); err != nil {
		return nativePrepareReply{}, err
	}
	return nativePrepareReply{Intent: i, Previous: nativeTarget(state.Previous), previous: state.Previous}, nil
}

func (h *nativeHistory) prepareGate(ctx context.Context, intent delivery.Intent, state nativeReleaseHistory) error {
	fingerprint, err := intent.Fingerprint()
	if err != nil {
		return err
	}
	if slices.ContainsFunc(state.Good, func(g nativeGoodRelease) bool { return g.Binding.Fingerprint == fingerprint }) {
		return nil
	}
	binding := state.Pending
	if state.Recovery != nil {
		binding = state.Recovery
	}
	if binding == nil || binding.Fingerprint != fingerprint {
		return delivery.ErrConflict
	}
	if err := nativeForwardAllowed(state, *binding); err != nil {
		return err
	}
	if !binding.Deadline.IsZero() {
		gateCtx, cancel := context.WithDeadline(ctx, binding.Deadline)
		defer cancel()
		ctx = gateCtx
	}
	if err := h.fencer.Guard(ctx, intent.AuthorityEpoch); err != nil {
		return err
	}
	if err := h.fences.prepare(ctx, intent); err != nil {
		return fmt.Errorf("%w: %w", errFencePrepare, err)
	}
	return nil
}

// profile only resolves a durably selected complete intent fingerprint. A
// caller cannot retrieve history by choosing an old ConfigDigest.
func (h *nativeHistory) profile(ctx context.Context, intent delivery.Intent) (WorkloadProfile, error) {
	state, _, err := h.load(ctx, intent.Role)
	if err != nil {
		return WorkloadProfile{}, err
	}
	fp, err := intent.Fingerprint()
	if err != nil {
		return WorkloadProfile{}, err
	}
	b := state.Pending
	if state.Recovery != nil {
		b = state.Recovery
	}
	if b == nil || b.Fingerprint != fp || state.Rejected == fp {
		return WorkloadProfile{}, fmt.Errorf("%w: native intent has no active persisted signed profile binding", delivery.ErrInvalid)
	}
	if err := nativeForwardAllowed(state, *b); err != nil {
		return WorkloadProfile{}, err
	}
	if err := h.refuseKnownBad(ctx, b.Artifact); err != nil {
		return WorkloadProfile{}, err
	}
	if err := h.verifyProfile(intent.Role, b.Profile, b.Provenance); err != nil {
		return WorkloadProfile{}, fmt.Errorf("%w: %w", delivery.ErrInvalid, err)
	}
	if err := nativeForwardAllowed(state, *b); err != nil {
		return WorkloadProfile{}, err
	}
	return cloneNativeProfile(b.Profile), nil
}

func (h *nativeHistory) allowDesired(ctx context.Context, d host.Desired) error {
	state, _, err := h.load(ctx, d.Role)
	if err != nil {
		return err
	}
	b := activeNativeBinding(state, d)
	if b == nil || state.Rejected == b.Fingerprint || d.Cell != b.Intent.Cell || d.Environment != b.Intent.Environment ||
		d.Generation != b.Intent.Generation && workload.ReleaseOf(d.Generation) != b.Intent.Generation {
		return fmt.Errorf("%w: native desired differs from active selection", delivery.ErrInvalid)
	}
	if !d.Withdrawn && (d.Digest != b.Artifact.Digest || delivery.ConfigDigestOf(d.Args, d.Env, d.Secrets) != b.Intent.ConfigDigest) {
		return fmt.Errorf("%w: native desired configuration differs from active selection", delivery.ErrInvalid)
	}
	if err := nativeForwardAllowed(state, *b); err != nil {
		return err
	}
	if err := h.verifyProfile(d.Role, b.Profile, b.Provenance); err != nil {
		return fmt.Errorf("%w: %w", delivery.ErrInvalid, err)
	}
	if err := h.refuseKnownBad(ctx, b.Artifact); err != nil {
		return err
	}
	if err := h.fencer.Guard(ctx, d.AuthorityEpoch); err != nil {
		return err
	}
	return nativeForwardAllowed(state, *b)
}

func (h *nativeHistory) refuseKnownBad(ctx context.Context, artifact delivery.ArtifactRecord) error {
	msg, err := nativeLeaderGet(ctx, h.js, releasechannel.Bucket, knownBadKey(artifact.Role, artifact.Digest))
	if errors.Is(err, nats.ErrMsgNotFound) || errors.Is(err, nats.ErrStreamNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if msg.Header.Get("KV-Operation") == "DEL" || msg.Header.Get("KV-Operation") == "PURGE" {
		return nil
	}
	return fmt.Errorf("%w: native artifact is known bad in this cell", delivery.ErrInvalid)
}

func activeNativeBinding(state nativeReleaseHistory, d host.Desired) *nativeReleaseBinding {
	if state.Recovery != nil {
		return state.Recovery
	}
	if state.Pending != nil {
		return state.Pending
	}
	for i := range state.Good {
		b := &state.Good[i].Binding
		if d.Generation == b.Intent.Generation || workload.ReleaseOf(d.Generation) == b.Intent.Generation {
			return b
		}
	}
	return nil
}

func committedNativeBinding(state nativeReleaseHistory, desired host.Desired) *nativeReleaseBinding {
	for _, b := range nativeBindings(&state) {
		if desired.Generation != b.Intent.Generation && workload.ReleaseOf(desired.Generation) != b.Intent.Generation {
			continue
		}
		if desired.Cell == b.Intent.Cell && desired.Environment == b.Intent.Environment && desired.Digest == b.Artifact.Digest &&
			delivery.ConfigDigestOf(desired.Args, desired.Env, desired.Secrets) == b.Intent.ConfigDigest {
			return b
		}
	}
	return nil
}

func (h *nativeHistory) ApplyDesired(ctx context.Context, d host.Desired) (host.Receipt, error) {
	if !slices.Contains(serviceReleaseRoles, d.Role) {
		return h.hosts.ApplyDesired(ctx, d)
	}
	// Reconciler writes hold their own lock; spec adoption holds launches while
	// replacing that reconciler. Waiting here would invert those locks.
	if !h.effects.TryLock() {
		return host.Receipt{}, delivery.ErrConflict
	}
	defer h.effects.Unlock()
	if !h.services.launches.TryRLock() {
		return host.Receipt{}, delivery.ErrConflict
	}
	defer h.services.launches.RUnlock()
	if err := h.allowDesired(ctx, d); err != nil {
		return host.Receipt{}, err
	}
	return h.hosts.ApplyDesired(ctx, d)
}

// Resources are placement reservations, absent from host.Desired. The current
// committed release selects them even after a newer cell profile is adopted.
func (h *nativeHistory) resources(ctx context.Context, desired []host.Desired, profiles map[string]placement.Resources) (map[string]placement.Resources, error) {
	profiles = maps.Clone(profiles)
	for _, role := range serviceReleaseRoles {
		var latest *host.Desired
		for i := range desired {
			d := &desired[i]
			if d.Role == role && !d.Withdrawn && (latest == nil || d.Generation > latest.Generation) {
				latest = d
			}
		}
		if latest == nil {
			continue
		}
		state, _, err := h.load(ctx, role)
		if err != nil {
			return nil, err
		}
		b := committedNativeBinding(state, *latest)
		if b == nil || state.Rejected == b.Fingerprint || latest.Generation != b.Intent.Generation && workload.ReleaseOf(latest.Generation) != b.Intent.Generation ||
			latest.Digest != b.Artifact.Digest || delivery.ConfigDigestOf(latest.Args, latest.Env, latest.Secrets) != b.Intent.ConfigDigest {
			return nil, errors.New("native reconciliation awaits the selected release profile")
		}
		if err := h.verifyProfile(role, b.Profile, b.Provenance); err != nil {
			return nil, err
		}
		profiles[role] = b.Profile.Resources
	}
	return profiles, nil
}

func (h *nativeHistory) observe(ctx context.Context, intent delivery.Intent) (ready bool, observeErr error) {
	epoch := h.fencer.Current().Epoch
	if err := h.fencer.Guard(ctx, epoch); err != nil {
		return false, err
	}
	h.services.launches.RLock()
	defer func() {
		h.services.launches.RUnlock()
		if errors.Is(observeErr, errBadRelease) {
			observeErr = errors.Join(observeErr, h.reject(ctx, intent, observeErr, epoch))
		}
	}()
	state, revision, err := h.load(ctx, intent.Role)
	if err != nil {
		return false, err
	}
	fp, err := intent.Fingerprint()
	if err != nil {
		return false, err
	}
	b := state.Pending
	if state.Recovery != nil {
		b = state.Recovery
	}
	if b == nil || b.Fingerprint != fp || state.Rejected == fp {
		return false, delivery.ErrConflict
	}
	if !slices.ContainsFunc(state.Good, func(g nativeGoodRelease) bool { return g.Binding.Fingerprint == fp }) {
		if err := nativeForwardAllowed(state, *b); err != nil {
			return false, err
		}
		if !b.Deadline.IsZero() {
			gateCtx, cancel := context.WithDeadline(ctx, b.Deadline)
			defer cancel()
			requestCtx := ctx
			ctx = gateCtx
			defer func() { ctx = requestCtx }()
		}
	}
	if h.fences != nil {
		if err := h.verifyProfile(intent.Role, b.Profile, b.Provenance); err != nil {
			return false, err
		}
		if state.Recovery == nil && state.Previous != nil {
			previous := state.Previous.Binding
			if err := h.verifyProfile(intent.Role, previous.Profile, previous.Provenance); err != nil {
				return false, err
			}
		}
		if !h.gates.TryLock() {
			return false, nil
		}
		defer h.gates.Unlock()
		receipt, err := h.deliveries.StatusFor(ctx, intent)
		if errors.Is(err, delivery.ErrPending) {
			return false, nil
		}
		if err != nil || receipt.Status != "accepted" {
			return false, err
		}
		gate := h.selectedCanaryGate(state, *b)
		if state.Recovery != nil {
			gate = nil
		}
		if err := h.fences.sequence(ctx, intent, gate); err != nil {
			return false, err
		}
		latest, latestRevision, err := h.load(ctx, intent.Role)
		if err != nil {
			return false, err
		}
		selected := latest.Pending
		if latest.Recovery != nil {
			selected = latest.Recovery
		}
		if selected == nil || selected.Fingerprint != fp || latest.Rejected == fp {
			return false, delivery.ErrConflict
		}
		state, revision, b = latest, latestRevision, selected
	}
	changed, err := h.observeBinding(ctx, &state, *b)
	if err != nil {
		return false, err
	}
	if !changed && !slices.ContainsFunc(state.Good, func(g nativeGoodRelease) bool { return g.Binding.Fingerprint == fp }) {
		return false, nil
	}
	if !h.effects.TryLock() {
		return false, delivery.ErrConflict
	}
	defer h.effects.Unlock()
	if bad, err := h.badProfile(ctx, *b); err != nil {
		return false, err
	} else if bad {
		return false, errors.New("native artifact/profile is known bad")
	}
	if err := h.refuseKnownBad(ctx, b.Artifact); err != nil {
		return false, err
	}
	if !changed {
		latest, _, err := h.load(ctx, intent.Role)
		if err != nil {
			return false, err
		}
		selected := latest.Pending
		if latest.Recovery != nil {
			selected = latest.Recovery
		}
		if selected == nil || selected.Fingerprint != fp || latest.Rejected == fp {
			return false, delivery.ErrConflict
		}
		return slices.ContainsFunc(latest.Good, func(g nativeGoodRelease) bool { return g.Binding.Fingerprint == fp }), nil
	}
	if err := h.save(ctx, epoch, intent.Role, state, revision); err != nil {
		return false, err
	}
	return true, nil
}

func nativeBadProfileKey(b nativeReleaseBinding) string {
	return "bad." + b.Intent.Role + "." + b.Artifact.Digest + "." + b.ProfileDigest
}

func (h *nativeHistory) badProfile(ctx context.Context, b nativeReleaseBinding) (bool, error) {
	msg, err := nativeLeaderGet(ctx, h.js, nativeHistoryBucket, nativeBadProfileKey(b))
	if errors.Is(err, nats.ErrMsgNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return msg.Header.Get("KV-Operation") != "DEL" && msg.Header.Get("KV-Operation") != "PURGE", nil
}

func (h *nativeHistory) reject(ctx context.Context, intent delivery.Intent, cause error, epoch uint64) error {
	h.effects.Lock()
	defer h.effects.Unlock()
	if err := h.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	state, revision, err := h.load(ctx, intent.Role)
	if err != nil {
		return err
	}
	fp, err := intent.Fingerprint()
	if err != nil || state.Pending == nil || state.Pending.Fingerprint != fp {
		return delivery.ErrConflict
	}
	state.Rejected = fp
	if errors.Is(cause, errBadRelease) {
		state.Good = slices.DeleteFunc(state.Good, func(g nativeGoodRelease) bool { return g.Binding.Fingerprint == fp })
		if err := h.fencer.Guard(ctx, epoch); err != nil {
			return err
		}
		_, err := h.kv.Create(ctx, nativeBadProfileKey(*state.Pending), []byte(`{"schema":1}`))
		if err != nil && !errors.Is(err, jetstream.ErrKeyExists) {
			return err
		}
	}
	return h.save(ctx, epoch, intent.Role, state, revision)
}

func (h *nativeHistory) artifactsInUse(ctx context.Context) ([]delivery.ArtifactUse, error) {
	var uses []delivery.ArtifactUse
	for _, role := range serviceReleaseRoles {
		state, _, err := h.load(ctx, role)
		if err != nil {
			return nil, err
		}
		bindings := []*nativeReleaseBinding{state.Pending, state.Recovery}
		if state.Previous != nil {
			bindings = append(bindings, &state.Previous.Binding)
		}
		for j := range state.Good {
			bindings = append(bindings, &state.Good[j].Binding)
		}
		for _, b := range bindings {
			if b != nil {
				uses = append(uses, delivery.ArtifactUse{Digest: b.Artifact.Digest, Role: role, Environment: b.Artifact.Environment})
			}
		}
	}
	return uses, nil
}

func (h *nativeHistory) run(ctx context.Context) error {
	for {
		if h.fencer.Current().CanMutate() {
			for _, role := range serviceReleaseRoles {
				state, revision, err := h.load(ctx, role)
				if err != nil {
					continue
				}
				b := state.Pending
				if state.Recovery != nil {
					b = state.Recovery
				}
				if b == nil && len(state.Good) == 0 {
					epoch := h.fencer.Current().Epoch
					h.services.launches.RLock()
					if good, err := h.baseline(ctx, role, &state); err == nil && good != nil {
						_ = h.save(ctx, epoch, role, state, revision)
					}
					h.services.launches.RUnlock()
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(defaultChannelInterval):
		}
	}
}

func (h *nativeHistory) serve(ctx context.Context, wire []byte, policy signerPolicy) (nativePrepareReply, error) {
	envelope, actor, err := verifyCellRequest(wire, policy, h.fencer)
	if err != nil {
		return nativePrepareReply{}, err
	}
	var request nativePrepareRequest
	if err := protocol.DecodeStrict(envelope.Payload, &request, maxRegistrationBytes); err != nil {
		return nativePrepareReply{}, err
	}
	if err := policy.authorizeIntent(ctx, actor, request.Intent); err != nil {
		return nativePrepareReply{}, err
	}
	if envelope.Kind == nativeObserveKind {
		ready, err := h.observe(ctx, request.Intent)
		return nativePrepareReply{Ready: ready}, err
	}
	if request.Intent.AuthorityEpoch != envelope.Epoch {
		return nativePrepareReply{}, authority.ErrFenced
	}
	if envelope.Kind == nativeRestoreKind {
		return h.restore(ctx, request, actor)
	}
	if request.RecoveryOf != "" {
		state, _, err := h.load(ctx, request.Intent.Role)
		if err != nil {
			return nativePrepareReply{}, err
		}
		if state.Pending == nil || state.Pending.Intent.OperationID != request.RecoveryOf {
			return nativePrepareReply{}, delivery.ErrConflict
		}
		if _, gateErr := h.ready(ctx, state.Pending.Intent); errors.Is(gateErr, errBadRelease) {
			if err := h.reject(ctx, state.Pending.Intent, gateErr, envelope.Epoch); err != nil {
				return nativePrepareReply{}, err
			}
		}
	}
	return h.prepare(ctx, request)
}
