package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
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
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
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

func nativeProfileDigest(profile WorkloadProfile) string {
	wire, _ := json.Marshal(profile, json.Deterministic(true))
	return controllerSHA256(wire)
}

func cloneNativeProfile(profile WorkloadProfile) WorkloadProfile {
	profile.Args, profile.Env, profile.Secrets = slices.Clone(profile.Args), maps.Clone(profile.Env), maps.Clone(profile.Secrets)
	return profile
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

type nativePrepareRequest struct {
	Intent     delivery.Intent `json:"intent"`
	RecoveryOf string          `json:"recovery_of,omitempty"`
	ResumeOf   string          `json:"resume_of,omitempty"`
	Deadline   time.Time       `json:"deadline,omitzero"`
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
