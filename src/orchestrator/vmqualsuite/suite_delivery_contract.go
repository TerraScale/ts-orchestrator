package vmqualsuite

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/edge"
	"terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/objectstore"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

var deliveryContractHosts = map[string][]string{
	"gru": {"gru-member-1", "gru-member-2"},
	"sfo": {"sfo-member-1", "sfo-member-2"},
	"fra": {"fra-member-1", "fra-member-2"},
}

// DeliveryContractConfig binds the in-process production delivery contracts
// to the persistent local providers and the real guest control surface.
type DeliveryContractConfig struct {
	Authority func(context.Context, *delivery.Request) error
	StateRoot string
	Endpoints *LocalProviderEndpoints
	Guest     vmqual.DeliveryGuestControl
	Client    *http.Client
}

type DeliveryMirrorObservation struct {
	Region string
	Bucket string
	Object string
	Digest string
	Size   int64
}

type DeliveryEdgeObservation struct {
	WorkerEvents       []string
	SnippetEvents      []string
	WorkerDigest       string
	SnippetDigest      string
	SnippetRuleDigest  string
	ReactiveResponses  uint64
	ReactiveCacheHits  uint64
	ReactiveWorkerFree bool
}

// DeliveryContractResult contains only values obtained from receipts,
// provider reads, guest reads, and mutation traces validated by the runner.
type DeliveryContractResult struct {
	ManifestDigest       string
	ArchitectureDigests  map[string]string
	NativeArchitecture   string
	GuestQualification   vmqual.TSNodeGuestObservation
	BadSignatureRejected bool
	BadDigestRejected    bool
	CanaryHost           string
	ForwardHosts         []string
	RollbackHosts        []string
	MaximumCordoned      map[string]int
	GateChecks           map[string]int
	PersistentMirrors    []DeliveryMirrorObservation
	SuccessfulReceipt    *delivery.Receipt
	RollbackReceipt      *delivery.Receipt
	WorkerReceipt        *delivery.Receipt
	SnippetReceipt       *delivery.Receipt
	Edge                 DeliveryEdgeObservation
	GuestsAfterRollback  []vmqual.DeliveryGuestObservation
}

// RunDeliveryContract exercises criteria 6-8 through delivery.NewServer,
// delivery.NewRollout, and delivery.NewArtifactMirror. It does not substitute
// an in-process host fake: Guest is mandatory and must reach participating
// Firecracker guests.
func RunDeliveryContract(ctx context.Context, config DeliveryContractConfig) (DeliveryContractResult, error) {
	var result DeliveryContractResult
	if ctx == nil {
		return result, errors.New("vmqual: delivery contract context is nil")
	}
	if config.Guest == nil {
		return result, errors.New("vmqual: delivery contract requires a guest-backed ts-node control")
	}
	if config.Authority == nil {
		return result, errors.New("vmqual: delivery requires a live control authority callback")
	}
	if err := validateDeliveryContractProviders(config); err != nil {
		return result, err
	}
	client := config.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	release, err := newDeliveryContractRelease()
	if err != nil {
		return result, err
	}
	result.ManifestDigest = release.candidateManifestDigest
	result.ArchitectureDigests = map[string]string{}
	for architecture, artifact := range release.candidates {
		result.ArchitectureDigests[architecture] = artifact.Identity.Digest
	}

	unit, err := deliveryContractSystemdUnit(release.candidates["linux/amd64"])
	if err != nil {
		return result, err
	}
	qualification := vmqual.TSNodeGuestQualification{
		Manifest:            release.candidateManifest,
		ManifestDigest:      release.candidateManifestDigest,
		PublicKey:           append(ed25519.PublicKey(nil), release.publicKey...),
		Candidates:          cloneDeliveryArtifacts(release.candidates),
		BadSignature:        cloneDeliveryArtifacts(release.badSignatures),
		BadDigest:           cloneDeliveryArtifacts(release.badDigests),
		ExpectedSystemdUnit: unit,
		PersistenceSentinel: []byte("vmqual-delivery-persistence-v1"),
	}
	guestProof, err := config.Guest.QualifyTSNode(ctx, vmqual.DeliveryContractCanary, qualification)
	if err != nil {
		return result, fmt.Errorf("vmqual: guest ts-node qualification: %w", err)
	}
	if err := validateTSNodeGuestObservation(guestProof, qualification); err != nil {
		return result, err
	}
	result.GuestQualification = guestProof
	result.NativeArchitecture = guestProof.NativeArchitecture
	result.BadSignatureRejected = true
	result.BadDigestRejected = true

	store := &deliveryContractObjectStore{endpoints: config.Endpoints, client: client, expected: make(map[string]map[string]delivery.ObjectIdentity)}
	if err := store.ensureReleaseBuckets(ctx); err != nil {
		return result, err
	}
	journal := delivery.NewJournal()
	store.setFenceChecker(journal.VerifyFence)
	mirror, err := delivery.NewArtifactMirror(estate.Default(), store)
	if err != nil {
		return result, fmt.Errorf("vmqual: build artifact mirror: %w", err)
	}

	tracker := newDeliveryContractHostControl(config.Guest)
	clock := &deliveryContractClock{now: time.Unix(1_800_000_000, 0).UTC()}
	gates := []*deliveryContractGate{
		{name: "process-health", guest: config.Guest, tracker: tracker},
		{name: "external-health", guest: config.Guest, tracker: tracker},
		{name: vmqual.DeliveryContractFailureGate, guest: config.Guest, tracker: tracker},
	}
	edgeArtifacts := newDeliveryProviderArtifactSource()
	edgePromoter, edgeClient, err := newDeliveryProviderEdge(ctx, config.Endpoints, client, edgeArtifacts)
	if err != nil {
		return result, err
	}
	rollout, err := delivery.NewRollout(delivery.RolloutConfig{
		Spec:        estate.Default(),
		Hosts:       deliveryContractInventory{},
		Control:     tracker,
		Gates:       []delivery.Gate{gates[0], gates[1], gates[2]},
		Edge:        edgePromoter,
		GateTimeout: time.Millisecond,
		Now:         clock.Now,
		Wait:        clock.Wait,
	})
	if err != nil {
		return result, fmt.Errorf("vmqual: build production rollout: %w", err)
	}

	fetcher := &deliveryContractFetcher{artifacts: make(map[string]deliveryContractFetch)}
	server, err := delivery.NewServer(delivery.ServerConfig{
		Authority: config.Authority,
		// This is the GRU-owned preparation contract; regional executors verify mirrors.
		MirrorMode: delivery.MirrorModePrepareAll,
		OwnerID:    "vmqual-delivery-contract",
		Token:      func() (string, error) { return vmqual.DeliveryContractToken, nil },
		Fetcher:    fetcher,
		Trust:      func() *delivery.TrustSet { return release.trust },
		Mirror:     mirror,
		Rollout:    rollout,
		Journal:    journal,
	})
	if err != nil {
		return result, fmt.Errorf("vmqual: build production delivery server: %w", err)
	}

	native := guestProof.NativeArchitecture
	priorArtifact := release.prior[native]
	candidateArtifact := release.candidates[native]
	priorRequest := deliveryContractRequest("vmqual-host-prior", vmqual.DeliveryContractService, "service", native, priorArtifact.Identity.Digest, release.priorManifestDigest, nil)
	fetcher.put(priorRequest.OperationID, priorArtifact)
	priorReceipt, err := submitDeliveryContract(ctx, server, priorRequest)
	if err != nil {
		return result, err
	}
	if err := requireSuccessfulDeliveryReceipt(priorReceipt, priorRequest); err != nil {
		return result, fmt.Errorf("vmqual: initial host delivery: %w", err)
	}
	result.SuccessfulReceipt = priorReceipt

	mutationsBeforeInvalid := tracker.mutationCount()
	badSignatureRequest := deliveryContractRequest("vmqual-bad-signature", vmqual.DeliveryContractService, "service", native, candidateArtifact.Identity.Digest, release.candidateManifestDigest, nil)
	fetcher.put(badSignatureRequest.OperationID, release.badSignatures[native])
	badSignatureReceipt, err := submitDeliveryContract(ctx, server, badSignatureRequest)
	if err != nil {
		return result, err
	}
	if err := requireUnverifiedReceipt(badSignatureReceipt); err != nil {
		return result, fmt.Errorf("vmqual: bad signature was not rejected: %w", err)
	}
	badDigestArtifact := release.badDigests[native]
	badDigestRequest := deliveryContractRequest("vmqual-bad-digest", vmqual.DeliveryContractService, "service", native, badDigestArtifact.Identity.Digest, release.candidateManifestDigest, nil)
	// Serve the correctly signed candidate bytes under a deliberately wrong
	// request digest. This reaches delivery's SHA check before rollout.
	fetcher.put(badDigestRequest.OperationID, candidateArtifact)
	badDigestReceipt, err := submitDeliveryContract(ctx, server, badDigestRequest)
	if err != nil {
		return result, err
	}
	if err := requireUnverifiedReceipt(badDigestReceipt); err != nil {
		return result, fmt.Errorf("vmqual: bad digest was not rejected: %w", err)
	}
	if tracker.mutationCount() != mutationsBeforeInvalid {
		return result, errors.New("vmqual: an unverified artifact reached guest mutation")
	}

	tracker.reset()
	gates[2].inject(candidateArtifact.Identity.Digest, vmqual.DeliveryContractFailureHost)
	rollback := &delivery.RollbackArtifact{
		ArtifactDigest: priorArtifact.Identity.Digest,
		ManifestDigest: release.priorManifestDigest,
		Kind:           "service",
		Architecture:   native,
	}
	candidateRequest := deliveryContractRequest("vmqual-host-rollback", vmqual.DeliveryContractService, "service", native, candidateArtifact.Identity.Digest, release.candidateManifestDigest, rollback)
	fetcher.put(candidateRequest.OperationID, candidateArtifact)
	rollbackReceipt, err := submitDeliveryContract(ctx, server, candidateRequest)
	if err != nil {
		return result, err
	}
	if err := requireRolledBackReceipt(rollbackReceipt, candidateRequest); err != nil {
		return result, fmt.Errorf("vmqual: host rollback delivery: %w", err)
	}
	result.RollbackReceipt = rollbackReceipt
	forward, backward, maximum, gateChecks := tracker.rolloutState(candidateArtifact.Identity.Digest, priorArtifact.Identity.Digest)
	if err := validateHostRolloutState(forward, backward, maximum, gateChecks); err != nil {
		return result, err
	}
	result.CanaryHost = forward[0]
	result.ForwardHosts = forward
	result.RollbackHosts = backward
	result.MaximumCordoned = maximum
	result.GateChecks = gateChecks

	for _, region := range []string{"gru", "sfo", "fra"} {
		for _, host := range deliveryContractHosts[region] {
			observation, observeErr := config.Guest.ObserveDeliveryGuest(ctx, host)
			if observeErr != nil {
				return result, fmt.Errorf("vmqual: observe rolled-back guest %s: %w", host, observeErr)
			}
			if observation.Host != host || !delivery.SameDigest(observation.ActiveDigest, priorArtifact.Identity.Digest) || observation.Cordoned || !observation.UnitActive {
				return result, fmt.Errorf("vmqual: guest %s did not return to the exact prior release", host)
			}
			if host == vmqual.DeliveryContractCanary && !bytes.Equal(observation.PersistentData, qualification.PersistenceSentinel) {
				return result, errors.New("vmqual: guest data did not survive delivery and rollback")
			}
			result.GuestsAfterRollback = append(result.GuestsAfterRollback, observation)
		}
	}

	workerPrior := release.edgeArtifact("ts-dashboard-prior")
	workerCandidate := release.edgeArtifact("ts-dashboard-candidate")
	edgeArtifacts.put("ts-dashboard", workerPrior.Identity.Digest, workerPrior.Body)
	edgeArtifacts.put("ts-dashboard", workerCandidate.Identity.Digest, workerCandidate.Body)
	if err := edgePromoter.PromoteWorkerGradual(ctx, "ts-dashboard", workerPrior.Identity.Digest); err != nil {
		return result, fmt.Errorf("vmqual: seed prior Worker release: %w", err)
	}
	workerRequest := deliveryContractRequest("vmqual-worker-rollback", "ts-dashboard", "site", "multi", workerCandidate.Identity.Digest, release.edgeManifestDigest("ts-dashboard-candidate"), &delivery.RollbackArtifact{
		ArtifactDigest: workerPrior.Identity.Digest,
		ManifestDigest: release.edgeManifestDigest("ts-dashboard-prior"),
		Kind:           "site",
		Architecture:   "multi",
	})
	fetcher.put(workerRequest.OperationID, workerCandidate)
	injectDeliveryWorkerFailure(config.Endpoints, "ts-dashboard")
	workerReceipt, err := submitDeliveryContract(ctx, server, workerRequest)
	if err != nil {
		return result, err
	}
	if err := requireRolledBackReceipt(workerReceipt, workerRequest); err != nil {
		return result, fmt.Errorf("vmqual: Worker rollback delivery: %w", err)
	}
	result.WorkerReceipt = workerReceipt

	snippetPrior := release.edgeArtifact("ts-proxy-snippet-prior")
	snippetCandidate := release.edgeArtifact("ts-proxy-snippet-candidate")
	edgeArtifacts.put("ts-proxy-snippet", snippetPrior.Identity.Digest, snippetPrior.Body)
	edgeArtifacts.put("ts-proxy-snippet", snippetCandidate.Identity.Digest, snippetCandidate.Body)
	if err := edgePromoter.PromoteSnippet(ctx, "ts-proxy-snippet", snippetPrior.Identity.Digest); err != nil {
		return result, fmt.Errorf("vmqual: seed prior Snippet release: %w", err)
	}
	if err := edgePromoter.CoordinateSnippetZoneRules(ctx, "ts-proxy-snippet", snippetPrior.Identity.Digest); err != nil {
		return result, fmt.Errorf("vmqual: seed prior Snippet rules: %w", err)
	}
	snippetRequest := deliveryContractRequest("vmqual-snippet-rollback", "ts-proxy-snippet", "package", "multi", snippetCandidate.Identity.Digest, release.edgeManifestDigest("ts-proxy-snippet-candidate"), &delivery.RollbackArtifact{
		ArtifactDigest: snippetPrior.Identity.Digest,
		ManifestDigest: release.edgeManifestDigest("ts-proxy-snippet-prior"),
		Kind:           "package",
		Architecture:   "multi",
	})
	fetcher.put(snippetRequest.OperationID, snippetCandidate)
	injectDeliverySnippetCodeFailure(config.Endpoints, "ts-gate")
	snippetReceipt, err := submitDeliveryContract(ctx, server, snippetRequest)
	if err != nil {
		return result, err
	}
	if err := requireRolledBackReceipt(snippetReceipt, snippetRequest); err != nil {
		return result, fmt.Errorf("vmqual: Snippet rollback delivery: %w", err)
	}
	result.SnippetReceipt = snippetReceipt

	edgeState, err := observeDeliveryProviderEdge(ctx, edgeClient, edgePromoter, workerPrior.Identity.Digest, workerCandidate.Identity.Digest, snippetPrior.Identity.Digest, snippetCandidate.Identity.Digest)
	if err != nil {
		return result, err
	}
	if edgeState.workerDigest != workerPrior.Identity.Digest || edgeState.snippetDigest != snippetPrior.Identity.Digest || edgeState.snippetRuleDigest != snippetPrior.Identity.Digest {
		return result, errors.New("vmqual: edge rollback did not restore exact prior versions")
	}
	if !hasEdgePromotionAndRollback(edgeState.workerEvents, workerCandidate.Identity.Digest, workerPrior.Identity.Digest) {
		return result, errors.New("vmqual: Worker candidate did not promote and roll back through the gradual edge adapter")
	}
	if !hasEdgePromotionAndRollback(edgeState.snippetEvents, snippetCandidate.Identity.Digest, snippetPrior.Identity.Digest) {
		return result, errors.New("vmqual: Snippet code and rule did not promote and roll back together")
	}
	reactive, err := probeProviderReactivePath(ctx, config.Endpoints, edgeClient, client)
	if err != nil {
		return result, err
	}
	result.Edge = DeliveryEdgeObservation{
		WorkerEvents:       edgeState.workerEvents,
		SnippetEvents:      edgeState.snippetEvents,
		WorkerDigest:       edgeState.workerDigest,
		SnippetDigest:      edgeState.snippetDigest,
		SnippetRuleDigest:  edgeState.snippetRuleDigest,
		ReactiveResponses:  reactive.responses,
		ReactiveCacheHits:  reactive.cacheHits,
		ReactiveWorkerFree: reactive.workerFree,
	}

	expectedObjects := []string{
		delivery.MirrorObject(vmqual.DeliveryContractService, priorArtifact.Identity.Digest),
		delivery.MirrorObject(vmqual.DeliveryContractService, candidateArtifact.Identity.Digest),
		delivery.MirrorObject("ts-dashboard", workerCandidate.Identity.Digest),
		delivery.MirrorObject("ts-proxy-snippet", snippetCandidate.Identity.Digest),
	}
	persistent, err := store.verifyPersistent(ctx, config.StateRoot, expectedObjects)
	if err != nil {
		return result, err
	}
	result.PersistentMirrors = persistent
	return result, nil
}

type deliveryContractRelease struct {
	publicKey               ed25519.PublicKey
	privateKey              ed25519.PrivateKey
	trust                   *delivery.TrustSet
	candidates              map[string]vmqual.DeliverySignedArtifact
	prior                   map[string]vmqual.DeliverySignedArtifact
	badSignatures           map[string]vmqual.DeliverySignedArtifact
	badDigests              map[string]vmqual.DeliverySignedArtifact
	candidateManifest       vmqual.DeliveryArchitectureManifest
	candidateManifestDigest string
	priorManifestDigest     string
}

func newDeliveryContractRelease() (*deliveryContractRelease, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("vmqual: generate delivery signing key: %w", err)
	}
	trust, err := delivery.NewTrustSet(map[string]ed25519.PublicKey{"vmqual-release": publicKey})
	if err != nil {
		return nil, err
	}
	build := func(version string) (vmqual.DeliveryArchitectureManifest, map[string]vmqual.DeliverySignedArtifact, string, error) {
		manifest := vmqual.DeliveryArchitectureManifest{SchemaVersion: vmqual.DeliveryContractSchemaVersion, Service: vmqual.DeliveryContractService, Version: version}
		artifacts := make(map[string]vmqual.DeliverySignedArtifact, 2)
		for _, architecture := range []string{"linux/amd64", "linux/arm64"} {
			body := []byte("terrabase-" + version + "-" + architecture + "\n")
			identity := vmqual.DeliveryArtifactIdentity{Architecture: architecture, Digest: delivery.SHA256Digest(body), Size: int64(len(body))}
			manifest.Artifacts = append(manifest.Artifacts, identity)
			artifacts[architecture] = vmqual.DeliverySignedArtifact{Identity: identity, Body: body, Signature: ed25519.Sign(privateKey, body)}
		}
		digest, validateErr := vmqual.ValidateDeliveryArchitectureManifest(manifest, artifacts, publicKey)
		return manifest, artifacts, digest, validateErr
	}
	candidateManifest, candidates, candidateDigest, err := build("qualification-candidate")
	if err != nil {
		return nil, err
	}
	_, prior, priorDigest, err := build("qualification-prior")
	if err != nil {
		return nil, err
	}
	badSignatures := cloneDeliveryArtifacts(candidates)
	badDigests := cloneDeliveryArtifacts(candidates)
	for architecture, artifact := range badSignatures {
		artifact.Signature[0] ^= 0xff
		badSignatures[architecture] = artifact
	}
	for architecture, artifact := range badDigests {
		artifact.Identity.Digest = delivery.SHA256Digest([]byte("wrong-" + architecture))
		badDigests[architecture] = artifact
	}
	return &deliveryContractRelease{
		publicKey: publicKey, privateKey: privateKey, trust: trust,
		candidates: candidates, prior: prior, badSignatures: badSignatures, badDigests: badDigests,
		candidateManifest: candidateManifest, candidateManifestDigest: candidateDigest, priorManifestDigest: priorDigest,
	}, nil
}

func (r *deliveryContractRelease) edgeArtifact(name string) vmqual.DeliverySignedArtifact {
	body := []byte(name + "\n")
	identity := vmqual.DeliveryArtifactIdentity{Architecture: "multi", Digest: delivery.SHA256Digest(body), Size: int64(len(body))}
	return vmqual.DeliverySignedArtifact{Identity: identity, Body: body, Signature: ed25519.Sign(r.privateKey, body)}
}

func (r *deliveryContractRelease) edgeManifestDigest(name string) string {
	return delivery.SHA256Digest([]byte("edge-manifest-v1:" + name))
}

func cloneDeliveryArtifacts(input map[string]vmqual.DeliverySignedArtifact) map[string]vmqual.DeliverySignedArtifact {
	output := make(map[string]vmqual.DeliverySignedArtifact, len(input))
	for architecture, artifact := range input {
		artifact.Body = append([]byte(nil), artifact.Body...)
		artifact.Signature = append([]byte(nil), artifact.Signature...)
		output[architecture] = artifact
	}
	return output
}

func deliveryContractSystemdUnit(artifact vmqual.DeliverySignedArtifact) (string, error) {
	spec, err := hostagent.NewComponentSpec(hostagent.ComponentSpec{
		Name: "terrabase", Version: "qualification-candidate",
		ArtifactURL: "https://forgejo.terrascale.invalid/releases/terrabase", SignatureURL: "https://forgejo.terrascale.invalid/releases/terrabase.sig",
		Sha256: strings.TrimPrefix(artifact.Identity.Digest, "sha256:"), User: "terrabase", DataVolume: "/var/lib/terrascale/terrabase",
		CPUWeight: 1000, MemoryMaxBytes: 8 << 30, IOWeight: 1000,
	})
	if err != nil {
		return "", err
	}
	return hostagent.RenderSystemdUnit("/opt/terrascale", spec)
}

func validateTSNodeGuestObservation(observation vmqual.TSNodeGuestObservation, qualification vmqual.TSNodeGuestQualification) error {
	if observation.Host != vmqual.DeliveryContractCanary {
		return fmt.Errorf("vmqual: ts-node qualification came from %q, want %s", observation.Host, vmqual.DeliveryContractCanary)
	}
	candidate, ok := qualification.Candidates[observation.NativeArchitecture]
	if !ok {
		return fmt.Errorf("vmqual: guest reported unsupported native architecture %q", observation.NativeArchitecture)
	}
	if !delivery.SameDigest(observation.InstalledDigest, candidate.Identity.Digest) || !delivery.SameDigest(observation.ActiveDigest, candidate.Identity.Digest) {
		return errors.New("vmqual: ts-node did not install and activate the native signed artifact")
	}
	if observation.SystemdUnit != qualification.ExpectedSystemdUnit {
		return errors.New("vmqual: guest systemd unit is not the exact hardened production unit")
	}
	if !bytes.Equal(observation.PersistentBeforeRestart, qualification.PersistenceSentinel) || !bytes.Equal(observation.PersistentAfterRestart, qualification.PersistenceSentinel) {
		return errors.New("vmqual: guest data was not persistent across restart")
	}
	wanted := map[string]bool{"candidate": true, "bad-signature": false, "bad-digest": false}
	wantedDigest := map[string]string{
		"candidate":     candidate.Identity.Digest,
		"bad-signature": qualification.BadSignature[observation.NativeArchitecture].Identity.Digest,
		"bad-digest":    qualification.BadDigest[observation.NativeArchitecture].Identity.Digest,
	}
	seen := make(map[string]bool, len(wanted))
	for _, attempt := range observation.InstallAttempts {
		expected, exists := wanted[attempt.Name]
		if !exists || seen[attempt.Name] || attempt.Architecture != observation.NativeArchitecture || attempt.Accepted != expected || !delivery.SameDigest(attempt.Digest, wantedDigest[attempt.Name]) {
			return errors.New("vmqual: guest returned invalid ts-node install-attempt evidence")
		}
		seen[attempt.Name] = true
	}
	if len(seen) != len(wanted) {
		return errors.New("vmqual: guest omitted a required ts-node install attempt")
	}
	return nil
}

func validateDeliveryContractProviders(config DeliveryContractConfig) error {
	if config.Endpoints == nil || config.Endpoints.Edge == nil || config.Endpoints.EdgeURL == "" || len(config.Endpoints.edgeKey) == 0 {
		return errors.New("vmqual: delivery contract requires the local edge endpoint")
	}
	if !filepath.IsAbs(config.StateRoot) || filepath.Clean(config.StateRoot) != config.StateRoot {
		return errors.New("vmqual: delivery contract state root must be clean and absolute")
	}
	if len(config.Endpoints.Object) != 3 || len(config.Endpoints.ObjectURL) != 3 {
		return errors.New("vmqual: delivery contract requires three local object stores")
	}
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		store := config.Endpoints.Object[region]
		if store == nil || config.Endpoints.ObjectURL[region] == "" || !vmqual.PathWithin(config.StateRoot, store.Root()) {
			return fmt.Errorf("vmqual: %s object store is not persistent under the qualification state root", region)
		}
	}
	return nil
}

type deliveryContractFetch struct {
	body      []byte
	signature []byte
}

type deliveryContractFetcher struct {
	mu        sync.RWMutex
	artifacts map[string]deliveryContractFetch
}

func (f *deliveryContractFetcher) put(operation string, artifact vmqual.DeliverySignedArtifact) {
	f.mu.Lock()
	f.artifacts[operation] = deliveryContractFetch{body: append([]byte(nil), artifact.Body...), signature: append([]byte(nil), artifact.Signature...)}
	f.mu.Unlock()
}

func (f *deliveryContractFetcher) Fetch(ctx context.Context, request *delivery.Request) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if request == nil {
		return nil, nil, errors.New("vmqual: delivery fetch request is nil")
	}
	f.mu.RLock()
	artifact, ok := f.artifacts[request.OperationID]
	f.mu.RUnlock()
	if !ok {
		return nil, nil, fmt.Errorf("vmqual: no artifact for operation %s", request.OperationID)
	}
	return append([]byte(nil), artifact.body...), append([]byte(nil), artifact.signature...), nil
}

func deliveryContractRequest(operation, service, kind, architecture, digest, manifestDigest string, rollback *delivery.RollbackArtifact) *delivery.Request {
	return &delivery.Request{
		SchemaVersion:         delivery.ContractVersion,
		OperationID:           operation,
		Source:                &delivery.Source{Repository: "terrascale/" + service, Commit: strings.Repeat("a", 40), TreeDigest: delivery.SHA256Digest([]byte("tree:" + operation))},
		Artifact:              &delivery.Artifact{Digest: digest, ManifestDigest: manifestDigest, Kind: kind, Architecture: architecture},
		Target:                &delivery.Target{Service: service, Environment: "local", Regions: []string{"gru", "sfo", "fra"}},
		ConfigurationRevision: delivery.SHA256Digest([]byte("configuration:v1")),
		RequestedBy:           "vmqual", Reason: "local delivery qualification", Rollback: rollback,
	}
}

func submitDeliveryContract(ctx context.Context, server *delivery.Server, request *delivery.Request) (*delivery.Receipt, error) {
	if err := delivery.ValidateRequest(request); err != nil {
		return nil, err
	}
	httpRequest := httptest.NewRequest(http.MethodPost, delivery.OperationsPath, bytes.NewBufferString(delivery.Serialize(request))).WithContext(ctx)
	httpRequest.Header.Set("Authorization", "Bearer "+vmqual.DeliveryContractToken)
	httpRequest.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httpRequest)
	response := recorder.Result()
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, delivery.MaxDocumentBytes+1))
	if err != nil || len(body) > delivery.MaxDocumentBytes {
		return nil, errors.New("vmqual: delivery API returned an invalid bounded response")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vmqual: delivery API returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	receipt, err := delivery.ParseReceipt(string(body))
	if err != nil {
		return nil, fmt.Errorf("vmqual: parse delivery receipt: %w", err)
	}
	if err := delivery.ValidateReceipt(receipt, request); err != nil {
		return nil, fmt.Errorf("vmqual: validate delivery receipt: %w", err)
	}
	return receipt, nil
}

func requireSuccessfulDeliveryReceipt(receipt *delivery.Receipt, request *delivery.Request) error {
	if receipt == nil || receipt.Status != delivery.StatusSucceeded || receipt.Provenance == nil || !receipt.Provenance.Verified || receipt.Health == nil || !receipt.Health.Converged || receipt.Rollback == nil || receipt.Rollback.Status != delivery.RollbackNotRequired {
		return errors.New("receipt is not a verified converged success")
	}
	return delivery.ValidateReceipt(receipt, request)
}

func requireUnverifiedReceipt(receipt *delivery.Receipt) error {
	if receipt == nil || receipt.Status != delivery.StatusFailed || receipt.Provenance == nil || receipt.Provenance.Verified || receipt.Health == nil || receipt.Health.Converged || receipt.Error == nil || receipt.Error.Code == nil || *receipt.Error.Code != "artifact_unverified" {
		return errors.New("receipt did not fail closed at artifact verification")
	}
	return nil
}

func requireRolledBackReceipt(receipt *delivery.Receipt, request *delivery.Request) error {
	if receipt == nil || receipt.Status != delivery.StatusRolledBack || receipt.Provenance == nil || !receipt.Provenance.Verified || receipt.Rollback == nil || !receipt.Rollback.Attempted || receipt.Rollback.Status != delivery.RollbackSucceeded || receipt.Rollback.TargetArtifactDigest == nil || receipt.Rollback.TargetManifestDigest == nil || request.Rollback == nil {
		return errors.New("receipt is not an exact successful rollback")
	}
	if !delivery.SameDigest(*receipt.Rollback.TargetArtifactDigest, request.Rollback.ArtifactDigest) || !delivery.SameDigest(*receipt.Rollback.TargetManifestDigest, request.Rollback.ManifestDigest) {
		return errors.New("receipt rollback identity does not match the exact prior artifact")
	}
	return delivery.ValidateReceipt(receipt, request)
}

type deliveryContractInventory struct{}

func (deliveryContractInventory) Hosts(ctx context.Context, region string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hosts, ok := deliveryContractHosts[region]
	if !ok || len(hosts) != 2 {
		return nil, fmt.Errorf("vmqual: Region %s does not have the required RF=2 inventory", region)
	}
	return append([]string(nil), hosts...), nil
}

type deliveryContractMutation struct {
	kind   string
	host   string
	digest string
}

type deliveryContractHostControl struct {
	guest       vmqual.DeliveryGuestControl
	mu          sync.Mutex
	mutations   []deliveryContractMutation
	cordoned    map[string]bool
	maxCordoned map[string]int
	gateChecks  map[string]int
}

func newDeliveryContractHostControl(guest vmqual.DeliveryGuestControl) *deliveryContractHostControl {
	return &deliveryContractHostControl{guest: guest, cordoned: make(map[string]bool), maxCordoned: make(map[string]int), gateChecks: make(map[string]int)}
}

func deliveryContractHostRegion(host string) string {
	if separator := strings.IndexByte(host, '-'); separator > 0 {
		return host[:separator]
	}
	return ""
}

func (c *deliveryContractHostControl) Cordon(ctx context.Context, host string, cordoned bool) error {
	region := deliveryContractHostRegion(host)
	if len(deliveryContractHosts[region]) != 2 {
		return fmt.Errorf("vmqual: rollout addressed unknown host %s", host)
	}
	if cordoned {
		c.mu.Lock()
		active := 0
		for _, candidate := range deliveryContractHosts[region] {
			if c.cordoned[candidate] {
				active++
			}
		}
		c.mu.Unlock()
		if active != 0 {
			return fmt.Errorf("vmqual: rollout attempted concurrent host drains in %s", region)
		}
	}
	if err := c.guest.Cordon(ctx, host, cordoned); err != nil {
		return err
	}
	c.mu.Lock()
	c.cordoned[host] = cordoned
	count := 0
	for _, candidate := range deliveryContractHosts[region] {
		if c.cordoned[candidate] {
			count++
		}
	}
	if count > c.maxCordoned[region] {
		c.maxCordoned[region] = count
	}
	c.mutations = append(c.mutations, deliveryContractMutation{kind: "cordon:" + strconv.FormatBool(cordoned), host: host})
	c.mu.Unlock()
	return nil
}

func (c *deliveryContractHostControl) DrainStatus(ctx context.Context, host string) (delivery.DrainReport, error) {
	report, err := c.guest.DrainStatus(ctx, host)
	if err != nil {
		return delivery.DrainReport{}, err
	}
	c.mu.Lock()
	c.mutations = append(c.mutations, deliveryContractMutation{kind: "drain", host: host})
	c.mu.Unlock()
	return report, nil
}

func (c *deliveryContractHostControl) Converge(ctx context.Context, host string, plan []byte) error {
	digest, err := digestFromDeliveryPlan(plan)
	if err != nil {
		return err
	}
	if err := c.guest.Converge(ctx, host, plan); err != nil {
		return err
	}
	c.mu.Lock()
	c.mutations = append(c.mutations, deliveryContractMutation{kind: "converge", host: host, digest: digest})
	c.mu.Unlock()
	return nil
}

func digestFromDeliveryPlan(plan []byte) (string, error) {
	var wire struct {
		ArtifactDigest struct {
			Value string `json:"value"`
		} `json:"artifactDigest"`
	}
	decoder := json.NewDecoder(bytes.NewReader(plan))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		// Runtime plans intentionally grow additively. Decode a bounded generic
		// projection when DisallowUnknownFields rejects those owned fields.
		var projection map[string]json.RawMessage
		if projectionErr := json.Unmarshal(plan, &projection); projectionErr != nil {
			return "", errors.New("vmqual: rollout emitted an invalid runtime plan")
		}
		if projectionErr := json.Unmarshal(projection["artifactDigest"], &wire.ArtifactDigest); projectionErr != nil {
			return "", errors.New("vmqual: rollout plan omitted its artifact digest")
		}
	}
	if len(wire.ArtifactDigest.Value) != 64 {
		return "", errors.New("vmqual: rollout plan carried an invalid artifact digest")
	}
	return "sha256:" + wire.ArtifactDigest.Value, nil
}

func (c *deliveryContractHostControl) recordGate(name string) {
	c.mu.Lock()
	c.gateChecks[name]++
	c.mu.Unlock()
}

func (c *deliveryContractHostControl) mutationCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.mutations)
}

func (c *deliveryContractHostControl) reset() {
	c.mu.Lock()
	c.mutations = nil
	c.maxCordoned = make(map[string]int)
	c.gateChecks = make(map[string]int)
	c.mu.Unlock()
}

func (c *deliveryContractHostControl) rolloutState(candidate, prior string) ([]string, []string, map[string]int, map[string]int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var forward, backward []string
	for _, mutation := range c.mutations {
		if mutation.kind != "converge" {
			continue
		}
		if delivery.SameDigest(mutation.digest, candidate) {
			forward = append(forward, mutation.host)
		}
		if delivery.SameDigest(mutation.digest, prior) {
			backward = append(backward, mutation.host)
		}
	}
	maximum := make(map[string]int, len(c.maxCordoned))
	for region, count := range c.maxCordoned {
		maximum[region] = count
	}
	checks := make(map[string]int, len(c.gateChecks))
	for gate, count := range c.gateChecks {
		checks[gate] = count
	}
	return forward, backward, maximum, checks
}

type deliveryContractGate struct {
	name       string
	guest      vmqual.DeliveryGuestControl
	tracker    *deliveryContractHostControl
	mu         sync.Mutex
	failDigest string
	failHost   string
}

func (g *deliveryContractGate) Name() string { return g.name }

func (g *deliveryContractGate) inject(digest, host string) {
	g.mu.Lock()
	g.failDigest, g.failHost = digest, host
	g.mu.Unlock()
}

func (g *deliveryContractGate) Check(ctx context.Context, host, digest string) error {
	observation, err := g.guest.CheckDeliveryGate(ctx, host, digest, g.name)
	if err != nil {
		return err
	}
	if observation.Host != host || observation.Gate != g.name || !delivery.SameDigest(observation.Digest, digest) || !observation.Passed {
		return fmt.Errorf("vmqual: guest %s did not pass %s for the candidate digest", host, g.name)
	}
	g.tracker.recordGate(g.name)
	g.mu.Lock()
	fail := host == g.failHost && delivery.SameDigest(digest, g.failDigest)
	g.mu.Unlock()
	if fail {
		return errors.New("vmqual: injected guest gate failure")
	}
	return nil
}

type deliveryContractClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *deliveryContractClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *deliveryContractClock) Wait(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
	return nil
}

func validateHostRolloutState(forward, backward []string, maximum, gateChecks map[string]int) error {
	wantForward := []string{"gru-member-1", "gru-member-2", "sfo-member-1", "sfo-member-2"}
	wantBackward := []string{"sfo-member-2", "sfo-member-1", "gru-member-2", "gru-member-1"}
	if strings.Join(forward, ",") != strings.Join(wantForward, ",") {
		return fmt.Errorf("vmqual: host rollout order %v does not start with the GRU canary and proceed one at a time", forward)
	}
	if strings.Join(backward, ",") != strings.Join(wantBackward, ",") {
		return fmt.Errorf("vmqual: touched-host rollback order %v is incomplete", backward)
	}
	for _, region := range []string{"gru", "sfo", "fra"} {
		if len(deliveryContractHosts[region]) != 2 || maximum[region] > 1 {
			return fmt.Errorf("vmqual: rollout did not preserve the two-host %s inventory", region)
		}
	}
	for _, gate := range []string{"process-health", "external-health", vmqual.DeliveryContractFailureGate} {
		if gateChecks[gate] == 0 {
			return fmt.Errorf("vmqual: rollout never observed the %s gate", gate)
		}
	}
	return nil
}

type deliveryContractEdgeState struct {
	workerEvents      []string
	snippetEvents     []string
	workerDigest      string
	snippetDigest     string
	snippetRuleDigest string
}

func hasEdgePromotionAndRollback(events []string, candidate, prior string) bool {
	candidateIndex, priorIndex := -1, -1
	for index, event := range events {
		if strings.Contains(event, candidate) && candidateIndex < 0 {
			candidateIndex = index
		}
		if strings.Contains(event, prior) {
			priorIndex = index
		}
	}
	return candidateIndex >= 0 && priorIndex > candidateIndex
}

type deliveryReactiveObservation struct {
	responses, cacheHits uint64
	workerFree           bool
}

func probeDeliveryReactivePath(ctx context.Context, endpoints *LocalProviderEndpoints, client *http.Client) (deliveryReactiveObservation, error) {
	var result deliveryReactiveObservation
	spec := estate.Default()
	hasSnippet := false
	for _, rule := range spec.Cloudflare.SnippetRules {
		if rule.Hostname == "sync.api.terrascale.tech" {
			hasSnippet = true
		}
	}
	for _, route := range spec.Cloudflare.WorkerRoutes {
		if route.Hostname == "sync.api.terrascale.tech" || route.Hostname == "*.terrascale.tech" {
			return result, errors.New("vmqual: a Worker route covers the reactive hot path")
		}
	}
	if !hasSnippet {
		return result, errors.New("vmqual: the reactive hot path has no Snippet capability rule")
	}
	now := time.Now().UTC()
	// Each probe must observe a fresh cache fill followed by a hit, even
	// when another scenario has already exercised this provider instance.
	viewID := "delivery-contract-" + rand.Text()
	capability, err := edge.MintCapability(endpoints.edgeKey, viewID, 1, "rule:v1", 1, "GRU", now)
	if err != nil {
		return result, err
	}
	before := endpoints.Edge.Metrics()
	for attempt := 0; attempt < 2; attempt++ {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, endpoints.EdgeURL+"/api/v1/reactive/views/"+viewID+"/1/log?offset=0", nil)
		if requestErr != nil {
			return result, requestErr
		}
		request.Header.Set(edge.CapabilityHeader, capability)
		response, requestErr := client.Do(request)
		if requestErr != nil {
			return result, requestErr
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK {
			return result, fmt.Errorf("vmqual: reactive Snippet-capability request returned %s", response.Status)
		}
		result.responses++
	}
	after := endpoints.Edge.Metrics()
	if after.CacheableResponses < before.CacheableResponses+1 || after.CacheHits < before.CacheHits+1 {
		return result, errors.New("vmqual: reactive Snippet path did not remain cache eligible")
	}
	result.cacheHits = after.CacheHits - before.CacheHits
	result.workerFree = true
	return result, nil
}

type deliveryContractObjectStore struct {
	endpoints *LocalProviderEndpoints
	client    *http.Client
	mu        sync.Mutex
	checker   delivery.FenceChecker
	expected  map[string]map[string]delivery.ObjectIdentity
}

func (s *deliveryContractObjectStore) setFenceChecker(checker delivery.FenceChecker) {
	s.mu.Lock()
	s.checker = checker
	s.mu.Unlock()
}

func (s *deliveryContractObjectStore) ensureReleaseBuckets(ctx context.Context) error {
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		payload := bytes.NewBufferString(`{"name":"releases","versioning":"Enabled"}`)
		target := s.endpoints.ObjectURL[region] + "/n/" + url.PathEscape(s.endpoints.Object[region].Namespace()) + "/b/"
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, payload)
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := s.client.Do(request)
		if err != nil {
			return fmt.Errorf("vmqual: create %s release bucket: %w", region, err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusConflict {
			return fmt.Errorf("vmqual: create %s release bucket returned %s", region, response.Status)
		}
		if response.StatusCode == http.StatusConflict {
			versionRequest, requestErr := http.NewRequestWithContext(ctx, http.MethodPut, target+"releases", bytes.NewBufferString(`{"versioning":"Enabled"}`))
			if requestErr != nil {
				return requestErr
			}
			versionRequest.Header.Set("Content-Type", "application/json")
			versionResponse, requestErr := s.client.Do(versionRequest)
			if requestErr != nil {
				return fmt.Errorf("vmqual: enable %s release bucket versioning: %w", region, requestErr)
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(versionResponse.Body, 4096))
			versionResponse.Body.Close()
			if versionResponse.StatusCode != http.StatusOK {
				return fmt.Errorf("vmqual: enable %s release bucket versioning returned %s", region, versionResponse.Status)
			}
		}
	}
	return nil
}

func (s *deliveryContractObjectStore) Put(ctx context.Context, region, bucket, object string, body []byte) error {
	_, err := s.put(ctx, region, bucket, object, body)
	return err
}

func (s *deliveryContractObjectStore) PutWithIdentity(ctx context.Context, region, bucket, object string, body []byte) (delivery.ObjectIdentity, error) {
	return s.put(ctx, region, bucket, object, body)
}

func (s *deliveryContractObjectStore) PutFenced(ctx context.Context, region, bucket, object string, body []byte, fence delivery.OperationFence) error {
	_, err := s.PutWithIdentityFenced(ctx, region, bucket, object, body, fence)
	return err
}

func (s *deliveryContractObjectStore) PutWithIdentityFenced(ctx context.Context, region, bucket, object string, body []byte, fence delivery.OperationFence) (delivery.ObjectIdentity, error) {
	s.mu.Lock()
	checker := s.checker
	s.mu.Unlock()
	if checker == nil || fence.OperationID == "" || fence.OwnerID == "" || fence.Generation == 0 {
		return delivery.ObjectIdentity{}, delivery.ErrOperationLeaseActive
	}
	if err := checker(fence); err != nil {
		return delivery.ObjectIdentity{}, err
	}
	return s.put(ctx, region, bucket, object, body)
}

func (s *deliveryContractObjectStore) put(ctx context.Context, region, bucket, object string, body []byte) (delivery.ObjectIdentity, error) {
	target, err := s.objectURL(region, bucket, object)
	if err != nil {
		return delivery.ObjectIdentity{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		return delivery.ObjectIdentity{}, err
	}
	request.Header.Set("If-None-Match", "*")
	request.Header.Set("opc-meta-terrascale-sha256", strings.TrimPrefix(delivery.SHA256Digest(body), "sha256:"))
	response, err := s.client.Do(request)
	if err != nil {
		return delivery.ObjectIdentity{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return delivery.ObjectIdentity{}, fmt.Errorf("object PUT returned %s: %s", response.Status, strings.TrimSpace(string(payload)))
	}
	identity, err := objectIdentityFromResponse(response)
	if err != nil {
		return delivery.ObjectIdentity{}, err
	}
	s.recordExpected(region, bucket, object, identity)
	return identity, nil
}

func (s *deliveryContractObjectStore) Head(ctx context.Context, region, bucket, object string) (delivery.ObjectIdentity, bool, error) {
	target, err := s.objectURL(region, bucket, object)
	if err != nil {
		return delivery.ObjectIdentity{}, false, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return delivery.ObjectIdentity{}, false, err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return delivery.ObjectIdentity{}, false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return delivery.ObjectIdentity{}, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return delivery.ObjectIdentity{}, false, fmt.Errorf("object HEAD returned %s", response.Status)
	}
	identity, err := objectIdentityFromResponse(response)
	if err == nil {
		s.recordExpected(region, bucket, object, identity)
	}
	return identity, err == nil, err
}

func (s *deliveryContractObjectStore) recordExpected(region, bucket, object string, identity delivery.ObjectIdentity) {
	key := bucket + "/" + object
	s.mu.Lock()
	if s.expected[region] == nil {
		s.expected[region] = make(map[string]delivery.ObjectIdentity)
	}
	s.expected[region][key] = identity
	s.mu.Unlock()
}

func (s *deliveryContractObjectStore) objectURL(region, bucket, object string) (string, error) {
	code := vmnet.RegionCode(strings.ToUpper(region))
	store, base := s.endpoints.Object[code], s.endpoints.ObjectURL[code]
	if store == nil || base == "" || bucket != "releases" || object == "" {
		return "", fmt.Errorf("vmqual: invalid local mirror target %s/%s/%s", region, bucket, object)
	}
	return base + "/n/" + url.PathEscape(store.Namespace()) + "/b/" + url.PathEscape(bucket) + "/o/" + url.PathEscape(object), nil
}

func objectIdentityFromResponse(response *http.Response) (delivery.ObjectIdentity, error) {
	digest := response.Header.Get("opc-meta-terrascale-sha256")
	if digest == "" {
		return delivery.ObjectIdentity{}, errors.New("vmqual: object response omitted sha256 metadata")
	}
	size := response.ContentLength
	if size < 0 {
		var err error
		size, err = strconv.ParseInt(response.Header.Get("Content-Length"), 10, 64)
		if err != nil {
			return delivery.ObjectIdentity{}, errors.New("vmqual: object response omitted size")
		}
	}
	return delivery.ObjectIdentity{Digest: "sha256:" + strings.TrimPrefix(digest, "sha256:"), Size: size, ETag: response.Header.Get("ETag"), Version: response.Header.Get("opc-version-id")}, nil
}

func (s *deliveryContractObjectStore) verifyPersistent(ctx context.Context, stateRoot string, expectedObjects []string) ([]DeliveryMirrorObservation, error) {
	s.mu.Lock()
	expected := make(map[string]map[string]delivery.ObjectIdentity, len(s.expected))
	for region, objects := range s.expected {
		expected[region] = make(map[string]delivery.ObjectIdentity, len(objects))
		for name, identity := range objects {
			expected[region][name] = identity
		}
	}
	s.mu.Unlock()
	var observations []DeliveryMirrorObservation
	for _, code := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		region := strings.ToLower(string(code))
		live := s.endpoints.Object[code]
		if live == nil || !vmqual.PathWithin(stateRoot, live.Root()) {
			return nil, fmt.Errorf("vmqual: %s mirror root is not persistent", region)
		}
		fresh, err := objectstore.New(objectstore.Config{Root: live.Root(), Namespace: live.Namespace()})
		if err != nil {
			return nil, fmt.Errorf("vmqual: reopen persistent %s mirror: %w", region, err)
		}
		for _, object := range expectedObjects {
			key := "releases/" + object
			want, ok := expected[region][key]
			if !ok {
				_ = fresh.Close()
				return nil, fmt.Errorf("vmqual: %s never recorded mirror %s", region, object)
			}
			request := httptest.NewRequest(http.MethodHead, "/n/"+url.PathEscape(live.Namespace())+"/b/releases/o/"+url.PathEscape(object), nil).WithContext(ctx)
			recorder := httptest.NewRecorder()
			fresh.ServeHTTP(recorder, request)
			response := recorder.Result()
			if response.StatusCode != http.StatusOK {
				response.Body.Close()
				_ = fresh.Close()
				return nil, fmt.Errorf("vmqual: reopened %s mirror cannot read %s", region, object)
			}
			got, identityErr := objectIdentityFromResponse(response)
			response.Body.Close()
			if identityErr != nil || !delivery.SameDigest(got.Digest, want.Digest) || got.Size != want.Size {
				_ = fresh.Close()
				return nil, fmt.Errorf("vmqual: reopened %s mirror identity changed for %s", region, object)
			}
			observations = append(observations, DeliveryMirrorObservation{Region: region, Bucket: "releases", Object: object, Digest: got.Digest, Size: got.Size})
		}
		_ = fresh.Close()
	}
	sort.Slice(observations, func(i, j int) bool {
		if observations[i].Region != observations[j].Region {
			return observations[i].Region < observations[j].Region
		}
		return observations[i].Object < observations[j].Object
	})
	return observations, nil
}

var (
	_ delivery.FencedRegionObjectStoreIdentityWriter = (*deliveryContractObjectStore)(nil)
	_ delivery.RegionObjectStoreInspector            = (*deliveryContractObjectStore)(nil)
)
