package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestReserveSlotRecoversLostAcknowledgementAndSurvivesRestart(t *testing.T) {
	fixture := newLedgerFixture(t)
	fixture.client.loseAckForBucket("bootstrap-ledger")
	scope := testBootstrapScope()
	intentBytes, _ := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
	headBytes := fixture.headBytes(t, scope, intentBytes, 1)

	reserved, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes)
	if err != nil {
		t.Fatalf("reserve after lost intent acknowledgement: %v", err)
	}
	if reserved.IntentDigest() != bodyDigest(intentBytes) || reserved.Attempt() != 1 || reserved.HeadETag() == "" {
		t.Fatalf("reservation does not identify the verified slot: %+v", reserved)
	}
	if got := fixture.client.putCalls.Load(); got != 2 {
		t.Fatalf("PUT calls = %d, want immutable intent and initial HEAD", got)
	}
	if got := fixture.client.getCalls.Load(); got != 9 {
		t.Fatalf("exact-key readbacks = %d, want intent/HEAD confirmations, final intent refresh, seed-receipt absence, and verified-slot reads", got)
	}

	restarted := fixture.newLedger(t)
	launch, err := restarted.ReadForLaunch(t.Context(), scope)
	if err != nil {
		t.Fatalf("read launch authorization after restart: %v", err)
	}
	if launch.IntentDigest() != reserved.IntentDigest() || launch.HeadETag() != reserved.HeadETag() {
		t.Fatalf("restart changed durable reservation: before=%+v after=%+v", reserved, launch)
	}

	duplicate, err := restarted.ReserveSlot(t.Context(), scope, intentBytes, headBytes)
	if err != nil {
		t.Fatalf("idempotently reserve exact signed bytes: %v", err)
	}
	if duplicate.HeadETag() != launch.HeadETag() {
		t.Fatalf("idempotent reservation changed HEAD ETag: got %q, want %q", duplicate.HeadETag(), launch.HeadETag())
	}
}

type seedReceiptReadErrorClient struct {
	ObjectStorageClient
	objectName string
	err        error
}

func (client seedReceiptReadErrorClient) GetObject(ctx context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	if request.ObjectName != nil && *request.ObjectName == client.objectName {
		return objectstorage.GetObjectResponse{}, client.err
	}
	return client.ObjectStorageClient.GetObject(ctx, request)
}

func (fixture *ledgerFixture) resignReceiptUntil(t *testing.T, body []byte, expiresAt time.Time) []byte {
	t.Helper()
	envelope, err := trust.DecodeEnvelope(body)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := fixture.authority.peerPrivate
	if envelope.Scope.Domain == seedReceiptDomain {
		privateKey = fixture.authority.rootPrivate
	}
	signed, err := trust.Sign([]byte(envelope.Payload), envelope.Scope, envelope.IssuedAt, expiresAt, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeEnvelope(signed)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestLedgerFailsClosedOnUnknownPermanentAndMalformedStorageOutcomes(t *testing.T) {
	t.Run("lost acknowledgement with missing readback", func(t *testing.T) {
		fixture := newLedgerFixture(t)
		fixture.client.failBeforeCommit.Store(true)
		scope := testBootstrapScope()
		intentBytes, _ := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
		headBytes := fixture.headBytes(t, scope, intentBytes, 1)
		if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes); !errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("missing exact-key readback after lost acknowledgement = %v, want ErrOutcomeUnknown", err)
		}
		if got := fixture.client.objectCount(); got != 0 {
			t.Fatalf("objects after pre-commit failure = %d, want zero", got)
		}
	})

	t.Run("permanent create failure", func(t *testing.T) {
		fixture := newLedgerFixture(t)
		fixture.client.rejectPut = fakeObjectStorageError{status: http.StatusForbidden}
		scope := testBootstrapScope()
		intentBytes, _ := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
		headBytes := fixture.headBytes(t, scope, intentBytes, 1)
		if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes); err == nil || errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("permanent storage rejection = %v, want the terminal service error", err)
		}
		if got := fixture.client.getCalls.Load(); got != 0 {
			t.Fatalf("GET calls after permanent storage rejection = %d, want no read after a terminal create error", got)
		}
	})

	t.Run("missing server Date", func(t *testing.T) {
		fixture := newLedgerFixture(t)
		scope := testBootstrapScope()
		intentBytes, _ := fixture.intentBytes(t, scope, 1, "create-key-1", "retry-token-1")
		headBytes := fixture.headBytes(t, scope, intentBytes, 1)
		if _, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes); err != nil {
			t.Fatalf("reserve before metadata fault: %v", err)
		}
		fixture.client.omitServerDate.Store(true)
		if _, err := fixture.ledger.ReadSlot(t.Context(), scope); err == nil {
			t.Fatal("slot read accepted missing server Date metadata")
		}
	})
}

func TestExternalSeedRequiresRootReceiptAndNeverAuthorizesOCIProvisioning(t *testing.T) {
	fixture := newLedgerFixture(t)
	scope := testBootstrapScope()
	intentBytes, intent := fixture.intentBytes(t, scope, 1, "bootstrap-create-a", "retry-token-1")
	intent.Mode = IntentModeExternalSeed
	intent.SchemaVersion = 1
	intent.RetryToken = ""
	intent.FounderPlanSHA256 = ""
	intent.PeerRowDigest = ""
	intent.ReviewedPlanDigest = bodyDigest([]byte("reviewed OpenTofu plan"))
	intentBytes, intent = fixture.bindIntentManifest(t, scope, intent, fixture.now)
	headBytes := fixture.headBytes(t, scope, intentBytes, 1)
	reserved, err := fixture.ledger.ReserveSlot(t.Context(), scope, intentBytes, headBytes)
	if err != nil {
		t.Fatalf("reserve external seed slot: %v", err)
	}
	if reserved.Intent.Mode != IntentModeExternalSeed || reserved.Intent.RetryToken != "" ||
		reserved.Intent.CreateKey != "bootstrap-create-a" || reserved.Intent.ReviewedPlanDigest != bodyDigest([]byte("reviewed OpenTofu plan")) {
		t.Fatalf("stored external seed identity is incomplete: %+v", reserved)
	}
	if _, err := fixture.ledger.ReadForLaunch(t.Context(), scope); !errors.Is(err, ErrExternalSeedMode) {
		t.Fatalf("external seed launch authorization returned %v, want explicit denial", err)
	}
	manifestBytes, receiptBytes, facts := fixture.seedProof(t, scope, intent, bodyDigest(intentBytes))
	result := fixture.result(scope, intent, bodyDigest(intentBytes))
	result.Mode = IntentModeExternalSeed
	result.SeedReceiptDigest = bodyDigest(receiptBytes)
	resultBytes := fixture.sign(t, scope, domainBootstrapResult, result, fixture.now)
	completedHead := reserved.Head
	completedHead.ResultDigest = bodyDigest(resultBytes)
	completedHeadBytes := fixture.sign(t, scope, domainBootstrapHead, completedHead, fixture.now)
	if _, err := fixture.ledger.RecordResult(t.Context(), scope, resultBytes, completedHeadBytes); !errors.Is(err, ErrExternalSeedMode) {
		t.Fatalf("generic OCI result write for external seed returned %v, want receipt-gated refusal", err)
	}
	if got := fixture.client.objectCount(); got != 2 {
		t.Fatalf("external seed generic result path wrote an object: object count = %d, want only intent and HEAD", got)
	}
	fixture.client.loseAckForBucket("bootstrap-head")
	state, err := fixture.ledger.RecordExternalSeed(t.Context(), scope, manifestBytes, receiptBytes, facts, resultBytes, completedHeadBytes)
	if err != nil {
		t.Fatalf("record root-receipt-gated external seed: %v", err)
	}
	if state.Result == nil || state.SeedReceipt == nil || state.SeedReceiptRecord == nil ||
		state.Result.SeedReceiptDigest != state.SeedReceiptRecord.SHA256 || state.Head.ResultDigest != bodyDigest(resultBytes) {
		t.Fatalf("external seed completion did not preserve its root receipt: %+v", state)
	}
	committedObjects := fixture.client.objectCount()
	if _, err := fixture.ledger.RecordExternalSeed(t.Context(), scope, manifestBytes, receiptBytes,
		facts, resultBytes, completedHeadBytes); err != nil || fixture.client.objectCount() != committedObjects {
		t.Fatalf("exact completed seed replay changed ledger: objects=%d prior=%d err=%v",
			fixture.client.objectCount(), committedObjects, err)
	}
	resignedHead := fixture.signInterval(t, scope, domainBootstrapHead, completedHead,
		fixture.now.Add(time.Second), fixture.now.Add(time.Hour))
	if _, err := fixture.ledger.RecordExternalSeed(t.Context(), scope, manifestBytes, receiptBytes,
		facts, resultBytes, resignedHead); !errors.Is(err, ErrSlotHeadConflict) ||
		fixture.client.objectCount() != committedObjects {
		t.Fatalf("re-signed completed HEAD replay changed ledger: objects=%d prior=%d err=%v",
			fixture.client.objectCount(), committedObjects, err)
	}
	if _, err := fixture.ledger.ReadForLaunch(t.Context(), scope); !errors.Is(err, ErrSlotAlreadyComplete) {
		t.Fatalf("completed external seed launch authorization returned %v, want completed-slot denial", err)
	}
	restarted := fixture.newLedger(t)
	recovered, err := restarted.ReadSlot(t.Context(), scope)
	if err != nil || recovered.SeedReceipt == nil || recovered.SeedReceiptRecord == nil ||
		recovered.SeedReceiptRecord.SHA256 != bodyDigest(receiptBytes) {
		t.Fatalf("restart did not recover the exact external seed receipt: state=%+v err=%v", recovered, err)
	}
	evidence := fixture.retirement(scope, recovered, "instance-retired")
	retirementBytes := fixture.sign(t, scope, domainSlotRetirement, evidence, fixture.now)
	nextIntentBytes, nextIntent := fixture.intentBytes(t, scope, 2, "bootstrap-create-b", "retry-token-2")
	nextIntent.Mode = IntentModeExternalSeed
	nextIntent.SchemaVersion = 1
	nextIntent.RetryToken = ""
	nextIntent.FounderPlanSHA256 = ""
	nextIntent.PeerRowDigest = ""
	nextIntent.ReviewedPlanDigest = bodyDigest([]byte("reviewed replacement OpenTofu plan"))
	nextIntent.RetirementDigest = bodyDigest(retirementBytes)
	nextIntentBytes, nextIntent = fixture.bindIntentManifest(t, scope, nextIntent, fixture.now)
	nextHead := SlotHead{
		SchemaVersion: 1, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment,
		Role: roleController, Slot: scope.Slot, Attempt: 2, Generation: 2,
		IntentDigest: bodyDigest(nextIntentBytes), PreviousAttempt: recovered.Head.Attempt,
		PreviousGeneration: recovered.Head.Generation, PreviousIntentDigest: recovered.Head.IntentDigest,
		PreviousResultDigest: recovered.Head.ResultDigest, RetirementDigest: bodyDigest(retirementBytes),
	}
	advanced, err := fixture.ledger.AdvanceSlot(t.Context(), scope, recovered.HeadRecord.ETag,
		retirementBytes, nextIntentBytes, fixture.sign(t, scope, domainBootstrapHead, nextHead, fixture.now))
	if err != nil || advanced.Intent.Mode != IntentModeExternalSeed || advanced.Head.Attempt != 2 {
		t.Fatalf("advance to fresh external-seed successor: state=%+v err=%v", advanced, err)
	}
	if _, err := fixture.ledger.ReadForLaunch(t.Context(), scope); !errors.Is(err, ErrExternalSeedMode) {
		t.Fatalf("external-seed successor launch authorization returned %v, want explicit denial", err)
	}
	previousReceiptName := fixture.ledger.objectName(scope, 1, ledgerSeedReceipt)
	previousReceiptKey := requestKey(new(fixture.ledger.config.Namespace), new(fixture.ledger.config.Bucket), new(previousReceiptName))
	fixture.client.mu.Lock()
	previousReceipt := fixture.client.objects[previousReceiptKey]
	previousReceipt.body = []byte("tampered root receipt")
	fixture.client.objects[previousReceiptKey] = previousReceipt
	fixture.client.mu.Unlock()
	if _, err := fixture.ledger.ReadSlot(t.Context(), scope); !errors.Is(err, ErrSlotNotReserved) {
		t.Fatalf("advanced slot accepted a missing/corrupt predecessor seed receipt: %v", err)
	}

	for _, mutate := range []func(*Intent){
		func(value *Intent) { value.ReviewedPlanDigest = "" },
	} {
		invalid := intent
		mutate(&invalid)
		if err := validateIntent(invalid); !errors.Is(err, ErrInvalidRecord) {
			t.Errorf("invalid external seed field combination passed validation: %+v", invalid)
		}
	}
}

type ledgerFixture struct {
	client      *fakeObjectStorageClient
	ledger      *Ledger
	authority   testBootstrapAuthority
	environment string
	maxLifetime time.Duration
	now         time.Time
}

type planBackedManagedPeerFixture struct {
	selected     founderPlanFixture
	plan         VerifiedFounderPlan
	client       *fakeObjectStorageClient
	ledger       *Ledger
	scope        BootstrapScope
	row          FounderPeerRow
	launch       LaunchAuthorization
	manifestWire []byte
}

func newPlanBackedManagedPeerFixture(t *testing.T, slot string) planBackedManagedPeerFixture {
	t.Helper()
	selected := newFounderPlanFixture(t)
	plan := selected.verify(t)
	row := selected.plan.Peers[0]
	if slot != "" {
		index := slices.IndexFunc(selected.plan.Peers, func(candidate FounderPeerRow) bool { return candidate.Slot == slot })
		if index < 0 {
			t.Fatalf("founder plan has no peer slot %q", slot)
		}
		row = selected.plan.Peers[index]
	}
	seedLaunch := selected.launchAuthorization(t, plan, row, "", "")
	client := newFakeObjectStorageClient()
	client.setNow(selected.now)
	anchor := selected.anchor.Anchor()
	ledgerGrant := signBootstrapLedgerGrant(t, selected.authority.rootPrivate, selected.authority.peerPublic,
		anchor.DeploymentID, anchor.Cell, anchor.Environment, anchor.ControllerSlots,
		selected.now.Add(-time.Minute), selected.now.Add(23*time.Hour))
	verifiedGrant, err := trust.VerifyDelegationCurrent(ledgerGrant, selected.authority.roots, selected.now, selected.policy)
	if err != nil {
		t.Fatalf("verify integrated ledger grant: %v", err)
	}
	config := LedgerConfig{
		DeploymentID: anchor.DeploymentID, Cell: anchor.Cell, ClusterID: anchor.ClusterID,
		InitialRegionIntentGeneration: anchor.InitialRegionIntentGeneration,
		InitialRegionIntentSHA256:     anchor.InitialRegionIntentSHA256,
		Namespace:                     anchor.StorageDomain.Namespace, Bucket: anchor.StorageDomain.LedgerBucket,
		KMSKeyID: anchor.StorageDomain.LedgerKMSKeyOCID, Prefix: anchor.StorageDomain.Prefix,
		HeadBucket: anchor.StorageDomain.HeadBucket, HeadKMSKeyID: anchor.StorageDomain.HeadKMSKeyOCID,
		Environment: anchor.Environment, ControllerSlots: slices.Clone(anchor.ControllerSlots),
		AnchorExpiresAt: selected.anchor.ExpiresAt(), TrustRoots: selected.authority.roots,
		Delegations: []trust.VerifiedDelegation{verifiedGrant}, TrustPolicy: selected.policy,
		VerificationNow: client.currentTime,
	}
	ledger, err := NewLedger(client, config)
	if err != nil {
		t.Fatalf("construct integrated ledger: %v", err)
	}
	scope := BootstrapScope{DeploymentID: anchor.DeploymentID, Cell: string(anchor.Cell), Slot: row.Slot}
	seedHead := seedLaunch.head
	seedHead.SchemaVersion = 1
	seedHeadPayload, err := trust.EncodePayload(seedHead)
	if err != nil {
		t.Fatalf("encode schema-v1 founder HEAD: %v", err)
	}
	seedHeadEnvelope, err := trust.Sign(seedHeadPayload, trust.Scope{
		Domain: domainBootstrapHead, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
		Environment: anchor.Environment, Role: roleController, Slot: scope.Slot,
	}, selected.now, selected.now.Add(23*time.Hour), selected.authority.peerPrivate)
	if err != nil {
		t.Fatalf("sign schema-v1 founder HEAD: %v", err)
	}
	seedHeadWire, err := trust.EncodeEnvelope(seedHeadEnvelope)
	if err != nil {
		t.Fatalf("encode signed schema-v1 founder HEAD: %v", err)
	}
	if _, err := ledger.ReserveSlot(t.Context(), scope, seedLaunch.intentRecord.Bytes, seedHeadWire); err != nil {
		t.Fatalf("reserve plan-pinned slot in integrated ledger: %v", err)
	}
	launch, err := ledger.ReadForLaunch(t.Context(), scope)
	if err != nil {
		t.Fatalf("read integrated launch authorization: %v", err)
	}
	return planBackedManagedPeerFixture{
		selected: selected, plan: plan, client: client, ledger: ledger, scope: scope,
		row: cloneFounderPeerRow(row), launch: launch, manifestWire: bytes.Clone(selected.manifestWires[row.Slot]),
	}
}

func (fixture planBackedManagedPeerFixture) refreshWith(plan VerifiedFounderPlan) ManagedPeerRecoveryRefresh {
	return func(ctx context.Context) (VerifiedFounderPeer, error) {
		recovery, err := fixture.ledger.ReadForManagedPeerRecovery(ctx, fixture.scope)
		if err != nil {
			return VerifiedFounderPeer{}, err
		}
		return plan.AuthorizePeerRecovery(fixture.scope.Slot, recovery, fixture.selected.authority.roots,
			recovery.AuthorizationTime(), fixture.selected.now.Add(23*time.Hour), fixture.selected.policy)
	}
}

func (fixture planBackedManagedPeerFixture) facts(instanceOCID string) InstanceFacts {
	intent := fixture.launch.intent
	return InstanceFacts{
		DeploymentID: intent.DeploymentID, Environment: intent.Environment,
		ClusterID: fixture.selected.anchor.Anchor().ClusterID, Cell: oci.Region(intent.Cell),
		OCIRegion: intent.OCIRegion, Role: intent.Role, Slot: intent.Slot, InstanceOCID: instanceOCID,
		CompartmentOCID: intent.CompartmentOCID, ImageOCID: intent.ImageOCID, CreateKey: intent.CreateKey,
		IntentSHA256: fixture.launch.intentRecord.SHA256, Profile: launchProfileForIntent(intent),
	}
}

func (fixture planBackedManagedPeerFixture) receiptBytes(t *testing.T, facts InstanceFacts) []byte {
	t.Helper()
	envelope, err := SignPeerReceipt(fixture.plan.manifests[fixture.scope.Slot], facts,
		fixture.selected.now, fixture.selected.now.Add(5*time.Minute), fixture.selected.authority.peerPrivate)
	if err != nil {
		t.Fatalf("sign integrated peer receipt: %v", err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("encode integrated peer receipt: %v", err)
	}
	return wire
}

func (fixture planBackedManagedPeerFixture) resultBytes(t *testing.T, facts InstanceFacts, receiptWire []byte) []byte {
	t.Helper()
	intent := fixture.launch.intent
	result := Result{
		SchemaVersion: 1, Mode: IntentModeManaged, DeploymentID: intent.DeploymentID, Cell: intent.Cell,
		Environment: intent.Environment, Role: intent.Role, Slot: intent.Slot, Attempt: intent.Attempt,
		Generation: intent.Generation, RegionIntentGeneration: intent.RegionIntentGeneration,
		IntentDigest: fixture.launch.intentRecord.SHA256, InstanceOCID: facts.InstanceOCID,
		ProviderRequestID: "integrated-request", ETag: "integrated-etag", OCIRegion: intent.OCIRegion,
		CompartmentOCID: intent.CompartmentOCID, ImageOCID: intent.ImageOCID, Shape: intent.Shape,
		ObservedProfileDigest: intent.LaunchRequestDigest, PeerReceiptDigest: digestBytes(receiptWire),
		CreateKey: intent.CreateKey, ObservedAt: fixture.selected.now,
	}
	return fixture.sign(t, domainBootstrapResult, result)
}

func (fixture planBackedManagedPeerFixture) completedHeadBytes(t *testing.T, resultWire []byte) []byte {
	t.Helper()
	head := fixture.launch.head
	head.ResultDigest = digestBytes(resultWire)
	return fixture.sign(t, domainBootstrapHead, head)
}

func (fixture planBackedManagedPeerFixture) sign(t *testing.T, domain string, payload any) []byte {
	t.Helper()
	encoded, err := trust.EncodePayload(payload)
	if err != nil {
		t.Fatalf("encode integrated %s payload: %v", domain, err)
	}
	envelope, err := trust.Sign(encoded, trust.Scope{
		Domain: domain, DeploymentID: fixture.scope.DeploymentID, Cell: fixture.scope.Cell,
		Environment: fixture.selected.plan.Environment, Role: roleController, Slot: fixture.scope.Slot,
	}, fixture.selected.now, fixture.selected.now.Add(23*time.Hour), fixture.selected.authority.peerPrivate)
	if err != nil {
		t.Fatalf("sign integrated %s payload: %v", domain, err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("encode integrated %s envelope: %v", domain, err)
	}
	return wire
}

func newLedgerFixture(t *testing.T) *ledgerFixture {
	t.Helper()
	client := newFakeObjectStorageClient()
	authority := newTestBootstrapAuthority(t)
	authority.now = client.currentTime()
	roots := make(trust.Keyring, len(authority.roots))
	for keyID, key := range authority.roots {
		roots[keyID] = bytes.Clone(key)
	}
	fixture := &ledgerFixture{
		client: client, authority: authority,
		environment: "production", maxLifetime: 24 * time.Hour, now: client.currentTime(),
	}
	var err error
	config := LedgerConfig{
		DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Cell: oci.RegionGRU, ClusterID: "0000000000RMSAJ9B0JFV7ESHN",
		InitialRegionIntentGeneration: 4, InitialRegionIntentSHA256: bodyDigest([]byte("region-intent")),
		Namespace: "namespace", Bucket: "bootstrap-ledger", KMSKeyID: "ocid1.key.oc1.sa-saopaulo-1.ledger", Prefix: "private/bootstrap",
		HeadBucket: "bootstrap-head", HeadKMSKeyID: "ocid1.key.oc1.sa-saopaulo-1.head", Environment: fixture.environment,
		ControllerSlots: []string{"controller-a", "seed-a"},
		TrustRoots:      roots, TrustPolicy: trust.Policy{MaxLifetime: fixture.maxLifetime, ClockSkew: 2 * time.Minute},
		VerificationNow: client.currentTime,
	}
	peerPublicWire, err := trust.EncodeDelegatedPublicKey(authority.peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerDelegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID(t, authority.peerPublic), SubjectPublicKey: peerPublicWire,
		Capabilities: []trust.Capability{
			{Domain: domainBootstrapHead, DeploymentID: config.DeploymentID, Cell: string(config.Cell), Environment: config.Environment,
				Role: roleController, Slots: slices.Clone(config.ControllerSlots), Actions: []string{"sign"}},
			{Domain: domainBootstrapIntent, DeploymentID: config.DeploymentID, Cell: string(config.Cell), Environment: config.Environment,
				Role: roleController, Slots: slices.Clone(config.ControllerSlots), Actions: []string{"sign"}},
			{Domain: domainBootstrapResult, DeploymentID: config.DeploymentID, Cell: string(config.Cell), Environment: config.Environment,
				Role: roleController, Slots: slices.Clone(config.ControllerSlots), Actions: []string{"sign"}},
			{Domain: domainBootstrapCandidate, DeploymentID: config.DeploymentID, Cell: string(config.Cell), Environment: config.Environment,
				Role: roleController, Slots: slices.Clone(config.ControllerSlots), Actions: []string{"sign"}},
			{Domain: domainBootstrapProgress, DeploymentID: config.DeploymentID, Cell: string(config.Cell), Environment: config.Environment,
				Role: roleController, Slots: slices.Clone(config.ControllerSlots), Actions: []string{"sign"}},
		},
	}, fixture.now, fixture.now.Add(fixture.maxLifetime), authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verifiedLedgerDelegation, err := trust.VerifyDelegationCurrent(ledgerDelegation, roots, fixture.now, config.TrustPolicy)
	if err != nil {
		t.Fatal(err)
	}
	config.Delegations = []trust.VerifiedDelegation{verifiedLedgerDelegation}
	fixture.authority.manifest.StorageDomain = config.storageDomain()
	fixture.authority.manifest.IntentGeneration = config.InitialRegionIntentGeneration
	fixture.authority.manifest.IntentSHA256 = config.InitialRegionIntentSHA256
	fixture.ledger, err = NewLedger(client, config)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *ledgerFixture) newLedger(t *testing.T) *Ledger {
	t.Helper()
	ledger, err := NewLedger(fixture.client, fixture.ledger.config)
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

func (fixture *ledgerFixture) sign(t *testing.T, scope BootstrapScope, domain string, payload any, issuedAt time.Time) []byte {
	t.Helper()
	return fixture.signInterval(t, scope, domain, payload, issuedAt, issuedAt.Add(fixture.maxLifetime))
}

func (fixture *ledgerFixture) signInterval(t *testing.T, scope BootstrapScope, domain string, payload any, issuedAt, expiresAt time.Time) []byte {
	t.Helper()
	privateKey := fixture.authority.peerPrivate
	if domain == domainSlotRetirement || domain == domainSeedHandoff {
		privateKey = fixture.authority.rootPrivate
	}
	encodedPayload, err := trust.EncodePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := trust.Sign(encodedPayload, trust.Scope{
		Domain: domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment,
		Role: roleController, Slot: scope.Slot,
	}, issuedAt, expiresAt, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeEnvelope(signed)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// managedPeerRefresh exercises the ledger's per-transition freshness contract
// without rebuilding the separate founder-plan signing fixture for every
// lower-level ledger invariant test. Public authorization tests verify the
// production path that constructs this unforgeable in-process value.
func (fixture *ledgerFixture) managedPeerRefresh(scope BootstrapScope) ManagedPeerRecoveryRefresh {
	return func(ctx context.Context) (VerifiedFounderPeer, error) {
		authorization, err := fixture.ledger.ReadForManagedPeerRecovery(ctx, scope)
		if err != nil {
			return VerifiedFounderPeer{}, err
		}
		state := authorization.state
		recovery := authorization
		recovery.state = cloneSlotState(state)
		intentEnvelope, err := trust.DecodeEnvelope(state.IntentRecord.Bytes)
		if err != nil {
			return VerifiedFounderPeer{}, err
		}
		return VerifiedFounderPeer{
			row:      FounderPeerRow{Slot: scope.Slot, ManifestSHA256: state.Intent.ManifestDigest},
			manifest: VerifiedManifest{digest: state.Intent.ManifestDigest, verified: true},
			launch: LaunchAuthorization{
				scope: scope, intent: state.Intent, intentRecord: cloneStoredRecord(state.IntentRecord),
				head: state.Head, headRecord: cloneStoredRecord(state.HeadRecord),
			},
			recovery: &recovery, planDigest: state.Intent.FounderPlanSHA256,
			rowDigest: state.Intent.PeerRowDigest, effectDeadline: intentEnvelope.ExpiresAt, verified: true,
		}, nil
	}
}

func (fixture *ledgerFixture) pinManagedPeerCandidate(
	t *testing.T,
	scope BootstrapScope,
	intent Intent,
	intentDigest string,
	facts InstanceFacts,
) []byte {
	t.Helper()
	candidate := ManagedPeerCandidate{
		SchemaVersion: 1, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
		Environment: fixture.environment, Role: roleController, Slot: scope.Slot,
		Attempt: intent.Attempt, Generation: intent.Generation, IntentDigest: intentDigest,
		CreateKey: intent.CreateKey, FounderPlanSHA256: intent.FounderPlanSHA256,
		PeerRowDigest: intent.PeerRowDigest, ManifestDigest: intent.ManifestDigest,
		LaunchProfileDigest: intent.LaunchRequestDigest, InstanceOCID: facts.InstanceOCID,
	}
	candidateWire := fixture.sign(t, scope, domainBootstrapCandidate, candidate, fixture.now)
	if err := fixture.ledger.RecordManagedPeerCandidate(t.Context(), scope, candidateWire,
		fixture.managedPeerProgressSigner(scope), fixture.managedPeerRefresh(scope)); err != nil {
		t.Fatalf("pin test managed-peer candidate: %v", err)
	}
	return candidateWire
}

func (fixture *ledgerFixture) managedPeerProgressSigner(scope BootstrapScope) ManagedPeerProgressSigner {
	return func(progress ManagedPeerProgress, issuedAt, expiresAt time.Time) ([]byte, error) {
		payload, err := trust.EncodePayload(progress)
		if err != nil {
			return nil, err
		}
		envelope, err := trust.Sign(payload, trust.Scope{
			Domain: domainBootstrapProgress, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
			Environment: fixture.environment, Role: roleController, Slot: scope.Slot,
		}, issuedAt, expiresAt, fixture.authority.peerPrivate)
		if err != nil {
			return nil, err
		}
		return trust.EncodeEnvelope(envelope)
	}
}

func (fixture *ledgerFixture) intentBytes(t *testing.T, scope BootstrapScope, attempt uint64, createKey, retryToken string) ([]byte, Intent) {
	t.Helper()
	profile := LaunchProfile{
		Slot: scope.Slot, CompartmentOCID: "ocid1.compartment.oc1.sa-saopaulo-1.compartment-a",
		AvailabilityDomain: "AD-1", FaultDomain: "FAULT-DOMAIN-1",
		SubnetOCID:                "ocid1.subnet.oc1.sa-saopaulo-1.subnet-a",
		NetworkSecurityGroupOCIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.nsg-a"},
		Shape:                     "VM.Standard.E5.Flex",
	}
	launchDigest, err := launchProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	intent := Intent{
		SchemaVersion: 1, Mode: IntentModeManaged, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment,
		Role: roleController, Slot: scope.Slot, Attempt: attempt, Generation: attempt,
		ReleaseReceiptDigest: bodyDigest([]byte("release")), RegionIntentGeneration: 4,
		ImageOCID: "ocid1.image.oc1.sa-saopaulo-1.image-a", RegionIntentDigest: bodyDigest([]byte("region-intent")),
		LaunchRequestDigest: launchDigest, FounderPlanSHA256: bodyDigest([]byte("founder-plan")),
		PeerRowDigest: bodyDigest([]byte("founder-peer-row")), CreateKey: createKey, RetryToken: retryToken,
		CreatedAt: fixture.now, OCIRegion: "sa-saopaulo-1", CompartmentOCID: "ocid1.compartment.oc1.sa-saopaulo-1.compartment-a",
		AvailabilityDomain: "AD-1", FaultDomain: "FAULT-DOMAIN-1", SubnetOCID: "ocid1.subnet.oc1.sa-saopaulo-1.subnet-a",
		NetworkSecurityGroupIDs: []string{"ocid1.networksecuritygroup.oc1.sa-saopaulo-1.nsg-a"}, Shape: "VM.Standard.E5.Flex", Node: "controller-a",
	}
	intentBytes, intent := fixture.bindIntentManifest(t, scope, intent, fixture.now)
	return intentBytes, intent
}

func (fixture *ledgerFixture) bindIntentManifest(t *testing.T, scope BootstrapScope, intent Intent, issuedAt time.Time) ([]byte, Intent) {
	t.Helper()
	manifestBytes, _ := fixture.manifestBytes(t, scope, intent)
	intent.ManifestDigest = objectDigest(manifestBytes)
	return fixture.sign(t, scope, domainBootstrapIntent, intent, issuedAt), intent
}

func (fixture *ledgerFixture) manifestBytes(t *testing.T, scope BootstrapScope, intent Intent) ([]byte, VerifiedManifest) {
	t.Helper()
	manifest := cloneManifest(fixture.authority.manifest)
	manifest.DeploymentID = intent.DeploymentID
	manifest.Environment = intent.Environment
	manifest.ClusterID = fixture.ledger.config.ClusterID
	manifest.Cell = oci.Region(intent.Cell)
	manifest.OCIRegion = intent.OCIRegion
	manifest.IntentGeneration = intent.RegionIntentGeneration
	manifest.IntentSHA256 = intent.RegionIntentDigest
	manifest.Slot = intent.Slot
	manifest.ImageOCID = intent.ImageOCID
	manifest.StorageDomain = fixture.ledger.config.storageDomain()
	manifest.Secrets = nil
	profile := launchProfileForIntent(intent)
	manifest.ControllerSlots = slices.Clone(fixture.ledger.config.ControllerSlots)
	seedSlot := "seed-a"
	if intent.Mode == IntentModeExternalSeed {
		seedSlot = intent.Slot
	} else if seedSlot == intent.Slot {
		seedSlot = "controller-a"
		if seedSlot == intent.Slot {
			seedSlot = "seed-authority"
		}
	}
	manifest.SeedSlot = seedSlot
	manifest.Profiles = make([]LaunchProfile, 0, len(manifest.ControllerSlots))
	for _, slot := range manifest.ControllerSlots {
		profileForSlot := cloneProfile(profile)
		profileForSlot.Slot = slot
		if slot == seedSlot && slot != intent.Slot {
			profileForSlot = cloneProfile(fixture.authority.manifest.Profiles[0])
			profileForSlot.Slot = slot
		}
		manifest.Profiles = append(manifest.Profiles, profileForSlot)
	}
	peerSlots := make([]string, 0, len(manifest.ControllerSlots)-1)
	for _, slot := range manifest.ControllerSlots {
		if slot != seedSlot {
			peerSlots = append(peerSlots, slot)
		}
	}
	manifest.PeerReceiptDelegation = nil
	if len(peerSlots) > 0 {
		delegation := fixture.peerDelegation(t, peerSlots)
		manifest.PeerReceiptDelegation = &delegation
	}
	envelope, err := SignManifest(manifest, fixture.now, fixture.now.Add(fixture.maxLifetime), fixture.authority.rootPrivate)
	if err != nil {
		t.Fatalf("sign test manifest: %v", err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("encode test manifest: %v", err)
	}
	verified, err := VerifyManifest(envelope, fixture.ledger.config.TrustRoots, ManifestExpectation{
		DeploymentID: fixture.ledger.config.DeploymentID, Environment: fixture.environment,
		ClusterID: fixture.ledger.config.ClusterID, Cell: fixture.ledger.config.Cell,
		Slot: scope.Slot, ImageOCID: intent.ImageOCID, StorageDomain: fixture.ledger.config.storageDomain(),
		ControllerSlots:  slices.Clone(fixture.ledger.config.ControllerSlots),
		IntentGeneration: fixture.ledger.config.InitialRegionIntentGeneration,
		IntentSHA256:     fixture.ledger.config.InitialRegionIntentSHA256,
	}, fixture.now, fixture.ledger.config.TrustPolicy)
	if err != nil {
		t.Fatalf("verify test manifest: %v", err)
	}
	return wire, verified
}

func (fixture *ledgerFixture) peerDelegation(t *testing.T, slots []string) trust.Envelope {
	t.Helper()
	peerPublic, err := trust.EncodeDelegatedPublicKey(fixture.authority.peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID(t, fixture.authority.peerPublic), SubjectPublicKey: peerPublic,
		Capabilities: []trust.Capability{{
			Domain: peerReceiptDomain, DeploymentID: fixture.ledger.config.DeploymentID, Cell: string(fixture.ledger.config.Cell),
			Environment: fixture.environment, Role: roleController, Slots: slices.Clone(slots), Actions: []string{"sign"},
		}},
	}, fixture.now, fixture.now.Add(fixture.maxLifetime), fixture.authority.rootPrivate)
	if err != nil {
		t.Fatalf("sign test peer delegation: %v", err)
	}
	return delegation
}

func (fixture *ledgerFixture) managedProof(t *testing.T, scope BootstrapScope, intent Intent, intentDigest string) ([]byte, []byte, InstanceFacts) {
	t.Helper()
	manifestBytes, manifest := fixture.manifestBytes(t, scope, intent)
	facts := InstanceFacts{
		DeploymentID: intent.DeploymentID, Environment: intent.Environment, ClusterID: fixture.ledger.config.ClusterID,
		Cell: oci.Region(intent.Cell), OCIRegion: intent.OCIRegion, Role: intent.Role, Slot: intent.Slot,
		InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.instance-a", CompartmentOCID: intent.CompartmentOCID,
		ImageOCID: intent.ImageOCID, CreateKey: intent.CreateKey, IntentSHA256: intentDigest,
		Profile: launchProfileForIntent(intent),
	}
	envelope, err := SignPeerReceipt(manifest, facts, fixture.now, fixture.now.Add(5*time.Minute), fixture.authority.peerPrivate)
	if err != nil {
		t.Fatalf("sign test peer receipt: %v", err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("encode test peer receipt: %v", err)
	}
	return manifestBytes, wire, facts
}

func (fixture *ledgerFixture) seedProof(t *testing.T, scope BootstrapScope, intent Intent, intentDigest string) ([]byte, []byte, InstanceFacts) {
	t.Helper()
	manifestBytes, manifest := fixture.manifestBytes(t, scope, intent)
	facts := InstanceFacts{
		DeploymentID: intent.DeploymentID, Environment: intent.Environment, ClusterID: fixture.ledger.config.ClusterID,
		Cell: oci.Region(intent.Cell), OCIRegion: intent.OCIRegion, Role: intent.Role, Slot: intent.Slot,
		InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.instance-a", CompartmentOCID: intent.CompartmentOCID,
		ImageOCID: intent.ImageOCID, CreateKey: intent.CreateKey, IntentSHA256: intentDigest,
		Profile: launchProfileForIntent(intent),
	}
	envelope, err := SignSeedReceipt(manifest, facts, fixture.now, fixture.now.Add(5*time.Minute), fixture.authority.rootPrivate)
	if err != nil {
		t.Fatalf("sign test seed receipt: %v", err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("encode test seed receipt: %v", err)
	}
	return manifestBytes, wire, facts
}

func (fixture *ledgerFixture) headBytes(t *testing.T, scope BootstrapScope, intentBytes []byte, attempt uint64) []byte {
	t.Helper()
	head := SlotHead{SchemaVersion: 1, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
		Environment: fixture.environment, Role: roleController, Slot: scope.Slot, Attempt: attempt,
		Generation: attempt, IntentDigest: bodyDigest(intentBytes)}
	return fixture.sign(t, scope, domainBootstrapHead, head, fixture.now)
}

func (fixture *ledgerFixture) result(scope BootstrapScope, intent Intent, intentDigest string) Result {
	return Result{
		SchemaVersion: 1, Mode: intent.Mode, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment,
		Role: roleController, Slot: scope.Slot, Attempt: intent.Attempt, Generation: intent.Generation,
		RegionIntentGeneration: intent.RegionIntentGeneration,
		IntentDigest:           intentDigest, InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.instance-a", ProviderRequestID: "request-a",
		ETag: "instance-etag-a", OCIRegion: intent.OCIRegion, CompartmentOCID: intent.CompartmentOCID,
		ImageOCID: intent.ImageOCID, Shape: intent.Shape, ObservedProfileDigest: intent.LaunchRequestDigest,
		CreateKey: intent.CreateKey, ObservedAt: fixture.now,
	}
}

func (fixture *ledgerFixture) retirement(scope BootstrapScope, state SlotState, disposition string) RetirementEvidence {
	return RetirementEvidence{
		SchemaVersion: 1, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment,
		Role: roleController, Slot: scope.Slot, PreviousAttempt: state.Head.Attempt,
		PreviousGeneration: state.Head.Generation, PreviousResultDigest: state.Head.ResultDigest,
		PriorInstanceOCID: state.Result.InstanceOCID, PriorCreateKey: state.Intent.CreateKey,
		Disposition: disposition, ObservedEvidenceDigest: bodyDigest([]byte("provider retirement evidence")),
		FencingAuthority: "oci-inspector", ObservedAt: fixture.now,
	}
}

func testBootstrapScope() BootstrapScope {
	return BootstrapScope{DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Cell: "GRU", Slot: "controller-a"}
}

type fakeObjectStorageClient struct {
	mu               sync.Mutex
	objects          map[string]fakeStoredObject
	clockAtCommit    map[string]time.Time
	clockAtGet       map[string]fakeClockAdvance
	getsByObject     map[string]int
	now              time.Time
	loseAckBucket    string
	putCalls         atomic.Int32
	getCalls         atomic.Int32
	invalidCondition atomic.Bool
	invalidKMSKey    atomic.Bool
	omitServerDate   atomic.Bool
	failBeforeCommit atomic.Bool
	rejectPut        error
	rejectPutBucket  string
}

type fakeClockAdvance struct {
	getNumber int
	now       time.Time
}

type fakeStoredObject struct {
	body         []byte
	etag         string
	lastModified time.Time
}

func newFakeObjectStorageClient() *fakeObjectStorageClient {
	return &fakeObjectStorageClient{
		objects: make(map[string]fakeStoredObject), clockAtCommit: make(map[string]time.Time),
		clockAtGet: make(map[string]fakeClockAdvance), getsByObject: make(map[string]int),
		now: time.Now().UTC().Truncate(time.Second),
	}
}

func (client *fakeObjectStorageClient) currentTime() time.Time {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.now
}

func (client *fakeObjectStorageClient) setNow(now time.Time) {
	client.mu.Lock()
	client.now = now.UTC()
	client.mu.Unlock()
}

func (client *fakeObjectStorageClient) setClockBeforePut(bucket, objectName string, now time.Time) {
	client.mu.Lock()
	client.clockAtCommit[requestKey(new("namespace"), new(bucket), new(objectName))] = now.UTC()
	client.mu.Unlock()
}

func (client *fakeObjectStorageClient) setClockOnGet(bucket, objectName string, after int, now time.Time) {
	client.mu.Lock()
	key := requestKey(new("namespace"), new(bucket), new(objectName))
	client.clockAtGet[key] = fakeClockAdvance{getNumber: client.getsByObject[key] + after, now: now.UTC()}
	client.mu.Unlock()
}

func (client *fakeObjectStorageClient) loseAckForBucket(bucket string) {
	client.mu.Lock()
	client.loseAckBucket = bucket
	client.mu.Unlock()
}

func (client *fakeObjectStorageClient) PutObject(_ context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	client.putCalls.Add(1)
	if request.IfNoneMatch == nil && request.IfMatch == nil || request.IfNoneMatch != nil && request.IfMatch != nil ||
		request.IfNoneMatch != nil && *request.IfNoneMatch != "*" {
		client.invalidCondition.Store(true)
	}
	expectedKey := "ocid1.key.oc1.sa-saopaulo-1.ledger"
	if request.BucketName != nil && *request.BucketName == "bootstrap-head" {
		expectedKey = "ocid1.key.oc1.sa-saopaulo-1.head"
	}
	if request.OpcSseKmsKeyId == nil || *request.OpcSseKmsKeyId != expectedKey {
		client.invalidKMSKey.Store(true)
	}
	body, err := io.ReadAll(request.PutObjectBody)
	if closeErr := request.PutObjectBody.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return objectstorage.PutObjectResponse{}, err
	}
	if request.ContentLength == nil || int64(len(body)) != *request.ContentLength {
		return objectstorage.PutObjectResponse{}, errors.New("incorrect content length")
	}
	digest := sha256.Sum256(body)
	digestHeader := base64.StdEncoding.EncodeToString(digest[:])
	if request.OpcContentSha256 == nil || *request.OpcContentSha256 != digestHeader ||
		request.OpcChecksumAlgorithm != objectstorage.PutObjectOpcChecksumAlgorithmSha256 {
		return objectstorage.PutObjectResponse{}, errors.New("incorrect SHA-256 checksum")
	}
	if client.failBeforeCommit.Swap(false) {
		return objectstorage.PutObjectResponse{}, errors.New("connection reset before object commit")
	}
	if client.rejectPut != nil && (client.rejectPutBucket == "" || request.BucketName != nil && *request.BucketName == client.rejectPutBucket) {
		return objectstorage.PutObjectResponse{}, client.rejectPut
	}
	key := requestKey(request.NamespaceName, request.BucketName, request.ObjectName)
	client.mu.Lock()
	if advanceTo, ok := client.clockAtCommit[key]; ok {
		client.now = advanceTo
		delete(client.clockAtCommit, key)
	}
	previous, exists := client.objects[key]
	if request.IfNoneMatch != nil && exists || request.IfMatch != nil && (!exists || *request.IfMatch != previous.etag) {
		client.mu.Unlock()
		return objectstorage.PutObjectResponse{}, fakeObjectStorageError{status: http.StatusPreconditionFailed}
	}
	etag := `"` + hex.EncodeToString(digest[:8]) + `"`
	client.objects[key] = fakeStoredObject{
		body: bytes.Clone(body), etag: etag, lastModified: client.now.UTC().Truncate(time.Second),
	}
	loseAck := client.loseAckBucket != "" && request.BucketName != nil && *request.BucketName == client.loseAckBucket
	if loseAck {
		client.loseAckBucket = ""
	}
	client.mu.Unlock()
	if loseAck {
		return objectstorage.PutObjectResponse{}, errors.New("connection reset after object commit")
	}
	return objectstorage.PutObjectResponse{ETag: &etag, OpcRequestId: new("fake-put-request")}, nil
}

func (client *fakeObjectStorageClient) GetObject(_ context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	client.getCalls.Add(1)
	key := requestKey(request.NamespaceName, request.BucketName, request.ObjectName)
	client.mu.Lock()
	client.getsByObject[key]++
	if advance, ok := client.clockAtGet[key]; ok && client.getsByObject[key] == advance.getNumber {
		client.now = advance.now
		delete(client.clockAtGet, key)
	}
	object, ok := client.objects[key]
	now := client.now
	client.mu.Unlock()
	if !ok {
		return objectstorage.GetObjectResponse{}, fakeObjectStorageError{status: http.StatusNotFound}
	}
	date := now.Format(http.TimeFormat)
	if client.omitServerDate.Load() {
		date = ""
	}
	headers := make(http.Header)
	if date != "" {
		headers.Set("Date", date)
	}
	length := int64(len(object.body))
	etag := object.etag
	lastModified := common.SDKTime{Time: object.lastModified}
	return objectstorage.GetObjectResponse{
		RawResponse: &http.Response{Header: headers}, Content: io.NopCloser(bytes.NewReader(object.body)),
		ContentLength: &length, ETag: &etag, LastModified: &lastModified, OpcRequestId: new("fake-get-request"),
	}, nil
}

func (client *fakeObjectStorageClient) objectCount() int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return len(client.objects)
}

type fakeObjectStorageError struct{ status int }

func (err fakeObjectStorageError) Error() string {
	return fmt.Sprintf("fake Object Storage status %d", err.status)
}
func (err fakeObjectStorageError) GetHTTPStatusCode() int  { return err.status }
func (err fakeObjectStorageError) GetMessage() string      { return err.Error() }
func (err fakeObjectStorageError) GetCode() string         { return "FakeError" }
func (err fakeObjectStorageError) GetOpcRequestID() string { return "fake-request" }

func requestKey(namespace, bucket, objectName *string) string {
	return *namespace + "\x00" + *bucket + "\x00" + *objectName
}

func bodyDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}
