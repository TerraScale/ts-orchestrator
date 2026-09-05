package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/contracts"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// These release/provider fixtures exercise the real executor, signature
// verification, durable journal and NATS ingress without external OCI calls.
type ingressReleaseFetcher struct {
	body, signature []byte
	before          func() error
}

func (f *ingressReleaseFetcher) Fetch(context.Context, *delivery.Request) ([]byte, []byte, error) {
	if f.before != nil {
		if err := f.before(); err != nil {
			return nil, nil, err
		}
	}
	return append([]byte(nil), f.body...), append([]byte(nil), f.signature...), nil
}

type ingressDeliveryEffects struct {
	before        func() error
	once          sync.Once
	mu            sync.Mutex
	puts, targets []string
	heads         []string
	artifact      []byte
	missingMirror bool
	corruptMirror bool
}

func (e *ingressDeliveryEffects) Put(context.Context, string, string, string, []byte) error {
	return errors.New("unfenced fixture write")
}
func (e *ingressDeliveryEffects) PutFenced(_ context.Context, region, bucket, object string, body []byte, _ delivery.OperationFence) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.puts = append(e.puts, region)
	return nil
}
func (e *ingressDeliveryEffects) Get(_ context.Context, region, bucket, object string) (io.ReadCloser, delivery.ObjectIdentity, error) {
	var beforeErr error
	e.once.Do(func() {
		if e.before != nil {
			beforeErr = e.before()
		}
	})
	if beforeErr != nil {
		return nil, delivery.ObjectIdentity{}, beforeErr
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.heads = append(e.heads, region)
	if e.missingMirror && region == "fra" {
		return nil, delivery.ObjectIdentity{}, errors.New("missing prepared mirror")
	}
	body := e.artifact
	if e.corruptMirror && region == "fra" {
		body = append([]byte(nil), body...)
		body[0] ^= 1
	}
	// Corruption deliberately retains the originally reported metadata.
	return io.NopCloser(bytes.NewReader(body)), delivery.ObjectIdentity{Digest: delivery.SHA256Digest(e.artifact), Size: int64(len(e.artifact))}, nil
}

func (e *ingressDeliveryEffects) Roll(context.Context, *delivery.Request, *delivery.ReleaseArtifact) (delivery.RolloutResult, error) {
	return delivery.RolloutResult{}, errors.New("unfenced fixture rollout")
}
func (e *ingressDeliveryEffects) RollFenced(ctx context.Context, request *delivery.Request, _ *delivery.ReleaseArtifact, fence delivery.OperationFence, check delivery.FenceChecker) (delivery.RolloutResult, error) {
	if err := check(fence); err != nil {
		return delivery.RolloutResult{}, err
	}
	if err := delivery.CheckExecutionFence(ctx); err != nil {
		return delivery.RolloutResult{}, err
	}
	authority, err := delivery.RegionalCommandAuthorityFromContext(ctx)
	if err != nil {
		return delivery.RolloutResult{}, err
	}
	if authority.AuthorityID != request.Target.Regions[0]+"-regional" || authority.DesiredGeneration != 1 {
		return delivery.RolloutResult{}, errors.New("wrong command authority binding")
	}
	e.mu.Lock()
	e.targets = append(e.targets, request.Target.Regions...)
	e.mu.Unlock()
	return delivery.RolloutResult{Status: delivery.StatusSucceeded, Converged: true, Checks: []*delivery.HealthCheck{{Name: "health", Status: "passed"}, {Name: "catch-up", Status: "passed"}, {Name: "drain", Status: "passed"}}}, nil
}

func TestSignedNatsIngressExecutesOnlyAdmittedRegionalDelivery(t *testing.T) {
	for _, cellName := range []string{"gru", "sfo"} {
		for _, mode := range []string{"success", "invalid-release-signature", "missing-release-signature", "bare-request", "multi-region", "wrong-region", "target-extension", "stale-epoch", "superseded", "lease-replaced", "missing-mirror", "corrupt-mirror", "future-global-lease", "duplicate-global-lease", "unknown-global-lease"} {
			t.Run(cellName+"/"+mode, func(t *testing.T) {
				ctx, nc, js := masterTestNATS(t)
				kv := masterTestKV(t, ctx, js, "delivery")
				leaders := masterTestKV(t, ctx, js, "leaders")
				globalLeaders := masterTestKV(t, ctx, js, "global_leaders")
				coordinator, err := authority.RegionalAuthorityCoordinatorStartAsync(ctx, leaders, cellName, "instance")
				if err != nil {
					t.Fatal(err)
				}
				defer coordinator.Dispose()
				global, err := authority.RegionalAuthorityCoordinatorStartGlobalAsync(ctx, globalLeaders, "gru", "master")
				if err != nil {
					t.Fatal(err)
				}
				defer global.Dispose()
				epoch := coordinator.Snapshot().Epoch
				store, err := newNatsDeliveryStore(ctx, kv, nc)
				if err != nil {
					t.Fatal(err)
				}
				journal, err := delivery.NewDurableJournal(store)
				if err != nil {
					t.Fatal(err)
				}
				masterSigner, masterVerifier := masterTestSigner(t)
				intentSigner, intentVerifier := masterTestSigner(t)
				delegation := &MasterDeliveryAdmissionConfig{Connection: nc, Leaders: globalLeaders, MasterVerifier: masterVerifier, IntentVerifier: intentVerifier}
				d := &signedDeliveryDispatcher{connection: nc, cell: cellName, instance: "instance", authority: coordinator, leaders: leaders, store: kv, delegation: delegation}
				public, private, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				trust, err := delivery.NewTrustSet(map[string]ed25519.PublicKey{"release": public})
				if err != nil {
					t.Fatal(err)
				}
				artifact := []byte("verified regional release bytes")
				fetcher := &ingressReleaseFetcher{body: artifact, signature: ed25519.Sign(private, artifact)}
				effects := &ingressDeliveryEffects{artifact: artifact, missingMirror: mode == "missing-mirror", corruptMirror: mode == "corrupt-mirror"}
				mirror, err := delivery.NewArtifactMirror(estate.Default(), effects)
				if err != nil {
					t.Fatal(err)
				}
				executor, err := delivery.NewExecutor(delivery.ExecutorConfig{MirrorMode: delivery.MirrorModeVerifyAll, OwnerID: cellName + "-instance", Trust: func() *delivery.TrustSet { return trust }, Mirror: mirror, Rollout: effects, Journal: journal, Authority: d.checkAuthority})
				if err != nil {
					t.Fatal(err)
				}
				d.executor = executor
				raw, err := os.ReadFile("../delivery/testdata/request-v1.json")
				if err != nil {
					t.Fatal(err)
				}
				parentRequest, err := delivery.ParseRequest(string(raw))
				if err != nil {
					t.Fatal(err)
				}
				parentRequest.OperationID = "regional-delivery"
				parentRequest.Target.Regions = []string{cellName}
				parentRequest.Artifact.Digest = delivery.SHA256Digest(artifact)
				if mode == "target-extension" {
					parentRequest.Target.Regions = []string{"fra"}
				}
				parentCell, _ := contracts.CellIdTryCreate("gru")
				parentAggregate, _ := contracts.AggregateIdTryCreate("delivery-master")
				parentWire := signedDeliveryTestWire(t, intentSigner, parentCell, parentAggregate, parentRequest, global.Snapshot().Epoch)
				parentEnvelope, err := protocol.DecodeCommandEnvelope(parentWire)
				if err != nil {
					t.Fatal(err)
				}
				operation := "delivery-" + masterKey(parentRequest.OperationID + "\x00" + delivery.SHA256Digest(parentEnvelope.Payload.Bytes()) + "\x00" + cellName)[:54]
				requestPayload, err := masterChildPayload(parentRequest, cellName, operation)
				if err != nil {
					t.Fatal(err)
				}
				request, err := delivery.ParseRequest(string(requestPayload))
				if err != nil {
					t.Fatal(err)
				}
				if mode == "multi-region" {
					request.Target.Regions = []string{"gru", "sfo", "fra"}
				}
				if mode == "wrong-region" {
					request.Target.Regions = []string{"fra"}
				}
				requestPayload, _ = json.Marshal(request)
				leaseEntry, err := globalLeaders.Get(ctx, "authority.global")
				if err != nil {
					t.Fatal(err)
				}
				lease, err := decodeMasterLease(leaseEntry.Value())
				if err != nil {
					t.Fatal(err)
				}
				if mode == "future-global-lease" {
					lease.IssuedAt = time.Now().Add(time.Minute)
				}
				releaseSignature := append([]byte(nil), fetcher.signature...)
				if mode == "invalid-release-signature" {
					releaseSignature[0] ^= 1
				}
				if mode == "missing-release-signature" {
					releaseSignature = nil
				}
				wrapped, err := json.Marshal(masterRegionalDelivery{Version: 1, ParentEnvelope: parentWire, GlobalLease: lease, ReleaseSignature: releaseSignature, Request: requestPayload})
				if err != nil {
					t.Fatal(err)
				}
				if mode == "bare-request" {
					wrapped = requestPayload
				}
				if mode == "duplicate-global-lease" {
					wrapped = bytes.Replace(wrapped, []byte(`"globalLease":{`), []byte(`"globalLease":{"Epoch":99,`), 1)
				}
				if mode == "unknown-global-lease" {
					wrapped = bytes.Replace(wrapped, []byte(`"globalLease":{`), []byte(`"globalLease":{"unexpected":true,`), 1)
				}
				if mode == "superseded" {
					effects.before = func() error {
						return d.admit(ctx, deliveryAdmission{Version: 1, OperationID: "replacement", PayloadDigest: "replacement", IdempotencyDigest: "replacement", Generation: 2}, epoch)
					}
				}
				if mode == "lease-replaced" {
					effects.before = func() error {
						entry, err := leaders.Get(ctx, "authority.regional")
						if err != nil {
							return err
						}
						var current authority.RegionalAuthorityLeaseDocument
						if err := json.Unmarshal(entry.Value(), &current); err != nil {
							return err
						}
						current.Epoch++
						current.CandidateId = cellName + "-controller-replacement"
						body, _ := json.Marshal(current)
						_, err = leaders.Update(ctx, "authority.regional", body, entry.Revision())
						return err
					}
				}
				replay, err := NewNatsCommandReplayStore(masterTestKV(t, ctx, js, "replay"))
				if err != nil {
					t.Fatal(err)
				}
				boundary, err := security.NewCommandSecurityBoundary(masterVerifier, replay, 0)
				if err != nil {
					t.Fatal(err)
				}
				cell, _ := contracts.CellIdTryCreate(cellName)
				aggregate, _ := contracts.AggregateIdTryCreate("delivery")
				generation, _ := protocol.DesiredGenerationTryCreate(1)
				minimumEpoch, _ := protocol.WriterEpochTryCreate(1)
				version, _ := protocol.ProtocolRevisionTryCreate(int64(protocol.ProtocolVersion.Current()))
				subject, _ := protocol.NatsSubjectTaxonomy.DirectDeliverySubject(cellName)
				ingress, err := NewNatsCommandIngress(NatsCommandIngressConfiguration{Connection: nc, Subject: subject, Boundary: boundary, Replay: replay, ExpectedCell: cell, ExpectedAggregateID: aggregate, MinimumDesiredGeneration: generation, MinimumWriterEpoch: minimumEpoch, AcceptedProtocolVersions: []protocol.ProtocolRevision{version}, PayloadDigestVerifier: ingressDigestVerifier{}, Dispatch: d.dispatch, MultiInstance: true})
				if err != nil {
					t.Fatal(err)
				}
				if err := ingress.Start(ctx); err != nil {
					t.Fatal(err)
				}
				defer ingress.Close()
				signedEpoch := epoch
				if mode == "stale-epoch" {
					signedEpoch++
				}
				wire := signedDeliveryPayloadWire(t, masterSigner, cell, aggregate, operation, wrapped, signedEpoch, parentEnvelope.ExpiresAt)
				reply, err := nc.Request(subject, wire, 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				effects.mu.Lock()
				puts := append([]string(nil), effects.puts...)
				targets := append([]string(nil), effects.targets...)
				reads := len(effects.heads)
				effects.mu.Unlock()
				stored, exists, err := journal.GetWithError(request.OperationID)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "success" {
					if string(reply.Data) != string(CommandIngressCodeAccepted) || !exists || stored.Receipt == nil || stored.Receipt.Status != delivery.StatusSucceeded {
						t.Fatalf("missing durable success: %s %+v", reply.Data, stored)
					}
					if !reflect.DeepEqual(stored.Request, request) || !reflect.DeepEqual(targets, []string{cellName}) || len(puts) != 0 || reads != len(estate.Default().Regions)+1 {
						t.Fatalf("child changed or wrong mirror/rollout effects: targets=%v puts=%v reads=%d", targets, puts, reads)
					}
					replayed, err := nc.Request(subject, wire, time.Second)
					if err != nil || string(replayed.Data) != string(CommandIngressCodeRejected) {
						t.Fatalf("replay: %v %v", replayed, err)
					}
				} else {
					if string(reply.Data) != string(CommandIngressCodeDispatchFailed) {
						t.Fatalf("rejected reply: %s", reply.Data)
					}
					if len(puts) != 0 || len(targets) != 0 {
						t.Fatalf("rejected delegation mutated providers: puts=%v targets=%v", puts, targets)
					}
					if exists && stored.Receipt != nil && stored.Receipt.Status == delivery.StatusSucceeded {
						t.Fatal("rejected delegation recorded success")
					}
				}
			})
		}
	}
}

func signedDeliveryTestWire(t *testing.T, signer *security.CommandSignatureSigner, cell contracts.CellId, aggregate contracts.AggregateId, request *delivery.Request, epochValue int64) []byte {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return signedDeliveryPayloadWire(t, signer, cell, aggregate, request.OperationID, body, epochValue, time.Now().Add(time.Minute))
}

func signedDeliveryPayloadWire(t *testing.T, signer *security.CommandSignatureSigner, cell contracts.CellId, aggregate contracts.AggregateId, operationID string, body []byte, epochValue int64, expires time.Time) []byte {
	t.Helper()
	version, _ := protocol.ProtocolRevisionTryCreate(int64(protocol.ProtocolVersion.Current()))
	generation, _ := protocol.DesiredGenerationTryCreate(1)
	epoch, _ := protocol.WriterEpochTryCreate(epochValue)
	operation, _ := contracts.OperationIdTryCreate(operationID)
	idempotency, _ := contracts.IdempotencyKeyTryCreate(operationID)
	attempt, _ := protocol.DeliveryAttemptTryCreate(1)
	payload := protocol.OpaquePayloadCopyFrom(body)
	sum := sha256.Sum256(body)
	digest, _ := protocol.PayloadDigestTryCopyFrom(sum[:])
	now := time.Now().UTC()
	envelope := protocol.NewCommandEnvelope(version, cell, aggregate, generation, epoch, operation, idempotency, now, expires, attempt, payload, digest, protocol.OpaqueSignature{})
	signature, err := signer.Sign(envelope.SignedMaterial)
	if err != nil {
		t.Fatal(err)
	}
	envelope = protocol.NewCommandEnvelope(version, cell, aggregate, generation, epoch, operation, idempotency, now, expires, attempt, payload, digest, signature)
	wire, err := protocol.EncodeCommandEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
