package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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

	"github.com/nats-io/nats.go/jetstream"
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
		for _, mode := range []string{"success", "multi-region", "wrong-region", "stale-epoch", "superseded", "lease-replaced", "missing-mirror", "corrupt-mirror"} {
			t.Run(cellName+"/"+mode, func(t *testing.T) {
				ctx, kv, leaders, nc := deliveryTestKV(t)
				coordinator, err := authority.RegionalAuthorityCoordinatorStartAsync(ctx, leaders, cellName, "instance")
				if err != nil {
					t.Fatal(err)
				}
				defer coordinator.Dispose()
				epoch := coordinator.Snapshot().Epoch
				store, err := newNatsDeliveryStore(ctx, kv, nc)
				if err != nil {
					t.Fatal(err)
				}
				journal, err := delivery.NewDurableJournal(store)
				if err != nil {
					t.Fatal(err)
				}
				d := &signedDeliveryDispatcher{connection: nc, cell: cellName, instance: "instance", authority: coordinator, leaders: leaders, store: kv}
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
				executor, err := delivery.NewExecutor(delivery.ExecutorConfig{MirrorMode: delivery.MirrorModeVerifyAll, OwnerID: cellName + "-instance", Fetcher: fetcher, Trust: func() *delivery.TrustSet { return trust }, Mirror: mirror, Rollout: effects, Journal: journal, Authority: d.checkAuthority})
				if err != nil {
					t.Fatal(err)
				}
				d.executor = executor
				raw, err := os.ReadFile("../delivery/testdata/request-v1.json")
				if err != nil {
					t.Fatal(err)
				}
				request, err := delivery.ParseRequest(string(raw))
				if err != nil {
					t.Fatal(err)
				}
				request.OperationID = "regional-delivery"
				request.Target.Regions = []string{cellName}
				request.Artifact.Digest = delivery.SHA256Digest(artifact)
				if mode == "multi-region" {
					request.Target.Regions = []string{"gru", "sfo", "fra"}
				}
				if mode == "wrong-region" {
					request.Target.Regions = []string{"fra"}
				}
				if mode == "superseded" {
					fetcher.before = func() error {
						return d.admit(ctx, deliveryAdmission{Version: 1, OperationID: "replacement", PayloadDigest: "replacement", IdempotencyDigest: "replacement", Generation: 2}, epoch)
					}
				}
				if mode == "lease-replaced" {
					fetcher.before = func() error {
						entry, err := leaders.Get(ctx, "authority.regional")
						if err != nil {
							return err
						}
						var lease authority.RegionalAuthorityLeaseDocument
						if err := json.Unmarshal(entry.Value(), &lease); err != nil {
							return err
						}
						lease.Epoch++
						lease.CandidateId = cellName + "-controller-replacement"
						body, _ := json.Marshal(lease)
						_, err = leaders.Update(ctx, "authority.regional", body, entry.Revision())
						return err
					}
				}
				signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				signer, err := security.NewCommandSignatureSignerFromKey(signerKey)
				if err != nil {
					t.Fatal(err)
				}
				verifier, err := security.NewCommandSignatureVerifierFromKeys([]security.CommandSignatureTrustKey{{KeyID: signer.PublicKeyID(), Algorithm: security.CommandSignatureAlgorithm, PublicKeySPKI: mustIngressSPKI(t, &signerKey.PublicKey)}})
				if err != nil {
					t.Fatal(err)
				}
				js, err := jetstream.New(nc)
				if err != nil {
					t.Fatal(err)
				}
				replayKV, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "replay", Storage: jetstream.FileStorage, TTL: 15 * time.Minute, MaxValueSize: 256})
				if err != nil {
					t.Fatal(err)
				}
				replay, err := NewNatsCommandReplayStore(replayKV)
				if err != nil {
					t.Fatal(err)
				}
				boundary, err := security.NewCommandSecurityBoundary(verifier, replay, 0)
				if err != nil {
					t.Fatal(err)
				}
				cell, _ := contracts.CellIdTryCreate(cellName)
				aggregate, _ := contracts.AggregateIdTryCreate("delivery")
				generation, _ := protocol.DesiredGenerationTryCreate(1)
				minimumEpoch, _ := protocol.WriterEpochTryCreate(1)
				version, _ := protocol.ProtocolRevisionTryCreate(int64(protocol.ProtocolVersion.Current()))
				subject := "ts.orch.v1." + cellName + ".command.delivery"
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
				wire := signedDeliveryTestWire(t, signer, cell, aggregate, request, signedEpoch)
				reply, err := nc.Request(subject, wire, 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				effects.mu.Lock()
				puts := append([]string(nil), effects.puts...)
				targets := append([]string(nil), effects.targets...)
				effects.mu.Unlock()
				operation, exists, err := journal.GetWithError(request.OperationID)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "success" {
					if string(reply.Data) != string(CommandIngressCodeAccepted) {
						t.Fatalf("reply: %s", reply.Data)
					}
					if !exists || operation.Receipt == nil || operation.Receipt.Status != delivery.StatusSucceeded {
						t.Fatalf("missing successful durable receipt: %+v", operation)
					}
					if !reflect.DeepEqual(operation.Request, request) || !reflect.DeepEqual(targets, []string{cellName}) {
						t.Fatalf("signed request changed or foreign rollout: %v", targets)
					}
					if len(puts) != 0 || len(effects.heads) != len(estate.Default().Regions) {
						t.Fatalf("regional delivery wrote mirrors or skipped availability checks: writes=%v reads=%v", puts, effects.heads)
					}
					replayed, err := nc.Request(subject, wire, time.Second)
					if err != nil || string(replayed.Data) != string(CommandIngressCodeRejected) {
						t.Fatalf("replay: %v %v", replayed, err)
					}
				} else {
					if string(reply.Data) != string(CommandIngressCodeDispatchFailed) {
						t.Fatalf("rejected command reply: %s", reply.Data)
					}
					if len(puts) != 0 || len(targets) != 0 {
						t.Fatalf("fenced command mutated providers: puts=%v targets=%v", puts, targets)
					}
					if exists && operation.Receipt != nil && operation.Receipt.Status == delivery.StatusSucceeded {
						t.Fatal("fenced command recorded success")
					}
				}
			})
		}
	}
}

func signedDeliveryTestWire(t *testing.T, signer *security.CommandSignatureSigner, cell contracts.CellId, aggregate contracts.AggregateId, request *delivery.Request, epochValue int64) []byte {
	t.Helper()
	version, _ := protocol.ProtocolRevisionTryCreate(int64(protocol.ProtocolVersion.Current()))
	generation, _ := protocol.DesiredGenerationTryCreate(1)
	epoch, _ := protocol.WriterEpochTryCreate(epochValue)
	operation, _ := contracts.OperationIdTryCreate(request.OperationID)
	idempotency, _ := contracts.IdempotencyKeyTryCreate(request.OperationID)
	attempt, _ := protocol.DeliveryAttemptTryCreate(1)
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	payload := protocol.OpaquePayloadCopyFrom(body)
	sum := sha256.Sum256(body)
	digest, _ := protocol.PayloadDigestTryCopyFrom(sum[:])
	now := time.Now().UTC()
	envelope := protocol.NewCommandEnvelope(version, cell, aggregate, generation, epoch, operation, idempotency, now, now.Add(time.Minute), attempt, payload, digest, protocol.OpaqueSignature{})
	signature, err := signer.Sign(envelope.SignedMaterial)
	if err != nil {
		t.Fatal(err)
	}
	envelope = protocol.NewCommandEnvelope(version, cell, aggregate, generation, epoch, operation, idempotency, now, now.Add(time.Minute), attempt, payload, digest, signature)
	wire, err := protocol.EncodeCommandEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
