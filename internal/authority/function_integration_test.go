package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestFunctionIntentAndRecipientGrantsUseDurableCurrentFloor(t *testing.T) {
	fixture := newAuthorityFunctionFixture(t)
	js := newAuthorityTestJetStream(t)
	runtime := startFunctionAuthority(t, js)
	epoch := runtime.Current().Epoch
	proof := fixture.proof(t, 42, "first", time.Hour)
	if _, err := runtime.CommitFunctionIntent(t.Context(), epoch, entityid.New(), 0, release.VerifiedFunction{}); err == nil {
		t.Fatal("zero proof admitted")
	}
	sequence, err := runtime.CommitFunctionIntent(t.Context(), epoch, entityid.New(), 0, proof)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenReader(t.Context(), js, "gru")
	if err != nil {
		t.Fatal(err)
	}
	entry, err := reader.ReadFunctionIntent(t.Context(), fixture.claim.TenantID, fixture.claim.FunctionID)
	if err != nil {
		t.Fatal(err)
	}
	for _, list := range []func(context.Context) ([]LogEntry, error){runtime.ListFunctionIntents, reader.ListFunctionIntents} {
		entries, err := list(t.Context())
		if err != nil || len(entries) != 1 || entries[0].Sequence != sequence || entries[0].SubjectKey != entry.SubjectKey {
			t.Fatalf("current function enumeration: %+v: %v", entries, err)
		}
	}
	intent, err := DecodeFunctionIntent(entry)
	if err != nil || entry.Sequence != sequence || !bytes.Equal(intent.Envelope, proof.Envelope()) ||
		!bytes.Equal(intent.Delegation, proof.Delegation()) || bytes.Contains(entry.Payload, fixture.module) {
		t.Fatalf("durable signed metadata: %+v, %v", intent, err)
	}
	if err := reader.VerifyFunctionIntent(t.Context(), proof); err != nil {
		t.Fatal(err)
	}
	resumed, err := release.VerifyFunctionCurrent(intent.Envelope, intent.Delegation, fixture.module, fixture.roots,
		release.FunctionExpectation{Environment: intent.Claim.Environment, Cell: intent.Claim.Cell, TenantID: intent.Claim.TenantID,
			FunctionID: intent.Claim.FunctionID, Revision: intent.Claim.Revision, Digest: intent.Claim.Digest,
			MinimumSequence: intent.Claim.Sequence}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.VerifyFunctionIntent(t.Context(), resumed); err != nil {
		t.Fatalf("retained signed metadata cannot resume admission: %v", err)
	}
	wire, delegation := proof.Envelope(), proof.Delegation()
	wire[0], delegation[0] = 0, 0
	if !bytes.Equal(proof.Envelope(), intent.Envelope) || !bytes.Equal(proof.Delegation(), intent.Delegation) {
		t.Fatal("mutable accessor changed sealed proof")
	}
	for _, rejected := range []release.VerifiedFunction{
		fixture.proof(t, 41, "old", time.Hour), fixture.proof(t, 42, "equivocated", time.Hour),
	} {
		if _, err := runtime.CommitFunctionIntent(t.Context(), epoch, entityid.New(), sequence, rejected); !errors.Is(err, ErrConflict) {
			t.Fatalf("rollback or same-sequence equivocation: %v", err)
		}
	}
	binding := authorityFunctionBinding()
	grantSequence, err := runtime.CommitFunctionGrant(t.Context(), epoch, entityid.New(), 0, proof, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.VerifyFunctionGrant(t.Context(), proof, binding); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*FunctionBinding){
		"service":     func(b *FunctionBinding) { b.ServiceID = strings.Repeat("z", 25) },
		"node":        func(b *FunctionBinding) { b.NodeID = strings.Repeat("z", 25) },
		"instance":    func(b *FunctionBinding) { b.InstanceID += "other" },
		"host":        func(b *FunctionBinding) { b.HostID = entityid.New() },
		"fingerprint": func(b *FunctionBinding) { b.Fingerprint = strings.Repeat("f", 64) },
		"material":    func(b *FunctionBinding) { b.MaterialManifestSHA256 = strings.Repeat("f", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := binding
			change(&changed)
			if err := reader.VerifyFunctionGrant(t.Context(), proof, changed); !errors.Is(err, ErrConflict) {
				t.Fatalf("retargeted grant verified: %v", err)
			}
			if _, err := runtime.CommitFunctionGrant(t.Context(), epoch, entityid.New(), grantSequence, proof, changed); !errors.Is(err, ErrConflict) {
				t.Fatalf("retargeted task grant replaced: %v", err)
			}
		})
	}
	next := fixture.proof(t, 43, "second", time.Hour)
	if _, err := runtime.CommitFunctionIntent(t.Context(), epoch, entityid.New(), 0, next); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale stream CAS: %v", err)
	}
	if _, err := runtime.CommitFunctionIntent(t.Context(), epoch, entityid.New(), sequence, next); err != nil {
		t.Fatal(err)
	}
	if err := reader.VerifyFunctionGrant(t.Context(), proof, binding); !errors.Is(err, ErrConflict) {
		t.Fatalf("old grant survived a newer release: %v", err)
	}
	binding.TaskID = strings.Repeat("d", 25)
	if _, err := runtime.CommitFunctionGrant(t.Context(), epoch, entityid.New(), 0, proof, binding); !errors.Is(err, ErrConflict) {
		t.Fatalf("old proof granted after newer release: %v", err)
	}
	if _, err := runtime.CommitFunctionGrant(t.Context(), epoch, entityid.New(), 0, next, binding); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.CommitHostMutation(t.Context(), epoch, MutationFunctionIntent, entry.SubjectKey, entityid.New(), entry.Sequence, entry.Payload); err == nil {
		t.Fatal("generic host mutation bypassed function admission")
	}
}

type functionExpiryRead struct {
	jetstream.Stream
	subject string
	expires time.Time
}

func (stream *functionExpiryRead) GetLastMsgForSubject(ctx context.Context, subject string) (*jetstream.RawStreamMsg, error) {
	entry, err := stream.Stream.GetLastMsgForSubject(ctx, subject)
	if subject == stream.subject {
		timer := time.NewTimer(max(0, time.Until(stream.expires.Add(time.Millisecond))))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return entry, err
}

func TestFunctionProofExpiresInsideFencedCommit(t *testing.T) {
	for _, stage := range []string{"compare-and-set-read", "verifier-read"} {
		t.Run(stage, func(t *testing.T) {
			fixture := newAuthorityFunctionFixture(t)
			js := newAuthorityTestJetStream(t)
			runtime := startFunctionAuthority(t, js)
			proof := fixture.proof(t, 42, "first", 2*time.Second)
			key, err := functionIntentKey(fixture.claim.TenantID, fixture.claim.FunctionID)
			if err != nil {
				t.Fatal(err)
			}
			if stage == "compare-and-set-read" {
				runtime.stream = &functionExpiryRead{Stream: runtime.stream,
					subject: mutationSubject("gru", MutationFunctionIntent, key), expires: proof.ExpiresAt()}
			} else {
				runtime.readStream = &functionExpiryRead{Stream: runtime.readStream,
					subject: mutationSubject("gru", MutationFunctionIntent, key), expires: proof.ExpiresAt()}
			}
			if _, err := runtime.CommitFunctionIntent(t.Context(), runtime.Current().Epoch, entityid.New(), 0, proof); !errors.Is(err, trust.ErrExpired) {
				t.Fatalf("signature expired during durable state read: %v", err)
			}
			if _, err := runtime.ReadFunctionIntent(t.Context(), fixture.claim.TenantID, fixture.claim.FunctionID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("expired function intent was published: %v", err)
			}
		})
	}
}

type functionConcurrentPublisher struct {
	jetstream.JetStream
	beforeGrant func(context.Context) error
}

func (js *functionConcurrentPublisher) PublishMsg(ctx context.Context, message *nats.Msg, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	if message.Header.Get("TerraScale-Control-Kind") == string(MutationFunctionGrant) && js.beforeGrant != nil {
		before := js.beforeGrant
		js.beforeGrant = nil
		if err := before(ctx); err != nil {
			return nil, err
		}
	}
	return js.JetStream.PublishMsg(ctx, message, opts...)
}

func TestFunctionGrantCannotRaceNewCurrentIntent(t *testing.T) {
	fixture := newAuthorityFunctionFixture(t)
	js := newAuthorityTestJetStream(t)
	wrapped := &functionConcurrentPublisher{JetStream: js}
	runtime := startFunctionAuthority(t, wrapped)
	proof := fixture.proof(t, 42, "first", time.Hour)
	sequence, err := runtime.CommitFunctionIntent(t.Context(), runtime.Current().Epoch, entityid.New(), 0, proof)
	if err != nil {
		t.Fatal(err)
	}
	next := fixture.proof(t, 43, "second", time.Hour)
	wrapped.beforeGrant = func(ctx context.Context) error {
		payload, err := json.Marshal(FunctionIntent{Claim: next.Claim(), EnvelopeSHA256: next.EnvelopeSHA256(),
			Envelope: next.Envelope(), Delegation: next.Delegation()}, json.FormatNilSliceAsNull(true))
		if err != nil {
			return err
		}
		key, err := functionIntentKey(fixture.claim.TenantID, fixture.claim.FunctionID)
		if err != nil {
			return err
		}
		wire, err := json.Marshal(controlRecord{Version: 1, Kind: MutationFunctionIntent, Scope: "gru", SubjectKey: key,
			OperationID: entityid.New(), Epoch: runtime.Current().Epoch, Payload: payload})
		if err != nil {
			return err
		}
		_, err = js.PublishMsg(ctx, controlMessage(mutationSubject("gru", MutationFunctionIntent, key),
			string(MutationFunctionIntent), entityid.New(), wire), jetstream.WithExpectLastSequenceForSubject(sequence, mutationSubject("gru", MutationFunctionIntent, key)))
		return err
	}
	binding := authorityFunctionBinding()
	if _, err := runtime.CommitFunctionGrant(t.Context(), runtime.Current().Epoch, entityid.New(), 0, proof, binding); !errors.Is(err, ErrConflict) {
		t.Fatalf("grant survived a release change before publication: %v", err)
	}
	if _, err := runtime.ReadFunctionGrant(t.Context(), binding.TaskID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("obsolete grant published: %v", err)
	}
}

type authorityFunctionFixture struct {
	claim      release.FunctionClaim
	module     []byte
	roots      trust.Keyring
	leaf       ed25519.PrivateKey
	delegation trust.Envelope
}

func newAuthorityFunctionFixture(t *testing.T) authorityFunctionFixture {
	t.Helper()
	module, err := hex.DecodeString("0061736d0100000001040160000003020100070a01065f737461727400000a040102000b")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(module)
	claim := release.FunctionClaim{Schema: release.FunctionSchema, ABI: release.FunctionABI,
		TenantID: entityid.Derive("tenant", "authority-function"), FunctionID: "echo", Revision: "first",
		Digest: hex.EncodeToString(digest[:]), Bytes: int64(len(module)), Environment: "canary", Cell: "GRU", Sequence: 42}
	root, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leaf, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := trust.EncodeDelegatedPublicKey(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	scope := release.FunctionScope(claim)
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
		SubjectKeyID: keyID, SubjectPublicKey: publicKey,
		Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
			Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}},
	}, now.Add(-time.Minute), now.Add(2*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		t.Fatal(err)
	}
	return authorityFunctionFixture{claim: claim, module: module, roots: roots, leaf: leaf, delegation: delegation}
}

func (fixture authorityFunctionFixture) proof(t *testing.T, sequence uint64, revision string, validFor time.Duration) release.VerifiedFunction {
	t.Helper()
	claim := fixture.claim
	claim.Sequence, claim.Revision = sequence, revision
	now := time.Now().UTC().Truncate(time.Second)
	envelope, err := release.SignFunctionClaim(claim, fixture.module, fixture.delegation, fixture.roots, fixture.leaf, now, validFor)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := trust.EncodeEnvelope(fixture.delegation)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := release.VerifyFunctionCurrent(wire, delegation, fixture.module, fixture.roots,
		release.FunctionExpectation{Environment: claim.Environment, Cell: claim.Cell, TenantID: claim.TenantID,
			FunctionID: claim.FunctionID, Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: sequence}, now)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func startFunctionAuthority(t *testing.T, js jetstream.JetStream) *Runtime {
	t.Helper()
	runtime, err := Start(t.Context(), js, Config{DeploymentID: entityid.Derive("deployment", "function-test"),
		Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	return runtime
}

func authorityFunctionBinding() FunctionBinding {
	return FunctionBinding{TaskID: strings.Repeat("a", 25), ServiceID: strings.Repeat("b", 25),
		NodeID: strings.Repeat("c", 25), InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.functionworker",
		Region: "sa-saopaulo-1", HostID: entityid.Derive("host", "function-test"),
		Fingerprint: strings.Repeat("a", 64), MaterialManifestSHA256: strings.Repeat("b", 64)}
}
