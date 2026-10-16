package authority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
)

func identityResetFixture(t *testing.T) (jetstream.JetStream, IdentityReset, IdentityResetTarget, trust.Keyring, ed25519.PrivateKey) {
	t.Helper()
	js := newAuthorityTestJetStream(t)
	for _, bucket := range []string{"TS_SERVICE_SET", "TS_TRUST_ROOTS"} {
		if _, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: bucket, Storage: jetstream.FileStorage, Replicas: 1}); err != nil {
			t.Fatal(err)
		}
	}
	return identityResetFixtureWithJetStream(t, js, 1)
}

func identityResetFixtureWithJetStream(t *testing.T, js jetstream.JetStream, replicas int) (jetstream.JetStream, IdentityReset, IdentityResetTarget, trust.Keyring, ed25519.PrivateKey) {
	t.Helper()
	stream, err := openControlStream(t.Context(), js, replicas)
	if err != nil {
		t.Fatal(err)
	}
	// Obsolete identities are opaque replacement preconditions, never admitted.
	old := []byte(`{"version":1,"scope":"gru","candidate_id":"old-controller","owner_id":"old-owner","epoch":7}`)
	ack, err := js.Publish(t.Context(), fmt.Sprintf("%s.gru.lease", controlSubjectRoot), old)
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	reset := IdentityReset{Version: 1, OperationID: entityid.New(), DeploymentID: entityid.New(), ClusterID: entityid.New(),
		Scope: "gru", Environment: "canary", CheckpointSHA256: strings.Repeat("a", 64), HostStatePlanSHA256: resetDigest([]byte("verified empty host plan")),
		LastSequence: info.State.LastSeq, PreviousSequence: ack.Sequence, PreviousSHA256: resetDigest(old), EpochFloor: 7, Epoch: 8,
		Records: []IdentityResetRecord{{Action: IdentityResetReplaceKV, Bucket: "TS_SERVICE_SET", Key: "current", SHA256: resetDigest([]byte("replacement spec"))},
			{Action: IdentityResetReplaceKV, Bucket: "TS_TRUST_ROOTS", Key: "chain", SHA256: resetDigest([]byte("replacement roots"))},
			{Action: IdentityResetReplaceKV, Bucket: "TS_TRUST_ROOTS", Key: "material-generations", SHA256: resetDigest([]byte("replacement material"))}}}
	target := IdentityResetTarget{OperationID: reset.OperationID, DeploymentID: reset.DeploymentID, ClusterID: reset.ClusterID,
		Scope: reset.Scope, Environment: reset.Environment, CheckpointSHA256: reset.CheckpointSHA256, HostStatePlanSHA256: reset.HostStatePlanSHA256, Replicas: replicas}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	return js, reset, target, roots, private
}

func signIdentityResetForTest(t *testing.T, reset IdentityReset, key ed25519.PrivateKey) trust.Envelope {
	t.Helper()
	now := time.Now().UTC()
	envelope, err := SignIdentityReset(reset, now.Add(-time.Minute), now.Add(30*time.Minute), key)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestIdentityResetFloorAndPermanentFenceProof(t *testing.T) {
	for _, scenario := range []string{"empty slot", "renewal", "other subject", "own barrier", "foreign barrier", "own barrier then renewal", "expired evidence", "expiring stream"} {
		t.Run(scenario, func(t *testing.T) {
			js, reset, target, roots, key := identityResetFixture(t)
			envelope := signIdentityResetForTest(t, reset, key)
			floor, err := ObserveIdentityResetFloor(t.Context(), js, reset.Scope, target.Replicas)
			if err != nil || floor.LastSequence != reset.LastSequence || floor.PreviousSequence != reset.PreviousSequence || floor.PreviousSHA256 != reset.PreviousSHA256 {
				t.Fatalf("opaque floor = %+v: %v", floor, err)
			}
			subject := fmt.Sprintf("%s.gru.lease", controlSubjectRoot)
			switch scenario {
			case "own barrier", "foreign barrier", "own barrier then renewal":
				chosen := envelope
				if scenario == "foreign barrier" {
					other := reset
					other.OperationID = entityid.New()
					chosen = signIdentityResetForTest(t, other, key)
				}
				var candidate IdentityReset
				if err := json.Unmarshal(chosen.Payload, &candidate); err != nil {
					t.Fatal(err)
				}
				barrier, err := identityResetLease(candidate, resetDigest(chosen.Payload))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := js.Publish(t.Context(), subject, barrier); err != nil {
					t.Fatal(err)
				}
				if scenario == "own barrier then renewal" {
					if _, err := js.Publish(t.Context(), subject, []byte("later ordinary lease")); err != nil {
						t.Fatal(err)
					}
				} else if _, err := ObserveIdentityResetFloor(t.Context(), js, reset.Scope, target.Replicas); !errors.Is(err, ErrConflict) {
					t.Fatalf("held barrier resampled: %v", err)
				}
			case "renewal", "other subject":
				if scenario == "other subject" {
					subject = fmt.Sprintf("%s.gru.host.registration.opaque", controlSubjectRoot)
				}
				if _, err := js.Publish(t.Context(), subject, []byte("opaque current writer bytes")); err != nil {
					t.Fatal(err)
				}
			case "expiring stream":
				stream, err := js.Stream(t.Context(), ControlStreamName)
				if err != nil {
					t.Fatal(err)
				}
				info, err := stream.Info(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				info.Config.MaxAge = time.Hour
				if _, err := js.UpdateStream(t.Context(), info.Config); err != nil {
					t.Fatal(err)
				}
				if _, err := ObserveIdentityResetFloor(t.Context(), js, reset.Scope, target.Replicas); err == nil {
					t.Fatal("expiring stream supplied a floor")
				}
			}
			stream, err := js.Stream(t.Context(), ControlStreamName)
			if err != nil {
				t.Fatal(err)
			}
			before, err := stream.Info(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			evidenceTime := time.Now()
			if scenario == "expired evidence" {
				evidenceTime = envelope.ExpiresAt.Add(time.Second)
			}
			err = VerifyIdentityResetUncommittable(t.Context(), js, envelope, roots, target, evidenceTime)
			allowed := scenario == "renewal" || scenario == "other subject"
			if (err == nil) != allowed {
				t.Fatalf("permanent fence evidence = %v, allowed=%v", err, allowed)
			}
			after, err := stream.Info(t.Context())
			if err != nil || before.State.LastSeq != after.State.LastSeq {
				t.Fatalf("read-only proof mutated history: %v", err)
			}
		})
	}
}

func TestRootSignedIdentityResetPreservesHistoryAndFencesOldDeployment(t *testing.T) {
	js, reset, target, roots, key := identityResetFixture(t)
	envelope := signIdentityResetForTest(t, reset, key)
	sequence, err := ResetIdentityLease(t.Context(), js, envelope, roots, target, time.Now())
	if err != nil || sequence <= reset.PreviousSequence {
		t.Fatalf("reset sequence=%d, error=%v", sequence, err)
	}
	if replay, err := ResetIdentityLease(t.Context(), js, envelope, roots, target, time.Now()); err != nil || replay != sequence {
		t.Fatalf("exact retry sequence=%d, error=%v", replay, err)
	}
	stream, err := js.Stream(t.Context(), ControlStreamName)
	if err != nil {
		t.Fatal(err)
	}
	old, err := stream.GetMsg(t.Context(), reset.PreviousSequence)
	if err != nil || resetDigest(old.Data) != reset.PreviousSHA256 {
		t.Fatalf("old audit bytes were lost: %v", err)
	}
	barrier, err := stream.GetMsg(t.Context(), sequence)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := decodeLease(barrier.Data)
	if err != nil || !lease.Released || lease.Epoch != reset.Epoch || lease.DeploymentID != target.DeploymentID {
		t.Fatalf("released replacement barrier=%+v, error=%v", lease, err)
	}
	var oldDecoder struct {
		Version       int    `json:"version"`
		Scope         string `json:"scope"`
		CandidateID   string `json:"candidate_id"`
		OwnerID       string `json:"owner_id"`
		Epoch         uint64 `json:"epoch"`
		LeaseDuration int64  `json:"lease_duration_ns"`
		TransitionID  string `json:"transition_id"`
		Released      bool   `json:"released"`
	}
	if err := json.Unmarshal(barrier.Data, &oldDecoder, json.RejectUnknownMembers(true)); err == nil {
		t.Fatal("old lease decoder admitted the new deployment binding")
	}
	current, err := Start(t.Context(), js, Config{Scope: "gru", DeploymentID: target.DeploymentID, CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	if current.Current().CanMutate() || current.Current().Reason != "identity-reset-pending" {
		t.Fatalf("new authority acquired during the identity replacement: %+v", current.Current())
	}
	stale, err := Start(t.Context(), js, Config{Scope: "gru", DeploymentID: entityid.New(), CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer stale.Close()
	guardErr := stale.Guard(t.Context(), current.Current().Epoch)
	if stale.Current().CanMutate() || !errors.Is(guardErr, ErrFenced) && !errors.Is(guardErr, ErrNotLeader) {
		t.Fatalf("foreign deployment retained authority: %+v", stale.Current())
	}
	if _, err := CompleteIdentityReset(t.Context(), js, envelope, roots, target, time.Now()); err == nil {
		t.Fatal("authority released before the replacement records existed")
	}
	values := [][]byte{[]byte("replacement spec"), []byte("replacement roots"), []byte("replacement material")}
	if _, err := ReplaceIdentityRecords(t.Context(), js, envelope, roots, target, values, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := CompleteIdentityReset(t.Context(), js, envelope, roots, target, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := current.reconcile(t.Context()); err != nil || !current.Current().CanMutate() || current.Current().Epoch <= reset.Epoch {
		t.Fatalf("new authority did not advance the floor after completion: %+v, %v", current.Current(), err)
	}
	if _, err := ResetIdentityLease(t.Context(), js, envelope, roots, target, time.Now()); !errors.Is(err, ErrConflict) {
		t.Fatalf("old operation rolled authority back: %v", err)
	}
}

func TestIdentityResetRejectsUntrustedOrChangedInputsBeforePublishing(t *testing.T) {
	for _, name := range []string{"wrong root", "wrong target", "expired", "wrong predecessor", "changed log", "unknown member"} {
		t.Run(name, func(t *testing.T) {
			js, reset, target, roots, key := identityResetFixture(t)
			now := time.Now().UTC()
			if name == "wrong predecessor" {
				reset.PreviousSHA256 = strings.Repeat("0", 64)
			}
			envelope := signIdentityResetForTest(t, reset, key)
			switch name {
			case "wrong root":
				_, other, _ := ed25519.GenerateKey(rand.Reader)
				envelope = signIdentityResetForTest(t, reset, other)
			case "wrong target":
				target.ClusterID = entityid.New()
			case "expired":
				now = envelope.ExpiresAt.Add(time.Second)
			case "changed log":
				if _, err := js.Publish(t.Context(), fmt.Sprintf("%s.gru.host.registration.ignored", controlSubjectRoot), []byte("new effect")); err != nil {
					t.Fatal(err)
				}
			case "unknown member":
				payload := bytes.TrimSuffix(envelope.Payload, []byte("}"))
				payload = append(payload, []byte(`,"allow_legacy":true}`)...)
				var err error
				envelope, err = trust.Sign(payload, reset.trustScope(), envelope.IssuedAt, envelope.ExpiresAt, key)
				if err != nil {
					t.Fatal(err)
				}
			}
			stream, err := js.Stream(t.Context(), ControlStreamName)
			if err != nil {
				t.Fatal(err)
			}
			before, err := stream.Info(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ResetIdentityLease(t.Context(), js, envelope, roots, target, now); err == nil {
				t.Fatal("rejected input was admitted")
			}
			after, err := stream.Info(t.Context())
			if err != nil || after.State.LastSeq != before.State.LastSeq {
				t.Fatalf("rejected reset changed log: %v", err)
			}
		})
	}
}

func TestIdentityResetRequiresV1AndMonotonicFloor(t *testing.T) {
	_, reset, _, _, key := identityResetFixture(t)
	for name, change := range map[string]func(*IdentityReset){
		"v2":                  func(reset *IdentityReset) { reset.Version = 2 },
		"legacy identity":     func(reset *IdentityReset) { reset.DeploymentID = "old-deployment" },
		"same epoch":          func(reset *IdentityReset) { reset.Epoch = reset.EpochFloor },
		"overflow":            func(reset *IdentityReset) { reset.Epoch = ^uint64(0) },
		"missing replacement": func(reset *IdentityReset) { reset.Records = reset.Records[:2] },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := reset
			change(&candidate)
			now := time.Now().UTC()
			if _, err := SignIdentityReset(candidate, now, now.Add(time.Minute), key); err == nil {
				t.Fatal("invalid reset was signed")
			}
		})
	}
}
