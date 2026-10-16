package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nkeys"
)

func TestRuntimeEffectR3Integration(t *testing.T) {
	js, _ := newIdentityHostR3(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	config := Config{DeploymentID: authorityTestDeployment, Scope: "gru", CandidateID: entityid.New(), Replicas: 3}
	old, err := Start(ctx, js, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = old.Close() })
	scope := WorkloadScope{DatabaseID: entityid.New(), PartitionID: entityid.New()}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	userPublic, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	material := []byte(`{"grant":"canonical-retained-proof"}`)
	materialDigest := sha256.Sum256(material)
	effect := RuntimeEffect{EffectID: entityid.New(), Scope: scope, RegistrationID: entityid.New(), HostSessionID: entityid.New(), WorkerPublicKey: base64.StdEncoding.EncodeToString(public), NATSUserPublicKey: userPublic, RegistrationGeneration: 1, InstanceID: "ocid1.instance.integration.runtime-a", NodeID: strings.Repeat("a", 25), TaskID: strings.Repeat("b", 25), ServiceID: strings.Repeat("c", 25), TaskSHA256: strings.Repeat("d", 64), AdmissionSHA256: strings.Repeat("e", 64), Material: material, MaterialSHA256: hex.EncodeToString(materialDigest[:]), Epoch: old.Current().Epoch, IssuedAt: now, ExpiresAt: now.Add(2 * time.Second), Phase: RuntimeEffectHeld}
	invalid := effect
	invalid.MaterialSHA256 = strings.Repeat("f", 64)
	if _, err := old.BeginRuntimeEffect(ctx, effect.Epoch, invalid); err == nil {
		t.Fatal("journal accepted material with a mismatched digest")
	}
	initial, err := old.BeginRuntimeEffect(ctx, effect.Epoch, effect)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := old.BeginRuntimeEffect(ctx, effect.Epoch, effect); err != nil || replay != initial {
		t.Fatalf("begin replay=%d,%v", replay, err)
	}
	pending, err := old.ListUnresolvedRuntimeEffects(ctx, scope)
	if err != nil || len(pending) != 1 || pending[0].Sequence != initial || !bytes.Equal(pending[0].Material, material) {
		t.Fatalf("retained effect=%+v,%v", pending, err)
	}
	pending[0].Material[0] ^= 1
	pending, err = old.ListUnresolvedRuntimeEffects(ctx, scope)
	if err != nil || !bytes.Equal(pending[0].Material, material) {
		t.Fatal("readback mutation changed retained material")
	}
	conflict := effect
	conflict.EffectID, conflict.HostSessionID = entityid.New(), entityid.New()
	if _, err := old.BeginRuntimeEffect(ctx, effect.Epoch, conflict); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("replacement session escaped held effect: %v", err)
	}
	replica := effect
	replica.EffectID, replica.RegistrationID, replica.HostSessionID = entityid.New(), entityid.New(), entityid.New()
	replica.InstanceID, replica.NodeID, replica.TaskID = "ocid1.instance.integration.runtime-b", strings.Repeat("f", 25), strings.Repeat("g", 25)
	replicaSequence, err := old.BeginRuntimeEffect(ctx, effect.Epoch, replica)
	if err != nil {
		t.Fatalf("distinct replica sharing a service: %v", err)
	}
	effect.ExpiresAt = now.Add(3 * time.Second)
	renewed, err := old.RenewRuntimeEffect(ctx, effect.Epoch, effect, initial)
	if err != nil || renewed <= initial {
		t.Fatalf("renew=%d,%v", renewed, err)
	}
	if replay, err := old.RenewRuntimeEffect(ctx, effect.Epoch, effect, initial); err != nil || replay != renewed {
		t.Fatalf("renew replay=%d,%v", replay, err)
	}
	changed := effect
	changed.HostSessionID = entityid.New()
	if _, err := old.RenewRuntimeEffect(ctx, effect.Epoch, changed, renewed); err == nil {
		t.Fatal("replacement Agent session renewed old grant")
	}
	changed = effect
	changed.Material = []byte(`{"grant":"different-retained-proof"}`)
	changedDigest := sha256.Sum256(changed.Material)
	changed.MaterialSHA256 = hex.EncodeToString(changedDigest[:])
	if _, err := old.RenewRuntimeEffect(ctx, effect.Epoch, changed, renewed); err == nil {
		t.Fatal("renew replaced retained grant material")
	}
	changed = effect
	changed.ExpiresAt = old.Current().ExpiresAt.Add(time.Second)
	if _, err := old.RenewRuntimeEffect(ctx, effect.Epoch, changed, renewed); err == nil {
		t.Fatal("grant outlived authority lease")
	}
	changed = effect
	changed.ExpiresAt = effect.ExpiresAt.Add(time.Millisecond)
	if _, err := old.RenewRuntimeEffect(ctx, effect.Epoch, changed, initial); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale renewal CAS=%v", err)
	}

	terminal := TerminalIntent{Cell: "gru", DatabaseID: scope.DatabaseID, PartitionID: scope.PartitionID, Region: "GRU", Owner: "runtime-test", CompartmentID: "ocid1.compartment.integration.runtime", FleetGeneration: 1, PlacementGeneration: 1, PlacementPayloadDigest: strings.Repeat("a", 64), OperationID: entityid.New(), Nonce: strings.Repeat("b", 32), Targets: []TerminalTarget{{SeatID: entityid.New(), MemberID: entityid.New(), HostCreateKey: entityid.New(), DataCreateKey: entityid.New()}}, DisposableWorkload: true, AcknowledgePermanentDataLoss: true, AuthorizeForcedStop: true}
	terminalBytes, err := json.Marshal(terminal, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	var terminalProofs atomic.Int64
	terminalCommit := func(r *Runtime) error {
		_, err := r.CommitTerminalIntent(ctx, r.Current().Epoch, scope, terminal.OperationID, terminalBytes, func(context.Context) error { terminalProofs.Add(1); return nil })
		return err
	}
	if err := terminalCommit(old); !errors.Is(err, ErrFenced) || terminalProofs.Load() != 0 {
		t.Fatalf("terminal bypassed held execution: %v", err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	config.CandidateID = entityid.New()
	current, err := Start(ctx, js, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = current.Close() })
	epoch := current.Current().Epoch
	if epoch <= effect.Epoch {
		t.Fatal("replacement leader did not advance epoch")
	}
	if _, err := current.RenewRuntimeEffect(ctx, epoch, effect, renewed); err == nil {
		t.Fatal("new leader renewed an earlier epoch")
	}
	all, err := current.ListAllUnresolvedRuntimeEffects(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("cross-epoch recovery=%+v,%v", all, err)
	}
	if err := terminalCommit(current); !errors.Is(err, ErrFenced) {
		t.Fatalf("new epoch bypassed retained runtime holds: %v", err)
	}
	if _, err := current.CloseRuntimeEffect(ctx, epoch, scope, effect.EffectID, initial); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale close CAS=%v", err)
	}
	closing, err := current.CloseRuntimeEffect(ctx, epoch, scope, effect.EffectID, renewed)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := current.CloseRuntimeEffect(ctx, epoch, scope, effect.EffectID, closing); err != nil || replay != closing {
		t.Fatalf("close replay=%d,%v", replay, err)
	}
	if err := terminalCommit(current); !errors.Is(err, ErrFenced) {
		t.Fatalf("closing released terminal hold: %v", err)
	}

	var stopped, wrongTask atomic.Bool
	var proofReads atomic.Int64
	retained := map[string]RuntimeEffect{effect.EffectID: effect, replica.EffectID: replica}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proofReads.Add(1)
		proof := retained[r.URL.Query().Get("effect")]
		if wrongTask.Load() {
			proof.TaskID = strings.Repeat("z", 25)
		}
		wire, _ := json.Marshal(struct {
			Effect  RuntimeEffect `json:"effect"`
			Stopped bool          `json:"stopped"`
		}{proof, stopped.Load()})
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	verify := func(ctx context.Context, expected RuntimeEffect) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"?effect="+expected.EffectID, nil)
		if err != nil {
			return err
		}
		response, err := server.Client().Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		var proof struct {
			Effect  RuntimeEffect `json:"effect"`
			Stopped bool          `json:"stopped"`
		}
		if err := json.UnmarshalRead(response.Body, &proof, json.RejectUnknownMembers(true)); err != nil {
			return err
		}
		proof.Effect.Phase, proof.Effect.Sequence = expected.Phase, expected.Sequence
		if !proof.Stopped || !reflect.DeepEqual(proof.Effect, expected) {
			return fmt.Errorf("independent exact stopped proof unavailable")
		}
		return nil
	}
	if _, err := current.SettleRuntimeEffect(ctx, epoch, scope, effect.EffectID, closing, verify); !errors.Is(err, ErrFenced) || proofReads.Load() != 0 {
		t.Fatalf("settled before latest expiry: %v", err)
	}
	timer := time.NewTimer(time.Until(effect.ExpiresAt) + 10*time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	if _, err := current.SettleRuntimeEffect(ctx, epoch, scope, effect.EffectID, closing, verify); err == nil {
		t.Fatal("settled running task after expiry")
	}
	stopped.Store(true)
	wrongTask.Store(true)
	if _, err := current.SettleRuntimeEffect(ctx, epoch, scope, effect.EffectID, closing, verify); err == nil {
		t.Fatal("settled with another task's stop proof")
	}
	wrongTask.Store(false)
	if _, err := current.SettleRuntimeEffect(ctx, epoch, scope, effect.EffectID, renewed, verify); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale settlement CAS=%v", err)
	}
	retryProofs := 0
	_, err = current.SettleRuntimeEffect(ctx, epoch, scope, effect.EffectID, closing, func(ctx context.Context, proof RuntimeEffect) error {
		retryProofs++
		if err := verify(ctx, proof); err != nil {
			return err
		}
		if retryProofs == 1 {
			// An independent acknowledged append invalidates the first global CAS.
			other := WorkloadScope{DatabaseID: entityid.New(), PartitionID: entityid.New()}
			effectID := entityid.New()
			key, _ := enrollmentEffectSubjectKey(other, effectID)
			payload, _ := enrollmentEffectBytes("ocid1.instance.integration.concurrent", "pending")
			wire, err := json.Marshal(controlRecord{Version: 1, Kind: MutationEnrollmentEffect, Scope: config.Scope, SubjectKey: key, OperationID: effectID, Epoch: epoch, Payload: payload})
			if err != nil {
				return err
			}
			if _, err := js.PublishMsg(ctx, controlMessage(mutationSubject(config.Scope, MutationEnrollmentEffect, key), string(MutationEnrollmentEffect), effectID, wire)); err != nil {
				return err
			}
			stopped.Store(false)
		}
		return nil
	})
	if err == nil || retryProofs != 2 {
		t.Fatalf("global CAS reused stale stopped proof: calls=%d,error=%v", retryProofs, err)
	}
	stopped.Store(true)
	settled, err := current.SettleRuntimeEffect(ctx, epoch, scope, effect.EffectID, closing, verify)
	if err != nil || settled <= closing {
		t.Fatalf("settle=%d,%v", settled, err)
	}
	if err := terminalCommit(current); !errors.Is(err, ErrFenced) {
		t.Fatalf("unsettled second replica lost hold: %v", err)
	}
	if _, err := current.SettleRuntimeEffect(ctx, epoch, scope, replica.EffectID, replicaSequence, verify); err != nil {
		t.Fatal(err)
	}
	if err := terminalCommit(current); err != nil {
		t.Fatalf("terminal remained held after independently verified settlement: %v", err)
	}
	all, err = current.ListAllUnresolvedRuntimeEffects(ctx)
	if err != nil || len(all) != 0 {
		t.Fatalf("settled effects unresolved=%+v,%v", all, err)
	}
	currentEffect, err := current.readRuntimeEffect(ctx, scope, effect.EffectID)
	if err != nil || currentEffect.Epoch != effect.Epoch || !bytes.Equal(currentEffect.Material, material) {
		t.Fatalf("settlement lost original epoch/material: %+v,%v", currentEffect, err)
	}
	expiring := effect
	expiring.Scope = WorkloadScope{DatabaseID: entityid.New(), PartitionID: entityid.New()}
	expiring.EffectID, expiring.Epoch = entityid.New(), epoch
	expiring.IssuedAt = time.Now().UTC()
	expiring.ExpiresAt = expiring.IssuedAt.Add(time.Second)
	expiringSequence, err := current.BeginRuntimeEffect(ctx, epoch, expiring)
	if err != nil {
		t.Fatal(err)
	}
	expiryTimer := time.NewTimer(time.Until(expiring.ExpiresAt) + 10*time.Millisecond)
	defer expiryTimer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-expiryTimer.C:
	}
	if _, err := current.BeginRuntimeEffect(ctx, epoch, expiring); !errors.Is(err, ErrFenced) {
		t.Fatalf("expired begin replay revived a grant: %v", err)
	}
	extension := expiring
	extension.ExpiresAt = time.Now().UTC().Add(time.Second)
	if _, err := current.RenewRuntimeEffect(ctx, epoch, extension, expiringSequence); !errors.Is(err, ErrFenced) {
		t.Fatalf("expired grant renewed: %v", err)
	}
	key, _ := enrollmentEffectSubjectKey(scope, entityid.New())
	corrupt, err := json.Marshal(controlRecord{Version: 1, Kind: MutationRuntimeEffect, Scope: config.Scope, SubjectKey: key, OperationID: entityid.New(), Epoch: epoch, Payload: []byte(`{"phase":"settled"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.PublishMsg(ctx, controlMessage(mutationSubject(config.Scope, MutationRuntimeEffect, key), string(MutationRuntimeEffect), entityid.New(), corrupt)); err != nil {
		t.Fatal(err)
	}
	if _, err := current.ListUnresolvedRuntimeEffects(ctx, scope); err == nil {
		t.Fatal("malformed settled history did not retain the scoped hold")
	}
	if _, err := current.ListAllUnresolvedRuntimeEffects(ctx); err == nil {
		t.Fatal("recovery inventory ignored malformed retained history")
	}
}
