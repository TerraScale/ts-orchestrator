//go:build linux

package host

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

type readinessDeadlineMutations struct {
	authority.HostMutationStore
	read func(context.Context, authority.HostMutationKind, string) error
}

func (m readinessDeadlineMutations) ReadHostMutation(ctx context.Context, kind authority.HostMutationKind, key string) (authority.LogEntry, error) {
	if err := m.read(ctx, kind, key); err != nil {
		return authority.LogEntry{}, err
	}
	return m.HostMutationStore.ReadHostMutation(ctx, kind, key)
}

func TestRootContainerReadinessCapsFirstSourceWait(t *testing.T) {
	for _, bound := range []string{"effect", "lease"} {
		t.Run(bound, func(t *testing.T) {
			c, _, _, _, _, effect, _, _ := readinessTransportFixture(t)
			deadline := time.Now().Add(100 * time.Millisecond)
			until := effect.ExpiresAt
			if bound == "effect" {
				effect.ExpiresAt = deadline
			} else {
				until = deadline
			}
			reads := 0
			c.mutations = readinessDeadlineMutations{HostMutationStore: c.mutations, read: func(ctx context.Context, _ authority.HostMutationKind, _ string) error {
				reads++
				actual, ok := ctx.Deadline()
				if !ok || actual.After(deadline) {
					t.Fatal("first source read exceeded known original deadline")
				}
				<-ctx.Done()
				return ctx.Err()
			}}
			if _, err := (&Reader{controller: c}).AdmitRuntimeReadinessSource(t.Context(), effect, until); err == nil || reads != 1 {
				t.Fatal("expired source wait accepted", err, reads)
			}
		})
	}
}

func TestRootContainerReadinessBoundsEntireEvidenceRead(t *testing.T) {
	for _, bound := range []string{"source deadline", "original cancellation"} {
		t.Run(bound, func(t *testing.T) {
			c, _, _, key, _, effect, report, current := readinessTransportFixture(t)
			c.credentialFloor = func(context.Context, Registration) (uint64, error) { return 1, nil }
			original, cancelOriginal := context.WithCancel(t.Context())
			defer cancelOriginal()
			until := effect.ExpiresAt
			if bound == "source deadline" {
				until = time.Now().Add(100 * time.Millisecond)
			}
			source, err := (&Reader{controller: c}).AdmitRuntimeReadinessSource(original, effect, until)
			if err != nil {
				t.Fatal(err)
			}
			challenge := ContainerReadinessChallenge{Nonce: strings.Repeat("d", 32), TaskID: effect.TaskID, TaskSHA256: effect.TaskSHA256, AdmissionSHA256: effect.AdmissionSHA256, EffectID: effect.EffectID, Deadline: source.Deadline()}
			query := containerReadinessQuery{TaskID: effect.TaskID, TaskSHA256: effect.TaskSHA256, AdmissionSHA256: effect.AdmissionSHA256, EffectID: effect.EffectID, Challenge: &challenge, Report: &report}
			req := signedHostRequest(t, key, "runtime-readiness", current.SessionID, current.Epoch, query)
			reads := 0
			c.mutations = readinessDeadlineMutations{HostMutationStore: c.mutations, read: func(ctx context.Context, kind authority.HostMutationKind, _ string) error {
				if kind != authority.MutationRegistration {
					return nil
				}
				reads++
				if reads != 2 {
					return nil
				}
				actual, ok := ctx.Deadline()
				if !ok || actual.After(source.Deadline()) {
					t.Fatal("signed evidence source read lost original deadline")
				}
				if bound == "original cancellation" {
					cancelOriginal()
				}
				<-ctx.Done()
				return ctx.Err()
			}}
			check, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			started := time.Now()
			if _, err := source.Verify(check, challenge, req.Envelope); err == nil || reads != 2 {
				t.Fatal("independent evidence read lost original lifetime", err, reads)
			}
			if bound == "original cancellation" && time.Since(started) > 500*time.Millisecond {
				t.Fatal("independent evidence read waited beyond original cancellation")
			}
		})
	}
}

func TestRootContainerReadinessRequiresOriginalWorkerEvidence(t *testing.T) {
	c, _, _, key, wrongKey, effect, report, current := readinessTransportFixture(t)
	c.credentialFloor = func(ctx context.Context, _ Registration) (uint64, error) {
		if err := GuardCredentialFloorSession(ctx); err != nil {
			return 0, err
		}
		return 1, nil
	}
	source, err := (&Reader{controller: c}).AdmitRuntimeReadinessSource(t.Context(), effect, effect.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	challenge := ContainerReadinessChallenge{Nonce: strings.Repeat("d", 32), TaskID: effect.TaskID, TaskSHA256: effect.TaskSHA256, AdmissionSHA256: effect.AdmissionSHA256, EffectID: effect.EffectID, Deadline: time.Now().Add(2 * time.Second)}
	query := containerReadinessQuery{TaskID: effect.TaskID, TaskSHA256: effect.TaskSHA256, AdmissionSHA256: effect.AdmissionSHA256, EffectID: effect.EffectID, Challenge: &challenge, Report: &report}
	req := signedHostRequest(t, key, "runtime-readiness", current.SessionID, current.Epoch, query)
	if _, err := source.Verify(t.Context(), challenge, req.Envelope); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*request, *containerReadinessQuery)
	}{
		{"another session", func(r *request, _ *containerReadinessQuery) { r.SessionID = entityid.New() }},
		{"another epoch", func(r *request, _ *containerReadinessQuery) { r.Epoch++ }},
		{"another node", func(r *request, _ *containerReadinessQuery) { r.Node = "other" }},
		{"another principal", func(r *request, _ *containerReadinessQuery) { r.NATSUserPublicKey = testNATSUserKey("other") }},
		{"another operation", func(r *request, _ *containerReadinessQuery) { r.Operation = "report" }},
		{"another nonce", func(_ *request, q *containerReadinessQuery) { q.Challenge.Nonce = strings.Repeat("e", 32) }},
		{"another deadline", func(_ *request, q *containerReadinessQuery) {
			q.Challenge.Deadline = q.Challenge.Deadline.Add(time.Second)
		}},
		{"another task", func(_ *request, q *containerReadinessQuery) { q.TaskID = "other" }},
		{"another task hash", func(_ *request, q *containerReadinessQuery) { q.TaskSHA256 = strings.Repeat("e", 64) }},
		{"another admission", func(_ *request, q *containerReadinessQuery) { q.AdmissionSHA256 = strings.Repeat("e", 64) }},
		{"another effect", func(_ *request, q *containerReadinessQuery) { q.EffectID = entityid.New() }},
		{"missing observation", func(_ *request, q *containerReadinessQuery) { q.Report = nil }},
		{"another attachment", func(_ *request, q *containerReadinessQuery) { q.Report.AttachmentETag = "other" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			copyChallenge, copyReport := challenge, report
			changed := query
			changed.Challenge, changed.Report = &copyChallenge, &copyReport
			r := req
			test.change(&r, &changed)
			payload, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			r.Payload = payload
			if err := signRequest(&r, key, "gru"); err != nil {
				t.Fatal(err)
			}
			if _, err := source.Verify(t.Context(), challenge, r.Envelope); err == nil {
				t.Fatal("changed original Source evidence accepted")
			}
		})
	}
	t.Run("controller signature", func(t *testing.T) {
		wrong := req
		if err := signRequest(&wrong, wrongKey, "gru"); err != nil {
			t.Fatal(err)
		}
		if _, err := source.Verify(t.Context(), challenge, wrong.Envelope); err == nil {
			t.Fatal("controller signature substituted for worker evidence")
		}
	})
	t.Run("changed signed bytes", func(t *testing.T) {
		wrong := req.Envelope
		wrong.Signature = strings.Repeat("A", len(wrong.Signature))
		if _, err := source.Verify(t.Context(), challenge, wrong); err == nil {
			t.Fatal("invalid original signature accepted")
		}
	})
	deadline := source.Deadline()
	latest, revision, _, err := c.sessionSnapshot(t.Context(), sessionKey(c.cell, "node-a"))
	if err != nil {
		t.Fatal(err)
	}
	latest.ExpiresAt = latest.ExpiresAt.Add(time.Minute)
	if _, err := c.cas(t.Context(), sessionKey(c.cell, "node-a"), latest, revision); err != nil {
		t.Fatal(err)
	}
	if err := source.Guard(t.Context()); err != nil || !source.Deadline().Equal(deadline) {
		t.Fatal("session renewal changed original Source lifetime", err)
	}
	_, revision, _, err = c.sessionSnapshot(t.Context(), sessionKey(c.cell, "node-a"))
	if err != nil {
		t.Fatal(err)
	}
	latest.SessionID = entityid.New()
	if _, err := c.cas(t.Context(), sessionKey(c.cell, "node-a"), latest, revision); err != nil {
		t.Fatal(err)
	}
	if err := source.Guard(t.Context()); err == nil {
		t.Fatal("root Source followed replacement session")
	}
}

func TestRootContainerReadinessRelayRetainsWorkerSignature(t *testing.T) {
	c, conn, registration, key, controllerKey, effect, report, current := readinessTransportFixture(t)
	c.credentialFloor = func(context.Context, Registration) (uint64, error) { return 1, nil }
	source, err := (&Reader{controller: c}).AdmitRuntimeReadinessSource(t.Context(), effect, effect.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	select {
	case <-c.Ready():
	case err := <-done:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	challenge := ContainerReadinessChallenge{Nonce: strings.Repeat("f", 32), TaskID: effect.TaskID, TaskSHA256: effect.TaskSHA256, AdmissionSHA256: effect.AdmissionSHA256, EffectID: effect.EffectID, Deadline: time.Now().Add(2 * time.Second)}
	type result struct {
		envelope protocol.Envelope
		err      error
	}
	observed := make(chan result, 1)
	go func() {
		envelope, err := c.ObserveSignedContainerReadiness(ctx, effect, challenge, func(_ context.Context, caller RuntimeEffectCaller) error {
			if caller.SessionID() != effect.HostSessionID {
				return context.Canceled
			}
			return nil
		})
		observed <- result{envelope: envelope, err: err}
	}()
	query := containerReadinessQuery{TaskID: effect.TaskID, TaskSHA256: effect.TaskSHA256, AdmissionSHA256: effect.AdmissionSHA256, EffectID: effect.EffectID}
	for {
		var reply containerReadinessReply
		if err := exchange(ctx, conn, registration.Cell, controllerKey.Public().(ed25519.PublicKey), signedHostRequest(t, key, "runtime-readiness", current.SessionID, current.Epoch, query), &reply); err != nil {
			t.Fatal(err)
		}
		if reply.Challenge != nil {
			if !sameContainerReadinessChallenge(*reply.Challenge, challenge) {
				t.Fatal("relay replaced root's nonce or deadline")
			}
			break
		}
	}
	query.Challenge, query.Report = &challenge, &report
	req := signedHostRequest(t, key, "runtime-readiness", current.SessionID, current.Epoch, query)
	var acknowledged containerReadinessReply
	if err := exchange(ctx, conn, registration.Cell, controllerKey.Public().(ed25519.PublicKey), req, &acknowledged); err != nil {
		t.Fatal(err)
	}
	resultValue := <-observed
	if resultValue.err != nil {
		t.Fatal(resultValue.err)
	}
	want, err := protocol.EncodeJSON(req.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	got, err := protocol.EncodeJSON(resultValue.envelope)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatal("relay replaced original worker-signed envelope")
	}
	if _, err := source.Verify(t.Context(), challenge, resultValue.envelope); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("readiness controller did not stop")
	}
}
