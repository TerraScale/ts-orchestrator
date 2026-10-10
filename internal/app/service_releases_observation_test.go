package app

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/releasechannel"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

func TestServiceReleaseDefersToleratedFutureClaim(t *testing.T) {
	r, kv, bucket, publish := servicePinsSignedFixture(t)
	ctx, role := t.Context(), terrabase.Role
	issued := time.Now().UTC().Add(time.Second)
	candidate := publish("future candidate", issued)
	if err := r.pass(ctx, kv, role); err == nil || !strings.Contains(err.Error(), "waiting for the cell clock") {
		t.Fatalf("future claim was not deferred: %v", err)
	}
	key := releasechannel.ServiceStatusKey("GRU", role)
	if state, revision, err := loadServiceRelease(ctx, kv, key); err != nil || revision != 0 || !state.IssuedAt.IsZero() {
		t.Fatalf("deferral changed the issuance watermark: %+v, revision %d: %v", state, revision, err)
	}
	if bucket.puts[releasechannel.ServiceStatusObject(role)] != 0 {
		t.Fatal("tolerated skew reported a terminal failure")
	}
	time.Sleep(time.Until(issued))
	if err := r.pass(ctx, kv, role); err != nil {
		t.Fatal(err)
	}
	state, _, err := loadServiceRelease(ctx, kv, key)
	if err != nil || state.Digest != candidate.Digest || !state.IssuedAt.Equal(issued) ||
		!strings.Contains(state.Reason, "has no terrabase profile") {
		t.Fatalf("claim did not enter admission at its original issuance: %+v: %v", state, err)
	}
}

func TestServiceReleaseRefusesExpiredUnsubmittedClaim(t *testing.T) {
	for _, age := range []time.Duration{rollout.ObservationBudget, 25 * time.Minute, time.Hour} {
		t.Run(age.String(), func(t *testing.T) {
			r, kv, _, publish := servicePinsSignedFixture(t)
			profileRead := false
			r.profiles = func() map[string]WorkloadProfile { profileRead = true; return nil }
			candidate := publish("untested expired candidate", time.Now().UTC().Add(-age))
			if err := r.pass(t.Context(), kv, terrabase.Role); err != nil {
				t.Fatal(err)
			}
			key := releasechannel.ServiceStatusKey("GRU", terrabase.Role)
			state, revision, err := loadServiceRelease(t.Context(), kv, key)
			if err != nil || state.State != releasechannel.StateFailed || state.Intent != nil || state.Rollback != nil ||
				!strings.Contains(state.Reason, "observation window") || profileRead {
				t.Fatalf("expired claim entered deployment: %+v, profile read %v: %v", state, profileRead, err)
			}
			if _, bad, err := knownBad(t.Context(), kv, terrabase.Role, candidate.Digest); err != nil || bad {
				t.Fatalf("untested candidate was blacklisted: %v, %v", bad, err)
			}
			if err := r.pass(t.Context(), kv, terrabase.Role); err != nil {
				t.Fatal(err)
			}
			if _, replayRevision, err := loadServiceRelease(t.Context(), kv, key); err != nil || replayRevision != revision {
				t.Fatalf("expired replay renewed state: %d -> %d, %v", revision, replayRevision, err)
			}
			publish("untested expired candidate", time.Now().UTC().Add(-time.Second))
			if err := r.pass(t.Context(), kv, terrabase.Role); err != nil || !profileRead {
				t.Fatalf("fresh issuance of untested candidate could not enter admission: %v", err)
			}
		})
	}
}

func TestServiceReleaseRefusesExpiredPendingAdmission(t *testing.T) {
	r, kv, _, _ := servicePinsSignedFixture(t)
	state := serviceReleaseState{IssuedAt: time.Now().UTC().Add(-rollout.ObservationBudget), State: releasechannel.StateRolling}
	finished, err := r.release(t.Context(), kv, terrabase.Role, state, r.fencer.Current().Epoch, func(serviceReleaseState) error {
		t.Fatal("expired pending admission persisted an intent")
		return nil
	})
	if err != nil || finished.State != releasechannel.StateFailed || finished.Intent != nil || finished.Rollback != nil ||
		!strings.Contains(finished.Reason, "observation window") {
		t.Fatalf("pending admission renewed expired observation: %+v, %v", finished, err)
	}
}

type expiringServiceBinary struct {
	*channelBucket
	object   string
	deadline time.Time
	read     bool
}

func (b *expiringServiceBinary) GetObject(ctx context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	if *request.ObjectName == b.object {
		b.read = true
		time.Sleep(time.Until(b.deadline))
	}
	return b.channelBucket.GetObject(ctx, request)
}

func TestServiceReleaseRefusesExpiryDuringInitialAdmission(t *testing.T) {
	r, kv, bucket, publish := servicePinsSignedFixture(t)
	ctx, role := t.Context(), terrabase.Role
	location := *r.channel.location
	serving := publish("serving before slow admission", time.Now().UTC().Add(-time.Minute))
	if _, _, err := r.admit(ctx, kv, location, role, bucket.objects[releasechannel.ServiceReleaseObject(role)]); err != nil {
		t.Fatal(err)
	}
	r.profiles = func() map[string]WorkloadProfile { return terraBaseSeats("gru-1-db-1=10.251.0.21:9443") }
	r.hosts = terraBaseMembers{reports: []host.Report{{Role: role, Environment: "test", State: "running", Digest: serving.Digest}}}
	issued := time.Now().UTC().Add(-rollout.ObservationBudget + time.Second)
	candidate := publish("candidate delayed until observation expires", issued)
	slow := &expiringServiceBinary{channelBucket: bucket, object: releasechannel.ServiceBinaryObject(role, candidate.Digest),
		deadline: issued.Add(rollout.ObservationBudget)}
	location.Client = slow
	state := serviceReleaseState{Digest: candidate.Digest, IssuedAt: issued, Previous: serving.Digest,
		Retained: []string{serving.Digest}, State: releasechannel.StateRolling,
		claim: bucket.objects[releasechannel.ServiceReleaseObject(role)], location: location}
	finished, err := r.release(ctx, kv, role, state, r.fencer.Current().Epoch, func(serviceReleaseState) error {
		t.Fatal("admission that expired during binary read persisted an intent")
		return nil
	})
	if err != nil || !slow.read || finished.State != releasechannel.StateFailed || finished.Intent != nil || finished.Rollback != nil ||
		!strings.Contains(finished.Reason, "observation window") || finished.Previous != serving.Digest ||
		!slices.Equal(finished.Retained, state.Retained) {
		t.Fatalf("late initial admission = %+v, binary read %v: %v", finished, slow.read, err)
	}
	if _, err := r.deliveries.ResolveAdmittedArtifact(ctx, candidate.Digest, role, "test"); err != nil {
		t.Fatalf("test did not complete artifact admission before expiry refusal: %v", err)
	}
	if _, bad, err := knownBad(ctx, kv, role, candidate.Digest); err != nil || bad {
		t.Fatalf("untested candidate was blacklisted: %v, %v", bad, err)
	}
	if _, err := r.deliveries.ResolveAdmittedArtifact(ctx, serving.Digest, role, "test"); err != nil {
		t.Fatalf("slow admission lost the serving predecessor: %v", err)
	}
	if persisted, revision, err := loadServiceRelease(ctx, kv, releasechannel.ServiceStatusKey("GRU", role)); err != nil || revision != 0 || persisted.Intent != nil {
		t.Fatalf("late admission persisted deployment state: %+v revision %d: %v", persisted, revision, err)
	}
}

func TestServiceReleaseRejectsClaimBeyondClockSkew(t *testing.T) {
	r, kv, _, publish := servicePinsSignedFixture(t)
	ctx, role := t.Context(), terrabase.Role
	publish("too far ahead", time.Now().UTC().Add(releasechannel.ClaimClockSkew+time.Minute))
	if err := r.pass(ctx, kv, role); err != nil {
		t.Fatal(err)
	}
	status, found, err := releasechannel.ReadServiceStatus(ctx, *r.channel.location, role)
	if err != nil || !found || status.State != releasechannel.StateFailed || !strings.Contains(status.Reason, "issued in the future") {
		t.Fatalf("excessive skew was not refused: %+v, found %v: %v", status, found, err)
	}
	if state, revision, err := loadServiceRelease(ctx, kv, releasechannel.ServiceStatusKey("GRU", role)); err != nil || revision != 0 || !state.IssuedAt.IsZero() {
		t.Fatalf("refusal changed the issuance watermark: %+v, revision %d: %v", state, revision, err)
	}
}
