package releasechannel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
)

func signedServiceClaim(t *testing.T, issued time.Time) []byte {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	record, err := delivery.NewArtifactRecord(delivery.ArtifactClaimRequest{Source: delivery.ArtifactSource{
		Repository: "https://github.com/TerraScale/ts-auth", Commit: strings.Repeat("a", 40),
		TreeDigest: strings.Repeat("b", 64)}, Cell: "gru", Role: "ts-auth", Environment: "canary"}, strings.Repeat("c", 64), 10)
	if err != nil {
		t.Fatal(err)
	}
	codec := delivery.Ed25519Codec{Cell: "gru", Actor: "ci-release", PrivateKey: private, Lifetime: time.Minute,
		MaxLifetime: 5 * time.Minute, Now: func() time.Time { return issued }}
	claim, err := codec.SignArtifact(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	return claim
}

func TestServiceChannelPublishesOnlyNewerClaims(t *testing.T) {
	ctx := context.Background()
	bucket := newFakeBucket()
	location := Location{Client: bucket, Namespace: "ns", Bucket: "gru-1-head"}
	now := time.Now().UTC().Truncate(time.Second)
	older, newer := signedServiceClaim(t, now.Add(-time.Hour)), signedServiceClaim(t, now)
	if issued, err := ClaimIssuedAt(newer); err != nil || !issued.Equal(now) {
		t.Fatalf("issued %v, %v", issued, err)
	}
	if err := PublishService(ctx, location, "ts-auth", newer); err != nil {
		t.Fatal(err)
	}
	if err := PublishService(ctx, location, "ts-auth", older); !errors.Is(err, ErrStale) {
		t.Fatalf("an older claim replaced a newer one: %v", err)
	}
	if err := PublishService(ctx, location, "ts-auth", newer); err != nil {
		t.Fatalf("republishing the same claim: %v", err)
	}
	if err := PublishService(ctx, location, "ts-auth", signedServiceClaim(t, now)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another claim issued at the same instant replaced the first: %v", err)
	}
	// A claim from a clock far ahead, which every leader refuses, does not
	// hold the channel once the clock is corrected.
	if err := PublishService(ctx, location, "ts-auth", signedServiceClaim(t, now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := PublishService(ctx, location, "ts-auth", newer); err != nil {
		t.Fatalf("a claim from a corrected clock: %v", err)
	}
	claim, found, err := ReadServiceClaim(ctx, location, "ts-auth")
	if err != nil || !found || !bytes.Equal(claim, newer) {
		t.Fatalf("read %q %v %v", claim, found, err)
	}
	if _, found, err := ReadServiceClaim(ctx, location, "terrabase"); err != nil || found {
		t.Fatalf("terrabase has no release: %v %v", found, err)
	}
}

func TestAwaitServiceFollowsTheRelease(t *testing.T) {
	ctx := context.Background()
	location := Location{Client: newFakeBucket(), Namespace: "ns", Bucket: "gru-1-head"}
	issued := time.Now().UTC().Truncate(time.Second)
	digest := strings.Repeat("c", 64)
	report := func(status ServiceStatus) {
		status.Cell, status.Role = "GRU", "ts-auth"
		if err := WriteServiceStatus(ctx, location, status); err != nil {
			t.Fatal(err)
		}
	}
	await := func() error {
		var progress bytes.Buffer
		return AwaitService(ctx, location, "GRU", "ts-auth", digest, issued, time.Millisecond,
			time.Now().Add(50*time.Millisecond), &progress)
	}
	report(ServiceStatus{Digest: digest, IssuedAt: issued.Add(-time.Hour), State: StateComplete})
	if err := await(); !errors.Is(err, ErrFailed) || !strings.Contains(err.Error(), "in time") {
		t.Fatalf("an older release's report completed this one: %v", err)
	}
	// A leader that has not decoded the claim yet names no digest: CI waits.
	report(ServiceStatus{IssuedAt: issued, State: StateRolling, Reason: "admitting the release"})
	if err := await(); !errors.Is(err, ErrFailed) || !strings.Contains(err.Error(), "in time") {
		t.Fatalf("a release being admitted: %v", err)
	}
	report(ServiceStatus{IssuedAt: issued, State: StateFailed, Reason: "the claim does not verify"})
	if err := await(); !errors.Is(err, ErrFailed) || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("a claim that does not verify: %v", err)
	}
	report(ServiceStatus{Digest: digest, IssuedAt: issued, State: StateRolling, Reason: "deploy"})
	if err := await(); !errors.Is(err, ErrFailed) {
		t.Fatalf("a rolling release completed: %v", err)
	}
	report(ServiceStatus{Digest: digest, IssuedAt: issued, State: StateFailed, Reason: "rolled back"})
	if err := await(); !errors.Is(err, ErrFailed) || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("failed release: %v", err)
	}
	report(ServiceStatus{Digest: digest, IssuedAt: issued.Add(time.Second), State: StateRolling})
	if err := await(); !errors.Is(err, ErrFailed) || !strings.Contains(err.Error(), "moved on") {
		t.Fatalf("a newer release: %v", err)
	}
	report(ServiceStatus{Digest: digest, IssuedAt: issued, State: StateComplete})
	if err := await(); err != nil {
		t.Fatal(err)
	}
}
