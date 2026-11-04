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
