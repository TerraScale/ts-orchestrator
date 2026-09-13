package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

type deliveryMirrorReadFixture struct {
	body                   string
	identity               delivery.ObjectIdentity
	region, bucket, object string
}

func (f *deliveryMirrorReadFixture) Put(context.Context, string, string, string, []byte) error {
	return nil
}
func (f *deliveryMirrorReadFixture) Get(_ context.Context, region, bucket, object string) (io.ReadCloser, delivery.ObjectIdentity, error) {
	f.region, f.bucket, f.object = region, bucket, object
	return io.NopCloser(strings.NewReader(f.body)), f.identity, nil
}
func TestProductionDeliveryEdgeUsesRootMirrorAndChecksIdentity(t *testing.T) {
	spec := estate.Default()
	body := "worker bytes"
	digest := delivery.SHA256Digest([]byte(body))
	store := &deliveryMirrorReadFixture{body: body, identity: delivery.ObjectIdentity{Digest: digest, Size: int64(len(body))}}
	mirror, err := delivery.NewArtifactMirror(spec, store)
	if err != nil {
		t.Fatal(err)
	}
	source := productionDeliveryMirrorSource{mirror: mirror, region: spec.Regions[0].Code}
	got, err := source.EdgeArtifact(t.Context(), "ts-proxy", digest)
	if err != nil || string(got) != body {
		t.Fatalf("read %q: %v", got, err)
	}
	bucket, _ := delivery.ReleaseBucket(spec.Regions[0])
	if store.region != spec.Regions[0].Code || store.bucket != bucket || store.object != delivery.MirrorObject("ts-proxy", digest) {
		t.Fatal("mirror scope changed")
	}
	store.identity.Size++
	if _, err = source.EdgeArtifact(t.Context(), "ts-proxy", digest); err == nil {
		t.Fatal("incorrect provider identity accepted")
	}
	store.identity.Size--
	store.body = "different content"
	if _, err = source.EdgeArtifact(t.Context(), "ts-proxy", digest); err == nil {
		t.Fatal("corrupted mirror accepted")
	}
	source.region = "missing"
	if _, err = source.EdgeArtifact(t.Context(), "ts-proxy", digest); err == nil {
		t.Fatal("unadmitted region accepted")
	}
}
func TestProductionDeliveryFileRejectsAbsentAdmission(t *testing.T) {
	if _, err := (productionDeliveryFile{}).Admit(estate.Default(), "gru"); err == nil {
		t.Fatal("missing admission accepted")
	}
}

func TestProductionCanaryProbeRequiresPrivateFixtureReferences(t *testing.T) {
	client := cloudflare.NewClient("token", "zone", "account")
	if _, err := productionCanaryProbe(productionDeliveryCloudflareFile{}, client); err == nil {
		t.Fatal("incomplete canary configuration accepted")
	}
	dir := t.TempDir()
	write := func(name, value string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	config := productionDeliveryCloudflareFile{
		CanaryRouteURL:          "https://api.terrascale.tech/api/v1/projects/p/databases/d",
		CanaryProjectID:         "p",
		CanaryDatabaseID:        "d",
		CanaryTokenFile:         write("canary", "canary-token"),
		CanaryForeignTokenFile:  write("foreign", "foreign-token"),
		CanaryExpectedMarker:    "marker",
		CanaryMinimumRevision:   1,
		CanaryDownstreamService: "ts-dashboard",
	}
	probe, err := productionCanaryProbe(config, client)
	if err != nil || probe.RouteURL != config.CanaryRouteURL || probe.CanaryToken != "canary-token" || probe.ForeignToken != "foreign-token" {
		t.Fatalf("canary probe construction failed: err=%v", err)
	}
}
