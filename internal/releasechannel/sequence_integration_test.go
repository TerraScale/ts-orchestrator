package releasechannel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestSequenceChannelHTTPMigrationPreservesLegacyFloors(t *testing.T) {
	location := newSequenceHTTPBucket(t)
	fixture := newChannelFixture(t)
	rootPublic, root, _ := ed25519.GenerateKey(rand.Reader)
	id, _ := trust.KeyID(rootPublic)
	fixture.roots[id] = rootPublic
	signer := fixture.leaf.Public().(ed25519.PublicKey)
	signerID, _ := trust.KeyID(signer)
	encoded, _ := trust.EncodeDelegatedPublicKey(signer)
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: "ns", Bucket: "gru-1-head", Region: "GRU", Role: "orchestrator", Environment: "production", SequenceFloor: 1000, SignerKeyID: signerID, SignerPublicKey: encoded}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		legacyWire, err := trust.EncodePayload(fixture.channel(t, cell))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(legacyWire)
		migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: testRunNumber, IssuedAt: fixture.now, EvidenceSHA256: hex.EncodeToString(sum[:])})
	}
	envelope, err := release.SignSequenceMigration(migration, fixture.now, root)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := trust.EncodeEnvelope(envelope)
	fingerprint, _ := trust.Fingerprint(envelope)
	legacy := fixture.channel(t, "GRU")
	if _, err := legacy.Verify(fixture.roots, "GRU", "production", fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := Publish(t.Context(), location, legacy); err != nil {
		t.Fatal(err)
	}
	next := legacy
	next.ReleaseSequence = 1001
	next.SequenceMigration = wire
	next.Receipts = nil
	for _, arch := range []string{"amd64", "arm64"} {
		receipt, err := release.SignBinaryUpdateReceiptSequenced(fixture.binaries[arch], fixture.qual, fixture.qualDigest, "GRU", "production", anyLineage{}, fixture.delegation, fixture.roots, fixture.leaf, fixture.now, 24*time.Hour, 1001, fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		receipt = fixture.qualify(t, receipt, "GRU", arch)
		encoded, _ := trust.EncodeEnvelope(receipt)
		next.Receipts = append(next.Receipts, jsontext.Value(encoded))
	}
	if _, err := next.Verify(fixture.roots, "GRU", "production", fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := Publish(t.Context(), location, next); err != nil {
		t.Fatal(err)
	}
	if err := Publish(t.Context(), location, legacy); !errors.Is(err, ErrStale) {
		t.Fatalf("legacy replaced sequenced state: %v", err)
	}
	tampered := next
	tampered.ReleaseSequence++
	if _, err := tampered.Verify(fixture.roots, "GRU", "production", fixture.now); err == nil {
		t.Fatal("unsigned sequence edit verified")
	}
	// The same first migration cannot erase a higher locally retained run.
	other := newSequenceHTTPBucket(t)
	retained := legacy
	retained.RunNumber++
	if err := Publish(t.Context(), other, retained); err != nil {
		t.Fatal(err)
	}
	if err := Publish(t.Context(), other, next); !errors.Is(err, ErrStale) {
		t.Fatalf("migration erased retained run floor: %v", err)
	}
	// Service claim order is independent of a producer's wall clock.
	migration.Role = "ts-auth"
	migration.SequenceFloor = 1
	for index := range migration.Regions {
		migration.Regions[index].RunNumber = 0
	}
	envelope, err = release.SignSequenceMigration(migration, fixture.now, root)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, _ = trust.Fingerprint(envelope)
	makeClaim := func(sequence uint64, issued time.Time, digest string) []byte {
		record, err := delivery.NewArtifactRecord(delivery.ArtifactClaimRequest{Source: delivery.ArtifactSource{Repository: "https://github.com/TerraScale/ts-auth", Commit: strings.Repeat("b", 40), TreeDigest: strings.Repeat("c", 64)}, Cell: "gru", Role: "ts-auth", Environment: "production", ReleaseSequence: sequence, SequenceMigrationSHA256: fingerprint}, digest, 10)
		if err != nil {
			t.Fatal(err)
		}
		codec := delivery.Ed25519Codec{Cell: "gru", Actor: "ci-release", PrivateKey: fixture.leaf, Lifetime: time.Minute, MaxLifetime: time.Minute, Now: func() time.Time { return issued }}
		claim, err := codec.SignArtifact(t.Context(), record)
		if err != nil {
			t.Fatal(err)
		}
		return claim
	}
	claim := makeClaim(2, fixture.now, strings.Repeat("d", 64))
	invalid := bytes.Replace(claim, []byte(`"signature":"`), []byte(`"signature":"x`), 1)
	if err := PublishServiceSequenced(t.Context(), location, "ts-auth", invalid, envelope, fixture.roots, fixture.now); err == nil {
		t.Fatal("invalid signed claim published")
	}
	if _, found, err := ReadSequenceMigration(t.Context(), location, fingerprint); err != nil || found {
		t.Fatalf("invalid claim mutated immutable migration metadata: %v %v", found, err)
	}
	if err := PublishServiceSequenced(t.Context(), location, "ts-auth", claim, envelope, fixture.roots, fixture.now); err != nil {
		t.Fatal(err)
	}
	newer := makeClaim(3, fixture.now.Add(-time.Hour), strings.Repeat("e", 64))
	if err := PublishServiceSequenced(t.Context(), location, "ts-auth", newer, envelope, fixture.roots, fixture.now); err != nil {
		t.Fatalf("new producer's older clock blocked shared order: %v", err)
	}
	if err := PublishServiceSequenced(t.Context(), location, "ts-auth", claim, envelope, fixture.roots, fixture.now); !errors.Is(err, ErrStale) {
		t.Fatalf("stale service sequence admitted: %v", err)
	}
	if err := PublishService(t.Context(), location, "ts-auth", signedServiceClaim(t, fixture.now.Add(time.Hour))); !errors.Is(err, ErrStale) {
		t.Fatalf("legacy service erased sequence floor: %v", err)
	}
	if _, found, err := ReadSequenceMigration(t.Context(), location, fingerprint); err != nil || !found {
		t.Fatalf("migration transport missing: %v %v", found, err)
	}
}

// HTTP and the filesystem retain the real wire bytes and enforce ETag CAS.
func newSequenceHTTPBucket(t *testing.T) Location {
	t.Helper()
	directory := t.TempDir()
	var lock sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		digest := sha256.Sum256([]byte(r.URL.Path))
		path := filepath.Join(directory, hex.EncodeToString(digest[:]))
		lock.Lock()
		defer lock.Unlock()
		current, err := os.ReadFile(path)
		found := err == nil
		sum := sha256.Sum256(current)
		etag := fmt.Sprintf(`"%x"`, sum)
		switch r.Method {
		case "GET":
			if !found {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("ETag", etag)
			w.Write(current)
		case "PUT":
			if r.Header.Get("If-None-Match") == "*" && found || r.Header.Get("If-Match") != "" && (!found || r.Header.Get("If-Match") != etag) {
				w.WriteHeader(412)
				return
			}
			wire, _ := io.ReadAll(r.Body)
			if err := os.WriteFile(path, wire, 0600); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.WriteHeader(200)
		}
	}))
	t.Cleanup(server.Close)
	return Location{Client: sequenceWireClient{server.URL, server.Client()}, Namespace: "ns", Bucket: "gru-1-head"}
}

type sequenceWireClient struct {
	endpoint string
	client   *http.Client
}

func (client sequenceWireClient) GetObject(ctx context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", client.endpoint+"/"+url.PathEscape(*request.ObjectName), nil)
	if err != nil {
		return objectstorage.GetObjectResponse{}, err
	}
	response, err := client.client.Do(req)
	if err != nil {
		return objectstorage.GetObjectResponse{}, err
	}
	if response.StatusCode != 200 {
		response.Body.Close()
		return objectstorage.GetObjectResponse{}, serviceError(response.StatusCode)
	}
	return objectstorage.GetObjectResponse{Content: response.Body, ETag: new(response.Header.Get("ETag"))}, nil
}
func (client sequenceWireClient) PutObject(ctx context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	wire, err := io.ReadAll(request.PutObjectBody)
	if err != nil {
		return objectstorage.PutObjectResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, "PUT", client.endpoint+"/"+url.PathEscape(*request.ObjectName), bytes.NewReader(wire))
	if err != nil {
		return objectstorage.PutObjectResponse{}, err
	}
	if request.IfMatch != nil {
		req.Header.Set("If-Match", *request.IfMatch)
	}
	if request.IfNoneMatch != nil {
		req.Header.Set("If-None-Match", *request.IfNoneMatch)
	}
	response, err := client.client.Do(req)
	if err != nil {
		return objectstorage.PutObjectResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return objectstorage.PutObjectResponse{}, serviceError(response.StatusCode)
	}
	return objectstorage.PutObjectResponse{}, nil
}
