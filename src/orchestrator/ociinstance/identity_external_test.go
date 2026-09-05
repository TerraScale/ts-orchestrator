package ociinstance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	fixture "terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/ociinstance"
)

func TestOfficialInstanceFederationAndLargeScopedObjectsOverMutualTLS(t *testing.T) {
	const region = "sa-saopaulo-1"
	observation := provider.OCIBucketObservation{ID: "bucket-id", CompartmentID: "compartment-id", Namespace: "ns", Name: "snapshots", FreeformTags: map[string]string{provider.OCIManagedTag: "bucket", provider.OCIScopeTag: "gru"}}
	server, err := fixture.New(fixture.Config{Buckets: []fixture.Bucket{{OCIRegion: region, Observation: observation}}, MaxObjectBytes: 32 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	cfg, key, err := server.Identity("source", region, "/var/lib/qualification/client.key")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	instance, err := ociinstance.NewFromConfig(ctx, cfg, func(path string) ([]byte, error) {
		if path != cfg.Qualification.ClientPrivateKeyFile {
			t.Fatal("unbound private key path")
		}
		return append([]byte(nil), key...), nil
	})
	if err != nil {
		t.Fatalf("%v requests=%+v", err, server.Requests())
	}
	defer instance.Close()
	transport, err := instance.NewTransport(provider.OCIServiceObjectStorage, 32<<20)
	if err != nil {
		t.Fatal(err)
	}
	bucket, found, err := provider.ObserveOCIBucket(ctx, transport, "ns", "snapshots")
	if err != nil || !found || bucket.ID != observation.ID || !provider.HasOCIOwnershipTags(bucket.FreeformTags, "bucket", "gru") {
		t.Fatalf("bucket %+v found %v err %v", bucket, found, err)
	}
	content := bytes.Repeat([]byte("capture"), (17<<20)/7+1)
	digest := sha256.Sum256(content)
	object := provider.ObjectRef{Namespace: "ns", Bucket: "snapshots", Name: "control/request/archive"}
	response, err := transport.PutObjectBody(ctx, object, bytes.NewReader(content), map[string]string{"Content-Type": "application/octet-stream", "If-None-Match": "*", "opc-meta-terrascale-sha256": hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("PUT status %d", response.StatusCode)
	}
	reader, err := provider.NewOCIObjectStorageReader(transport, provider.ObjectReadScope{Namespace: "ns", Bucket: "snapshots", Prefix: "control/request/", MaxObjectBytes: 32 << 20})
	if err != nil {
		t.Fatal(err)
	}
	head, found, err := reader.HeadObject(ctx, object)
	if err != nil || !found || head.Size != int64(len(content)) {
		t.Fatalf("HEAD %+v %v", head, err)
	}
	stream, metadata, err := reader.GetObject(ctx, object)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(stream)
	closed := stream.Close()
	if err != nil || closed != nil || !bytes.Equal(body, content) || metadata != head {
		t.Fatal("large immutable readback failed")
	}
	federation := 0
	puts := 0
	for _, request := range server.Requests() {
		if request.Host == "auth."+region+".oraclecloud.com" {
			federation++
		}
		if request.Method == "PUT" {
			puts++
		}
	}
	if federation != 1 || puts != 1 {
		t.Fatalf("federation=%d PUT=%d", federation, puts)
	}
	instance.Close()
	before := len(server.Requests())
	if _, _, err = reader.HeadObject(ctx, object); err == nil {
		t.Fatal("closed identity reached provider")
	}
	if len(server.Requests()) != before {
		t.Fatal("post-close request reached network")
	}
}
