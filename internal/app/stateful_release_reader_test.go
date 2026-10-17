package app

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestStatefulAllocationReadIsFiniteAndExact(t *testing.T) {
	source, cancel := context.WithCancel(t.Context())
	defer cancel()
	reader := statefulAllocationObject{ctx: source, observation: rootoci.ContainerAllocationObservation{
		Namespace: "namespace", Bucket: "releases", ObjectName: "immutable/reservation.json", Data: []byte("signed reservation"), ExpiresAt: time.Now().Add(time.Minute),
	}}
	request := objectstorage.GetObjectRequest{NamespaceName: new("namespace"), BucketName: new("releases"), ObjectName: new("immutable/reservation.json")}
	response, err := reader.GetObject(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Content)
	if err != nil || string(data) != "signed reservation" {
		t.Fatalf("exact reservation: %q, %v", data, err)
	}
	_ = response.Content.Close()
	for _, change := range []func(*objectstorage.GetObjectRequest){
		func(r *objectstorage.GetObjectRequest) { r.NamespaceName = new("other") },
		func(r *objectstorage.GetObjectRequest) { r.BucketName = new("other") },
		func(r *objectstorage.GetObjectRequest) { r.ObjectName = new("mutable/head.json") },
		func(r *objectstorage.GetObjectRequest) { r.Range = new("bytes=0-1") },
		func(r *objectstorage.GetObjectRequest) { r.VersionId = new("other-version") },
	} {
		changed := request
		change(&changed)
		if _, err := reader.GetObject(t.Context(), changed); !errors.Is(err, execution.ErrUnsafe) {
			t.Fatalf("reservation target broadened: %v", err)
		}
	}
	if _, err := reader.PutObject(t.Context(), objectstorage.PutObjectRequest{}); err == nil {
		t.Fatal("reservation adapter allowed a write")
	}
	response, err = reader.GetObject(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Content.Close()
	cancel()
	if _, err := response.Content.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("original source cancellation did not revoke open body: %v", err)
	}
	if _, err := reader.GetObject(t.Context(), request); !errors.Is(err, execution.ErrUnsafe) {
		t.Fatalf("original source cancellation did not revoke reservation: %v", err)
	}
}

func TestStatefulAllocationExpiryRevokesOpenBody(t *testing.T) {
	reader := statefulAllocationObject{ctx: t.Context(), observation: rootoci.ContainerAllocationObservation{
		Namespace: "namespace", Bucket: "releases", ObjectName: "immutable/reservation.json", Data: []byte("signed reservation"), ExpiresAt: time.Now().Add(time.Minute),
	}}
	request := objectstorage.GetObjectRequest{NamespaceName: new("namespace"), BucketName: new("releases"), ObjectName: new("immutable/reservation.json")}
	response, err := reader.GetObject(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Content.Close()
	// Advance the retained deadline without sleeping or extending the source.
	response.Content.(*statefulMaterialBytes).expires = time.Now().Add(-time.Second)
	if _, err := response.Content.Read(make([]byte, 1)); !errors.Is(err, execution.ErrUnsafe) {
		t.Fatalf("expired material remained readable: %v", err)
	}
	reader.observation.ExpiresAt = time.Now().Add(-time.Second)
	if _, err := reader.GetObject(t.Context(), request); !errors.Is(err, execution.ErrUnsafe) {
		t.Fatalf("expired reservation remained available: %v", err)
	}
}
