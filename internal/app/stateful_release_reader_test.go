package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestStatefulEvidenceRetainsOriginalContextAndMinimumExpiry(t *testing.T) {
	reader, intent := statefulEvidenceSelector(t)
	source, cancel := context.WithCancel(t.Context())
	defer cancel()
	data := []byte("four")
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	now := time.Now()
	expiries := []time.Time{now.Add(time.Minute), now.Add(30 * time.Second), now.Add(2 * time.Minute), now.Add(3 * time.Minute)}
	want := []time.Time{{}, expiries[0], expiries[1], expiries[1]}
	var calls []context.Context
	body, err := reader.readEvidence(source, "operation", digest, intent, func(ctx context.Context, request rootoci.ContainerEvidenceRequest) (rootoci.ContainerEvidenceChunk, error) {
		index := len(calls)
		calls = append(calls, ctx)
		deadline, bounded := ctx.Deadline()
		if bounded != !want[index].IsZero() || bounded && !deadline.Equal(want[index]) {
			t.Fatalf("chunk %d deadline = %v, want %v", index, deadline, want[index])
		}
		return rootoci.ContainerEvidenceChunk{OperationID: request.OperationID, Fingerprint: request.ExpectedFingerprint, EvidenceSHA256: digest,
			Offset: request.Offset, TotalBytes: int64(len(data)), Data: data[index : index+1], ExpiresAt: expiries[index]}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	for _, call := range calls[1:] {
		if !errors.Is(call.Err(), context.Canceled) {
			t.Fatalf("completed RPC retained its temporary context: %v", call.Err())
		}
	}
	material := body.(*statefulMaterialBytes)
	if material.ctx != source || !material.expires.Equal(expiries[1]) {
		t.Fatal("returned material lost its original caller or earliest expiry")
	}
	got, err := io.ReadAll(body)
	if err != nil || string(got) != string(data) {
		t.Fatalf("material after RPC cancellation: %q, %v", got, err)
	}
	cancel()
	if _, err := body.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("original cancellation did not revoke material: %v", err)
	}
}

// This exercises a real blocked Unix read, with controlled chunk selectors. It
// does not produce or qualify sealed root/domain authority.
func TestStatefulEvidenceExpiryCancelsBlockedUnixRead(t *testing.T) {
	reader, intent := statefulEvidenceSelector(t)
	watchdog, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	path := filepath.Join(t.TempDir(), "evidence.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	expires := time.Now().Add(100 * time.Millisecond)
	_, err = reader.readEvidence(watchdog, "operation", "digest", intent, func(ctx context.Context, request rootoci.ContainerEvidenceRequest) (rootoci.ContainerEvidenceChunk, error) {
		if request.Offset == 0 {
			return rootoci.ContainerEvidenceChunk{OperationID: request.OperationID, Fingerprint: request.ExpectedFingerprint, EvidenceSHA256: request.EvidenceSHA256,
				TotalBytes: 2, Data: []byte("a"), ExpiresAt: expires}, nil
		}
		deadline, ok := ctx.Deadline()
		if !ok || !deadline.Equal(expires) {
			t.Fatalf("blocked chunk deadline = %v, want original %v", deadline, expires)
		}
		connection, err := new(net.Dialer).DialContext(ctx, "unix", path)
		if err != nil {
			return rootoci.ContainerEvidenceChunk{}, err
		}
		defer connection.Close()
		peer, err := listener.AcceptUnix()
		if err != nil {
			return rootoci.ContainerEvidenceChunk{}, err
		}
		defer peer.Close()
		closeOnExpiry := context.AfterFunc(ctx, func() { _ = connection.Close() })
		defer closeOnExpiry()
		_, err = connection.Read(make([]byte, 1))
		if err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) || watchdog.Err() != nil {
			t.Fatalf("blocked Unix read did not end at original expiry: read=%v, context=%v, watchdog=%v", err, ctx.Err(), watchdog.Err())
		}
		return rootoci.ContainerEvidenceChunk{}, ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired evidence read = %v", err)
	}
}

// Only canonical claim selectors are needed by readEvidence; callbacks below
// remain controlled unit inputs and grant no production authority.
func statefulEvidenceSelector(t *testing.T) (statefulReleaseReader, func(context.Context, string) (delivery.Intent, error)) {
	t.Helper()
	now := time.Now()
	envelope, err := trust.Sign([]byte(`{}`), trust.Scope{Domain: "test.stateful-evidence", DeploymentID: trust.DelegationDeploymentID,
		Cell: "GRU", Environment: "test", Role: "terrabase", Slot: "test"}, now.Add(-time.Second), now.Add(time.Minute), ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return statefulReleaseReader{client: new(rootoci.Client), deliveries: new(delivery.Service)}, func(context.Context, string) (delivery.Intent, error) {
		return delivery.Intent{Role: "terrabase", Container: &release.ContainerBundle{Claim: wire}}, nil
	}
}

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
