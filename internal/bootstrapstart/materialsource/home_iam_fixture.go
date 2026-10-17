//go:build fixturetest

package materialsource

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const fixtureHomeIAMKey = "orchestrator/foundation/v1/iam-lease.json"

// Actors retain the measured binary, current roots and actual signed SDK reads.
func assertHomeIAMLeases(t *testing.T, first, second *region.HomeIAMAuthority, objects *objectstorage.ObjectStorageClient, protocol *materialProtocol) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	domain := first.StorageDomain()
	path := "/n/" + domain.Namespace + "/b/" + domain.HeadBucket + "/o/" + fixtureHomeIAMKey
	var fault atomic.Int32
	fault.Store(1)
	if protocol.interceptObject != nil {
		t.Fatal("home IAM scenario requires the unused object fault hook")
	}
	protocol.interceptObject = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPut || r.URL.Path != path {
			return false
		}
		mode := fault.Swap(0)
		if mode == 0 {
			return false
		}
		// Use the same durable CAS handler without recursively invoking the hook.
		protocol.mu.Lock()
		defer protocol.mu.Unlock()
		normal := &materialProtocol{directory: protocol.directory, target: protocol.target}
		response := httptest.NewRecorder()
		normal.ServeHTTP(response, r)
		if response.Code != http.StatusOK {
			for key, values := range response.Header() {
				w.Header()[key] = values
			}
			w.WriteHeader(response.Code)
			w.Write(response.Body.Bytes())
			return true
		}
		if mode == 2 {
			wire, err := os.ReadFile(protocol.objectPath(path))
			var stored map[string]any
			if err != nil || json.Unmarshal(wire, &stored) != nil {
				t.Error("read accepted lease before competing operation")
				w.WriteHeader(500)
				return true
			}
			stored["operationId"] = entityid.New()
			wire, err = json.Marshal(stored, json.Deterministic(true))
			if err != nil || protocol.put(path, wire) != nil {
				t.Error("persist competing operation tuple")
				w.WriteHeader(500)
				return true
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"code":"ServiceUnavailable","message":"accepted PUT response lost"}`)
		return true
	}
	defer func() { protocol.interceptObject = nil }()
	child, release, err := first.HomeWrite(ctx, 0)
	if err != nil || fault.Load() != 0 {
		t.Fatalf("identical ambiguous lease was not recovered: %v", err)
	}
	defer release()
	if child.Err() != nil {
		release()
		t.Fatal("recovered lease child was canceled")
	}
	if _, wrongRelease, err := second.HomeWrite(ctx, 0); !errors.Is(err, region.ErrFoundationBusy) {
		if wrongRelease != nil {
			wrongRelease()
		}
		release()
		t.Fatalf("second genuine actor did not contend on shared object: %v", err)
	}
	release()
	_, releaseSecond, err := second.HomeWrite(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	releaseSecond()
	fault.Store(2)
	if _, wrongRelease, err := first.HomeWrite(ctx, 0); err == nil || fault.Load() != 0 {
		if wrongRelease != nil {
			wrongRelease()
		}
		t.Fatal("ambiguous acquisition adopted another operation tuple")
	}
	rewriteFixtureHomeLease(t, ctx, objects, domain, false, true)
	child, release, err = first.HomeWrite(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	factory, guarded, err := first.GuardedFactory(child)
	if err != nil {
		t.Fatal(err)
	}
	entered, joined := make(chan struct{}), make(chan struct{})
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(entered)
		select {
		case <-r.Context().Done():
		case <-ctx.Done():
		}
		close(joined)
	}))
	defer func() { cancel(); blocked.Close() }()
	iam := fixtureHomeIAMClient(t, factory, blocked)
	result := make(chan error, 1)
	go func() {
		_, err := iam.CreatePolicy(ociclient.RequestContext(guarded), fixtureHomeIAMRequest())
		result <- err
	}()
	awaitFixtureIAM(t, ctx, entered, "actual IAM mutation did not reach blocked HTTP handler")
	rewriteFixtureHomeLease(t, ctx, objects, domain, true, false)
	if err := first.Guard(child, 0); !errors.Is(err, region.ErrFoundationFenced) || !errors.Is(child.Err(), context.Canceled) || !errors.Is(context.Cause(child), region.ErrFoundationFenced) {
		t.Fatalf("durable owner loss did not cancel the SDK child: %v", err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Cause(child)) {
			t.Fatalf("blocked IAM request did not return cancellation: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("blocked actual IAM caller did not join after durable lease loss")
	}
	awaitFixtureIAM(t, ctx, joined, "blocked IAM handler did not observe request cancellation")
	release()
	stored, _ := readFixtureHomeLease(t, ctx, objects, domain)
	if _, released := stored["releasedAt"]; released {
		t.Fatal("former owner released the replacement owner's durable lease")
	}
	rewriteFixtureHomeLease(t, ctx, objects, domain, false, true)
}

func fixtureHomeIAMClient(t *testing.T, factory *ociclient.Factory, endpoint *httptest.Server) identity.IdentityClient {
	t.Helper()
	iam, err := factory.Identity()
	if err != nil {
		t.Fatal(err)
	}
	iam.Host, iam.HTTPClient = endpoint.URL, endpoint.Client()
	ociclient.ConfigureRequestCancellation(&iam.BaseClient)
	return iam
}

func fixtureHomeIAMRequest() identity.CreatePolicyRequest {
	policy := common.NoRetryPolicy()
	return identity.CreatePolicyRequest{CreatePolicyDetails: identity.CreatePolicyDetails{
		Name: new("blocked-home-iam-integration"), CompartmentId: new("ocid1.compartment.oc1..control"),
		Description: new("disposable HTTP protocol scenario"), Statements: []string{"Allow any-user to read secret-bundles in compartment id ocid1.compartment.oc1..control where request.principal.id = 'ocid1.instance.oc1.sa-saopaulo-1.test'"}},
		RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}}
}

func awaitFixtureIAM(t *testing.T, ctx context.Context, signal <-chan struct{}, failure string) {
	t.Helper()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatal(failure)
	}
}

func readFixtureHomeLease(t *testing.T, ctx context.Context, objects *objectstorage.ObjectStorageClient, domain bootstrap.StorageDomain) (map[string]any, string) {
	t.Helper()
	response, err := objects.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{
		NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(fixtureHomeIAMKey)})
	if err != nil {
		t.Fatal(err)
	}
	if response.Content == nil || response.ETag == nil {
		t.Fatal("actual lease read omitted body or ETag")
	}
	defer response.Content.Close()
	var record map[string]any
	if json.UnmarshalRead(io.LimitReader(response.Content, 16<<10), &record) != nil {
		t.Fatal("actual lease read omitted bounded JSON")
	}
	return record, *response.ETag
}

func rewriteFixtureHomeLease(t *testing.T, ctx context.Context, objects *objectstorage.ObjectStorageClient, domain bootstrap.StorageDomain, takeover, released bool) {
	t.Helper()
	record, etag := readFixtureHomeLease(t, ctx, objects, domain)
	now := time.Now().UTC()
	if takeover {
		record["ownerId"], record["operationId"], record["leaseId"] = entityid.New(), entityid.New(), entityid.New()
		record["generation"] = record["generation"].(float64) + 1
		record["acquiredAt"] = now
	}
	record["updatedAt"], record["expiresAt"] = now, now.Add(45*time.Second)
	delete(record, "releasedAt")
	if released {
		record["releasedAt"], record["expiresAt"] = now, now
	}
	wire, err := json.Marshal(record, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	policy := common.NoRetryPolicy()
	_, err = objects.PutObject(ociclient.RequestContext(ctx), objectstorage.PutObjectRequest{
		NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(fixtureHomeIAMKey), IfMatch: new(etag),
		OpcSseKmsKeyId: new(domain.HeadKMSKeyOCID), ContentLength: new(int64(len(wire))), PutObjectBody: io.NopCloser(bytes.NewReader(wire)),
		RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}})
	if err != nil {
		t.Fatalf("actual conditional lease replacement: %v", err)
	}
}

// Run last: the valid remote rotation retires this scenario's original root.
func assertHomeIAMRetiredRoot(t *testing.T, authority *region.HomeIAMAuthority, objects *objectstorage.ObjectStorageClient, roots trust.Keyring, root ed25519.PrivateKey, anchor bootstrap.VerifiedBootstrapAnchor) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	factory, guarded, err := authority.GuardedFactory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var mutations atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mutations.Add(1); w.WriteHeader(500) }))
	defer endpoint.Close()
	iam := fixtureHomeIAMClient(t, factory, endpoint)
	id := trust.ChainIdentity{DeploymentID: anchor.Anchor().DeploymentID, Cell: "gru", Environment: "production"}
	chain := trust.RootChain{Version: 1}
	verified, err := trust.VerifyRootChain(roots, id, chain)
	if err != nil {
		t.Fatal(err)
	}
	public, next, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := trust.NextRotation(verified, public)
	if err != nil {
		t.Fatal(err)
	}
	var signed trust.SignedRotation
	for _, signer := range []ed25519.PrivateKey{root, next} {
		envelope, err := trust.SignRotation(rotation, id, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour), signer)
		if err != nil {
			t.Fatal(err)
		}
		signed.Signatures = append(signed.Signatures, envelope)
	}
	chain.Rotations = append(chain.Rotations, signed)
	if _, err := trust.VerifyRootChain(roots, id, chain); err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeRootChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	domain := authority.StorageDomain()
	response, err := objects.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new("orchestrator/foundation/v1/root-chain.json")})
	if err != nil {
		t.Fatal(err)
	}
	if response.Content == nil || response.ETag == nil {
		t.Fatal("remote root-chain omitted conditional identity")
	}
	response.Content.Close()
	policy := common.NoRetryPolicy()
	_, err = objects.PutObject(ociclient.RequestContext(ctx), objectstorage.PutObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new("orchestrator/foundation/v1/root-chain.json"),
		IfMatch: response.ETag, OpcSseKmsKeyId: new(domain.HeadKMSKeyOCID), ContentLength: new(int64(len(wire))), PutObjectBody: io.NopCloser(bytes.NewReader(wire)), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iam.CreatePolicy(ociclient.RequestContext(guarded), fixtureHomeIAMRequest()); !errors.Is(err, trust.ErrUntrustedKey) || mutations.Load() != 0 {
		t.Fatalf("retired terminal root did not deny before mutation wire: count=%d err=%v", mutations.Load(), err)
	}
}
