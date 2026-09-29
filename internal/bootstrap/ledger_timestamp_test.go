package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestWaitForLedgerRecordStorageBoundary(t *testing.T) {
	issuedAt := time.Now().UTC().Add(100 * time.Millisecond)
	firstStorageAt := issuedAt.UTC().Truncate(time.Second)
	if firstStorageAt.Before(issuedAt) {
		firstStorageAt = firstStorageAt.Add(time.Second)
	}
	envelope := trust.Envelope{
		IssuedAt:  issuedAt,
		ExpiresAt: firstStorageAt.Add(2 * time.Second),
	}

	if err := waitForLedgerRecordStorageBoundary(t.Context(), envelope); err != nil {
		t.Fatalf("wait for signed storage boundary: %v", err)
	}
	if got := time.Now().UTC().Truncate(time.Second); got.Before(firstStorageAt) {
		t.Fatalf("returned before the signed whole-second boundary: got %s, want at least %s", got, firstStorageAt)
	}
}

func TestLedgerRecordStorageBucketRequiresFullSignedSecond(t *testing.T) {
	base := time.Date(2026, time.September, 29, 12, 0, 0, 0, time.UTC)
	envelope := trust.Envelope{
		IssuedAt:  base.Add(100 * time.Millisecond),
		ExpiresAt: base.Add(2500 * time.Millisecond),
	}
	for _, test := range []struct {
		name string
		now  time.Time
		want error
	}{
		{name: "before issue bucket", now: base, want: ErrRecordAuthorization},
		{name: "full second fits", now: base.Add(time.Second), want: nil},
		{name: "expiry second does not fit", now: base.Add(2 * time.Second), want: ErrRecordAuthorization},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateLedgerRecordStorageBucket(envelope, test.now)
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("validate storage bucket error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestPutObjectAfterTimestampBoundaryDoesNotAttemptPreflightFailures(t *testing.T) {
	t.Run("cancelled before put", func(t *testing.T) {
		client := newFakeObjectStorageClient()
		ledger := &Ledger{client: client}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		issuedAt := time.Now().UTC().Add(time.Minute)
		_, err, attempted := ledger.putObjectAfterTimestampBoundary(ctx, objectStoragePutRequestForTest(), trust.Envelope{
			IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Minute),
		})
		if !errors.Is(err, context.Canceled) || attempted {
			t.Fatalf("cancelled PUT = (%v, %t), want cancellation before an attempted PUT", err, attempted)
		}
		if got := client.putCalls.Load(); got != 0 {
			t.Fatalf("cancelled PUT calls = %d, want 0", got)
		}
	})

	t.Run("no whole second before expiry", func(t *testing.T) {
		client := newFakeObjectStorageClient()
		ledger := &Ledger{client: client}
		base := time.Now().UTC().Truncate(time.Second)
		_, err, attempted := ledger.putObjectAfterTimestampBoundary(t.Context(), objectStoragePutRequestForTest(), trust.Envelope{
			IssuedAt: base.Add(100 * time.Millisecond), ExpiresAt: base.Add(1500 * time.Millisecond),
		})
		if !errors.Is(err, ErrRecordAuthorization) || attempted {
			t.Fatalf("expired storage window PUT = (%v, %t), want authorization failure before PUT", err, attempted)
		}
		if got := client.putCalls.Load(); got != 0 {
			t.Fatalf("expired storage window PUT calls = %d, want 0", got)
		}
	})

	t.Run("anchor expires during wait", func(t *testing.T) {
		client := newFakeObjectStorageClient()
		anchorExpiry := time.Now().UTC().Add(50 * time.Millisecond)
		ledger := &Ledger{client: client, config: LedgerConfig{AnchorExpiresAt: anchorExpiry}}
		issuedAt := time.Now().UTC().Add(100 * time.Millisecond)
		_, err, attempted := ledger.putObjectAfterTimestampBoundary(t.Context(), objectStoragePutRequestForTest(), trust.Envelope{
			IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(3 * time.Second),
		})
		if !errors.Is(err, ErrRecordAuthorization) || attempted {
			t.Fatalf("expired anchor PUT = (%v, %t), want authorization failure before PUT", err, attempted)
		}
		if got := client.putCalls.Load(); got != 0 {
			t.Fatalf("expired anchor PUT calls = %d, want 0", got)
		}
	})
}

func TestPutObjectAfterTimestampBoundaryMarksClientCallAttempted(t *testing.T) {
	client := newFakeObjectStorageClient()
	ledger := &Ledger{client: client}
	issuedAt := time.Now().UTC().Add(-2 * time.Second).Truncate(time.Second)
	client.rejectPut = errors.New("injected service failure")
	_, err, attempted := ledger.putObjectAfterTimestampBoundary(t.Context(), objectStoragePutRequestForTest(), trust.Envelope{
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Minute),
	})
	if err == nil || !attempted {
		t.Fatalf("attempted PUT = (%v, %t), want injected client error after attempt", err, attempted)
	}
	if got := client.putCalls.Load(); got != 1 {
		t.Fatalf("attempted PUT calls = %d, want 1", got)
	}
}

func TestImmutableWriteDoesNotReadExistingMatchAfterPreflightCancellation(t *testing.T) {
	fixture := newLedgerFixture(t)
	scope := testBootstrapScope()
	issuedAt := fixture.now
	body := fixture.signInterval(t, scope, domainBootstrapIntent, map[string]string{"marker": "matching intent"}, issuedAt, issuedAt.Add(time.Minute))
	objectName := fixture.ledger.objectName(scope, 1, ledgerIntent)
	firstStorageAt, err := firstLedgerRecordStorageBucket(mustEnvelopeForTimestampTest(t, body))
	if err != nil {
		t.Fatal(err)
	}
	storeFakeObjectForTimestampTest(fixture.client, fixture.ledger.config.Namespace, fixture.ledger.config.Bucket,
		objectName, body, firstStorageAt, fixture.now)
	putCalls, getCalls := fixture.client.putCalls.Load(), fixture.client.getCalls.Load()
	ctx := cancelAtHelperContextForTimestampTest()

	_, err = fixture.ledger.createOrReadNamed(ctx, scope, 1, ledgerIntent, objectName, body)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("immutable write after wait cancellation = %v, want context cancellation", err)
	}
	if got := fixture.client.putCalls.Load(); got != putCalls {
		t.Fatalf("immutable write PUT calls = %d, want unchanged %d", got, putCalls)
	}
	if got := fixture.client.getCalls.Load(); got != getCalls {
		t.Fatalf("immutable write read back matching object: GET calls = %d, want unchanged %d", got, getCalls)
	}
}

func TestHeadCASDoesNotReadExistingMatchAfterPreflightCancellation(t *testing.T) {
	fixture := newLedgerFixture(t)
	scope := testBootstrapScope()
	intentBytes, _ := fixture.intentBytes(t, scope, 1, "timestamp-head", "timestamp-head-retry")
	initialHeadBytes := fixture.headBytes(t, scope, intentBytes, 1)
	initialEnvelope := mustEnvelopeForTimestampTest(t, initialHeadBytes)
	var head SlotHead
	if err := decodeCanonicalPayload(initialEnvelope.Payload, &head); err != nil {
		t.Fatalf("decode initial HEAD payload: %v", err)
	}
	issuedAt := fixture.now
	body := fixture.signInterval(t, scope, domainBootstrapHead, head, issuedAt, issuedAt.Add(time.Hour))
	envelope := mustEnvelopeForTimestampTest(t, body)
	firstStorageAt, err := firstLedgerRecordStorageBucket(envelope)
	if err != nil {
		t.Fatal(err)
	}
	storeFakeObjectForTimestampTest(fixture.client, fixture.ledger.config.Namespace, fixture.ledger.config.HeadBucket,
		fixture.ledger.headObjectName(scope), body, firstStorageAt, fixture.now)
	putCalls, getCalls := fixture.client.putCalls.Load(), fixture.client.getCalls.Load()
	ctx := cancelAtHelperContextForTimestampTest()

	_, _, err = fixture.ledger.writeHead(ctx, scope, "", head, body, true)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("HEAD CAS after wait cancellation = %v, want context cancellation", err)
	}
	if got := fixture.client.putCalls.Load(); got != putCalls {
		t.Fatalf("HEAD CAS PUT calls = %d, want unchanged %d", got, putCalls)
	}
	if got := fixture.client.getCalls.Load(); got != getCalls {
		t.Fatalf("HEAD CAS read back matching object: GET calls = %d, want unchanged %d", got, getCalls)
	}
}

func TestManagedProgressWriteDoesNotReadExistingMatchAfterPreflightCancellation(t *testing.T) {
	fixture := newPlanBackedManagedPeerFixture(t, "")
	facts := fixture.facts("ocid1.instance.oc1.sa-saopaulo-1.timestamp-candidate")
	candidateWire := managedPeerCandidateWire(t, fixture, facts)
	if err := fixture.ledger.RecordManagedPeerCandidate(t.Context(), fixture.scope, candidateWire,
		managedPeerProgressSigner(fixture), managedPeerRecoveryRefresh(fixture, fixture.plan)); err != nil {
		t.Fatalf("pin candidate and create progress: %v", err)
	}
	progressRecord, progress, err := fixture.ledger.readManagedPeerProgress(t.Context(), fixture.scope,
		fixture.launch.Attempt(), false)
	if err != nil {
		t.Fatalf("read existing managed progress: %v", err)
	}
	issuedAt := fixture.selected.now
	expiresAt := issuedAt.Add(time.Minute)
	body, err := managedPeerProgressSigner(fixture)(progress, issuedAt, expiresAt)
	if err != nil {
		t.Fatalf("sign matching managed progress: %v", err)
	}
	envelope := mustEnvelopeForTimestampTest(t, body)
	firstStorageAt, err := firstLedgerRecordStorageBucket(envelope)
	if err != nil {
		t.Fatal(err)
	}
	objectName := fixture.ledger.progressObjectName(fixture.scope, fixture.launch.Attempt())
	storeFakeObjectForTimestampTest(fixture.client, fixture.ledger.config.Namespace, fixture.ledger.config.HeadBucket,
		objectName, body, firstStorageAt, fixture.selected.now)
	putCalls, getCalls := fixture.client.putCalls.Load(), fixture.client.getCalls.Load()
	ctx := cancelAtHelperContextForTimestampTest()

	_, _, err = fixture.ledger.writeManagedPeerProgress(ctx, fixture.scope, fixture.launch.Attempt(),
		progressRecord.ETag, progress, body, envelope)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("managed progress write after wait cancellation = %v, want context cancellation", err)
	}
	if got := fixture.client.putCalls.Load(); got != putCalls {
		t.Fatalf("managed progress PUT calls = %d, want unchanged %d", got, putCalls)
	}
	if got := fixture.client.getCalls.Load(); got != getCalls {
		t.Fatalf("managed progress read back matching object: GET calls = %d, want unchanged %d", got, getCalls)
	}
}

func mustEnvelopeForTimestampTest(t *testing.T, body []byte) trust.Envelope {
	t.Helper()
	envelope, err := trust.DecodeEnvelope(body)
	if err != nil {
		t.Fatalf("decode timestamp test envelope: %v", err)
	}
	return envelope
}

type cancelAtHelperContext struct {
	context.Context
	calls atomic.Int32
	once  sync.Once
	done  chan struct{}
}

func cancelAtHelperContextForTimestampTest() *cancelAtHelperContext {
	return &cancelAtHelperContext{Context: context.Background(), done: make(chan struct{})}
}

func (ctx *cancelAtHelperContext) Err() error {
	if ctx.calls.Add(1) < 2 {
		return nil
	}
	ctx.once.Do(func() { close(ctx.done) })
	return context.Canceled
}

func (ctx *cancelAtHelperContext) Done() <-chan struct{} {
	return ctx.done
}

func storeFakeObjectForTimestampTest(
	client *fakeObjectStorageClient,
	namespace string,
	bucket string,
	objectName string,
	body []byte,
	lastModified time.Time,
	serverDate time.Time,
) {
	key := requestKey(new(namespace), new(bucket), new(objectName))
	client.mu.Lock()
	client.objects[key] = fakeStoredObject{body: bytes.Clone(body), etag: `"matching-object"`, lastModified: lastModified}
	client.now = serverDate
	client.mu.Unlock()
}

func objectStoragePutRequestForTest() objectstorage.PutObjectRequest {
	body := []byte("timestamp test record")
	digest := sha256.Sum256(body)
	digestHeader := base64.StdEncoding.EncodeToString(digest[:])
	length := int64(len(body))
	ifNoneMatch := "*"
	return objectstorage.PutObjectRequest{
		NamespaceName: new("namespace"), BucketName: new("bootstrap-ledger"), ObjectName: new("record"),
		PutObjectBody: io.NopCloser(bytes.NewReader(body)), ContentLength: &length,
		IfNoneMatch: &ifNoneMatch, OpcSseKmsKeyId: new("ocid1.key.oc1.sa-saopaulo-1.ledger"),
		OpcChecksumAlgorithm: objectstorage.PutObjectOpcChecksumAlgorithmSha256, OpcContentSha256: &digestHeader,
	}
}
