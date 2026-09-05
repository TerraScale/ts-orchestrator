package sourcepublication

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/restoresnapshot"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type publicationCAS struct {
	data      map[string][]byte
	revisions map[string]uint64
	writes    int
}

func (c *publicationCAS) Get(_ context.Context, k string) ([]byte, uint64, error) {
	return append([]byte(nil), c.data[k]...), c.revisions[k], nil
}
func (c *publicationCAS) CompareAndSwap(_ context.Context, k string, r uint64, v []byte) error {
	if c.revisions[k] != r {
		return provider.OwnershipCASConflict{}
	}
	c.data[k] = append([]byte(nil), v...)
	c.revisions[k]++
	c.writes++
	return nil
}

type publicationSigner struct{}

func (publicationSigner) Sign(r *http.Request) error {
	r.Header.Set("Authorization", "fixture")
	return nil
}

type publicationRoundTrip func(*http.Request) (*http.Response, error)

func (f publicationRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type publicationBackend struct {
	destinations map[string]preliminarytransfer.Destination
	bodies       map[string][]byte
	puts         int
	badBucket    bool
	uncertain    bool
	unavailable  bool
	beforePut    func()
}

func (b *publicationBackend) serve(r *http.Request) (*http.Response, error) {
	if b.unavailable {
		return nil, errors.New("provider unavailable after committed PUT")
	}
	if r.Header.Get("Authorization") == "" {
		return nil, errors.New("unsigned")
	}
	header := make(http.Header)
	status := http.StatusOK
	var body []byte
	if !strings.Contains(r.URL.Path, "/o/") {
		parts := strings.Split(r.URL.Path, "/")
		d := b.destinations[parts[len(parts)-1]]
		id := d.BucketResourceID
		if b.badBucket {
			id = "wrong"
		}
		body, _ = json.Marshal(provider.OCIBucketObservation{ID: id, CompartmentID: d.CompartmentID, Namespace: d.Namespace, Name: d.Bucket, FreeformTags: d.OwnershipTags})
	} else {
		key := r.URL.Host + r.URL.Path
		var found bool
		body, found = b.bodies[key]
		switch r.Method {
		case "PUT":
			if r.Header.Get("If-None-Match") != "*" {
				return nil, errors.New("mutable put")
			}
			if found {
				status = 412
			} else {
				body, _ = io.ReadAll(r.Body)
				if r.Header.Get("opc-meta-terrascale-sha256") != strings.TrimPrefix(delivery.SHA256Digest(body), "sha256:") {
					return nil, errors.New("digest differs")
				}
				b.bodies[key] = append([]byte(nil), body...)
				b.puts++
				if b.beforePut != nil {
					b.beforePut()
				}
				if b.uncertain {
					b.uncertain = false
					b.unavailable = true
					return nil, errors.New("uncertain committed PUT")
				}
			}
		case "GET", "HEAD":
			if !found {
				status = 404
			}
		default:
			return nil, errors.New("unexpected method")
		}
		header.Set("ETag", "fixture-etag")
		header.Set("opc-meta-terrascale-sha256", strings.TrimPrefix(delivery.SHA256Digest(body), "sha256:"))
		header.Set("Content-Length", fmt.Sprint(len(body)))
		if r.Method != "GET" {
			body = nil
		}
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body))}, nil
}
func publicationKeyPair(t *testing.T) (*security.CommandSignatureSigner, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { signer.Close() })
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

type publicationFixture struct {
	config  Config
	backend *publicationBackend
	cas     *publicationCAS
	owner   *security.CommandSignatureSigner
	public  []byte
	now     time.Time
}

func newPublicationFixture(t *testing.T, large bool) *publicationFixture {
	t.Helper()
	owner, public := publicationKeyPair(t)
	source, sourcePublic := publicationKeyPair(t)
	_, sfo := publicationKeyPair(t)
	_, fra := publicationKeyPair(t)
	now := time.Now().UTC()
	issued := now.Add(-2 * time.Hour)
	request := preliminarycapture.Request{Version: 1, TransitionID: "transition-1", SourceNodeID: "gru-1", InitialGrantSHA256: strings.Repeat("a", 64), StoreScopeSHA256: strings.Repeat("b", 64), ProfileSHA256: strings.Repeat("c", 64), Accounts: []preliminarycapture.AccountInventory{{Account: "REGIONAL", Streams: []string{"EVENTS"}}, {Account: "GLOBAL", Streams: []string{"SPEC"}}}, ControlEpoch: 5, IssuedAt: issued, ExpiresAt: issued.Add(time.Hour)}
	capture, err := preliminarycapture.SignRequest(owner, request)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "capture")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, body []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(".lock", nil)
	write("request.json", capture)
	receipt := preliminarycapture.Receipt{Version: 1, Preliminary: true, TransitionID: request.TransitionID, RequestSHA256: preliminarytransfer.Digest(capture), SourceNodeID: request.SourceNodeID, ControlEpoch: 5, CreatedAt: issued.Add(time.Minute)}
	maximum := int64(1024)
	if large {
		maximum = 18 << 20
	}
	for i, a := range request.Accounts {
		key, _ := preliminarycapture.ObjectKey(a.Account, a.Streams[0], 5)
		body := []byte("archived-" + a.Account)
		if large && i == 0 {
			body = make([]byte, 17<<20)
			if _, err := rand.Read(body); err != nil {
				t.Fatal(err)
			}
		}
		sum := sha256.Sum256([]byte(key))
		write(hex.EncodeToString(sum[:])+".snapshot", body)
		receipt.Objects = append(receipt.Objects, preliminarycapture.Object{Account: a.Account, Stream: a.Streams[0], Key: key, SHA256: delivery.SHA256Digest(body), Size: int64(len(body)), CreatedAt: receipt.CreatedAt})
	}
	signedReceipt, err := preliminarycapture.SignReceipt(source, receipt)
	if err != nil {
		t.Fatal(err)
	}
	write("receipt.json", signedReceipt)
	scope := preliminarytransfer.Scope{Version: 1, TransitionID: request.TransitionID, SourceNodeID: request.SourceNodeID, InitialGrantSHA256: request.InitialGrantSHA256, StoreScopeSHA256: request.StoreScopeSHA256, ProfileSHA256: request.ProfileSHA256, SourcePublicKeyPEM: string(sourcePublic), CaptureRequest: capture, CaptureReceipt: signedReceipt, RequestSHA256: preliminarytransfer.Digest(capture), ReceiptSHA256: preliminarytransfer.Digest(signedReceipt), PreparationGrantSHA256: strings.Repeat("e", 64), Prefix: "preliminary/transition-1", MaxRestoreBytes: 2 * maximum, MaxSnapshotBytes: maximum, MaxTotalBytes: 2 * maximum}
	backend := &publicationBackend{destinations: map[string]preliminarytransfer.Destination{}, bodies: map[string][]byte{}}
	regions := map[string]restoresnapshot.Region{}
	for i, region := range []string{"gru", "sfo", "fra"} {
		oci := []string{"sa-saopaulo-1", "us-sanjose-1", "eu-frankfurt-1"}[i]
		d := preliminarytransfer.Destination{Region: region, OCIRegion: oci, Namespace: "namespace", Bucket: "bucket-" + region, BucketResourceID: "ocid1.bucket." + region, CompartmentID: "ocid1.compartment.test", OwnershipGeneration: 1, OwnershipTags: map[string]string{"terrascale-managed": "orchestrator", "terrascale-region": region}}
		scope.Destinations = append(scope.Destinations, d)
		backend.destinations[d.Bucket] = d
		for _, o := range receipt.Objects {
			scope.Objects = append(scope.Objects, preliminarytransfer.ObjectMapping{Region: region, Account: o.Account, Stream: o.Stream, LocalKey: o.Key, ObjectKey: scope.Prefix + "/" + scope.RequestSHA256 + "/" + o.Key, SHA256: o.SHA256, Size: o.Size})
		}
		transportCfg, err := provider.NewOCIServiceTransportConfig(provider.OCIServiceObjectStorage, oci, "https://objectstorage."+oci+".oraclecloud.com")
		if err != nil {
			t.Fatal(err)
		}
		transportCfg.MaxObjectBytes = max(maximum, preliminarytransfer.MaximumBytes)
		transport, err := provider.NewOCIHTTPTransport(transportCfg, &http.Client{Transport: publicationRoundTrip(backend.serve)}, publicationSigner{})
		if err != nil {
			t.Fatal(err)
		}
		regions[region] = restoresnapshot.Region{Transport: transport, OCIRegion: oci, Namespace: d.Namespace, Bucket: d.Bucket, BucketResourceID: d.BucketResourceID, CompartmentID: d.CompartmentID, OwnershipGeneration: 1}
	}
	for i, region := range []string{"sfo", "fra"} {
		scope.Candidates = append(scope.Candidates, preliminarytransfer.Candidate{Region: region, NodeID: region + "-1", ServerName: region + "-candidate-1", BootstrapGrantSHA256: strings.Repeat("f", 64), ManifestSHA256: strings.Repeat("1", 64), ReceiptPublicKeyPEM: string([][]byte{sfo, fra}[i])})
	}
	signed, err := preliminarytransfer.SignScope(owner, scope)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := preliminarytransfer.VerifyScope(public, signed)
	if err != nil {
		t.Fatal(err)
	}
	cas := &publicationCAS{data: map[string][]byte{}, revisions: map[string]uint64{}}
	f := &publicationFixture{config: Config{OutputDir: dir, StateDir: filepath.Join(filepath.Dir(dir), "publication"), Journal: cas, Regions: regions, Signer: source, Guard: func(context.Context) error { return nil }}, backend: backend, cas: cas, owner: owner, public: public, now: now}
	f.config.Upload = f.authorize(t, verified, 7, now.Add(-time.Minute))
	return f
}
func (f *publicationFixture) authorize(t *testing.T, scope preliminarytransfer.VerifiedScope, epoch uint64, issued time.Time) preliminarytransfer.VerifiedUpload {
	t.Helper()
	auth, err := preliminarytransfer.SignUploadAuthorization(f.owner, preliminarytransfer.UploadAuthorization{Version: 1, ScopeSHA256: scope.Digest, ControlEpoch: epoch, IssuedAt: issued, ExpiresAt: issued.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := preliminarytransfer.MarshalRequest(scope.Signed, auth)
	if err != nil {
		t.Fatal(err)
	}
	v, err := preliminarytransfer.VerifyUploadRequest(f.public, raw, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestPublishHistoricalLargeCaptureRenewal(t *testing.T) {
	f := newPublicationFixture(t, true)
	ctx := context.Background()
	first, err := Publish(ctx, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if f.backend.puts != 9 {
		t.Fatalf("puts=%d", f.backend.puts)
	}
	captureBefore, err := os.ReadFile(filepath.Join(f.config.OutputDir, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	f.config.Upload = f.authorize(t, f.config.Upload.Scope, 8, f.now.Add(-30*time.Second))
	again, err := Publish(ctx, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, again) || f.backend.puts != 9 {
		t.Fatal("renewal replaced immutable publication")
	}
	captureAfter, _ := os.ReadFile(filepath.Join(f.config.OutputDir, "receipt.json"))
	if !bytes.Equal(captureBefore, captureAfter) {
		t.Fatal("capture receipt changed")
	}
	f.config.Upload = f.authorize(t, f.config.Upload.Scope, 7, f.now.Add(-time.Minute))
	if _, err := Publish(ctx, f.config); err == nil {
		t.Fatal("stale authorization accepted")
	}
}
func TestPublishRefusesBucketBeforeJournalAndRetriesUncertainPut(t *testing.T) {
	f := newPublicationFixture(t, false)
	f.backend.badBucket = true
	if _, err := Publish(context.Background(), f.config); err == nil {
		t.Fatal("wrong bucket accepted")
	}
	if f.cas.writes != 0 || f.backend.puts != 0 {
		t.Fatal("ownership written before bucket proof")
	}
	f.backend.badBucket = false
	f.backend.uncertain = true
	if _, err := Publish(context.Background(), f.config); err == nil {
		t.Fatal("uncertain PUT appeared complete")
	}
	if _, err := os.Stat(filepath.Join(f.config.StateDir, "receipt.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("receipt created before all objects")
	}
	f.backend.unavailable = false
	raw, err := Publish(context.Background(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	if f.backend.puts != 9 {
		t.Fatalf("puts=%d", f.backend.puts)
	}
	if _, err := preliminarytransfer.CheckPublication(f.config.Upload, raw); err != nil {
		t.Fatal(err)
	}
}
func TestPublishCancellationStopsAfterUncertainMutation(t *testing.T) {
	f := newPublicationFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.backend.beforePut = cancel
	if _, err := Publish(ctx, f.config); err == nil {
		t.Fatal("cancellation accepted")
	}
	if f.backend.puts != 1 {
		t.Fatalf("puts after cancellation=%d", f.backend.puts)
	}
}
