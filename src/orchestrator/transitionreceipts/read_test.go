package transitionreceipts

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func receiptKey(t *testing.T) (*security.CommandSignatureSigner, string) {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s, e := security.NewCommandSignatureSignerFromKey(k)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	b, e := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	return s, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}))
}

type receiptFixture struct {
	ownerPublic string
	signedPlan  []byte
	plan        controltransition.VerifiedPlan
	p           controltransition.Plan
	buckets     map[string]provider.OCIBucketObservation
	objects     map[string][]byte
	future      []byte
	digests     []string
}

func newReceiptFixture(t *testing.T, separate bool) receiptFixture {
	t.Helper()
	owner, ownerPublic := receiptKey(t)
	source, sourcePublic := receiptKey(t)
	h := strings.Repeat("a", 64)
	p := controltransition.Plan{Version: 1, Mode: controltransition.Mode, PreliminaryScopeSHA256: h, EstateID: "launch", TransitionID: "first-r3", IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour), ClusterName: "control-r3", TrustBundleSHA256: h, SourceTopologyEpoch: 1, TargetTopologyEpoch: 2, GlobalElectionFloor: 11, RegionalElectionFloor: 7, Source: controltransition.Source{NodeID: "gru-one", ServerName: "source-r1", BootstrapGrantSHA256: h, InitialManifestSHA256: h, CaptureManifestSHA256: strings.Repeat("b", 64), LaunchSHA256: h, StoreScopeSHA256: h, ProfileSHA256: h, StoreDir: "/data/source", CaptureDir: "/data/capture", ArchiveDir: "/data/archive", ReceiptPublicKeyPEM: sourcePublic}, Limits: controltransition.Limits{MaxStoreBytes: 1 << 30, MaxStoreFiles: 10000, MaxSnapshotBytes: 1 << 20, MaxTransferBytes: 1 << 30, MaxRestoreBytes: 1 << 30}}
	f := receiptFixture{buckets: map[string]provider.OCIBucketObservation{}, objects: map[string][]byte{}}
	signers := map[string]*security.CommandSignatureSigner{p.Source.NodeID: source}
	for i, region := range []string{"gru", "sfo", "fra"} {
		s, public := receiptKey(t)
		node := region + "-one"
		if separate && region == "gru" {
			node = "gru-other"
		}
		d := controltransition.Destination{Region: region, NodeID: node, ServerName: region + "-r3", BootstrapGrantSHA256: h, PreparedManifestSHA256: strings.Repeat("b", 64), ActivationManifestSHA256: strings.Repeat("c", 64), RouteURL: "nats-route://" + region + ".internal:6222", CertificateSHA256: strings.Repeat(string(rune('d'+i)), 64), ReceiptPublicKeyPEM: public, PreliminaryStoreDir: "/data/preliminary", StoreDir: "/data/r3", StagingDir: "/data/staging", Objects: controltransition.ObjectLocation{OCIRegion: []string{"sa-saopaulo-1", "us-sanjose-1", "eu-frankfurt-1"}[i], Namespace: "tenancy", Bucket: region + "-control", BucketResourceID: "ocid1.bucket." + region, CompartmentID: "ocid1.compartment.launch", Prefix: "control-transitions/first-r3"}}
		o := provider.OCIBucketObservation{ID: d.Objects.BucketResourceID, CompartmentID: d.Objects.CompartmentID, Namespace: d.Objects.Namespace, Name: d.Objects.Bucket, FreeformTags: map[string]string{"terrascale-managed": "orchestrator", "terrascale-region": region}}
		var e error
		d.Objects.OwnershipObservationSHA256, e = BucketObservationDigest(o)
		if e != nil {
			t.Fatal(e)
		}
		f.buckets["/n/tenancy/b/"+d.Objects.Bucket] = o
		if node != p.Source.NodeID {
			signers[node] = s
		}
		p.Destinations = append(p.Destinations, d)
	}
	for _, role := range []string{"global", "gru-regional"} {
		p.Accounts = append(p.Accounts, controltransition.Account{Role: role, SourceName: role, DestinationName: role, Streams: []controltransition.Stream{{Name: "EVENTS", SourceConfigSHA256: h, FinalConfigSHA256: h}}})
	}
	signed, e := controltransition.SignPlan(owner, p)
	if e != nil {
		t.Fatal(e)
	}
	f.plan, e = controltransition.VerifyPlan([]byte(ownerPublic), signed)
	if e != nil {
		t.Fatal(e)
	}
	f.p = p
	f.ownerPublic = ownerPublic
	f.signedPlan = signed
	nodes := []string{p.Source.NodeID}
	for _, d := range p.Destinations {
		if d.NodeID != p.Source.NodeID {
			nodes = append(nodes, d.NodeID)
		}
	}
	for _, node := range nodes {
		receipt := controltransition.PinReceipt{Version: 1, Phase: "plan-pinned", PlanSHA256: f.plan.Digest(), NodeID: node, Role: "destination", PinSHA256: controltransition.Digest([]byte(node)), BootstrapGrantSHA256: h, ManifestSHA256: strings.Repeat("b", 64), AdmittedAt: p.IssuedAt.Add(time.Second), PublishedAt: p.IssuedAt.Add(2 * time.Second)}
		if node == p.Source.NodeID {
			receipt.Role = "source"
			receipt.ManifestSHA256 = p.Source.InitialManifestSHA256
			receipt.CommandID = "capture-plan"
			receipt.CommandSHA256 = h
			receipt.AuthorityID = "gru-regional"
			receipt.Epoch = 7
			receipt.CandidateID = "gru-controller"
			receipt.LeaseID = "lease-one"
		}
		raw, e := controltransition.SignPinReceipt(signers[node], f.plan, receipt)
		if e != nil {
			t.Fatal(e)
		}
		region, key, e := PinObjectKey(f.plan, node)
		if e != nil {
			t.Fatal(e)
		}
		f.objects["/n/tenancy/b/"+region+"-control/o/"+key] = raw
		f.digests = append(f.digests, controltransition.Digest(raw))
		if node == p.Source.NodeID {
			receipt.PublishedAt = time.Now().UTC().Add(time.Minute)
			f.future, e = controltransition.SignPinReceipt(signers[node], f.plan, receipt)
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	return f
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type remoteFixture struct {
	mu          sync.Mutex
	mode        string
	calls       []string
	bucketReads map[string]int
	f           receiptFixture
}

func (r *remoteFixture) set(mode string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mode = mode
	r.calls = nil
	r.bucketReads = map[string]int{}
}
func (r *remoteFixture) serve(t *testing.T, w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, req.Method+" "+req.Host+req.URL.Path)
	if req.Method != "GET" || !strings.HasPrefix(req.Host, "objectstorage.") || !strings.Contains(req.Header.Get("Authorization"), "Signature version=") {
		t.Error("request lost signed read-only OCI authority")
	}
	if observation, ok := r.f.buckets[req.URL.Path]; ok {
		r.bucketReads[req.URL.Path]++
		if r.mode == "ownership" || r.mode == "ownership-after" && r.bucketReads[req.URL.Path] > 1 {
			observation.CompartmentID = "ocid1.compartment.foreign"
		}
		raw, e := json.Marshal(observation, json.Deterministic(true))
		if e != nil {
			t.Error(e)
		}
		w.Write(raw)
		return
	}
	raw, ok := r.f.objects[req.URL.Path]
	if !ok || r.mode == "missing" {
		http.NotFound(w, req)
		return
	}
	if r.mode == "redirect" {
		http.Redirect(w, req, "/unexpected", http.StatusFound)
		return
	}
	if r.mode == "wrong-host" {
		for path, other := range r.f.objects {
			if path != req.URL.Path {
				raw = other
				break
			}
		}
	}
	if r.mode == "altered" {
		raw = bytes.Clone(raw)
		raw[len(raw)-2] = '0'
	}
	if r.mode == "future" && strings.HasSuffix(req.URL.Path, "/gru-one.json") {
		raw = r.f.future
	}
	size := len(raw)
	if r.mode == "oversize" {
		size = controltransition.PinReceiptMaximumBytes + 1
	}
	if r.mode == "truncated" {
		size++
	}
	digest := controltransition.Digest(raw)
	if r.mode == "metadata" {
		digest = strings.Repeat("f", 64)
	}
	w.Header().Set("Content-Length", fmt.Sprint(size))
	w.Header().Set("Etag", "receipt-etag")
	w.Header().Set("opc-meta-terrascale-sha256", digest)
	w.Write(raw)
}

func TestReadPlanPinsUsesRegionalHTTPAndRequiresCompleteUnchangedEvidence(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := provider.NewInstancePrincipalSigner("ST$test-only", key)
	if e != nil {
		t.Fatal(e)
	}
	for _, separate := range []bool{false, true} {
		t.Run(fmt.Sprint("separate-gru-", separate), func(t *testing.T) {
			f := newReceiptFixture(t, separate)
			remote := &remoteFixture{f: f}
			remote.set("")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { remote.serve(t, w, r) }))
			defer server.Close()
			endpoint, e := url.Parse(server.URL)
			if e != nil {
				t.Fatal(e)
			}
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				copy := r.Clone(r.Context())
				copy.URL = r.URL.Clone()
				copy.URL.Scheme = endpoint.Scheme
				copy.URL.Host = endpoint.Host
				return http.DefaultTransport.RoundTrip(copy)
			})}
			transports := map[string]*provider.OCIHTTPTransport{}
			for _, d := range f.p.Destinations {
				host, ok := provider.OCIServiceHost(provider.OCIServiceObjectStorage, d.Objects.OCIRegion)
				if !ok {
					t.Fatal("invalid region")
				}
				cfg, e := provider.NewOCIServiceTransportConfig(provider.OCIServiceObjectStorage, d.Objects.OCIRegion, "https://"+host)
				if e != nil {
					t.Fatal(e)
				}
				cfg.MaxRetries = 0
				transport, e := provider.NewOCIHTTPTransport(cfg, client, signer)
				if e != nil {
					t.Fatal(e)
				}
				transports[d.Region] = transport
			}
			proof, e := ReadPlanPins(t.Context(), f.plan, transports)
			if e != nil {
				t.Fatal(e)
			}
			digests, e := proof.ReceiptDigests(time.Now())
			if e != nil || !slices.Equal(digests, f.digests) {
				t.Fatal("lost remote receipt ordering", e)
			}
			if _, e := proof.ReceiptDigests(f.p.ExpiresAt); e == nil {
				t.Fatal("expired plan receipts remained live")
			}
			// Exercise the real command composition against the same local HTTP
			// server. Production Run supplies no transport override.
			dir := t.TempDir()
			write := func(name string, raw []byte) string {
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				return path
			}
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			keyBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
			keyPath := write("oci.pem", keyBytes)
			clear(der)
			clear(keyBytes)
			input := commandInput{OwnerPublicKeyFile: write("owner.pem", []byte(f.ownerPublic)), SignedPlanFile: write("plan.json", f.signedPlan), OCIKeyID: "ST$test-only", OCIPrivateKeyFile: keyPath}
			inputRaw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			inputPath := write("input.json", inputRaw)
			var output bytes.Buffer
			if err := run(t.Context(), inputPath, &output, client); err != nil {
				t.Fatal("command composition failed", err)
			}
			var summary struct {
				Status        string    `json:"status"`
				PlanSHA256    string    `json:"planSha256"`
				ReceiptSHA256 []string  `json:"receiptSha256"`
				CheckedAt     time.Time `json:"checkedAt"`
			}
			if err := json.Unmarshal(output.Bytes(), &summary, json.RejectUnknownMembers(true)); err != nil || summary.Status != "plan-pins-verified" || summary.PlanSHA256 != f.plan.Digest() || !slices.Equal(summary.ReceiptSHA256, f.digests) {
				t.Fatal("command lost verified evidence", err)
			}
			for name, raw := range map[string][]byte{
				"duplicate": bytes.Replace(inputRaw, []byte(`"ociKeyId":`), []byte(`"ociKeyId":"ignored","ociKeyId":`), 1),
				"case":      bytes.Replace(inputRaw, []byte(`"ociKeyId":`), []byte(`"OciKeyId":`), 1),
				"unknown":   append([]byte(`{"unknown":true,`), inputRaw[1:]...),
			} {
				t.Run("input-"+name, func(t *testing.T) {
					remote.set("")
					write("input.json", raw)
					output.Reset()
					if err := run(t.Context(), inputPath, &output, client); err == nil || output.Len() != 0 {
						t.Fatal("invalid command input accepted", err)
					}
					remote.mu.Lock()
					defer remote.mu.Unlock()
					if len(remote.calls) != 0 {
						t.Fatal("invalid input made requests")
					}
				})
			}
			write("input.json", inputRaw)
			remote.set("missing")
			output.Reset()
			if err := run(t.Context(), inputPath, &output, client); err == nil || output.Len() != 0 {
				t.Fatal("partial command emitted success", err)
			}
			remote.set("")
			if err := run(t.Context(), inputPath, shortWriter{}, client); err == nil {
				t.Fatal("short command output accepted")
			}
			for _, mode := range []string{"missing", "ownership", "ownership-after", "wrong-host", "altered", "metadata", "oversize", "truncated", "future", "redirect"} {
				t.Run(mode, func(t *testing.T) {
					remote.set(mode)
					proof, e := ReadPlanPins(t.Context(), f.plan, transports)
					if e == nil {
						t.Fatal("invalid remote receipts verified")
					}
					if _, e := proof.ReceiptDigests(time.Now()); e == nil {
						t.Fatal("failed collection returned verified proof")
					}
					remote.mu.Lock()
					defer remote.mu.Unlock()
					for _, call := range remote.calls {
						if strings.Contains(call, "/unexpected") {
							t.Fatal("redirect followed")
						}
					}
				})
			}
			remote.set("")
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, e := ReadPlanPins(ctx, f.plan, transports); e == nil {
				t.Fatal("canceled read accepted")
			}
			wrong := map[string]*provider.OCIHTTPTransport{"gru": transports["gru"], "sfo": transports["gru"], "fra": transports["fra"]}
			if _, e := ReadPlanPins(t.Context(), f.plan, wrong); e == nil {
				t.Fatal("foreign regional transport accepted")
			}
			remote.mu.Lock()
			defer remote.mu.Unlock()
			if len(remote.calls) != 0 {
				t.Fatal("invalid scope made HTTP requests")
			}
		})
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
