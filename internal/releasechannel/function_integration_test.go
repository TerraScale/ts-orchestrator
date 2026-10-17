package releasechannel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestFunctionChannelSDKPublicationPreservesTenantsAndRecoversLostReplies(t *testing.T) {
	fixture := newFunctionChannelFixture(t)
	location, backend := functionObjectEndpoint(t)
	first := fixture.proof(t, entityid.New(), "echo", 1, "first")
	other := fixture.proof(t, entityid.New(), "echo", 1, "other")
	backend.dropModule, backend.dropChannel = true, true
	if err := PublishFunction(t.Context(), location, first); err != nil {
		t.Fatalf("lost committed replies: %v", err)
	}
	if err := PublishFunction(t.Context(), location, first); err != nil {
		t.Fatalf("same provenance retry: %v", err)
	}
	channel, found, err := ReadFunctionChannel(t.Context(), location)
	if err != nil || !found || len(channel.Entries) != 1 {
		t.Fatalf("initial channel: %+v %v", channel, err)
	}
	verifyFunctionChannelEntry(t, location, channel.Entries[0], fixture.roots, first.Claim().Sequence)
	otherEntry := FunctionRelease{Envelope: other.Envelope(), Delegation: other.Delegation()}
	concurrent := FunctionChannel{Schema: FunctionChannelSchema, Entries: []FunctionRelease{channel.Entries[0], otherEntry}}
	slices.SortFunc(concurrent.Entries, func(a, b FunctionRelease) int {
		left, _ := a.Claim()
		right, _ := b.Claim()
		return strings.Compare(functionReleaseKey(left), functionReleaseKey(right))
	})
	concurrentWire, err := json.Marshal(concurrent)
	if err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	backend.concurrent = concurrentWire
	backend.objects[FunctionModuleObject(other.Claim().Digest)] = functionObject{data: other.Module(), version: 1}
	backend.mu.Unlock()
	advanced := fixture.proof(t, first.Claim().TenantID, "echo", 2, "second")
	if err := PublishFunction(t.Context(), location, advanced); err != nil {
		t.Fatalf("concurrent tenant CAS: %v", err)
	}
	channel, _, err = ReadFunctionChannel(t.Context(), location)
	if err != nil || len(channel.Entries) != 2 {
		t.Fatalf("tenant lost after CAS: %+v %v", channel, err)
	}
	seen := map[string]uint64{}
	for _, entry := range channel.Entries {
		claim, err := entry.Claim()
		if err != nil {
			t.Fatal(err)
		}
		seen[claim.TenantID] = claim.Sequence
		verifyFunctionChannelEntry(t, location, entry, fixture.roots, claim.Sequence)
	}
	if seen[first.Claim().TenantID] != 2 || seen[other.Claim().TenantID] != 1 {
		t.Fatal("CAS did not preserve independent tenant release floors")
	}
	if err := PublishFunction(t.Context(), location, first); !errors.Is(err, ErrStale) {
		t.Fatalf("stale sequence accepted: %v", err)
	}
	equivocation := fixture.proof(t, first.Claim().TenantID, "echo", 2, "different")
	if err := PublishFunction(t.Context(), location, equivocation); !errors.Is(err, ErrInvalid) {
		t.Fatalf("same-sequence equivocation accepted: %v", err)
	}
	if err := PublishFunction(t.Context(), location, release.VerifiedFunction{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsealed publication accepted: %v", err)
	}
	foreign := location
	foreign.Bucket = "sfo-1-head"
	if err := PublishFunction(t.Context(), foreign, advanced); !errors.Is(err, ErrInvalid) {
		t.Fatalf("foreign region bucket accepted: %v", err)
	}
	backend.mu.Lock()
	backend.objects[FunctionModuleObject(advanced.Claim().Digest)] = functionObject{data: []byte("tampered module"), version: 1}
	backend.mu.Unlock()
	if _, err := ReadFunctionModule(t.Context(), location, advanced.Claim().Digest); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered module accepted: %v", err)
	}
	for i, entry := range channel.Entries {
		claim, _ := entry.Claim()
		if claim.TenantID != first.Claim().TenantID {
			continue
		}
		envelope, err := trust.DecodeEnvelope(entry.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		if envelope.Signature[0] == 'A' {
			envelope.Signature = "B" + envelope.Signature[1:]
		} else {
			envelope.Signature = "A" + envelope.Signature[1:]
		}
		channel.Entries[i].Envelope, err = trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
	}
	wire, err := json.Marshal(channel)
	if err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	backend.objects[FunctionChannelObject] = functionObject{data: wire, version: 99}
	backend.objects[FunctionModuleObject(advanced.Claim().Digest)] = functionObject{data: advanced.Module(), version: 2}
	backend.mu.Unlock()
	tampered, _, err := ReadFunctionChannel(t.Context(), location)
	if err == nil {
		for _, entry := range tampered.Entries {
			claim, _ := entry.Claim()
			if claim.TenantID != first.Claim().TenantID {
				continue
			}
			module, err := ReadFunctionModule(t.Context(), location, claim.Digest)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := release.VerifyFunctionCurrent(entry.Envelope, entry.Delegation, module, fixture.roots, functionExpected(claim, 2), time.Now()); err == nil {
				t.Fatal("unsigned channel authorized a tampered signed receipt")
			}
		}
	}
}

func TestFunctionChannelRejectsOversizedSourceAndCrossNamespaceModules(t *testing.T) {
	fixture := newFunctionChannelFixture(t)
	location, backend := functionObjectEndpoint(t)
	proof := fixture.proof(t, entityid.New(), "echo", 1, "first")
	backend.mu.Lock()
	backend.objects[ServiceBinaryObject("terrabase", proof.Claim().Digest)] = functionObject{data: proof.Module(), version: 1}
	backend.mu.Unlock()
	if _, err := ReadFunctionModule(t.Context(), location, proof.Claim().Digest); err == nil {
		t.Fatal("native service artifact substituted for function module")
	}
	backend.mu.Lock()
	backend.objects[FunctionModuleObject(proof.Claim().Digest)] = functionObject{data: bytes.Repeat([]byte{'x'}, release.MaxFunctionModuleBytes+1), version: 1}
	backend.mu.Unlock()
	if _, err := ReadFunctionModule(t.Context(), location, proof.Claim().Digest); err == nil {
		t.Fatal("oversized module accepted")
	}
	backend.mu.Lock()
	backend.objects[FunctionChannelObject] = functionObject{data: bytes.Repeat([]byte{' '}, MaxFunctionChannelBytes+1), version: 1}
	backend.mu.Unlock()
	if _, _, err := ReadFunctionChannel(t.Context(), location); err == nil {
		t.Fatal("oversized channel accepted")
	}
	entry := FunctionRelease{Envelope: proof.Envelope(), Delegation: proof.Delegation()}
	channel := FunctionChannel{Schema: FunctionChannelSchema, Entries: []FunctionRelease{entry, entry}}
	wire, err := json.Marshal(channel)
	if err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	backend.objects[FunctionChannelObject] = functionObject{data: wire, version: 2}
	backend.mu.Unlock()
	if _, _, err := ReadFunctionChannel(t.Context(), location); err == nil {
		t.Fatal("duplicate tenant/function index entry accepted")
	}
}

func verifyFunctionChannelEntry(t *testing.T, location Location, entry FunctionRelease, roots trust.Keyring, floor uint64) {
	t.Helper()
	claim, err := entry.Claim()
	if err != nil {
		t.Fatal(err)
	}
	module, err := ReadFunctionModule(t.Context(), location, claim.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyFunctionCurrent(entry.Envelope, entry.Delegation, module, roots, functionExpected(claim, floor), time.Now()); err != nil {
		t.Fatal(err)
	}
}

func functionExpected(claim release.FunctionClaim, floor uint64) release.FunctionExpectation {
	return release.FunctionExpectation{Environment: claim.Environment, Cell: claim.Cell, TenantID: claim.TenantID, FunctionID: claim.FunctionID, Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: floor}
}

type functionChannelFixture struct {
	root  ed25519.PrivateKey
	roots trust.Keyring
}

func newFunctionChannelFixture(t *testing.T) functionChannelFixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	return functionChannelFixture{root: private, roots: roots}
}

func (fixture functionChannelFixture) proof(t *testing.T, tenant, function string, sequence uint64, revision string) release.VerifiedFunction {
	t.Helper()
	module := []byte("function module " + revision)
	digest := sha256.Sum256(module)
	claim := release.FunctionClaim{Schema: release.FunctionSchema, ABI: release.FunctionABI, TenantID: tenant, FunctionID: function, Revision: revision, Digest: hex.EncodeToString(digest[:]), Bytes: int64(len(module)), Environment: "production", Cell: "GRU", Sequence: sequence}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	scope := release.FunctionScope(claim)
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded, Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, now.Add(-time.Minute), now.Add(2*time.Hour), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := release.SignFunctionClaim(claim, module, delegation, fixture.roots, private, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := release.VerifyFunctionCurrent(wire, grant, module, fixture.roots, functionExpected(claim, sequence), now)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

type functionObject struct {
	data     []byte
	version  int
	modified time.Time
}
type functionBucketBackend struct {
	mu                      sync.Mutex
	objects                 map[string]functionObject
	dropModule, dropChannel bool
	concurrent              []byte
	modifiedAt              time.Time
}

func functionObjectEndpoint(t *testing.T) (Location, *functionBucketBackend) {
	t.Helper()
	backend := &functionBucketBackend{objects: map[string]functionObject{}}
	endpoint := httptest.NewServer(http.HandlerFunc(backend.serve))
	t.Cleanup(endpoint.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..function", "ocid1.user.oc1..function", "sa-saopaulo-1", "fp", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	client.Configuration.RetryPolicy = new(common.NoRetryPolicy())
	client.Host = endpoint.URL
	return Location{Client: client, Namespace: "namespace", Bucket: "gru-1-head"}, backend
}

func (backend *functionBucketBackend) serve(w http.ResponseWriter, r *http.Request) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	_, name, ok := strings.Cut(r.URL.Path, "/o/")
	if !ok {
		http.Error(w, "route", 404)
		return
	}
	object, found := backend.objects[name]
	if r.Method == http.MethodGet {
		if !found {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"code":"ObjectNotFound","message":"absent"}`)
			return
		}
		if object.version != 0 {
			w.Header().Set("ETag", fmt.Sprint(object.version))
		}
		if !object.modified.IsZero() {
			w.Header().Set("Last-Modified", object.modified.UTC().Format(http.TimeFormat))
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(object.data)))
		_, _ = w.Write(object.data)
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method", 405)
		return
	}
	if name == FunctionChannelObject && len(backend.concurrent) > 0 {
		backend.objects[name] = functionObject{data: bytes.Clone(backend.concurrent), version: object.version + 1}
		backend.concurrent = nil
		http.Error(w, "concurrent", 412)
		return
	}
	if r.Header.Get("If-None-Match") == "*" && found || r.Header.Get("If-Match") != "" && (!found || r.Header.Get("If-Match") != fmt.Sprint(object.version)) {
		http.Error(w, "changed", 412)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, release.MaxFunctionModuleBytes+1))
	if err != nil {
		http.Error(w, "read", 400)
		return
	}
	if strings.HasPrefix(name, "releases/functions/modules/") && r.Header.Get("Content-Type") != "application/wasm" {
		http.Error(w, "module type", 400)
		return
	}
	backend.objects[name] = functionObject{data: body, version: object.version + 1, modified: backend.modifiedAt}
	drop := name == FunctionChannelObject && backend.dropChannel || strings.HasPrefix(name, "releases/functions/modules/") && backend.dropModule
	if drop {
		if name == FunctionChannelObject {
			backend.dropChannel = false
		} else {
			backend.dropModule = false
		}
		connection, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = connection.Close()
		}
		return
	}
	w.Header().Set("ETag", fmt.Sprint(object.version+1))
	w.WriteHeader(http.StatusOK)
}
