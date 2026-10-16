package release

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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// The signer crosses the OCI HTTP boundary and a persistent filesystem; no
// live credentials, OCI resources or in-memory storage substitute are used.
func TestSequenceSignerHTTPDurableMigrationAndConcurrentProducers(t *testing.T) {
	directory := t.TempDir()
	var lock sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unsigned OCI request", 401)
			return
		}
		sum := sha256.Sum256([]byte(r.URL.Path))
		name := filepath.Join(directory, hex.EncodeToString(sum[:]))
		lock.Lock()
		defer lock.Unlock()
		current, err := os.ReadFile(name)
		found := err == nil
		digest := sha256.Sum256(current)
		etag := fmt.Sprintf(`"%x"`, digest)
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
			if r.Header.Get("If-Match") == "" && r.Header.Get("If-None-Match") == "" {
				http.Error(w, "missing CAS", 400)
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if err := os.WriteFile(name, body, 0600); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.WriteHeader(200)
		default:
			w.WriteHeader(405)
		}
	}))
	defer server.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	newLocation := func() SequenceLocation {
		client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(common.NewRawConfigurationProvider("tenancy", "user", "sa-saopaulo-1", "fingerprint", string(keyPEM), nil))
		if err != nil {
			t.Fatal(err)
		}
		client.Host = server.URL
		client.HTTPClient = sequenceHTTPClient{server}
		policy := common.NoRetryPolicy()
		client.SetCustomClientConfiguration(common.CustomClientConfiguration{RetryPolicy: &policy})
		return SequenceLocation{Client: client, Namespace: "ns", Bucket: "gru-1-head"}
	}
	rootPublic, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, _ := trust.ParseKeyring(rootPublic)
	keyID, _ := trust.KeyID(public)
	encoded, _ := trust.EncodeDelegatedPublicKey(public)
	now := time.Now().UTC().Truncate(time.Second)
	migration := SequenceMigration{Schema: SequenceMigrationSchema, Namespace: "ns", Bucket: "gru-1-head", Region: "GRU", Role: "orchestrator", Environment: "production", SequenceFloor: 900, SignerKeyID: keyID, SignerPublicKey: encoded}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		migration.Regions = append(migration.Regions, SequenceFloor{Cell: cell, RunNumber: 900, IssuedAt: now, EvidenceSHA256: strings.Repeat("a", 64)})
	}
	envelope, err := SignSequenceMigration(migration, now, root)
	if err != nil {
		t.Fatal(err)
	}
	identity := SequenceIdentity{Role: "orchestrator", Environment: "production", SourceRevision: strings.Repeat("b", 40), ManifestSHA256: strings.Repeat("c", 64)}
	location := newLocation()
	if _, err := location.Allocate(t.Context(), identity, roots, signer); err != ErrSequenceMigrationRequired {
		t.Fatalf("unsigned initialization: %v", err)
	}
	var importers sync.WaitGroup
	importErrors := make(chan error, 8)
	for range 8 {
		importers.Go(func() {
			importErrors <- newLocation().ImportMigration(t.Context(), envelope, roots, identity.Role, identity.Environment, now)
		})
	}
	importers.Wait()
	close(importErrors)
	for err := range importErrors {
		if err != nil {
			t.Fatal(err)
		}
	}
	first, firstEvidence, err := location.AllocateWithEvidence(t.Context(), identity, roots, signer)
	if err != nil || first != 901 {
		t.Fatalf("first allocation %d: %v", first, err)
	}
	retry, retryEvidence, err := newLocation().AllocateWithEvidence(t.Context(), identity, roots, signer)
	if err != nil || retry != first || !bytes.Equal(firstEvidence, retryEvidence) {
		t.Fatalf("restart lost reservation %d: %v", retry, err)
	}
	var workers sync.WaitGroup
	sequences := make(chan uint64, 8)
	failures := make(chan error, 8)
	for index := range 8 {
		workers.Go(func() {
			candidate := identity
			candidate.ManifestSHA256 = fmt.Sprintf("%064x", index+1)
			sequence, evidence, err := newLocation().AllocateWithEvidence(t.Context(), candidate, roots, signer)
			if err != nil {
				failures <- err
				return
			}
			head, err := verifySequenceHead(evidence, roots, identity.Role, identity.Environment)
			if err != nil || head.Sequence != sequence || head.Identity != candidate {
				failures <- fmt.Errorf("winning reservation differs from returned allocation %d: %v", sequence, err)
				return
			}
			sequences <- sequence
		})
	}
	workers.Wait()
	close(sequences)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	seen := map[uint64]bool{}
	for sequence := range sequences {
		if sequence <= first || seen[sequence] {
			t.Errorf("duplicate or stale allocation %d", sequence)
		}
		seen[sequence] = true
	}
	if len(seen) != 8 {
		t.Fatalf("allocated %d sequences", len(seen))
	}
	retained, err := verifySequenceHead(firstEvidence, roots, identity.Role, identity.Environment)
	if err != nil || retained.Sequence != first || retained.Identity != identity {
		t.Fatalf("later allocations invalidated historical immutable family: %+v %v", retained, err)
	}
	// Immutable evidence must survive both SDK-client restart and head advancement.
	recovered, err := newLocation().retainReservation(t.Context(), retained, roots)
	if err != nil || !bytes.Equal(recovered, firstEvidence) {
		t.Fatalf("immutable allocation changed after restart: %v", err)
	}
	conflicting := retained
	conflicting.Identity.ManifestSHA256 = strings.Repeat("e", 64)
	payload, err := trust.EncodePayload(sequenceReservation{Sequence: conflicting.Sequence, Identity: conflicting.Identity})
	if err != nil {
		t.Fatal(err)
	}
	conflicting.Reservation, err = trust.Sign(payload, sequenceReservationScope(identity.Role, identity.Environment), now, now.Add(MaxReceiptLifetime), signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newLocation().retainReservation(t.Context(), conflicting, roots); err == nil {
		t.Fatal("different signed family overwrote immutable winning reservation")
	}

	if err := location.ImportMigration(t.Context(), envelope, roots, identity.Role, identity.Environment, now); err != nil {
		t.Fatal(err)
	}
	if err := location.ImportMigration(t.Context(), envelope, roots, identity.Role, identity.Environment, now.Add(2*MaxSequenceMigrationLifetime)); err != nil {
		t.Fatalf("durable imported migration expired: %v", err)
	}
	alternate := location
	alternate.Namespace = "other"
	if err := alternate.ImportMigration(t.Context(), envelope, roots, identity.Role, identity.Environment, now); err == nil {
		t.Fatal("migration initialized a second allocator location")
	}
	candidate := identity
	candidate.ManifestSHA256 = strings.Repeat("d", 64)
	if sequence, err := newLocation().Allocate(t.Context(), candidate, roots, signer); err != nil || sequence != 910 {
		t.Fatalf("migration retry erased floor %d: %v", sequence, err)
	}
	_, otherSigner, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := location.Allocate(t.Context(), candidate, roots, otherSigner); err == nil {
		t.Fatal("unapproved signer allocated")
	}
	verified, err := VerifySequenceMigrationHistorical(envelope, roots, identity.Role, identity.Environment)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.AdmitsLegacyFloor("GRU", 900, now) || verified.AdmitsLegacyFloor("GRU", 901, now) || verified.AdmitsLegacyFloor("SFO", 0, now.Add(time.Second)) {
		t.Fatal("migration erased a retained floor")
	}
	// Unsigned head edits must fail even when they keep a plausible floor.
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		wire, _ := os.ReadFile(path)
		var head sequenceHead
		if json.Unmarshal(wire, &head) == nil {
			head.Sequence++
			corrupt, _ := json.Marshal(head)
			if err := os.WriteFile(path, corrupt, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := location.Allocate(t.Context(), candidate, roots, signer); err == nil {
		t.Fatal("unsigned head mutation accepted")
	}
	rootAsSigner := migration
	rootAsSigner.SignerKeyID, _ = trust.KeyID(rootPublic)
	rootAsSigner.SignerPublicKey, _ = trust.EncodeDelegatedPublicKey(rootPublic)
	if _, err := SignSequenceMigration(rootAsSigner, now, root); err == nil {
		t.Fatal("offline root became online sequence signer")
	}
	incomplete := migration
	incomplete.Regions = incomplete.Regions[:2]
	if _, err := SignSequenceMigration(incomplete, now, root); err == nil {
		t.Fatal("incomplete regional migration accepted")
	}
	expired, _ := SignSequenceMigration(migration, now.Add(-2*MaxSequenceMigrationLifetime), root)
	if err := location.ImportMigration(t.Context(), expired, roots, identity.Role, identity.Environment, now); err == nil {
		t.Fatal("expired migration imported")
	}
}

type sequenceHTTPClient struct{ server *httptest.Server }

func (client sequenceHTTPClient) Do(request *http.Request) (*http.Response, error) {
	cloned := request.Clone(request.Context())
	address := *request.URL
	cloned.URL = &address
	cloned.URL.Scheme = "http"
	cloned.URL.Host = strings.TrimPrefix(client.server.URL, "http://")
	return client.server.Client().Do(cloned)
}
