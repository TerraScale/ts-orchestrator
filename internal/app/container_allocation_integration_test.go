package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestContainerAllocationSourceIntegration(t *testing.T) {
	rootPublic, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, _ := trust.ParseKeyring(rootPublic)
	signerID, _ := trust.KeyID(public)
	signerPublic, _ := trust.EncodeDelegatedPublicKey(public)
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: "signed-namespace", Bucket: "gru-1-head", Region: "GRU", Role: "ts-auth", Environment: "production", SequenceFloor: 100, SignerKeyID: signerID, SignerPublicKey: signerPublic}
	for _, cell := range []string{"GRU", "SJC", "FRA"} {
		migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 100, EvidenceSHA256: strings.Repeat("a", 64)})
	}
	envelope, err := release.SignSequenceMigration(migration, time.Now().UTC().Add(-2*release.MaxSequenceMigrationLifetime), root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	factory, err := ociclient.New(common.NewRawConfigurationProvider("tenancy", "user", "us-sanjose-1", "fingerprint", string(keyPEM), nil), ociclient.Options{Region: "us-sanjose-1"})
	if err != nil {
		t.Fatal(err)
	}
	bundle := release.ContainerBundle{Migration: wire}
	target := release.ContainerTarget{Cell: "SJC", Role: migration.Role, Environment: migration.Environment, Architecture: "arm64"}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") == "" || r.URL.Path != "/n/signed-namespace/b/gru-1-head/o/immutable-winner" {
			http.Error(w, "wrong allocation request", http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, "retained immutable winner")
	}))
	t.Cleanup(server.Close)
	forged := migration
	forged.Namespace = "redirected-namespace"
	forgedEnvelope := envelope
	forgedEnvelope.Payload, err = trust.EncodePayload(forged)
	if err != nil {
		t.Fatal(err)
	}
	forgedWire, err := trust.EncodeEnvelope(forgedEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if location, err := currentContainerAllocations(t.Context(), factory, release.ContainerBundle{Migration: forgedWire}, roots, target); err == nil || location.Client != nil || requests.Load() != 0 {
		t.Fatal("forged migration routing selected an allocation capability or made an SDK request")
	}
	location, err := currentContainerAllocations(t.Context(), factory, bundle, roots, target)
	if err != nil {
		t.Fatal(err)
	}
	reader, ok := location.Client.(containerAllocationReader)
	if !ok || location.Namespace != migration.Namespace || location.Bucket != migration.Bucket || !strings.Contains(reader.client.Host, ".sa-saopaulo-1.") || requests.Load() != 0 {
		t.Fatal("allocation source differs from root-signed global location or read before final verification")
	}
	reader.client.Host = server.URL
	reader.client.HTTPClient = containerAllocationHTTPClient{server}
	location.Client = reader
	response, err := location.Client.GetObject(t.Context(), objectstorage.GetObjectRequest{NamespaceName: new(location.Namespace), BucketName: new(location.Bucket), ObjectName: new("immutable-winner")})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Content.Close()
	body, err := io.ReadAll(response.Content)
	if err != nil || string(body) != "retained immutable winner" || requests.Load() != 1 {
		t.Fatalf("read signed OCI allocation: %q: %v", body, err)
	}
	if _, err := location.Client.PutObject(t.Context(), objectstorage.PutObjectRequest{}); err == nil || requests.Load() != 1 {
		t.Fatal("runtime allocation source permitted a write")
	}
}

type containerAllocationHTTPClient struct{ server *httptest.Server }

func (client containerAllocationHTTPClient) Do(request *http.Request) (*http.Response, error) {
	cloned := request.Clone(request.Context())
	cloned.URL = request.URL.Clone()
	cloned.URL.Scheme = "http"
	cloned.URL.Host = strings.TrimPrefix(client.server.URL, "http://")
	return client.server.Client().Do(cloned)
}
