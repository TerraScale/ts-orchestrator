//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

func TestArtifactCertificateRequiresGeneratedCAAndReleaseSAN(t *testing.T) {
	now := time.Now().UTC()
	certificate, caPEM, err := generateArtifactCertificate(now)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.Leaf == nil {
		t.Fatal("generated certificate has no parsed leaf")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("generated CA is not parseable")
	}
	if _, err := certificate.Leaf.Verify(x509.VerifyOptions{DNSName: artifactReleaseHostname, Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("release certificate did not verify: %v", err)
	}
	if _, err := certificate.Leaf.Verify(x509.VerifyOptions{DNSName: "localhost", Roots: roots, CurrentTime: now}); err == nil {
		t.Fatal("release certificate verified for an unplanned DNS name")
	}
	if _, err := certificate.Leaf.Verify(x509.VerifyOptions{DNSName: artifactReleaseHostname, Roots: x509.NewCertPool(), CurrentTime: now}); err == nil {
		t.Fatal("release certificate verified without its generated CA")
	}
}

func TestDesiredHostManifestAndArtifactRoutesAreExact(t *testing.T) {
	artifacts := []guestArtifactInput{
		{manifest: vmimage.GuestArtifact{Component: "orchestrator", Version: "v1.2.3", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		{manifest: vmimage.GuestArtifact{Component: "terrabase", Version: "v4.5.6", SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
	}
	manifestData, err := desiredHostManifest(artifacts, 8443)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := hostagent.ParseHostManifest(manifestData)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Components) != 2 || manifest.Components[0].Name != "orchestrator" || manifest.Components[1].Name != "terrabase" {
		t.Fatalf("manifest components = %+v", manifest.Components)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != string(manifestData) {
		t.Fatalf("manifest is not canonical: %s", manifestData)
	}

	artifactPath, signaturePath := releasePaths("orchestrator", "v1.2.3")
	services := &qualificationRuntimeServices{resources: map[string][]byte{artifactPath: []byte("artifact"), signaturePath: []byte("signature")}}
	handler := services.artifactHandler(8443)
	request := httptest.NewRequest(http.MethodGet, "https://"+artifactReleaseHostname+":8443"+artifactPath, nil)
	request.TLS = &tls.ConnectionState{}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "artifact" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("artifact response = %d %q", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "https://localhost:8443"+artifactPath, nil)
	request.TLS = &tls.ConnectionState{}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("wrong Host response = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "https://"+artifactReleaseHostname+":8443"+artifactPath+"?mirror=true", nil)
	request.TLS = &tls.ConnectionState{}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("query-bearing route response = %d", response.Code)
	}
}

func TestQualificationServicesCloseZerosArtifactMaterial(t *testing.T) {
	binary := []byte("verified artifact bytes")
	signature := make([]byte, 64)
	publicKey := make([]byte, 32)
	manifest := []byte("manifest")
	ca := []byte("ca")
	services := &qualificationRuntimeServices{
		artifacts: []guestArtifactInput{{binary: binary, signature: signature}},
		publicKey: publicKey, manifest: manifest, caCertificate: ca,
		resources: map[string][]byte{"/artifact": binary},
	}
	if err := services.Close(nil); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"binary": binary, "signature": signature, "publicKey": publicKey, "manifest": manifest, "ca": ca} {
		for _, value := range data {
			if value != 0 {
				t.Fatalf("%s was not zeroed", name)
			}
		}
	}
	if err := services.VerifyStopped(); err != nil {
		t.Fatal(err)
	}
}

func TestQualificationServicesCloseRetainsStoreForRetry(t *testing.T) {
	services := &qualificationRuntimeServices{stateRoot: t.TempDir(), plan: vmnet.NetworkPlan{RunID: "11111111111141118111111111111111"}}
	path, err := services.prepareNATSStore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if services.natsStoreParent != nil {
			_ = services.natsStoreParent.Close()
		}
	})
	if len(services.natsStoreRunID) != 36 || services.natsStoreRunID == services.plan.RunID {
		t.Fatal("direct fixture did not allocate separate cleanup UUID")
	}
	markerPath := filepath.Join(path, ".vmqual-owner.json")
	marker, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	dataPath := filepath.Join(path, "stored-message")
	if err := os.WriteFile(dataPath, []byte("retained data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := services.Close(nil); err == nil {
		t.Fatal("mismatched ownership accepted")
	}
	if services.natsStoreParent == nil || services.natsStoreName == "" || services.VerifyStopped() == nil {
		t.Fatal("failed removal discarded cleanup obligation")
	}
	if data, err := os.ReadFile(dataPath); err != nil || string(data) != "retained data" {
		t.Fatalf("failed removal altered data: %v", err)
	}
	if err := os.WriteFile(markerPath, marker, 0600); err != nil {
		t.Fatal(err)
	}
	if err := services.Close(nil); err != nil {
		t.Fatal(err)
	}
	if err := services.VerifyStopped(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retry retained store")
	}
	if err := services.Close(nil); err != nil {
		t.Fatal(err)
	}
}

// Capture the real Stack.Apply context so the regression exercises its private
// run identity and durable fixture registrar rather than manufacturing either.
type fixtureStoreIdentityNetwork struct {
	services *qualificationRuntimeServices
	inspect  func(context.Context) error
}

func (network *fixtureStoreIdentityNetwork) Apply(ctx context.Context) error {
	return network.inspect(ctx)
}
func (network *fixtureStoreIdentityNetwork) Cleanup(ctx context.Context) error {
	return network.services.Close(ctx)
}

type fixtureStoreNoVMFactory struct{}

func (fixtureStoreNoVMFactory) Create(context.Context, vmqual.Guest) (vmqual.VM, error) {
	return nil, errors.New("unexpected VM creation")
}

func TestQualificationStoreUsesStackUUIDInsteadOfNetworkID(t *testing.T) {
	root := t.TempDir()
	const stackID = "11111111-1111-4111-8111-111111111111"
	const networkID = "22222222222242228222222222222222"
	services := &qualificationRuntimeServices{stateRoot: filepath.Join(root, "state"), plan: vmnet.NetworkPlan{RunID: networkID}}
	stop := errors.New("stop after fixture store regression")
	var created string
	network := &fixtureStoreIdentityNetwork{services: services}
	network.inspect = func(ctx context.Context) error {
		var err error
		created, err = services.prepareNATSStore(ctx)
		if err != nil {
			return err
		}
		if services.natsStoreRunID != stackID || filepath.Base(created) != "nats-fixture-"+stackID || services.plan.RunID != networkID {
			return errors.New("store conflates network and cleanup identity")
		}
		data, err := os.ReadFile(filepath.Join(root, "journal.json"))
		if err != nil {
			return err
		}
		var journal vmqual.Journal
		if err := json.Unmarshal(data, &journal); err != nil {
			return err
		}
		if journal.RunID != stackID || journal.NATSFixtureStore != created {
			return errors.New("store ownership differs from durable stack journal")
		}
		return stop
	}
	stack, err := vmqual.NewStack(vmqual.StackConfig{RunID: stackID, ResourceRoot: root, StateRoot: services.stateRoot, JournalPath: filepath.Join(root, "journal.json"), Network: network, VMFactory: fixtureStoreNoVMFactory{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := stack.StartBootstrap(context.Background()); !errors.Is(err, stop) {
		t.Fatalf("fixture setup: %v", err)
	}
	if created == "" {
		t.Fatal("fixture store was not created")
	}
	if _, err := os.Lstat(created); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stack cleanup retained fixture store")
	}
	if services.natsStoreRunID != "" || services.natsStoreParent != nil {
		t.Fatal("stack cleanup retained store identity")
	}
}
