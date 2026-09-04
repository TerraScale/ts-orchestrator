//go:build sandboxvm

package vmqual

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
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
	signatureFile := []byte("raw signature file")
	publicKey := make([]byte, 32)
	manifest := []byte("manifest")
	ca := []byte("ca")
	services := &qualificationRuntimeServices{
		artifacts: []guestArtifactInput{{binary: binary, signature: signature, signatureFile: signatureFile}},
		publicKey: publicKey, manifest: manifest, caCertificate: ca,
		resources: map[string][]byte{"/artifact": binary},
	}
	if err := services.Close(nil); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"binary": binary, "signature": signature, "signatureFile": signatureFile, "publicKey": publicKey, "manifest": manifest, "ca": ca} {
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
