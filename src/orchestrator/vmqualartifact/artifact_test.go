package vmqualartifact
import (
 "crypto/tls"
 "crypto/x509"
 "net/http"
 "net/http/httptest"
 "testing"
 "time"
)
const artifactReleaseHostname = "releases.terrascale.test"
func TestArtifactCertificateRequiresGeneratedCAAndReleaseSAN(t *testing.T) {
	now := time.Now().UTC()
	certificate, caPEM, err := GenerateCertificate(artifactReleaseHostname, now)
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

func TestArtifactRoutesAreExact(t *testing.T) {
	artifactPath, signaturePath := ReleasePaths("orchestrator", "v1.2.3")
	resources := map[string][]byte{artifactPath: []byte("artifact"), signaturePath: []byte("signature")}
	handler := Handler(artifactReleaseHostname, 8443, resources)
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
