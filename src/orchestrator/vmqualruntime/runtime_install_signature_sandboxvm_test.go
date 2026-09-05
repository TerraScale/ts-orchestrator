//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"context"
"terrascale.tech/orchestrator/src/orchestrator/vmqualartifact"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
)

// Exercise the actual HTTPS handler and installer together. A signature that
// the qualifier alone can decode does not prove that ts-node can install it.
func TestQualificationHTTPSReleaseInstallsThroughTSNode(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact := bytes.Repeat([]byte("signed production binary payload\n"), 32768)
	signature := ed25519.Sign(private, artifact)
	digest := sha256.Sum256(artifact)
	artifactPath, signaturePath := vmqualartifact.ReleasePaths("orchestrator", "v1")
	certificate, caPEM, err := generateArtifactCertificate(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	_, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	services := &qualificationRuntimeServices{resources: map[string][]byte{artifactPath: artifact, signaturePath: signature}}
	handler := services.artifactHandler(uint16(port))
	var requests atomic.Int64
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		handler.ServeHTTP(w, r)
	})
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA invalid")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != net.JoinHostPort(artifactReleaseHostname, portText) {
				return nil, fmt.Errorf("unexpected release authority %s", address)
			}
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	defer transport.CloseIdleConnections()
	root := filepath.Join(t.TempDir(), "install")
	installer, err := hostagent.NewInstaller(hostagent.InstallerConfig{InstallRoot: root, PublicKeyHex: hex.EncodeToString(public), Downloader: hostagent.DownloadClient{Client: &http.Client{Transport: transport, Timeout: 5 * time.Second}, AllowedHosts: []string{artifactReleaseHostname}}})
	if err != nil {
		t.Fatal(err)
	}
	base := "https://" + net.JoinHostPort(artifactReleaseHostname, portText)
	spec := hostmanifest.ComponentSpec{Name: "orchestrator", Version: "v1", ArtifactURL: base + artifactPath, SignatureURL: base + signaturePath, Sha256: hex.EncodeToString(digest[:]), User: "terrascale-orchestrator", DataVolume: "/var/lib/terrascale/orchestrator", CPUWeight: 100, MemoryMaxBytes: 128 << 20, IOWeight: 100}
	installed, err := installer.InstallContext(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(installed, "orchestrator"))
	if err != nil || !bytes.Equal(got, artifact) {
		t.Fatalf("installed artifact differs: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(installed, "orchestrator.sig"))
	if err != nil || len(raw) != ed25519.SignatureSize || !bytes.Equal(raw, signature) {
		t.Fatalf("raw signature differs: %v", err)
	}
	if _, err := installer.InstallContext(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Fatalf("requests=%d; immutable second install must not download again", requests.Load())
	}
}
