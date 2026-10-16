package bootstrapmaterial_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestFunctionClientTLSAuthenticatesOnlyItsTenantAndFunction(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	material := generationtest.New(t, now)
	issuer := loadIssuer(t, material)
	tenant := entityid.Derive("tenant", t.Name())
	proof := functionTLSProof(t, tenant, "echo", "GRU", "production", now, 2*time.Hour)
	serverPEM, serverKey, _, err := issuer.IssueFunctionTLS(proof)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(serverKey)
	serverPair, err := tls.X509KeyPair(serverPEM, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	serverLeaf := serverPair.Leaf
	if !slices.Equal(serverLeaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Fatal("server certificate gained client authentication authority")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(material.Files["ca.pem"]) {
		t.Fatal("fixture CA is invalid")
	}
	expectedURI := "spiffe://terrascale.tech/tenants/" + tenant + "/functions/echo"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverPair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || len(state.PeerCertificates[0].URIs) != 1 || state.PeerCertificates[0].URIs[0].String() != expectedURI {
				return errors.New("client does not belong to this tenant and function")
			}
			return nil
		}}
	server.StartTLS()
	t.Cleanup(server.Close)
	for _, test := range []struct {
		name  string
		proof release.VerifiedFunction
		allow bool
	}{
		{"same tenant and function", proof, true},
		{"another tenant", functionTLSProof(t, entityid.New(), "echo", "GRU", "production", now, time.Hour), false},
		{"another function", functionTLSProof(t, tenant, "other", "GRU", "production", now, time.Hour), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			certPEM, keyPEM, issuerPEM, err := issuer.IssueFunctionClientTLS(test.proof)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(keyPEM)
			if !bytes.Equal(issuerPEM, material.Files["controller-tls-issuer-cert.pem"]) {
				t.Fatal("returned public issuer differs from the loaded generation")
			}
			pair, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				t.Fatal(err)
			}
			leaf := pair.Leaf
			uri := "spiffe://terrascale.tech/tenants/" + test.proof.Claim().TenantID + "/functions/" + test.proof.Claim().FunctionID
			if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) || len(leaf.URIs) != 1 || leaf.URIs[0].String() != uri || len(leaf.DNSNames) != 0 || leaf.IsCA {
				t.Fatalf("client certificate is not restricted to its function: %+v", leaf)
			}
			if leaf.NotAfter.After(time.Now().Add(time.Hour)) || leaf.NotAfter.After(test.proof.ExpiresAt()) || leaf.NotAfter.After(material.ControllerIssuer.Certificate.NotAfter) {
				t.Fatal("client certificate outlives its admitted authority")
			}
			transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool,
				ServerName: serverLeaf.DNSNames[0], Certificates: []tls.Certificate{pair}}}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				if test.allow {
					t.Fatalf("same-scope mTLS request denied: %v", err)
				}
				return
			}
			defer response.Body.Close()
			if !test.allow || response.StatusCode != http.StatusNoContent {
				t.Fatalf("mTLS authorization: allowed=%t, status=%d", test.allow, response.StatusCode)
			}
		})
	}
	t.Run("expiry and generation scope", func(t *testing.T) {
		for name, rejected := range map[string]release.VerifiedFunction{
			"unverified":  release.VerifiedFunction{},
			"expired":     functionTLSProof(t, tenant, "echo", "GRU", "production", now.Add(-2*time.Hour), time.Hour),
			"cell":        functionTLSProof(t, tenant, "echo", "SFO", "production", now, time.Hour),
			"environment": functionTLSProof(t, tenant, "echo", "GRU", "canary", now, time.Hour),
		} {
			cert, key, _, err := issuer.IssueFunctionClientTLS(rejected)
			clear(key)
			if err == nil || len(cert) != 0 || len(key) != 0 {
				t.Errorf("%s proof received a client identity: %v", name, err)
			}
		}
		short := functionTLSProof(t, tenant, "echo", "GRU", "production", now, 15*time.Minute)
		cert, key, _, err := issuer.IssueFunctionClientTLS(short)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(key)
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil || !pair.Leaf.NotAfter.Equal(short.ExpiresAt()) {
			t.Fatalf("short function expiry did not bound client certificate: %v", err)
		}
		for _, expiry := range []time.Time{now.Add(10 * time.Minute), now.Add(-time.Minute)} {
			_, issuerCert, issuerKey := generationtest.Certificate(t, generationtest.ControllerIssuer(now.Add(-time.Hour), expiry), &material.CA)
			bounded := loadIssuer(t, material.With(map[string][]byte{"controller-tls-issuer-cert.pem": issuerCert, "controller-tls-issuer-key.pem": issuerKey}))
			cert, key, _, err := bounded.IssueFunctionClientTLS(proof)
			defer clear(key)
			if expiry.Before(now) {
				if err == nil || len(cert) != 0 || len(key) != 0 {
					t.Fatal("expired controller issuer issued a client identity")
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			pair, err := tls.X509KeyPair(cert, key)
			if err != nil || !pair.Leaf.NotAfter.Equal(expiry) {
				t.Fatalf("controller issuer expiry did not bound client certificate: %v", err)
			}
		}
	})
}

func functionTLSProof(t *testing.T, tenant, function, cell, environment string, now time.Time, validFor time.Duration) release.VerifiedFunction {
	t.Helper()
	module := []byte("\x00asm\x01\x00\x00\x00")
	digest := sha256.Sum256(module)
	claim := release.FunctionClaim{Schema: release.FunctionSchema, ABI: release.FunctionABI, TenantID: tenant, FunctionID: function, Revision: "first",
		Digest: hex.EncodeToString(digest[:]), Bytes: int64(len(module)), Environment: environment, Cell: cell, Sequence: 1}
	root, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(leaf)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(leaf)
	if err != nil {
		t.Fatal(err)
	}
	scope := release.FunctionScope(claim)
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment,
			Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, now.Add(-time.Minute), now.Add(validFor+time.Hour), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := release.SignFunctionClaim(claim, module, delegation, roots, key, now, validFor)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := release.VerifyFunctionCurrent(wire, delegationWire, module, roots, release.FunctionExpectation{Environment: environment, Cell: cell,
		TenantID: tenant, FunctionID: function, Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: claim.Sequence}, now)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
