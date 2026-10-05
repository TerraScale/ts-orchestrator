package publicapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func originPullFixture(t *testing.T, name string) string {
	t.Helper()
	wire, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(wire)
}

func testOriginPull(t *testing.T) OriginPull {
	t.Helper()
	return OriginPull{CACertificate: originPullFixture(t, "origin-pull-test-ca.pem"), CertificateID: "test-origin-pull"}
}

// The fixture keys are fixed, public test data. These cannot be deployment CAs.
func originPullTestPEM(t *testing.T, rootEdit, leafEdit func(*x509.Certificate)) (string, string) {
	t.Helper()
	parse := func(name string) *x509.Certificate {
		block, _ := pem.Decode([]byte(originPullFixture(t, name)))
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return certificate
	}
	root, leaf := parse("origin-pull-test-ca.pem"), parse("origin-pull-test-client.pem")
	if rootEdit != nil {
		rootEdit(root)
	}
	if leafEdit != nil {
		leafEdit(leaf)
	}
	rootKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	encode := func(certificate, signer *x509.Certificate) string {
		der, err := x509.CreateCertificate(rand.Reader, certificate, signer, certificate.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	return encode(root, root), encode(leaf, root)
}

func TestOriginPullValidate(t *testing.T) {
	want := testOriginPull(t)
	if err := want.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "../unsafe", "has space", "bad?query", "bad_unicode_é"} {
		bad := want
		bad.CertificateID = id
		if err := bad.Validate(); err == nil {
			t.Errorf("accepted certificate ID %q", id)
		}
	}
	for _, ca := range []string{"", "not PEM", originPullCA, originPullFixture(t, "origin-pull-test-client.pem"), want.CACertificate + want.CACertificate} {
		bad := want
		bad.CACertificate = ca
		if err := bad.Validate(); err == nil {
			t.Error("accepted missing, shared, leaf or bundled CA")
		}
	}
	for name, edit := range map[string]func(*x509.Certificate){
		"expired":        func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Hour) },
		"future":         func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) },
		"not signing":    func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature },
		"no constraints": func(c *x509.Certificate) { c.BasicConstraintsValid = false },
	} {
		t.Run(name, func(t *testing.T) {
			bad := want
			bad.CACertificate, _ = originPullTestPEM(t, edit, nil)
			if err := bad.Validate(); err == nil {
				t.Fatal("accepted unusable root")
			}
		})
	}
	// Changing the subject without changing the issuer is not a self-signed root.
	block, _ := pem.Decode([]byte(want.CACertificate))
	root, _ := x509.ParseCertificate(block.Bytes)
	parent := *root
	root.Subject.CommonName = "TEST ONLY intermediate"
	root.RawSubject = nil
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	der, err := x509.CreateCertificate(rand.Reader, root, &parent, root.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	want.CACertificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err := want.Validate(); err == nil {
		t.Fatal("accepted a non-self-signed CA")
	}
}

func TestOriginPullRefusesUnreviewedZoneCertificateBeforeWrites(t *testing.T) {
	for name, edit := range map[string]func(*fakeCloudflare){
		"missing":               func(f *fakeCloudflare) { f.certificates = nil },
		"wrong ID":              func(f *fakeCloudflare) { f.certificates[0].ID = "unreviewed" },
		"ambiguous":             func(f *fakeCloudflare) { f.certificates = append(f.certificates, f.certificates[0]) },
		"pending":               func(f *fakeCloudflare) { f.certificates[0].Status = "pending_deployment" },
		"missing status":        func(f *fakeCloudflare) { f.certificates[0].Status = "" },
		"shared CA":             func(f *fakeCloudflare) { f.certificates[0].Certificate = originPullCA },
		"CA as client":          func(f *fakeCloudflare) { f.certificates[0].Certificate = testOriginPull(t).CACertificate },
		"foreign CA":            func(f *fakeCloudflare) { f.certificates[0].Certificate = testCA(t) },
		"no PEM":                func(f *fakeCloudflare) { f.certificates[0].Certificate = "invalid" },
		"chain instead of leaf": func(f *fakeCloudflare) { f.certificates[0].Certificate += testOriginPull(t).CACertificate },
	} {
		t.Run(name, func(t *testing.T) {
			f, cloudflare := newFakeCloudflare(t)
			edit(f)
			steps, err := cloudflare.edgeSteps(t.Context(), []string{"gru.api.terrascale.tech", "gru.auth.terrascale.tech"}, netip.MustParseAddr("203.0.113.10"), "gru-1", testOriginPull(t))
			if err == nil || len(steps) != 0 || len(f.writes) != 0 {
				t.Fatalf("steps=%d writes=%v err=%v", len(steps), f.writes, err)
			}
		})
	}
	for name, edit := range map[string]func(*x509.Certificate){
		"CA":                func(c *x509.Certificate) { c.IsCA = true },
		"no explicit usage": func(c *x509.Certificate) { c.ExtKeyUsage = nil },
		"any usage":         func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} },
		"server auth only":  func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"expired":           func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Hour) },
		"future":            func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			f, cloudflare := newFakeCloudflare(t)
			_, f.certificates[0].Certificate = originPullTestPEM(t, nil, edit)
			if _, err := cloudflare.edgeSteps(t.Context(), []string{"gru.api.terrascale.tech"}, netip.MustParseAddr("203.0.113.10"), "gru-1", testOriginPull(t)); err == nil || len(f.writes) != 0 {
				t.Fatalf("writes=%v err=%v", f.writes, err)
			}
		})
	}
}

func TestOriginPullHostnameOverrideAndUnverifiableState(t *testing.T) {
	name := "gru.api.terrascale.tech"
	for _, association := range []any{
		map[string]any{"hostname": name, "enabled": true, "cert_id": "foreign"},
		map[string]any{"hostname": name, "enabled": false},
		map[string]any{"hostname": name},
		map[string]any{"hostname": "other.example", "enabled": nil},
	} {
		f, cloudflare := newFakeCloudflare(t)
		f.hostnameOverrides[name] = association
		if _, err := cloudflare.edgeSteps(t.Context(), []string{name}, netip.MustParseAddr("203.0.113.10"), "gru-1", testOriginPull(t)); err == nil || len(f.writes) != 0 {
			t.Fatalf("accepted override %+v: writes=%v err=%v", association, f.writes, err)
		}
	}
	// An explicit null association and Cloudflare's 1553 absence both leave zone AOP in force.
	for _, association := range []any{map[string]any{"hostname": name, "enabled": nil}, nil} {
		f, cloudflare := newFakeCloudflare(t)
		if association != nil {
			f.hostnameOverrides[name] = association
		}
		if _, err := cloudflare.edgeSteps(t.Context(), []string{name}, netip.MustParseAddr("203.0.113.10"), "gru-1", testOriginPull(t)); err != nil {
			t.Fatalf("refused association %+v: %v", association, err)
		}
	}
	for _, path := range []string{"", "/settings", "/hostnames/" + name} {
		for _, status := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusInternalServerError} {
			f, cloudflare := newFakeCloudflare(t)
			f.aopErrorPath, f.aopErrorStatus = "/zones/zone/origin_tls_client_auth"+path, status
			if _, err := cloudflare.edgeSteps(t.Context(), []string{name}, netip.MustParseAddr("203.0.113.10"), "gru-1", testOriginPull(t)); err == nil || len(f.writes) != 0 {
				t.Fatalf("path=%s status=%d writes=%v err=%v", path, status, f.writes, err)
			}
		}
	}
}

func TestOriginPullRefusesForeignSigner(t *testing.T) {
	f, cloudflare := newFakeCloudflare(t)
	reviewed := testOriginPull(t)
	reviewed.CACertificate = testCA(t)
	steps, err := cloudflare.edgeSteps(t.Context(), []string{"gru.api.terrascale.tech"}, netip.MustParseAddr("203.0.113.10"), "gru-1", reviewed)
	if err == nil || !strings.Contains(err.Error(), "not directly signed") || len(steps) != 0 || len(f.writes) != 0 {
		t.Fatalf("steps=%d writes=%v err=%v", len(steps), f.writes, err)
	}
}

func TestOriginPullReadbackBlocksDNSWrites(t *testing.T) {
	for _, alreadyEnabled := range []bool{false, true} {
		for _, failure := range []string{"foreign certificate", "hostname override", "disabled settings", "stale PUT", "certificate expired"} {
			t.Run(failure+" enabled="+strconv.FormatBool(alreadyEnabled), func(t *testing.T) {
				f, cloudflare := newFakeCloudflare(t)
				f.aop = alreadyEnabled
				names := []string{"gru.api.terrascale.tech", "gru.auth.terrascale.tech"}
				steps, err := cloudflare.edgeSteps(t.Context(), names, netip.MustParseAddr("203.0.113.10"), "gru-1", testOriginPull(t))
				if err != nil {
					t.Fatal(err)
				}
				switch failure {
				case "foreign certificate":
					f.certificates = append(f.certificates, originPullCertificate{ID: "foreign", Certificate: f.certificates[0].Certificate, Status: "active"})
				case "hostname override":
					f.hostnameOverrides["gru.auth.terrascale.tech"] = map[string]any{"hostname": "gru.auth.terrascale.tech", "enabled": false}
				case "disabled settings":
					f.aop = false
					f.staleAOP = true
				case "stale PUT":
					if alreadyEnabled {
						return
					}
					f.staleAOP = true
				case "certificate expired":
					_, f.certificates[0].Certificate = originPullTestPEM(t, nil, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Hour) })
				}
				if err := run(t.Context(), steps, true, io.Discard); err == nil {
					t.Fatal("accepted stale origin pull readback")
				}
				for _, write := range f.writes {
					if strings.Contains(write, "/dns_records") {
						t.Fatalf("DNS written despite failed readback: %v", f.writes)
					}
				}
			})
		}
	}
}

func TestOriginPullRechecksAfterEnableAndBeforeEachDNSWrite(t *testing.T) {
	for _, changedAfter := range []string{"/origin_tls_client_auth/settings", "/dns_records"} {
		t.Run(changedAfter, func(t *testing.T) {
			f, cloudflare := newFakeCloudflare(t)
			steps, err := cloudflare.edgeSteps(t.Context(), []string{"gru.api.terrascale.tech", "gru.auth.terrascale.tech"}, netip.MustParseAddr("203.0.113.10"), "gru-1", testOriginPull(t))
			if err != nil {
				t.Fatal(err)
			}
			f.afterWrite = func(r *http.Request) {
				if strings.HasSuffix(r.URL.Path, changedAfter) {
					f.certificates[0].ID = "foreign"
				}
			}
			if err := run(t.Context(), steps, true, io.Discard); err == nil {
				t.Fatal("missed newly deployed foreign certificate")
			}
			if changedAfter == "/origin_tls_client_auth/settings" && len(f.records) != 0 || changedAfter == "/dns_records" && len(f.records) != 1 {
				t.Fatalf("DNS writes continued after foreign certificate: %v", f.writes)
			}
		})
	}
}
