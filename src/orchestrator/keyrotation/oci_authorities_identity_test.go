package keyrotation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/certificates"
	cm "github.com/oracle/oci-go-sdk/v65/certificatesmanagement"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type identityVaultFake struct {
	seeds              map[string][]byte
	generates, retires int
	requests           map[string]security.CapabilityRequest
}

func (v *identityVaultFake) Generate(_ context.Context, r security.CapabilityRequest) (security.CapabilityMaterial, error) {
	v.generates++
	if v.requests == nil {
		v.requests = map[string]security.CapabilityRequest{}
	}
	v.requests[r.IdempotencyKey] = r
	seed := sha256.Sum256([]byte(r.IdempotencyKey))
	v.seeds[r.IdempotencyKey] = bytes.Clone(seed[:])
	return security.CapabilityMaterial{Version: r.Generation, NotBefore: r.NotBefore, ExpiresAt: r.ExpiresAt, Reference: r.IdempotencyKey, Key: bytes.Clone(seed[:])}, nil
}
func (v *identityVaultFake) Fetch(_ context.Context, ref string) (security.CapabilityMaterial, error) {
	seed, ok := v.seeds[ref]
	if !ok {
		return security.CapabilityMaterial{}, errors.New("missing seed")
	}
	r := v.requests[ref]
	return security.CapabilityMaterial{Version: r.Generation, NotBefore: r.NotBefore, ExpiresAt: r.ExpiresAt, Reference: ref, Key: bytes.Clone(seed)}, nil
}
func (v *identityVaultFake) Retire(context.Context, string, string) error { v.retires++; return nil }

type identityProviderFake struct {
	t                *testing.T
	ca               *x509.Certificate
	key              *ecdsa.PrivateKey
	chain            string
	summaries        map[string]cm.CertificateSummary
	bundles          map[string]certificates.CertificateBundlePublicOnly
	csrs             []*x509.CertificateRequest
	creates, deletes int
	uncertain        bool
}

func (f *identityProviderFake) ListCertificates(_ context.Context, r cm.ListCertificatesRequest) (cm.ListCertificatesResponse, error) {
	out := cm.ListCertificatesResponse{}
	if c, ok := f.summaries[*r.Name]; ok {
		out.Items = []cm.CertificateSummary{c}
	}
	return out, nil
}
func (f *identityProviderFake) CreateCertificate(_ context.Context, r cm.CreateCertificateRequest) (cm.CreateCertificateResponse, error) {
	f.creates++
	config := r.CertificateConfig.(cm.CreateCertificateManagedExternallyIssuedByInternalCaConfigDetails)
	block, _ := pem.Decode([]byte(*config.CsrPem))
	if block == nil {
		f.t.Fatal("missing CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		f.t.Fatal(err)
	}
	if err = csr.CheckSignature(); err != nil {
		f.t.Fatal(err)
	}
	f.csrs = append(f.csrs, csr)
	cert := &x509.Certificate{SerialNumber: big.NewInt(int64(f.creates + 1)), Subject: csr.Subject, URIs: csr.URIs, NotBefore: config.Validity.TimeOfValidityNotBefore.Time, NotAfter: config.Validity.TimeOfValidityNotAfter.Time, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, f.ca, csr.PublicKey, f.key)
	if err != nil {
		f.t.Fatal(err)
	}
	id := *r.Name
	f.summaries[id] = cm.CertificateSummary{Id: new(id), Name: r.Name, CompartmentId: r.CompartmentId, IssuerCertificateAuthorityId: config.IssuerCertificateAuthorityId, FreeformTags: r.FreeformTags, LifecycleState: cm.CertificateLifecycleStateActive}
	f.bundles[id] = certificates.CertificateBundlePublicOnly{CertificateId: new(id), VersionNumber: new(int64(1)), CertificatePem: new(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))), CertChainPem: new(f.chain)}
	if f.uncertain {
		return cm.CreateCertificateResponse{}, errors.New("lost acknowledgement")
	}
	return cm.CreateCertificateResponse{}, nil
}
func (f *identityProviderFake) GetCertificateBundle(_ context.Context, r certificates.GetCertificateBundleRequest) (certificates.GetCertificateBundleResponse, error) {
	return certificates.GetCertificateBundleResponse{CertificateBundle: f.bundles[*r.CertificateId]}, nil
}
func (f *identityProviderFake) ScheduleCertificateDeletion(context.Context, cm.ScheduleCertificateDeletionRequest) (cm.ScheduleCertificateDeletionResponse, error) {
	f.deletes++
	return cm.ScheduleCertificateDeletionResponse{}, nil
}
func identityFixture(t *testing.T) (*OCIIdentityIssuer, *identityProviderFake, *identityVaultFake, security.IdentityRequest) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f := &identityProviderFake{t: t, ca: ca, key: key, chain: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), summaries: map[string]cm.CertificateSummary{}, bundles: map[string]certificates.CertificateBundlePublicOnly{}}
	v := &identityVaultFake{seeds: map[string][]byte{}}
	i := &OCIIdentityIssuer{config: OCIIdentityIssuerConfig{CompartmentID: "compartment", CertificateAuthorityID: "ca", Principals: []OCIIdentityPrincipal{{ID: "workload", SPIFFEID: "spiffe://terrascale/workload"}, {ID: "control", SPIFFEID: "spiffe://terrascale/control", Control: true}}, KeyVault: v, Authority: func(context.Context) error { return nil }}, management: f, retrieval: f}
	return i, f, v, security.IdentityRequest{OperationID: "operation", IdempotencyKey: "identity", Generation: 7, NotBefore: now, ExpiresAt: now.Add(24 * time.Hour)}
}
func TestOCIIdentitySignsVaultBackedDistinctScopedKeys(t *testing.T) {
	i, f, v, r := identityFixture(t)
	material, err := i.Issue(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if material.Version != r.Generation || !material.NotBefore.Equal(r.NotBefore) || !material.ExpiresAt.Equal(r.ExpiresAt) {
		t.Fatal("incorrect identity metadata")
	}
	var workload, control map[string][]byte
	if err = json.Unmarshal(material.WorkloadTLS, &workload); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(material.ControlTLS, &control); err != nil {
		t.Fatal(err)
	}
	if len(workload) != 1 || len(control) != 1 || workload["workload"] == nil || control["control"] == nil {
		t.Fatal("identity envelope crossed principal scopes")
	}
	keys := map[string]*ecdsa.PrivateKey{}
	for id, raw := range map[string][]byte{"workload": workload["workload"], "control": control["control"]} {
		pair, err := tls.X509KeyPair(raw, raw)
		if err != nil {
			t.Fatal(err)
		}
		key := pair.PrivateKey.(*ecdsa.PrivateKey)
		keys[id] = key
		if key.Curve != elliptic.P256() || len(pair.Leaf.URIs) != 1 || pair.Leaf.URIs[0].String() != "spiffe://terrascale/"+id {
			t.Fatal("incorrect key curve or SPIFFE URI")
		}
		summary := f.summaries[identityName(material.Reference, OCIIdentityPrincipal{ID: id})]
		expected, err := identityPrivate(v.seeds[summary.FreeformTags["rotation-seed"]])
		if err != nil {
			t.Fatal(err)
		}
		if !key.Equal(expected) {
			t.Fatal("private key did not derive from persisted vault seed")
		}
	}
	if keys["workload"].Equal(keys["control"]) {
		t.Fatal("principals share private key")
	}
	if len(f.csrs) != 2 {
		t.Fatal("missing signed CSRs")
	}
	restarted := &OCIIdentityIssuer{config: i.config, management: f, retrieval: f}
	fetched, err := restarted.Fetch(t.Context(), material.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fetched.WorkloadTLS, material.WorkloadTLS) || !bytes.Equal(fetched.ControlTLS, material.ControlTLS) {
		t.Fatal("restart changed identity material")
	}
}
func TestOCIIdentityRecoversLostCreateAcknowledgement(t *testing.T) {
	i, f, v, r := identityFixture(t)
	f.uncertain = true
	first, err := i.Issue(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &OCIIdentityIssuer{config: i.config, management: f, retrieval: f}
	second, err := restarted.Issue(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if first.Reference != second.Reference || !bytes.Equal(first.WorkloadTLS, second.WorkloadTLS) || f.creates != 2 || v.generates != 2 {
		t.Fatal("create acknowledgement recovery duplicated keys or certificates")
	}
}
func TestOCIIdentityStaleAuthorityBlocksMutations(t *testing.T) {
	i, f, v, r := identityFixture(t)
	material, err := i.Issue(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	i.config.Authority = func(context.Context) error { return errors.New("stale authority") }
	r.IdempotencyKey = "next"
	if _, err = i.Issue(t.Context(), r); err == nil {
		t.Fatal("stale issuer created identity")
	}
	if err = i.Retire(t.Context(), material.Reference, "retire"); err == nil {
		t.Fatal("stale issuer retired identity")
	}
	if f.creates != 2 || v.generates != 2 || f.deletes != 0 || v.retires != 0 {
		t.Fatal("mutation escaped authority fence")
	}
}
func TestOCIIdentityRejectsMalformedAndRevokedBundles(t *testing.T) {
	for _, kind := range []string{"certificate", "chain", "version", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			i, f, _, r := identityFixture(t)
			material, err := i.Issue(t.Context(), r)
			if err != nil {
				t.Fatal(err)
			}
			id := identityName(material.Reference, i.config.Principals[0])
			b := f.bundles[id]
			switch kind {
			case "certificate":
				b.CertificatePem = new("invalid")
			case "chain":
				b.CertChainPem = new("invalid")
			case "version":
				b.VersionNumber = new(int64(2))
			case "revoked":
				b.RevocationStatus = &certificates.RevocationStatus{}
			}
			f.bundles[id] = b
			if _, err = i.Fetch(t.Context(), material.Reference); err == nil {
				t.Fatal("accepted invalid bundle")
			}
		})
	}
}
