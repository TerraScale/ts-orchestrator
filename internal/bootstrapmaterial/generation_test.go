package bootstrapmaterial_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/roleidentity"
)

// generationNow is the real clock: the fixture's NATS JWTs are always issued
// now (jwt.Encode stamps iat itself), and a check at a fixed earlier instant
// would see them issued in the future.
var generationNow = time.Now().UTC().Truncate(time.Second)

func generationExpectation() bootstrap.MaterialGenerationExpectation {
	return bootstrap.MaterialGenerationExpectation{DeploymentID: "gru-1-deployment", Environment: "production",
		ClusterID: "gru-1", Cell: "GRU", ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}}
}

func check(material generationtest.Material) (time.Time, error) {
	return bootstrapmaterial.CheckGenerationFiles(material.Generation(generationExpectation(), 1, ""), material.Read, generationNow)
}

// cellJWT re-signs the material's cell account JWT after edit.
func cellJWT(t *testing.T, material generationtest.Material, edit func(*jwt.AccountClaims)) []byte {
	t.Helper()
	claims, err := jwt.DecodeAccountClaims(strings.TrimSpace(string(material.Files["cell.jwt"])))
	if err != nil {
		t.Fatal(err)
	}
	edit(claims)
	encoded, err := claims.Encode(material.Operator)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(encoded + "\n")
}

func TestCheckGenerationFiles(t *testing.T) {
	material := generationtest.New(t, generationNow)
	first, err := check(material)
	if err != nil {
		t.Fatal(err)
	}
	if want := generationNow.AddDate(1, 0, 0).Add(-time.Hour); !first.Equal(want) {
		t.Fatalf("first expiry = %s, want the issuers' %s", first, want)
	}
	// A rollover bundle keeps the old CA beside the new one; the issuers
	// may already be the new CA's.
	rollover := generationtest.Rollover(t, generationNow, material)
	bundle := append(append([]byte(nil), material.Files["ca.pem"]...), rollover.Files["ca.pem"]...)
	if _, err := check(rollover.With(map[string][]byte{"ca.pem": bundle})); err != nil {
		t.Fatalf("a rollover bundle: %v", err)
	}
}

func TestCheckGenerationFilesRefusesUnsafeMaterial(t *testing.T) {
	material := generationtest.New(t, generationNow)
	other := generationtest.New(t, generationNow)
	year := generationNow.AddDate(1, 0, 0)
	stranger, _, _ := generationtest.Certificate(t, generationtest.CA("stranger CA", generationNow, year), nil)
	_, strangerIssuer, strangerKey := generationtest.Certificate(t, generationtest.ControllerIssuer(generationNow, year), &stranger)
	wideTemplate := generationtest.ControllerIssuer(generationNow, year)
	wideTemplate.MaxPathLenZero = false
	_, wideIssuer, wideKey := generationtest.Certificate(t, wideTemplate, &material.CA)
	clientOnly := generationtest.ControllerIssuer(generationNow, year)
	clientOnly.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	_, clientIssuer, clientKey := generationtest.Certificate(t, clientOnly, &material.CA)
	expiredTemplate := generationtest.ControllerIssuer(generationNow.Add(-time.Hour), generationNow.Add(-time.Minute))
	_, expiredCert, expiredKey := generationtest.Certificate(t, expiredTemplate, &material.CA)
	unconstrained := generationtest.HostIssuer(generationNow, year)
	unconstrained.PermittedDNSDomains, unconstrained.PermittedURIDomains = nil, nil
	_, looseHost, looseHostKey := generationtest.Certificate(t, unconstrained, &material.CA)
	serverHost := generationtest.HostIssuer(generationNow, year)
	serverHost.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	_, serverHostCert, serverHostKey := generationtest.Certificate(t, serverHost, &material.CA)
	selfSigned := generationtest.ControllerIssuer(generationNow, year)
	selfSignedIssuer, selfSignedCert, selfSignedKey := generationtest.Certificate(t, selfSigned, nil)
	_ = selfSignedIssuer
	_, leafPEM, _ := generationtest.Certificate(t, &x509.Certificate{Subject: pkix.Name{CommonName: "gru-1-ctl-1"},
		NotBefore: generationNow.Add(-time.Hour), NotAfter: year}, &material.CA)
	extraSigner, _ := other.Signer.PublicKey()
	expiredJWT := cellJWT(t, material, func(claims *jwt.AccountClaims) { claims.Expires = generationNow.Add(-time.Minute).Unix() })
	for name, files := range map[string]map[string][]byte{
		"an issuer from another CA": {"controller-tls-issuer-cert.pem": strangerIssuer,
			"controller-tls-issuer-key.pem": strangerKey},
		"an issuer that can issue CAs": {"controller-tls-issuer-cert.pem": wideIssuer, "controller-tls-issuer-key.pem": wideKey},
		"a client-only controller issuer": {"controller-tls-issuer-cert.pem": clientIssuer,
			"controller-tls-issuer-key.pem": clientKey},
		"an expired issuer": {"controller-tls-issuer-cert.pem": expiredCert, "controller-tls-issuer-key.pem": expiredKey},
		"a self-signed issuer added to the bundle": {"controller-tls-issuer-cert.pem": selfSignedCert,
			"controller-tls-issuer-key.pem": selfSignedKey,
			"ca.pem":                        append(append([]byte(nil), material.Files["ca.pem"]...), selfSignedCert...)},
		"the CA as host issuer": {"host-tls-issuer-cert.pem": material.Files["ca.pem"],
			"host-tls-issuer-key.pem": material.Files["controller-tls-issuer-key.pem"]},
		"an unconstrained host issuer":      {"host-tls-issuer-cert.pem": looseHost, "host-tls-issuer-key.pem": looseHostKey},
		"a host issuer that serves":         {"host-tls-issuer-cert.pem": serverHostCert, "host-tls-issuer-key.pem": serverHostKey},
		"an issuer key that does not match": {"controller-tls-issuer-key.pem": material.Files["host-tls-issuer-key.pem"]},
		"another account signer":            {"controller-account-signer.seed": other.Files["controller-account-signer.seed"]},
		"another operator's cell account":   {"cell.jwt": other.Files["cell.jwt"]},
		"another operator's JWT":            {"operator.jwt": other.Files["operator.jwt"]},
		"another system account's user":     {"system.creds": other.Files["system.creds"]},
		"a leaf in the CA bundle":           {"ca.pem": append(append([]byte(nil), material.Files["ca.pem"]...), leafPEM...)},
		"an intermediate in the CA bundle":  {"ca.pem": material.Files["controller-tls-issuer-cert.pem"]},
		"an extra cell signing key": {"cell.jwt": cellJWT(t, material, func(claims *jwt.AccountClaims) {
			claims.SigningKeys.Add(extraSigner)
		})},
		"a scoped account signer": {"cell.jwt": cellJWT(t, material, func(claims *jwt.AccountClaims) {
			claims.SigningKeys.AddScopedSigner(bootstrapmaterial.HostScope("gru", material.SignerID))
		})},
		"no host scope": {"cell.jwt": cellJWT(t, material, func(claims *jwt.AccountClaims) {
			delete(claims.SigningKeys, material.HostSignerID)
		})},
		"a widened host scope": {"cell.jwt": cellJWT(t, material, func(claims *jwt.AccountClaims) {
			scope := bootstrapmaterial.HostScope("gru", material.HostSignerID)
			scope.Template.Pub.Allow.Add(">")
			claims.SigningKeys.AddScopedSigner(scope)
		})},
		"a cell account without JetStream": {"cell.jwt": cellJWT(t, material, func(claims *jwt.AccountClaims) {
			claims.Limits.JetStreamLimits = jwt.JetStreamLimits{}
		})},
		"an expired cell account": {"cell.jwt": expiredJWT},
		"trailing data in the CA bundle": {"ca.pem": append(append([]byte(nil), material.Files["ca.pem"]...),
			[]byte("not a certificate\n")...)},
	} {
		if _, err := check(material.With(files)); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}

// Schema 2 (TS-668): gru-1's shape, without controller issuers, with the role
// signer and the interregion files, and one representative of each refusal.
func TestCheckGenerationFilesSchemaTwo(t *testing.T) {
	slots := generationExpectation().ControllerSlots
	withIssuers := generationtest.New(t, generationNow).SchemaTwo(t)
	material := withIssuers.WithoutIssuers(t).InterRegion(t, generationNow, slots)
	for name, valid := range map[string]generationtest.Material{"no issuers, with interregion": material,
		"issuers, without interregion": withIssuers} {
		if _, err := check(valid); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A controller holds only its own slot's leaf TLS and config.
	own := func(name string) ([]byte, error) {
		if strings.Contains(name, "-controller-b") || strings.Contains(name, "-controller-c") {
			return nil, fs.ErrNotExist
		}
		return material.Read(name)
	}
	generation := material.Generation(generationExpectation(), 1, "")
	if _, err := bootstrapmaterial.CheckGenerationFiles(generation, own, generationNow); err != nil {
		t.Fatalf("one slot's files: %v", err)
	}
	noConfigs := func(name string) ([]byte, error) {
		if strings.HasSuffix(name, ".json") {
			return nil, fs.ErrNotExist
		}
		return material.Read(name)
	}
	if _, err := bootstrapmaterial.CheckGenerationFiles(generation, noConfigs, generationNow); err == nil {
		t.Error("checked the interregion files without a contract")
	}
	changed := material.With(map[string][]byte{"controller-controller-a.json": material.Files["controller-controller-b.json"]})
	if _, err := bootstrapmaterial.CheckGenerationFiles(generation, changed.Read, generationNow); err == nil {
		t.Error("accepted a controller config that differs from its pin")
	}

	stranger, _, _ := generationtest.Certificate(t, generationtest.CA("stranger CA", generationNow, generationNow.AddDate(1, 0, 0)), nil)
	_, strangerCert, strangerKey := generationtest.Certificate(t, &x509.Certificate{
		DNSNames: []string{"leaf.gru.interregion.terrascale.internal"}, NotBefore: generationNow.Add(-time.Hour),
		NotAfter: generationNow.AddDate(1, 0, 0), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, &stranger)
	other := generationtest.New(t, generationNow)
	extraSigner, _ := other.Signer.PublicKey()
	config := string(material.Files["controller-controller-a.json"])
	_, parent, _ := strings.Cut(config, `"peer_account":"`)
	for name, files := range map[string]map[string][]byte{
		"an extra cell signing key": {"cell.jwt": material.Account(t, "cell.jwt", func(claims *jwt.AccountClaims) {
			claims.SigningKeys.Add(extraSigner)
		})},
		"a widened role scope": {"cell.jwt": material.Account(t, "cell.jwt", func(claims *jwt.AccountClaims) {
			scope := roleidentity.Scope(material.RoleSignerID)
			scope.Template.Pub.Allow.Add(">")
			claims.SigningKeys.AddScopedSigner(scope)
		})},
		"no role signer": {"cell.jwt": material.Account(t, "cell.jwt", func(claims *jwt.AccountClaims) {
			delete(claims.SigningKeys, material.RoleSignerID)
		})},
		"a system account that accepts leaf users": {"system.jwt": material.Account(t, "system.jwt",
			func(claims *jwt.AccountClaims) { claims.Limits.LeafNodeConn = -1 })},
		"a leaf certificate of another CA": {"interregion-tls-controller-a-cert.pem": strangerCert,
			"interregion-tls-controller-a-key.pem": strangerKey},
		"a leaf key of another slot": {
			"interregion-tls-controller-a-key.pem": material.Files["interregion-tls-controller-b-key.pem"]},
		"a regional user as leaf credentials": {"leaf-sfo.creds": material.Files["system.creds"]},
		"a config pointing at an unpinned account JWT": {"controller-controller-a.json": []byte(
			strings.Replace(config, `secrets/interregion.jwt"`, `secrets/cell-interregion.jwt"`, 1))},
		"a remote pinning another account": {"controller-controller-a.json": []byte(
			strings.Replace(config, parent[:56], other.CellID, 1))},
	} {
		if _, err := check(material.With(files)); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}

// A JWT issued after the check's time, beyond the clock skew, would not yet
// be active when the generation is applied.
func TestCheckGenerationFilesRefusesFutureJWTs(t *testing.T) {
	issued := time.Now()
	material := generationtest.New(t, issued)
	generation := material.Generation(generationExpectation(), 1, "")
	if _, err := bootstrapmaterial.CheckGenerationFiles(generation, material.Read, issued.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapmaterial.CheckGenerationFiles(generation, material.Read, issued.Add(-10*time.Minute)); err == nil ||
		!strings.Contains(err.Error(), "issued in the future") {
		t.Fatalf("JWTs issued after the check: %v", err)
	}
}
