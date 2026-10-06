package bootstrapmaterial_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
)

func loadIssuer(t *testing.T, material generationtest.Material) *bootstrapmaterial.ControllerIssuer {
	t.Helper()
	issuer, err := bootstrapmaterial.LoadControllerIssuer(material.Generation(generationExpectation(), 1, ""),
		material.Files["controller-tls-issuer-cert.pem"], material.Files["controller-tls-issuer-key.pem"],
		material.Files["controller-account-signer.seed"])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuer.Wipe)
	return issuer
}

// bootstrapCredentials is a controller user signed by the cell account
// itself, as bootstrap material issues it.
func bootstrapCredentials(t *testing.T, cell nkeys.KeyPair, expires time.Time) []byte {
	t.Helper()
	user, _ := nkeys.CreateUser()
	public, _ := user.PublicKey()
	seed, _ := user.Seed()
	claims := jwt.NewUserClaims(public)
	claims.Expires = expires.Unix()
	claims.Pub.Allow = jwt.StringList{"ts.orch.v1.gru.>"}
	claims.Sub.Allow = jwt.StringList{"_INBOX.gru." + public + ".>"}
	claims.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second}
	encoded, err := claims.Encode(cell)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := jwt.FormatUserConfig(encoded, seed)
	if err != nil {
		t.Fatal(err)
	}
	return creds
}

func TestRenewAndCheckIssuedTLS(t *testing.T) {
	material := generationtest.New(t, generationNow)
	generation := material.Generation(generationExpectation(), 1, "")
	issuer := loadIssuer(t, material)
	identity := bootstrapmaterial.ControllerLeafIdentity("gru", "controller-a", "10.0.1.10")
	certPEM, keyPEM, err := issuer.RenewTLS(identity, generationNow)
	if err != nil {
		t.Fatal(err)
	}
	issuerPEM, bundle := material.Files["controller-tls-issuer-cert.pem"], material.Files["ca.pem"]
	if err := bootstrapmaterial.CheckIssuedTLS(generation, issuerPEM, bundle, certPEM, keyPEM, identity, generationNow); err != nil {
		t.Fatal(err)
	}
	other := generationtest.New(t, generationNow)
	otherCert, otherKey, _ := loadIssuer(t, other).RenewTLS(identity, generationNow)
	slotB := bootstrapmaterial.ControllerLeafIdentity("gru", "controller-b", "10.0.1.11")
	slotBCert, slotBKey, _ := issuer.RenewTLS(slotB, generationNow)
	_, leafOnly, _ := generationtest.Certificate(t, &x509.Certificate{Subject: pkix.Name{CommonName: identity.CommonName},
		NotBefore: generationNow.Add(-time.Hour), NotAfter: generationNow.Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP(identity.IP)}, DNSNames: []string{identity.DNSName},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}, &material.ControllerIssuer)
	longTemplate := &x509.Certificate{Subject: pkix.Name{CommonName: identity.CommonName},
		NotBefore: generationNow.Add(-time.Hour), NotAfter: generationNow.AddDate(0, 6, 0),
		IPAddresses: []net.IP{net.ParseIP(identity.IP)}, DNSNames: []string{identity.DNSName},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	_, longLeaf, longKey := generationtest.Certificate(t, longTemplate, &material.ControllerIssuer)
	_, caLeaf, caKey := generationtest.Certificate(t, &x509.Certificate{Subject: pkix.Name{CommonName: identity.CommonName},
		NotBefore: generationNow.Add(-time.Hour), NotAfter: generationNow.Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP(identity.IP)}, DNSNames: []string{identity.DNSName},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}, &material.CA)
	for name, files := range map[string][2][]byte{
		"another generation's issuer": {otherCert, otherKey},
		"another slot's leaf":         {slotBCert, slotBKey},
		"a leaf without its issuer":   {leafOnly, keyPEM},
		"a longer lifetime":           {append(longLeaf, issuerPEM...), longKey},
		"a leaf signed by the CA":     {append(caLeaf, issuerPEM...), caKey},
		"a key that does not match":   {certPEM, slotBKey},
		"trailing data":               {append(append([]byte(nil), certPEM...), "tampered"...), keyPEM},
	} {
		if bootstrapmaterial.CheckIssuedTLS(generation, issuerPEM, bundle, files[0], files[1], identity, generationNow) == nil {
			t.Errorf("accepted %s", name)
		}
	}
	if bootstrapmaterial.CheckIssuedTLS(generation, issuerPEM, bundle, certPEM, keyPEM, identity,
		generationNow.Add(time.Duration(generation.IssuedLifetimeHours)*time.Hour)) == nil {
		t.Error("accepted an expired leaf")
	}
}

func TestRenewAndCheckIssuedCredentials(t *testing.T) {
	material := generationtest.New(t, generationNow)
	generation := material.Generation(generationExpectation(), 1, "")
	issuer := loadIssuer(t, material)
	now := time.Now()
	current := bootstrapCredentials(t, material.Cell, now.Add(time.Hour))
	renewed, err := issuer.RenewCredentials(current)
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrapmaterial.CheckIssuedCredentials(generation, renewed, now); err != nil {
		t.Fatal(err)
	}
	before, _ := jwt.ParseDecoratedJWT(current)
	after, _ := jwt.ParseDecoratedJWT(renewed)
	old, _ := jwt.DecodeUserClaims(before)
	fresh, _ := jwt.DecodeUserClaims(after)
	if fresh.Subject != old.Subject || !slices.Equal(fresh.Pub.Allow, old.Pub.Allow) ||
		!slices.Equal(fresh.Sub.Allow, old.Sub.Allow) || fresh.Resp == nil || *fresh.Resp != *old.Resp {
		t.Fatalf("renewal changed the user or its grants: %+v", fresh)
	}
	other := generationtest.New(t, generationNow)
	otherRenewed, _ := loadIssuer(t, other).RenewCredentials(current)
	long := func() []byte {
		raw, _ := jwt.ParseDecoratedJWT(renewed)
		claims, _ := jwt.DecodeUserClaims(raw)
		claims.Expires = now.AddDate(0, 6, 0).Unix()
		encoded, _ := claims.Encode(material.Signer)
		user, _ := jwt.ParseDecoratedUserNKey(renewed)
		seed, _ := user.Seed()
		creds, _ := jwt.FormatUserConfig(encoded, seed)
		return creds
	}()
	swapped := func() []byte {
		user, _ := jwt.ParseDecoratedUserNKey(renewed)
		seed, _ := user.Seed()
		stranger, _ := nkeys.CreateUser()
		strangerSeed, _ := stranger.Seed()
		return bytes.Replace(renewed, seed, strangerSeed, 1)
	}()
	for name, creds := range map[string][]byte{
		"bootstrap credentials":         current,
		"another generation's signer":   otherRenewed,
		"a longer lifetime":             long,
		"a seed of another user":        swapped,
		"credentials that do not parse": []byte("not credentials"),
	} {
		if bootstrapmaterial.CheckIssuedCredentials(generation, creds, now) == nil {
			t.Errorf("accepted %s", name)
		}
	}
	if bootstrapmaterial.CheckIssuedCredentials(generation, renewed,
		now.Add(time.Duration(generation.IssuedLifetimeHours)*time.Hour)) == nil {
		t.Error("accepted expired credentials")
	}
	// Checked before it was issued, beyond the clock skew, the renewal would
	// last past the generation's window.
	if bootstrapmaterial.CheckIssuedCredentials(generation, renewed, now.Add(-10*time.Minute)) == nil {
		t.Error("accepted credentials issued in the future")
	}
}
