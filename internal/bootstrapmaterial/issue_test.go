package bootstrapmaterial_test

import (
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
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
	if bootstrapmaterial.CheckIssuedCredentials(generation, current, now) == nil {
		t.Error("accepted credentials without the current generation's signer")
	}
	if bootstrapmaterial.CheckIssuedCredentials(generation, renewed,
		now.Add(time.Duration(generation.IssuedLifetimeHours)*time.Hour)) == nil {
		t.Error("accepted expired credentials")
	}
}
