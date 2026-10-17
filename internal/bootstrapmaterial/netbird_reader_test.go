package bootstrapmaterial_test

import (
	"crypto/x509"
	"encoding/pem"
	"slices"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestNetBirdReaderUsesExistingIssuerAndClosedReadRole(t *testing.T) {
	material := generationtest.New(t, generationNow)
	issuer := loadIssuer(t, material)
	deadline := time.Now().Add(time.Minute)
	creds, err := issuer.IssueNetBirdReadCredentials(deadline)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(creds) })
	if err := bootstrapmaterial.CheckNetBirdReadCredentials(creds, "gru", material.CellID, material.SignerID, deadline, time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.ParseDecoratedJWT(creds)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Issuer != material.SignerID || claim.IssuerAccount != material.CellID ||
		!slices.Equal(claim.Sub.Allow, jwt.StringList{protocol.InboxGrant("gru", claim.Subject)}) ||
		claim.Expires != deadline.Unix() {
		t.Fatal("reader did not retain the existing signer, original deadline and own private inbox")
	}
	user, err := jwt.ParseDecoratedUserNKey(creds)
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	seed, err := user.Seed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	for name, mutate := range map[string]func(*jwt.UserClaims){
		"private trust material":   func(c *jwt.UserClaims) { c.Pub.Allow.Add("$JS.API.STREAM.MSG.GET.KV_TS_TRUST_ROOTS") },
		"whole control log":        func(c *jwt.UserClaims) { c.Pub.Allow.Add("$JS.API.STREAM.MSG.GET.TS_CONTROL_LOG") },
		"direct read":              func(c *jwt.UserClaims) { c.Pub.Allow.Add("$JS.API.DIRECT.GET.KV_TS_SERVICE_SET.>") },
		"consumer create":          func(c *jwt.UserClaims) { c.Pub.Allow.Add("$JS.API.CONSUMER.CREATE.TS_CONTROL_LOG.>") },
		"consumer delete":          func(c *jwt.UserClaims) { c.Pub.Allow.Add("$JS.API.CONSUMER.DELETE.TS_CONTROL_LOG.NET_ACCOUNT_READ") },
		"consumer acknowledgement": func(c *jwt.UserClaims) { c.Pub.Allow.Add("$JS.ACK.>") },
		"other cursor":             func(c *jwt.UserClaims) { c.Pub.Allow.Add("$JS.API.CONSUMER.MSG.NEXT.TS_CONTROL_LOG.OTHER") },
		"other inbox":              func(c *jwt.UserClaims) { c.Sub.Allow = jwt.StringList{"_INBOX.>"} },
		"response grant":           func(c *jwt.UserClaims) { c.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: time.Second} },
		"bearer":                   func(c *jwt.UserClaims) { c.BearerToken = true },
		"native TCP connection":    func(c *jwt.UserClaims) { c.AllowedConnectionTypes = jwt.StringList{jwt.ConnectionTypeStandard} },
		"leaf connection":          func(c *jwt.UserClaims) { c.AllowedConnectionTypes = jwt.StringList{jwt.ConnectionTypeLeafnode} },
		"extended deadline":        func(c *jwt.UserClaims) { c.Expires++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed, err := jwt.DecodeUserClaims(raw)
			if err != nil {
				t.Fatal(err)
			}
			mutate(changed)
			encoded, err := changed.Encode(material.Signer)
			if err != nil {
				t.Fatal(err)
			}
			changedCreds, err := jwt.FormatUserConfig(encoded, seed)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(changedCreds)
			if err := bootstrapmaterial.CheckNetBirdReadCredentials(changedCreds, "gru", material.CellID, material.SignerID, deadline, time.Now()); err == nil {
				t.Fatal("accepted a reader outside the fixed source contract")
			}
		})
	}
	if _, err := issuer.IssueNetBirdReadCredentials(time.Now().Add(-time.Second)); err == nil {
		t.Fatal("issued an expired source")
	}
	if err := bootstrapmaterial.CheckNetBirdReadCredentials(creds, "gru", material.CellID, material.SignerID, deadline, deadline); err == nil {
		t.Fatal("accepted an expired source")
	}
	other := generationtest.New(t, generationNow)
	if err := bootstrapmaterial.CheckNetBirdReadCredentials(creds, "gru", other.CellID, other.SignerID, deadline, time.Now()); err == nil {
		t.Fatal("accepted a different regional signer")
	}
	if err := natscell.ValidateNetBirdReaderCredentialBytes(creds, "fra"); err == nil {
		t.Fatal("accepted another cell's private inbox and read-open route")
	}
}

func TestNetBirdReaderTLSRetainsOriginalDeadline(t *testing.T) {
	material := generationtest.New(t, generationNow)
	issuer := loadIssuer(t, material)
	deadline := time.Now().Truncate(time.Second).Add(time.Minute)
	certPEM, keyPEM, err := issuer.IssueNetBirdReadTLS("10.251.1.10", deadline)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyPEM)
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("missing manager leaf")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.NotAfter.Equal(deadline) || cert.Subject.CommonName != "terrascale-gru-netbird-manager" ||
		!slices.Equal(cert.DNSNames, []string{"netbird-manager"}) || len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "10.251.1.10" {
		t.Fatal("manager TLS differs from its exact identity or original deadline")
	}
	if cert.CheckSignatureFrom(material.ControllerIssuer.Certificate) != nil {
		t.Fatal("manager TLS uses another issuer")
	}
	if _, _, err := issuer.IssueNetBirdReadTLS("10.251.1.10", time.Now().Add(-time.Second)); err == nil {
		t.Fatal("issued expired manager TLS")
	}
	if _, _, err := issuer.IssueNetBirdReadTLS("", deadline); err == nil {
		t.Fatal("issued manager TLS without exact private IP")
	}
}
