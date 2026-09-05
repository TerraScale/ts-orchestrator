package transitiongrant_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

func owner(t *testing.T) (*security.CommandSignatureSigner, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = signer.Close() })
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
func grantFixture() (transitiongrant.Grant, transitiongrant.Config) {
	issued := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	config := transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: "transition-1", NodeID: "sfo-1", Region: "sfo", ServerName: "sfo-store", StoreDir: "/var/lib/terrascale/orchestrator/candidate", GrantFile: "/etc/terrascale/candidate/grant.json", GrantPublicKeyFile: "/etc/terrascale/candidate/owner.pem"}
	grant := transitiongrant.Grant{Version: 1, TransitionID: config.TransitionID, IssuedAt: issued, ExpiresAt: issued.Add(time.Hour), TargetEpoch: 2, MinimumControlEpoch: 1, Source: transitiongrant.SourceIdentity{NodeID: "gru-source", ServerName: "gru-source-store", InitialGrantSHA256: strings.Repeat("a", 64), StoreScopeSHA256: strings.Repeat("b", 64)}}
	for _, region := range []string{"gru", "sfo", "fra"} {
		grant.Peers = append(grant.Peers, transitiongrant.Peer{Region: region, NodeID: region + "-1", ServerName: region + "-store", BootstrapGrantSHA256: strings.Repeat("c", 64), PreparedManifestSHA256: strings.Repeat("d", 64)})
	}
	return grant, config
}

func TestGrantOwnerSignatureAndDomainSeparation(t *testing.T) {
	signer, public := owner(t)
	_, foreign := owner(t)
	grant, _ := grantFixture()
	signed, err := transitiongrant.SignGrant(signer, grant)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := transitiongrant.VerifyGrant(public, signed)
	if err != nil {
		t.Fatal(err)
	}
	if verified.OwnerKeyID != signer.PublicKeyID() || len(verified.Digest) != 64 {
		t.Fatal("verified owner identity or digest absent")
	}
	if _, err := transitiongrant.VerifyGrant(foreign, signed); err == nil {
		t.Fatal("foreign owner accepted")
	}
	tampered := bytes.Replace(signed, []byte(`"targetEpoch":2`), []byte(`"targetEpoch":3`), 1)
	if _, err := transitiongrant.VerifyGrant(public, tampered); err == nil {
		t.Fatal("signed payload tampering accepted")
	}
	var document struct {
		Payload   json.RawMessage `json:"payload"`
		Signature []byte          `json:"signature"`
	}
	if err := json.Unmarshal(signed, &document); err != nil {
		t.Fatal(err)
	}
	document.Signature[len(document.Signature)-1] ^= 1
	modified, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transitiongrant.VerifyGrant(public, modified); err == nil {
		t.Fatal("modified signature accepted")
	}
	canonical, err := transitiongrant.CanonicalGrant(grant)
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"", "TS-NODE-INITIAL-GRANT-V1\x00", "TS-NODE-INITIAL-COMMAND-V1\x00"} {
		sig, err := signer.SignCanonicalMaterial(append([]byte(domain), canonical...))
		if err != nil {
			t.Fatal(err)
		}
		document.Payload = canonical
		document.Signature = sig.Bytes()
		wire, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := transitiongrant.VerifyGrant(public, wire); err == nil {
			t.Fatalf("signature from foreign domain %q accepted", domain)
		}
	}
}

func TestGrantAndConfigRejectNoncanonicalDocuments(t *testing.T) {
	signer, public := owner(t)
	grant, config := grantFixture()
	signed, err := transitiongrant.SignGrant(signer, grant)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transitiongrant.ParseConfig(raw); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"whitespace", func(b []byte) []byte { return append(b, '\n') }},
		{"duplicate", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
		}},
		{"unknown", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"version":1`), []byte(`"version":1,"unknown":1`), 1)
		}},
		{"case alias", func(b []byte) []byte { return bytes.Replace(b, []byte(`"version":1`), []byte(`"Version":1`), 1) }},
		{"trailing document", func(b []byte) []byte { return append(b, []byte(`{}`)...) }},
		{"oversize", func(b []byte) []byte { return bytes.Repeat([]byte(" "), transitiongrant.MaximumBytes+1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := transitiongrant.ParseConfig(test.mutate(append([]byte(nil), raw...))); err == nil {
				t.Fatal("noncanonical config accepted")
			}
			if _, err := transitiongrant.VerifyGrant(public, test.mutate(append([]byte(nil), signed...))); err == nil {
				t.Fatal("noncanonical grant accepted")
			}
		})
	}
	for _, bad := range [][]byte{
		bytes.Replace(signed, []byte(`"payload":`), []byte(`"unknown":0,"payload":`), 1),
		bytes.Replace(signed, []byte(`"region":"sfo"`), []byte(`"region":"sfo","region":"sfo"`), 1),
		bytes.Replace(signed, []byte(`"region":"sfo"`), []byte(`"region":"sfo","unknown":0`), 1),
	} {
		if _, err := transitiongrant.VerifyGrant(public, bad); err == nil {
			t.Fatal("duplicate or unknown envelope/peer field accepted")
		}
	}
}

func TestCandidateGrantExactIdentityHashesAndTimeBounds(t *testing.T) {
	signer, public := owner(t)
	grant, config := grantFixture()
	signed, err := transitiongrant.SignGrant(signer, grant)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := transitiongrant.VerifyGrant(public, signed)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, manifest := grant.Peers[1].BootstrapGrantSHA256, grant.Peers[1].PreparedManifestSHA256
	if err := verified.CheckCandidate(grant.IssuedAt, config, bootstrap, manifest); err != nil {
		t.Fatal(err)
	}
	if err := verified.CheckCandidate(grant.ExpiresAt.Add(-time.Nanosecond), config, bootstrap, manifest); err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{grant.IssuedAt.Add(-time.Nanosecond), grant.ExpiresAt, grant.ExpiresAt.Add(time.Second)} {
		if err := verified.CheckCandidate(now, config, bootstrap, manifest); err == nil {
			t.Fatal("out-of-window candidate accepted")
		}
	}
	for _, mutate := range []func(*transitiongrant.Config){
		func(c *transitiongrant.Config) { c.TransitionID = "other-transition" }, func(c *transitiongrant.Config) { c.NodeID = "sfo-other" }, func(c *transitiongrant.Config) { c.ServerName = "other-store" }, func(c *transitiongrant.Config) { c.Region = "fra"; c.NodeID = "fra-other" }, func(c *transitiongrant.Config) { c.Mode = "run" },
	} {
		changed := config
		mutate(&changed)
		if err := verified.CheckCandidate(grant.IssuedAt, changed, bootstrap, manifest); err == nil {
			t.Fatal("ungranted candidate configuration accepted")
		}
	}
	if err := verified.CheckCandidate(grant.IssuedAt, config, strings.Repeat("e", 64), manifest); err == nil {
		t.Fatal("foreign bootstrap grant accepted")
	}
	if err := verified.CheckCandidate(grant.IssuedAt, config, bootstrap, strings.Repeat("f", 64)); err == nil {
		t.Fatal("changed prepared manifest accepted")
	}
	raw, _ := json.Marshal(config)
	component := hostmanifest.ComponentSpec{Name: "orchestrator", User: "terrascale-orchestrator", Arguments: transitiongrant.Arguments, Configuration: string(raw), DataVolume: "/var/lib/terrascale/orchestrator"}
	parsed, found, err := transitiongrant.ComponentConfig(component)
	if err != nil || !found || !parsed.Equal(config) {
		t.Fatal("exact preparation config not recognized")
	}
	for _, mutate := range []func(*hostmanifest.ComponentSpec){func(c *hostmanifest.ComponentSpec) { c.Arguments = "run --config @config" }, func(c *hostmanifest.ComponentSpec) { c.User = "root" }, func(c *hostmanifest.ComponentSpec) { c.Name = "terrabase" }, func(c *hostmanifest.ComponentSpec) { c.DataVolume = config.StoreDir }, func(c *hostmanifest.ComponentSpec) { c.DataVolume = config.StoreDir + "/nested" }} {
		changed := component
		mutate(&changed)
		if _, _, err := transitiongrant.ComponentConfig(changed); err == nil {
			t.Fatal("candidate launch escaped exact service/storage scope")
		}
	}
}

func TestGrantRejectsInvalidPeerInventoryAndBounds(t *testing.T) {
	for name, mutate := range map[string]func(*transitiongrant.Grant){
		"duplicate Region":       func(g *transitiongrant.Grant) { g.Peers[2].Region = "sfo" },
		"reordered Regions":      func(g *transitiongrant.Grant) { g.Peers[1], g.Peers[2] = g.Peers[2], g.Peers[1] },
		"missing peer":           func(g *transitiongrant.Grant) { g.Peers = g.Peers[:2] },
		"duplicate node":         func(g *transitiongrant.Grant) { g.Peers[2].NodeID = g.Peers[1].NodeID },
		"duplicate server":       func(g *transitiongrant.Grant) { g.Peers[2].ServerName = g.Peers[1].ServerName },
		"cross Region node":      func(g *transitiongrant.Grant) { g.Peers[1].NodeID = "fra-other" },
		"invalid node":           func(g *transitiongrant.Grant) { g.Peers[1].NodeID = "sfo-node with spaces" },
		"invalid bootstrap hash": func(g *transitiongrant.Grant) { g.Peers[1].BootstrapGrantSHA256 = strings.Repeat("C", 64) },
		"invalid manifest hash":  func(g *transitiongrant.Grant) { g.Peers[1].PreparedManifestSHA256 = "missing" },
		"foreign source":         func(g *transitiongrant.Grant) { g.Source.NodeID = "sfo-source" },
		"missing target epoch":   func(g *transitiongrant.Grant) { g.TargetEpoch = 0 },
		"missing minimum epoch":  func(g *transitiongrant.Grant) { g.MinimumControlEpoch = 0 },
		"empty interval":         func(g *transitiongrant.Grant) { g.ExpiresAt = g.IssuedAt },
		"unbounded lifetime":     func(g *transitiongrant.Grant) { g.ExpiresAt = g.IssuedAt.Add(24*time.Hour + time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			grant, _ := grantFixture()
			mutate(&grant)
			if _, err := transitiongrant.CanonicalGrant(grant); err == nil {
				t.Fatal("invalid grant accepted")
			}
		})
	}
}

func TestCandidatePreparationProtectsAdmissionPathsWithoutSync(t *testing.T) {
	for name, mutate := range map[string]func(*transitiongrant.Config){
		"grant in store":    func(c *transitiongrant.Config) { c.GrantFile = c.StoreDir + "/grant.json" },
		"key in store":      func(c *transitiongrant.Config) { c.GrantPublicKeyFile = c.StoreDir + "/owner.pem" },
		"grant is store":    func(c *transitiongrant.Config) { c.GrantFile = c.StoreDir },
		"key is store":      func(c *transitiongrant.Config) { c.GrantPublicKeyFile = c.StoreDir },
		"store below grant": func(c *transitiongrant.Config) { c.StoreDir = c.GrantFile + "/store" },
		"store below key":   func(c *transitiongrant.Config) { c.StoreDir = c.GrantPublicKeyFile + "/store" },
		"grant below key":   func(c *transitiongrant.Config) { c.GrantFile = c.GrantPublicKeyFile + "/grant.json" },
		"key below grant":   func(c *transitiongrant.Config) { c.GrantPublicKeyFile = c.GrantFile + "/owner.pem" },
	} {
		t.Run(name, func(t *testing.T) {
			_, config := grantFixture()
			mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("overlapping admission and storage paths accepted")
			}
		})
	}
}

func TestCandidateManifestKeepsOwnerMaterialOutsideWritableVolume(t *testing.T) {
	const volume = "/var/lib/terrascale/orchestrator"
	for _, field := range []string{"grant", "owner"} {
		for _, path := range []string{volume, volume + "/admission/material", "/var/lib/terrascale"} {
			t.Run(field+path, func(t *testing.T) {
				_, config := grantFixture()
				if field == "grant" {
					config.GrantFile = path
				} else {
					config.GrantPublicKeyFile = path
				}
				raw, err := json.Marshal(config)
				if err != nil {
					t.Fatal(err)
				}
				spec := hostmanifest.ComponentSpec{Name: "orchestrator", User: "terrascale-orchestrator", Arguments: transitiongrant.Arguments, Configuration: string(raw), DataVolume: volume}
				if _, found, err := transitiongrant.ComponentConfig(spec); !found || err == nil {
					t.Fatal("owner material admitted within writable volume")
				}
			})
		}
	}
	// Lexically similar sibling paths do not overlap the writable directory.
	_, config := grantFixture()
	config.GrantFile = volume + "-admission/grant.json"
	config.GrantPublicKeyFile = volume + "-admission/owner.pem"
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	spec := hostmanifest.ComponentSpec{Name: "orchestrator", User: "terrascale-orchestrator", Arguments: transitiongrant.Arguments, Configuration: string(raw), DataVolume: volume}
	if _, found, err := transitiongrant.ComponentConfig(spec); !found || err != nil {
		t.Fatalf("separate admission directory refused: %v", err)
	}
}
