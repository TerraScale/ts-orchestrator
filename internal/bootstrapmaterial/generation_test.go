package bootstrapmaterial_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json/v2"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/roleidentity"
)

// generationNow anchors certificate validity and expiry assertions. Keep it
// older than the clock skew to catch checks using it for wall-clock JWTs
// (jwt.Encode stamps iat itself), without waiting for the fixture to age.
var generationNow = time.Now().UTC().Truncate(time.Second).Add(-10 * time.Minute)

func generationExpectation() bootstrap.MaterialGenerationExpectation {
	return bootstrap.MaterialGenerationExpectation{DeploymentID: "0000000000YY15F5R431V5JPJ9", Environment: "production",
		ClusterID: "00000000006GRRF84JEVN9TX7M", Cell: "GRU", ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}}
}

func check(material generationtest.Material) (time.Time, error) {
	return bootstrapmaterial.CheckGenerationFiles(material.Generation(generationExpectation(), 1, ""), material.Read, time.Now())
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

// The v1 contract (TS-668): gru-1's shape, without controller issuers, with the role
// signer and the interregion files, and one representative of each refusal.
func TestCheckGenerationFilesWithRoleSigner(t *testing.T) {
	slots := generationExpectation().ControllerSlots
	withIssuers := generationtest.New(t, generationNow)
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
	if _, err := bootstrapmaterial.CheckGenerationFiles(generation, own, time.Now()); err != nil {
		t.Fatalf("one slot's files: %v", err)
	}
	noConfigs := func(name string) ([]byte, error) {
		if strings.HasSuffix(name, ".json") {
			return nil, fs.ErrNotExist
		}
		return material.Read(name)
	}
	if _, err := bootstrapmaterial.CheckGenerationFiles(generation, noConfigs, time.Now()); err == nil {
		t.Error("checked the interregion files without a contract")
	}
	changed := material.With(map[string][]byte{"controller-controller-a.json": material.Files["controller-controller-b.json"]})
	if _, err := bootstrapmaterial.CheckGenerationFiles(generation, changed.Read, time.Now()); err == nil {
		t.Error("accepted a controller config that differs from its pin")
	}

	stranger, _, _ := generationtest.Certificate(t, generationtest.CA("stranger CA", generationNow, generationNow.AddDate(1, 0, 0)), nil)
	_, strangerCert, strangerKey := generationtest.Certificate(t, &x509.Certificate{
		DNSNames: []string{"leaf.gru.interregion.terrascale.internal"}, NotBefore: generationNow.Add(-time.Hour),
		NotAfter: generationNow.AddDate(1, 0, 0), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, &stranger)
	other := generationtest.New(t, generationNow)
	extraSigner, _ := other.Signer.PublicKey()
	config := string(material.Files["controller-controller-a.json"])
	for _, version := range []string{"", `"version":0`, `"version":2`, `"version":6`} {
		changed := strings.Replace(config, `"version":1`, version, 1)
		if version == "" {
			changed = strings.Replace(config, `,"version":1`, "", 1)
		}
		if changed == config {
			t.Fatal("version-1 fixture was not changed")
		}
		if _, err := check(material.With(map[string][]byte{"controller-controller-a.json": []byte(changed)})); err == nil || !strings.Contains(err.Error(), "not a controller config") {
			t.Errorf("invalid config version %q: %v", version, err)
		}
	}
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

func TestCheckGenerationControllerCredentials(t *testing.T) {
	slots := generationExpectation().ControllerSlots
	material := generationtest.New(t, generationNow).WithoutIssuers(t).
		InterRegion(t, generationNow, slots).WithControllerCredentials(t, slots)
	if strings.Contains(string(material.Files["controller-controller-a.json"]), `"observability"`) {
		t.Fatal("credential fixture should use observability defaults without a config block")
	}
	if _, err := check(material); err != nil {
		t.Fatal(err)
	}
	for _, grant := range natscell.GlobalControllerPublishes() {
		t.Run("non-home "+grant, func(t *testing.T) {
			creds := material.Files["controller-a.creds"]
			raw, _ := jwt.ParseDecoratedJWT(creds)
			claim, _ := jwt.DecodeUserClaims(raw)
			claim.Pub.Allow.Add(grant)
			encoded, err := claim.Encode(material.Cell)
			if err != nil {
				t.Fatal(err)
			}
			user, _ := jwt.ParseDecoratedUserNKey(creds)
			defer user.Wipe()
			seed, _ := user.Seed()
			defer clear(seed)
			widened, _ := jwt.FormatUserConfig(encoded, seed)
			if _, err := check(material.With(map[string][]byte{"controller-a.creds": widened})); err == nil ||
				!strings.Contains(err.Error(), "unscoped publish") {
				t.Fatalf("non-home global grant passed generation validation: %v", err)
			}
		})
	}
	for name, files := range map[string]map[string][]byte{
		"another slot's user": {"controller-a.creds": material.Files["controller-b.creds"]},
		"missing config version": {"controller-controller-a.json": []byte(strings.Replace(string(material.Files["controller-controller-a.json"]),
			`"version":1,`, "", 1))},
		"zero config version": {"controller-controller-a.json": []byte(strings.Replace(string(material.Files["controller-controller-a.json"]),
			`"version":1`, `"version":0`, 1))},
		"unsupported config version": {"controller-controller-a.json": []byte(strings.Replace(string(material.Files["controller-controller-a.json"]),
			`"version":1`, `"version":2`, 1))},
		"null config version": {"controller-controller-a.json": []byte(strings.Replace(string(material.Files["controller-controller-a.json"]),
			`"version":1`, `"version":null`, 1))},
		"tampered user":           {"controller-a.creds": []byte("invalid")},
		"wrong config slot":       {"controller-controller-a.json": material.Files["controller-controller-b.json"]},
		"another credential path": {"controller-controller-a.json": []byte(strings.ReplaceAll(string(material.Files["controller-controller-a.json"]), "controller-a.creds", "controller-b.creds"))},
		"credential outside installed directory": {"controller-controller-a.json": []byte(strings.ReplaceAll(string(material.Files["controller-controller-a.json"]),
			"/var/lib/terrascale-orchestrator-secrets/controller-a.creds", "/tmp/controller-a.creds"))},
		"interregion outside installed directory": {"controller-controller-a.json": []byte(strings.ReplaceAll(string(material.Files["controller-controller-a.json"]),
			"/var/lib/terrascale-orchestrator-secrets/interregion.jwt", "/tmp/interregion.jwt"))},
		"obsolete aggregation switch": {"controller-controller-a.json": []byte(strings.Replace(string(material.Files["controller-controller-a.json"]),
			`"controller":`, `"observability":{"cluster_aggregation":true},"controller":`, 1))},
		"obsolete dashboard switch": {"controller-controller-a.json": []byte(strings.Replace(string(material.Files["controller-controller-a.json"]),
			`"controller":`, `"observability":{"dashboard":false},"controller":`, 1))},
		"obsolete off sentinel": {"controller-controller-a.json": []byte(strings.Replace(string(material.Files["controller-controller-a.json"]),
			`"controller":`, `"observability":{"listen_address":"off"},"controller":`, 1))},
		"conflicting global home": {"controller-controller-a.json": []byte(strings.ReplaceAll(string(material.Files["controller-controller-a.json"]),
			`"candidate_id":"controller-a"`, `"candidate_id":"controller-a","global":{"home":"gru"}`))},
	} {
		if _, err := check(material.With(files)); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	raw, _ := jwt.ParseDecoratedJWT(material.Files["controller-a.creds"])
	claim, _ := jwt.DecodeUserClaims(raw)
	claim.Expires = time.Now().Add(-time.Minute).Unix()
	encoded, _ := claim.Encode(material.Cell)
	user, _ := jwt.ParseDecoratedUserNKey(material.Files["controller-a.creds"])
	defer user.Wipe()
	seed, _ := user.Seed()
	defer clear(seed)
	expired, _ := jwt.FormatUserConfig(encoded, seed)
	if _, err := check(material.With(map[string][]byte{"controller-a.creds": expired})); err == nil {
		t.Fatal("expired user accepted")
	}
	own := func(name string) ([]byte, error) {
		if name == "controller-b.creds" || name == "controller-c.creds" ||
			strings.Contains(name, "-controller-b") || strings.Contains(name, "-controller-c") {
			return nil, fs.ErrNotExist
		}
		return material.Read(name)
	}
	generation := material.Generation(generationExpectation(), 1, "")
	if _, err := bootstrapmaterial.CheckGenerationFiles(generation, own, time.Now()); err != nil {
		t.Fatal(err)
	}
	missingOwn := func(name string) ([]byte, error) {
		if name == "controller-a.creds" {
			return nil, fs.ErrNotExist
		}
		return own(name)
	}
	if _, err := bootstrapmaterial.CheckGenerationFiles(generation, missingOwn, time.Now()); err == nil {
		t.Fatal("own config accepted without its pinned credential")
	}
	missingConfig := func(name string) ([]byte, error) {
		if name == "controller-controller-a.json" {
			return nil, fs.ErrNotExist
		}
		return own(name)
	}
	if _, err := bootstrapmaterial.CheckGenerationFiles(generation, missingConfig, time.Now()); err == nil {
		t.Fatal("own credential accepted without its config")
	}
}

func TestCheckGenerationControllerCredentialsWithoutInterRegion(t *testing.T) {
	slots := generationExpectation().ControllerSlots
	for name, test := range map[string]struct {
		embedded *natscell.Embedded
		global   map[string]any
	}{
		"no embedded server": {},
		"isolated cell":      {embedded: &natscell.Embedded{}},
		"explicit home":      {embedded: &natscell.Embedded{}, global: map[string]any{"home": "gru"}},
	} {
		t.Run(name, func(t *testing.T) {
			material := generationtest.New(t, generationNow).WithoutIssuers(t)
			for _, slot := range slots {
				controller := map[string]any{"candidate_id": slot}
				if test.global != nil {
					controller["global"] = test.global
				}
				config, err := json.Marshal(map[string]any{"version": 1, "controller": controller,
					"nats": natscell.Config{Cell: "gru", Instance: slot, Embedded: test.embedded}})
				if err != nil {
					t.Fatal(err)
				}
				material.Files["controller-"+slot+".json"] = config
			}
			material = material.WithControllerCredentials(t, slots)
			if _, err := check(material); err != nil {
				t.Fatal(err)
			}
			raw, _ := jwt.ParseDecoratedJWT(material.Files["controller-a.creds"])
			claim, _ := jwt.DecodeUserClaims(raw)
			for _, grant := range natscell.GlobalControllerPublishes() {
				claim.Pub.Allow.Remove(grant)
			}
			encoded, err := claim.Encode(material.Cell)
			if err != nil {
				t.Fatal(err)
			}
			user, _ := jwt.ParseDecoratedUserNKey(material.Files["controller-a.creds"])
			defer user.Wipe()
			seed, _ := user.Seed()
			defer clear(seed)
			missing, _ := jwt.FormatUserConfig(encoded, seed)
			if _, err := check(material.With(map[string][]byte{"controller-a.creds": missing})); err == nil {
				t.Fatal("isolated global home accepted without global grants")
			}
		})
	}
}

func TestGenerationRejectsRemovedGlobalAndInterRegionSwitches(t *testing.T) {
	slots := generationExpectation().ControllerSlots
	material := generationtest.New(t, generationNow).WithoutIssuers(t).InterRegion(t, generationNow, slots)
	name := "controller-" + slots[0] + ".json"
	config := string(material.Files[name])
	for _, value := range []string{"true", "false"} {
		for _, candidate := range []string{
			strings.Replace(config, `"candidate_id":`, `"global":{"enabled":`+value+`},"candidate_id":`, 1),
			strings.Replace(config, `"interregion":{`, `"interregion":{"enabled":`+value+`,`, 1),
		} {
			if _, err := check(material.With(map[string][]byte{name: []byte(candidate)})); err == nil {
				t.Fatalf("removed enabled field accepted: %s", candidate)
			}
		}
	}
}

// A JWT issued after the check's time, beyond the clock skew, would not yet
// be active when the generation is applied.
func TestCheckGenerationFilesRefusesFutureJWTs(t *testing.T) {
	issued := time.Now()
	material := generationtest.New(t, issued)
	generation := material.Generation(generationExpectation(), 1, "")
	if _, err := bootstrapmaterial.CheckGenerationFiles(generation, material.Read, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapmaterial.CheckGenerationFiles(generation, material.Read, issued.Add(-10*time.Minute)); err == nil ||
		!strings.Contains(err.Error(), "issued in the future") {
		t.Fatalf("JWTs issued after the check: %v", err)
	}
}

// TS-803: the home's link needs the link signer in cell.jwt; a spoke's
// needs its own link user. Each config names exactly the pinned link files.
func TestCheckGenerationFilesWithLink(t *testing.T) {
	slots := generationExpectation().ControllerSlots
	spokeExpectation := generationExpectation()
	spokeExpectation.Cell = "SFO"
	home := generationtest.New(t, generationNow).WithoutIssuers(t).Link(t, generationNow, slots)
	spoke := generationtest.NewCell(t, generationNow, "sfo").WithoutIssuers(t).Link(t, generationNow, slots)
	checkSpoke := func(material generationtest.Material) error {
		_, err := bootstrapmaterial.CheckGenerationFiles(material.Generation(spokeExpectation, 1, ""), material.Read, time.Now())
		return err
	}
	if _, err := check(home); err != nil {
		t.Fatalf("home: %v", err)
	}
	if err := checkSpoke(spoke); err != nil {
		t.Fatalf("spoke: %v", err)
	}
	unlinked := cellJWT(t, home, func(claims *jwt.AccountClaims) {
		for key, scope := range claims.SigningKeys {
			if user, ok := scope.(*jwt.UserScope); ok && user.Role == "link" {
				delete(claims.SigningKeys, key)
			}
		}
	})
	if _, err := check(home.With(map[string][]byte{"cell.jwt": unlinked})); err == nil || !strings.Contains(err.Error(), "link home") {
		t.Errorf("home without the link signer: %v", err)
	}
	if _, err := check(home.With(map[string][]byte{bootstrap.LinkCredentialsFile: spoke.Files[bootstrap.LinkCredentialsFile]})); err == nil {
		t.Error("accepted link credentials on the home")
	}
	signer, _ := nkeys.CreateAccount()
	homeAccount, _ := nkeys.CreateAccount()
	homeID, _ := homeAccount.PublicKey()
	fra, err := natscell.IssueLinkUser(signer, homeID, "fra", generationNow, generationNow.AddDate(1, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkSpoke(spoke.With(map[string][]byte{bootstrap.LinkCredentialsFile: fra})); err == nil {
		t.Error("accepted another region's link user")
	}
	name := "controller-" + slots[0] + ".json"
	config := strings.Replace(string(spoke.Files[name]), `"credentials_file":"`+bootstrap.MaterialDirectory+`/link.creds",`, "", 1)
	if config == string(spoke.Files[name]) {
		t.Fatal("spoke config fixture was not changed")
	}
	if err := checkSpoke(spoke.With(map[string][]byte{name: []byte(config)})); err == nil {
		t.Error("accepted a spoke config without its link credentials")
	}
	withAccount := spoke.With(map[string][]byte{"interregion.jwt": []byte("unused")})
	if err := checkSpoke(withAccount); err == nil {
		t.Error("accepted the interregion account beside a link")
	}
}
