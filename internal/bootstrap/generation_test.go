package bootstrap_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

var generationNow = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func generationExpectation() bootstrap.MaterialGenerationExpectation {
	return bootstrap.MaterialGenerationExpectation{DeploymentID: "0000000000YY15F5R431V5JPJ9", Environment: "production",
		ClusterID: "00000000006GRRF84JEVN9TX7M", Cell: "GRU", ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}}
}

func signGeneration(t *testing.T, generation bootstrap.MaterialGeneration, key ed25519.PrivateKey) trust.Envelope {
	t.Helper()
	envelope, err := bootstrap.SignMaterialGeneration(generation, generationNow, generationNow.AddDate(0, 6, 0), key)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func keyring(t *testing.T, keys ...ed25519.PublicKey) trust.Keyring {
	t.Helper()
	roots, err := trust.ParseKeyring(keys...)
	if err != nil {
		t.Fatal(err)
	}
	return roots
}

func TestMaterialGenerationChain(t *testing.T) {
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	roots := keyring(t, rootPublic)
	expected := generationExpectation()
	material := generationtest.New(t, generationNow)
	first := signGeneration(t, material.Generation(expected, 1, ""), rootPrivate)
	verified, err := bootstrap.VerifyMaterialGenerationChain([]trust.Envelope{first}, roots, expected, generationNow)
	if err != nil {
		t.Fatal(err)
	}
	if firstGeneration := verified[0].Generation(); firstGeneration.SchemaVersion != 1 || firstGeneration.RoleSigner == "" {
		t.Fatal("v1 generation must bind its role signer")
	}
	rollover := generationtest.Rollover(t, generationNow, material)
	second := signGeneration(t, rollover.Generation(expected, 2, verified[0].Fingerprint()), rootPrivate)
	chain := []trust.Envelope{first, second}
	if verified, err := bootstrap.VerifyMaterialGenerationChain(chain, roots, expected, generationNow); err != nil ||
		len(verified) != 2 || verified[1].Generation().Generation != 2 {
		t.Fatalf("generation 2 extends generation 1: %v", err)
	}
	wire, err := bootstrap.EncodeMaterialGenerationChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := bootstrap.DecodeMaterialGenerationChain(wire); err != nil || len(decoded) != 2 {
		t.Fatalf("the chain round-trips: %v", err)
	}
	if _, err := bootstrap.DecodeMaterialGenerationChain([]byte(" " + string(wire))); err == nil {
		t.Fatal("non-canonical chain JSON decoded")
	}

	_, otherRoot, _ := ed25519.GenerateKey(rand.Reader)
	otherDeployment := expected
	otherDeployment.DeploymentID = "00000000000ZGTG9F4ZD9XG0T1"
	tampered := second
	tampered.Payload = []byte(strings.Replace(string(tampered.Payload), `"issuedLifetimeHours":168`, `"issuedLifetimeHours":2160`, 1))
	newCell := generationtest.New(t, generationNow).Generation(expected, 2, verified[0].Fingerprint())
	newCell.Operator = material.OperatorID
	for name, refused := range map[string][]trust.Envelope{
		"generation 2 alone":    {second},
		"a reordered chain":     {second, first},
		"a skipped generation":  {first, signGeneration(t, rollover.Generation(expected, 3, verified[0].Fingerprint()), rootPrivate)},
		"a rival generation 2":  {first, signGeneration(t, rollover.Generation(expected, 2, strings.Repeat("a", 64)), rootPrivate)},
		"new NATS accounts":     {first, signGeneration(t, newCell, rootPrivate)},
		"an untrusted root":     {signGeneration(t, material.Generation(expected, 1, ""), otherRoot)},
		"a tampered newest":     {first, tampered},
		"another deployment's":  {signGeneration(t, generationtest.New(t, generationNow).Generation(otherDeployment, 1, ""), rootPrivate)},
		"an empty chain":        {},
		"a forged older member": {signGeneration(t, material.Generation(otherDeployment, 1, ""), rootPrivate), second},
	} {
		if _, err := bootstrap.VerifyMaterialGenerationChain(refused, roots, expected, generationNow); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	if _, err := bootstrap.VerifyMaterialGenerationChain([]trust.Envelope{first}, roots, expected, generationNow.AddDate(1, 0, 0)); err == nil {
		t.Fatal("an expired newest generation was current")
	}
	if _, err := bootstrap.VerifyAdoptedMaterialGenerationChain([]trust.Envelope{first}, roots, expected); err != nil {
		t.Fatalf("a restarting controller verifies an adopted chain after its expiry: %v", err)
	}
}

// After a root rotation the chain is extended under the new root alone,
// and a retired root can no longer extend it.
func TestMaterialGenerationChainAcrossRootRotation(t *testing.T) {
	oldPublic, oldPrivate, _ := ed25519.GenerateKey(rand.Reader)
	newPublic, newPrivate, _ := ed25519.GenerateKey(rand.Reader)
	expected := generationExpectation()
	material := generationtest.New(t, generationNow)
	first := signGeneration(t, material.Generation(expected, 1, ""), oldPrivate)
	verified, err := bootstrap.VerifyMaterialGenerationChain([]trust.Envelope{first}, keyring(t, oldPublic), expected, generationNow)
	if err != nil {
		t.Fatal(err)
	}
	next := generationtest.Rollover(t, generationNow, material).Generation(expected, 2, verified[0].Fingerprint())
	current := keyring(t, newPublic)
	if _, err := bootstrap.VerifyMaterialGenerationChain([]trust.Envelope{first, signGeneration(t, next, newPrivate)}, current,
		expected, generationNow); err != nil {
		t.Fatalf("the new root extends a chain the old root began: %v", err)
	}
	retired := []trust.Envelope{first, signGeneration(t, next, oldPrivate)}
	if _, err := bootstrap.VerifyMaterialGenerationChain(retired, current, expected, generationNow); err == nil {
		t.Fatal("a retired root extended the chain")
	}
}

func TestMaterialGenerationShape(t *testing.T) {
	material := generationtest.New(t, generationNow)
	expected := generationExpectation()
	if err := material.Generation(expected, 1, "").Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*bootstrap.MaterialGeneration){
		"a missing renewable file": func(generation *bootstrap.MaterialGeneration) { generation.Secrets = generation.Secrets[1:] },
		"a cell-issued leaf": func(generation *bootstrap.MaterialGeneration) {
			generation.Secrets[0].TargetFile, generation.Secrets[0].Purpose = "controller-a-tls-cert.pem", bootstrap.SecretController
		},
		"a slot-bound secret": func(generation *bootstrap.MaterialGeneration) {
			generation.Secrets[0].Slot = "controller-a"
		},
		"a wrong purpose": func(generation *bootstrap.MaterialGeneration) {
			for index := range generation.Secrets {
				if generation.Secrets[index].TargetFile == "controller-tls-issuer-key.pem" {
					generation.Secrets[index].Purpose = bootstrap.SecretRegionalShared
				}
			}
		},
		"a duplicate file": func(generation *bootstrap.MaterialGeneration) { generation.Secrets[1] = generation.Secrets[0] },
		"generation 1 with a parent": func(generation *bootstrap.MaterialGeneration) {
			generation.Previous = strings.Repeat("a", 64)
		},
		"no issued lifetime":       func(generation *bootstrap.MaterialGeneration) { generation.IssuedLifetimeHours = 0 },
		"a 91-day issued lifetime": func(generation *bootstrap.MaterialGeneration) { generation.IssuedLifetimeHours = 91 * 24 },
		"the cell account as signer": func(generation *bootstrap.MaterialGeneration) {
			generation.AccountSigner = generation.CellAccount
		},
		"the host signer as system account": func(generation *bootstrap.MaterialGeneration) {
			generation.SystemAccount = generation.HostSigner
		},
		"unsorted controller slots": func(generation *bootstrap.MaterialGeneration) {
			generation.ControllerSlots = []string{"controller-b", "controller-a"}
		},
		"a repeated controller slot": func(generation *bootstrap.MaterialGeneration) {
			generation.ControllerSlots = []string{"controller-a", "controller-a"}
		},
		"a user key as the operator": func(generation *bootstrap.MaterialGeneration) {
			generation.Operator = "U" + generation.Operator[1:]
		},
		"a secret outside OCI Vault": func(generation *bootstrap.MaterialGeneration) {
			generation.Secrets[0].SecretOCID = "ocid1.bucket.oc1..x"
		},
		"an unsupported schema": func(generation *bootstrap.MaterialGeneration) { generation.SchemaVersion = 2 },
		"a missing role signer": func(generation *bootstrap.MaterialGeneration) {
			generation.RoleSigner = ""
		},
		"an unpinned digest": func(generation *bootstrap.MaterialGeneration) { generation.Secrets[0].SHA256 = "" },
		"an unbounded secret": func(generation *bootstrap.MaterialGeneration) {
			generation.Secrets[0].MaxBytes = bootstrap.MaxSecretBytes + 1
		},
		"no generation": func(generation *bootstrap.MaterialGeneration) { generation.Generation = 0 },
	} {
		generation := material.Generation(expected, 1, "")
		change(&generation)
		if generation.Validate() == nil {
			t.Errorf("accepted %s", name)
		}
	}
}

// An extended v1 chain retains the role signer, configs and credentials.
func TestMaterialGenerationPinnedConfigChain(t *testing.T) {
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	roots := keyring(t, rootPublic)
	expected := generationExpectation()
	material := generationtest.New(t, generationNow)
	first := signGeneration(t, material.Generation(expected, 1, ""), rootPrivate)
	verified, err := bootstrap.VerifyMaterialGenerationChain([]trust.Envelope{first}, roots, expected, generationNow)
	if err != nil {
		t.Fatal(err)
	}
	withoutCredentials := material.WithoutIssuers(t).InterRegion(t, generationNow, expected.ControllerSlots)
	upgraded := withoutCredentials.WithControllerCredentials(t, expected.ControllerSlots)
	second := signGeneration(t, upgraded.Generation(expected, 2, verified[0].Fingerprint()), rootPrivate)
	verified, err = bootstrap.VerifyMaterialGenerationChain([]trust.Envelope{first, second}, roots, expected, generationNow)
	if err != nil {
		t.Fatalf("v1 generation extends its predecessor: %v", err)
	}
	if generation := verified[1].Generation(); generation.SchemaVersion != 1 || len(generation.ControllerConfigs) != 3 ||
		generation.AccountSigner != "" || generation.RoleSigner == "" {
		t.Fatalf("generation 2 = %+v", generation)
	}
	otherRole := upgraded.Generation(expected, 3, verified[1].Fingerprint())
	otherRole.RoleSigner = material.SignerID
	for name, generation := range map[string]bootstrap.MaterialGeneration{
		"dropped controller credentials": withoutCredentials.Generation(expected, 3, verified[1].Fingerprint()),
		"dropped controller configs":     material.Generation(expected, 3, verified[1].Fingerprint()),
		"another role signer":            otherRole,
	} {
		if err := generation.Validate(); err != nil {
			t.Fatalf("%s is valid alone: %v", name, err)
		}
		chain := []trust.Envelope{first, second, signGeneration(t, generation, rootPrivate)}
		if _, err := bootstrap.VerifyMaterialGenerationChain(chain, roots, expected, generationNow); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
}

func TestMaterialGenerationControllerCredentialShape(t *testing.T) {
	expected := generationExpectation()
	material := generationtest.New(t, generationNow).WithoutIssuers(t).
		InterRegion(t, generationNow, expected.ControllerSlots).WithControllerCredentials(t, expected.ControllerSlots)
	if err := material.Generation(expected, 1, "").Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*bootstrap.MaterialGeneration){
		"missing one slot": func(g *bootstrap.MaterialGeneration) {
			g.Secrets = slices.DeleteFunc(g.Secrets, func(ref bootstrap.SecretReference) bool { return ref.TargetFile == "controller-b.creds" })
		},
		"wrong slot": func(g *bootstrap.MaterialGeneration) {
			for i := range g.Secrets {
				if g.Secrets[i].TargetFile == "controller-a.creds" {
					g.Secrets[i].Slot = "controller-b"
				}
			}
		},
		"no configs": func(g *bootstrap.MaterialGeneration) { g.ControllerConfigs = nil },
	} {
		t.Run(name, func(t *testing.T) {
			generation := material.Generation(expected, 1, "")
			mutate(&generation)
			if generation.Validate() == nil {
				t.Fatal("invalid credential pins accepted")
			}
		})
	}
}

func TestMaterialGenerationInterRegionShape(t *testing.T) {
	expected := generationExpectation()
	withIssuers := generationtest.New(t, generationNow)
	material := withIssuers.WithoutIssuers(t).InterRegion(t, generationNow, expected.ControllerSlots)
	for name, valid := range map[string]generationtest.Material{"no issuers, with interregion": material,
		"issuers, without interregion": withIssuers} {
		if err := valid.Generation(expected, 1, "").Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	pin := func(generation *bootstrap.MaterialGeneration, name string) {
		reference := generation.Secrets[0]
		reference.Purpose, reference.Slot, reference.TargetFile = bootstrap.SecretInterRegion, "", name
		generation.Secrets = append(generation.Secrets, reference)
	}
	for name, change := range map[string]func(*bootstrap.MaterialGeneration){
		"a duplicate slot config": func(generation *bootstrap.MaterialGeneration) {
			generation.ControllerConfigs[1] = generation.ControllerConfigs[0]
		},
		"a foreign slot config": func(generation *bootstrap.MaterialGeneration) {
			generation.ControllerConfigs[2].Slot = "controller-z"
		},
		"a non-canonical config digest": func(generation *bootstrap.MaterialGeneration) {
			generation.ControllerConfigs[0].SHA256 = strings.ToUpper(generation.ControllerConfigs[0].SHA256)
		},
		"a config over the manifest's limit": func(generation *bootstrap.MaterialGeneration) {
			generation.ControllerConfigs[0].Size = bootstrap.MaxControllerConfigBytes + 1
		},
		"a pinned interregion CA key":   func(generation *bootstrap.MaterialGeneration) { pin(generation, "interregion-ca.key") },
		"a pinned child seed":           func(generation *bootstrap.MaterialGeneration) { pin(generation, "child-fra.seed") },
		"a second parent's credentials": func(generation *bootstrap.MaterialGeneration) { pin(generation, "leaf-fra.creds") },
		"credentials to its own cell":   func(generation *bootstrap.MaterialGeneration) { pin(generation, "leaf-gru.creds") },
		"a leaf key bound to another slot": func(generation *bootstrap.MaterialGeneration) {
			for index, secret := range generation.Secrets {
				if secret.Slot == "controller-a" {
					generation.Secrets[index].Slot = "controller-b"
				}
			}
		},
		"interregion files without configs": func(generation *bootstrap.MaterialGeneration) {
			generation.ControllerConfigs = nil
		},
		"a slot without leaf TLS": func(generation *bootstrap.MaterialGeneration) {
			generation.Secrets = slices.DeleteFunc(generation.Secrets, func(secret bootstrap.SecretReference) bool {
				return secret.Slot == "controller-c"
			})
		},
		"no role signer": func(generation *bootstrap.MaterialGeneration) { generation.RoleSigner = "" },
		"the host signer as role signer": func(generation *bootstrap.MaterialGeneration) {
			generation.RoleSigner = generation.HostSigner
		},
		"an account signer without issuers": func(generation *bootstrap.MaterialGeneration) {
			generation.AccountSigner = withIssuers.SignerID
		},
		"an issued lifetime without issuers": func(generation *bootstrap.MaterialGeneration) {
			generation.IssuedLifetimeHours = 24
		},
	} {
		generation := material.Generation(expected, 1, "")
		change(&generation)
		if generation.Validate() == nil {
			t.Errorf("accepted %s", name)
		}
	}
	partial := withIssuers.Generation(expected, 1, "")
	partial.Secrets = slices.DeleteFunc(partial.Secrets, func(secret bootstrap.SecretReference) bool {
		return secret.TargetFile == "controller-tls-issuer-key.pem"
	})
	if partial.Validate() == nil {
		t.Error("accepted partially pinned controller issuers")
	}
	lone := withIssuers.Generation(expected, 1, "")
	cert, _ := bootstrap.InterRegionTLSFiles("controller-a")
	reference := lone.Secrets[0]
	reference.Purpose, reference.Slot, reference.TargetFile = bootstrap.SecretInterRegion, "controller-a", cert
	if lone.Secrets = append(lone.Secrets, reference); lone.Validate() == nil {
		t.Error("accepted one slot's leaf TLS without the rest of the interregion files")
	}
}

// A link (TS-803) pins the CA and every slot's leaf TLS without the
// interregion account, and on a spoke its link user alone.
func TestMaterialGenerationLinkShape(t *testing.T) {
	expected := generationExpectation()
	expected.Cell = "SFO"
	spoke := generationtest.NewCell(t, generationNow, "sfo").WithoutIssuers(t).Link(t, generationNow, expected.ControllerSlots)
	if err := spoke.Generation(expected, 1, "").Validate(); err != nil {
		t.Fatal(err)
	}
	pin := func(generation *bootstrap.MaterialGeneration, name string) {
		reference := generation.Secrets[0]
		reference.Purpose, reference.Slot, reference.TargetFile = bootstrap.SecretInterRegion, "", name
		generation.Secrets = append(generation.Secrets, reference)
	}
	for name, change := range map[string]func(*bootstrap.MaterialGeneration){
		"the interregion account beside the link": func(generation *bootstrap.MaterialGeneration) { pin(generation, "interregion.jwt") },
		"a parent's leaf credentials":             func(generation *bootstrap.MaterialGeneration) { pin(generation, "leaf-gru.creds") },
		"link credentials bound to a slot": func(generation *bootstrap.MaterialGeneration) {
			for index, secret := range generation.Secrets {
				if secret.TargetFile == bootstrap.LinkCredentialsFile {
					generation.Secrets[index].Slot = "controller-a"
				}
			}
		},
		"link credentials without the CA": func(generation *bootstrap.MaterialGeneration) {
			generation.Secrets = slices.DeleteFunc(generation.Secrets, func(secret bootstrap.SecretReference) bool {
				return secret.TargetFile == "interregion-ca.pem"
			})
		},
	} {
		generation := spoke.Generation(expected, 1, "")
		change(&generation)
		if generation.Validate() == nil {
			t.Errorf("accepted %s", name)
		}
	}
}
