package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"encoding/pem"
	"gopkg.in/yaml.v2"
	"io"
	"maps"
	"slices"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"

	"math/big"
	"os"
	"path/filepath"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func TestBootstrapControlSeedCarriesOnlyPublicVaultReferences(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "seed"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	pair, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Wipe()
	seed, err := pair.Seed()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(owner)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&owner.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := write("owner.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
	manifest := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{{Name: "orchestrator", Version: "1.2.3", ArtifactURL: "https://releases.terrascale.tech/orchestrator", SignatureURL: "https://releases.terrascale.tech/orchestrator.sig", Sha256: strings.Repeat("ab", 32), User: "terrascale-orchestrator", DataVolume: "/var/lib/terrascale/orchestrator", CPUWeight: 100, MemoryMaxBytes: 1 << 30, IOWeight: 100}}}
	grant := hostagent.BootstrapGrant{Version: 1, GrantID: "gru-initial", NodeID: "gru-1", Manifest: manifest, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)}
	signed, err := hostagent.SignBootstrapGrant(signer, grant)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := loadControlActivation(bootstrapControlActivation{HostID: "gru-1", GrantFile: write("grant.json", signed), OwnerPublicKeyFile: publicPath})
	if err != nil {
		t.Fatal(err)
	}
	runtimeSigner, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	runtimeDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	runtimePath := write("runtime.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: runtimeDER}))
	hostSeed := bootstrapControlHostSeed{HostID: "gru-1", NATS: bootstrapcredentials.Reference{URL: "tls://nats.example:4222", CAFile: write("ca.pem", certificatePEM), CertificateFile: write("client.pem", certificatePEM), PrivateKeyFile: write("client.key", privatePEM), NKeySeedFile: write("user.seed", seed)}, PrivateKeySecretID: "ocid1.vaultsecret.oc1.test.client", PrivateKeyVersion: 1, NKeySecretID: "ocid1.vaultsecret.oc1.test.user", NKeyVersion: 2, CommandTrust: []bootstrapHostTrustReference{{CandidateID: "gru-controller-gru-1", PublicKeyFile: runtimePath}}}

	readerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	readerDER, _ := x509.MarshalPKCS8PrivateKey(readerKey)
	readerPrivate := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: readerDER})
	readerCertificate, _ := x509.CreateCertificate(rand.Reader, template, template, &readerKey.PublicKey, key)
	readerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: readerCertificate})
	readerPair, _ := nkeys.CreateUser()
	defer readerPair.Wipe()
	readerSeed, _ := readerPair.Seed()
	readerPublic, _ := readerPair.PublicKey()
	caHash, certHash := sha256.Sum256(certificatePEM), sha256.Sum256(readerPEM)
	const readerRoot = "/etc/terrascale/ts-node-authority/"
	hostSeed.AuthorityReader = nodeauthority.ReaderConfig{Endpoint: "tls://guest.example:4222", ServerName: "gru-1", Account: "GRU_REGIONAL", NKeySeedFile: readerRoot + "user.seed", PublicNKey: readerPublic, CAFile: readerRoot + "ca.pem", CASHA256: hex.EncodeToString(caHash[:]), CertificateFile: readerRoot + "client.pem", CertificateSHA256: hex.EncodeToString(certHash[:]), KeyFile: readerRoot + "client.key"}
	hostSeed.Files = []bootstrapHostFileReference{{SourceFile: write("reader-ca.pem", certificatePEM), Path: readerRoot + "ca.pem"}, {SourceFile: write("reader-client.pem", readerPEM), Path: readerRoot + "client.pem"}, {SourceFile: write("reader-client.key", readerPrivate), Path: readerRoot + "client.key", Private: true, SecretID: "ocid1.vaultsecret.oc1.test.readerkey", VersionNumber: 1}, {SourceFile: write("reader-user.seed", readerSeed), Path: readerRoot + "user.seed", Private: true, SecretID: "ocid1.vaultsecret.oc1.test.readeruser", VersionNumber: 1}}

	for _, name := range []string{"copied NKey", "reissued TLS same key"} {
		t.Run(name, func(t *testing.T) {
			bad := hostSeed
			bad.Files = append([]bootstrapHostFileReference(nil), hostSeed.Files...)
			if name == "copied NKey" {
				public, _ := pair.PublicKey()
				bad.AuthorityReader.PublicNKey = public
				for i := range bad.Files {
					if bad.Files[i].Path == readerRoot+"user.seed" {
						bad.Files[i].SourceFile = write("copied-reader.seed", seed)
					}
				}
			} else {
				reissue := *template
				reissue.SerialNumber = big.NewInt(99)
				der, err := x509.CreateCertificate(rand.Reader, &reissue, template, &key.PublicKey, key)
				if err != nil {
					t.Fatal(err)
				}
				renewed := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
				hash := sha256.Sum256(renewed)
				bad.AuthorityReader.CertificateSHA256 = hex.EncodeToString(hash[:])
				for i := range bad.Files {
					switch bad.Files[i].Path {
					case readerRoot + "client.pem":
						bad.Files[i].SourceFile = write("reissued-reader.pem", renewed)
					case readerRoot + "client.key":
						bad.Files[i].SourceFile = write("copied-reader.key", privatePEM)
					}
				}
			}
			if err := validateBootstrapAuthorityReader(bad, activation); err == nil {
				t.Fatal("copied public identity accepted under different credential files")
			}
		})
	}

	t.Run("same-path captured store substitution", func(t *testing.T) {
		first, err := bootstrapcredentials.Load(hostSeed.NATS)
		if err != nil {
			t.Fatal(err)
		}
		defer first.Close()
		alternate, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal(err)
		}
		defer alternate.Wipe()
		alternateSeed, _ := alternate.Seed()
		defer clear(alternateSeed)
		for _, name := range []string{"administrative", "revoked"} {
			t.Run(name, func(t *testing.T) {
				scoped := loadedBootstrapControl{declaration: bootstrapControlConfig{Generation: 1, Stores: map[string]bootstrapcredentials.Reference{"administrative": hostSeed.NATS, "revoked": hostSeed.NATS}}, storeIdentities: map[string]bootstrapcredentials.Identity{"administrative": first.PublicIdentity(), "revoked": first.PublicIdentity()}}
				before, err := bootstrapControlIntentDigest(scoped)
				if err != nil {
					t.Fatal(err)
				}
				receipt := filepath.Join(t.TempDir(), "receipt.json")
				if err = persistBootstrapControlReceipt(receipt, bootstrapControlReceipt{Generation: 1, DeclarationSHA256: before, Regions: []bootstrap.ControlRegionBinding{{Code: "gru"}}}); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(hostSeed.NATS.NKeySeedFile, alternateSeed, 0600); err != nil {
					t.Fatal(err)
				}
				changed, err := bootstrapcredentials.Load(hostSeed.NATS)
				if restoreErr := os.WriteFile(hostSeed.NATS.NKeySeedFile, seed, 0600); restoreErr != nil {
					t.Fatal(restoreErr)
				}
				if err != nil {
					t.Fatal(err)
				}
				defer changed.Close()
				scoped.storeIdentities[name] = changed.PublicIdentity()
				after, err := bootstrapControlIntentDigest(scoped)
				if err != nil || before == after {
					t.Fatal("changed captured identity omitted from immutable intent")
				}
				if err = persistBootstrapControlReceipt(receipt, bootstrapControlReceipt{Generation: 1, DeclarationSHA256: after, Regions: []bootstrap.ControlRegionBinding{{Code: "gru"}}}); err == nil {
					t.Fatal("same-path credential substitution accepted for persisted generation")
				}
			})
		}
	})
	loaded := loadedBootstrapControl{declaration: bootstrapControlConfig{Generation: 1, Regions: []bootstrapControlRegion{{Code: "gru", OCIRegion: "sa-saopaulo-1", MemberCount: 1, CommandCandidateID: "gru-controller-gru-1"}}, Members: []bootstrapControlMember{{HostID: "gru-1", Region: "gru", Index: 1}}, Seeds: []bootstrapControlHostSeed{hostSeed}, Activations: []bootstrapControlActivation{{HostID: "gru-1", OwnerPublicKeyFile: publicPath}}}, activations: map[string]loadedControlActivation{"gru-1": activation}, signers: map[string]*security.CommandSignatureSigner{"gru": runtimeSigner}, workerCounts: map[string]int{"gru": 2}}
	lookup := func(key string) (string, bool) {
		values := map[string]string{ocireconcile.TSNodeVersionEnvironment: "1.2.3", ocireconcile.TSNodeSHA256Environment: strings.Repeat("ab", 32), ocireconcile.TSNodeURLEnvironment: "https://releases.terrascale.tech/ts-node", bootstrapReleaseKeyEnvironment: hex.EncodeToString(bytes.Repeat([]byte{1}, 32))}
		value, ok := values[key]
		return value, ok
	}
	if err := prepareBootstrapControlSeeds(lookup, &loaded); err != nil {
		t.Fatal(err)
	}
	if len(loaded.workerSeeds["gru"]) != 2 || loaded.workerSeeds["gru"][1] != loaded.seeds["gru"][1] || loaded.workerSeeds["gru"][2] != loaded.seeds["gru"][1] {
		t.Fatalf("worker seed map = %#v, want two dedicated worker slots", loaded.workerSeeds["gru"])
	}
	raw, err := base64.StdEncoding.DecodeString(loaded.seeds["gru"][1])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, readerSeed) || bytes.Contains(raw, readerPrivate) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(readerSeed))) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(readerPrivate))) || bytes.Contains(raw, privatePEM) || bytes.Contains(raw, seed) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(privatePEM))) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(seed))) {
		t.Fatal("private credential leaked into OCI user-data")
	}
	if !bytes.Contains(raw, []byte("/etc/terrascale/host-secrets.json")) || !bytes.Contains(raw, []byte("User=root")) {
		t.Fatal("public secret references or canonical host unit missing")
	}
	t.Run("transition receipt Vault provisioning", func(t *testing.T) {
		receiptKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(receiptKey)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(der)
		receiptPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		defer clear(receiptPEM)
		reference := bootstrapHostFileReference{SourceFile: write("transition-receipt.pem", receiptPEM), Path: hostsecrets.StorageTransitionReceiptKeyPath, Private: true, SecretID: "ocid1.vaultsecret.oc1.test.receipt", VersionNumber: 7}
		transitionSeed := hostSeed
		transitionSeed.HostID = "sfo-1"
		transitionSeed.CommandTrust = []bootstrapHostTrustReference{{CandidateID: "sfo-controller-sfo-1", PublicKeyFile: runtimePath}}
		transitionSeed.Files = append(slices.Clone(hostSeed.Files), reference)
		cfg := transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: "first-r3", NodeID: "sfo-1", Region: "sfo", ServerName: "sfo-r3", StoreDir: "/var/lib/terrascale/orchestrator/preliminary", GrantFile: "/etc/terrascale/prepare.json", GrantPublicKeyFile: "/etc/terrascale/owner.pem", StorageTransition: controltransition.Delivery{TransitionID: "first-r3", PlanFile: "/etc/terrascale/transition-plan.json", ReceiptPrivateKeyFile: hostsecrets.StorageTransitionReceiptKeyPath}}
		scope := loaded
		scope.activations = maps.Clone(loaded.activations)
		delete(scope.activations, "gru-1")
		scope.signers = map[string]*security.CommandSignatureSigner{"sfo": runtimeSigner}
		scope.declaration = bootstrapControlConfig{Generation: 1, Regions: []bootstrapControlRegion{{Code: "sfo", OCIRegion: "us-sanjose-1", MemberCount: 1, CommandCandidateID: "sfo-controller-sfo-1"}}, Members: []bootstrapControlMember{{HostID: "sfo-1", Region: "sfo", Index: 1}}, Seeds: []bootstrapControlHostSeed{transitionSeed}, Activations: []bootstrapControlActivation{{HostID: "sfo-1", OwnerPublicKeyFile: publicPath}}}
		sign := func() {
			t.Helper()
			m := hostmanifest.HostManifest{Components: slices.Clone(manifest.Components)}
			wire, err := json.Marshal(cfg, jsonv1.DefaultOptionsV1())
			if err != nil {
				t.Fatal(err)
			}
			m.Components[0].Arguments = transitiongrant.Arguments
			m.Components[0].Configuration = string(wire)
			g := grant
			g.NodeID = "sfo-1"
			g.Manifest = m
			signed, err := hostagent.SignBootstrapGrant(signer, g)
			if err != nil {
				t.Fatal(err)
			}
			a, err := loadControlActivation(bootstrapControlActivation{HostID: "sfo-1", GrantFile: write("candidate-grant.json", signed), OwnerPublicKeyFile: publicPath})
			if err != nil {
				t.Fatal(err)
			}
			scope.activations["sfo-1"] = a
		}
		sign()
		if err := prepareBootstrapControlSeeds(lookup, &scope); err != nil {
			t.Fatal(err)
		}
		cloud, err := base64.StdEncoding.DecodeString(scope.seeds["sfo"][1])
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(cloud, receiptPEM) || bytes.Contains(cloud, []byte(base64.StdEncoding.EncodeToString(receiptPEM))) {
			t.Fatal("receipt private key entered metadata")
		}
		var document struct {
			Files []struct {
				Path     string `yaml:"path"`
				Encoding string `yaml:"encoding"`
				Content  string `yaml:"content"`
			} `yaml:"write_files"`
		}
		if err := yaml.Unmarshal(cloud, &document); err != nil {
			t.Fatal(err)
		}
		foundReceipt := false
		for _, file := range document.Files {
			if file.Encoding != "b64" && file.Encoding != "gz+b64" {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(file.Content)
			if err != nil {
				t.Fatal(err)
			}
			if file.Encoding == "gz+b64" {
				reader, err := gzip.NewReader(bytes.NewReader(raw))
				if err != nil {
					t.Fatal(err)
				}
				raw, err = io.ReadAll(io.LimitReader(reader, (32<<10)+1))
				reader.Close()
				if err != nil || len(raw) > 32<<10 {
					t.Fatal("invalid generated compressed seed")
				}
			}
			if bytes.Contains(raw, receiptPEM) || bytes.Contains(raw, der) {
				t.Fatal("receipt secret in decoded metadata file")
			}
			if file.Path != hostsecrets.SeedPath {
				continue
			}
			declaration, err := hostsecrets.ParseSeed(raw)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range declaration.Entries {
				if entry.Destination != reference.Path {
					continue
				}
				sum := sha256.Sum256(receiptPEM)
				if entry.SecretID != reference.SecretID || entry.VersionNumber != reference.VersionNumber || entry.SHA256 != hex.EncodeToString(sum[:]) {
					t.Fatal("generated Vault receipt reference differs")
				}
				foundReceipt = true
			}
		}
		if !foundReceipt {
			t.Fatal("generated metadata omitted receipt Vault reference")
		}

		// Test every failure through the actual compiler, with an owner-signed
		// manifest and protected local source files.
		for _, mode := range []string{"missing", "public", "wrong type", "shared TLS key", "owner key", "unbound destination"} {
			t.Run(mode, func(t *testing.T) {
				original := scope.declaration.Seeds[0].Files
				files := slices.Clone(transitionSeed.Files)
				last := len(files) - 1
				switch mode {
				case "missing":
					files = files[:last]
				case "public":
					files[last].Private = false
				case "wrong type":
					files[last].SourceFile = hostSeed.NATS.NKeySeedFile
				case "shared TLS key":
					files[last].SourceFile = hostSeed.NATS.PrivateKeyFile
				case "owner key":
					key, err := x509.MarshalPKCS8PrivateKey(owner)
					if err != nil {
						t.Fatal(err)
					}
					defer clear(key)
					files[last].SourceFile = write("owner-private.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
				case "unbound destination":
					files[last].Path = "/etc/terrascale/orchestrator/command.key"
				}
				scope.declaration.Seeds[0].Files = files
				if err := prepareBootstrapControlSeeds(lookup, &scope); err == nil {
					t.Fatal("invalid transition seed compiled")
				}
				scope.declaration.Seeds[0].Files = original
			})
		}
		cfg.StorageTransition.ReceiptPrivateKeyFile = "/etc/terrascale/orchestrator/command.key"
		sign()
		if err := prepareBootstrapControlSeeds(lookup, &scope); err == nil {
			t.Fatal("service-owned receipt key accepted")
		}
	})

	for _, source := range []string{hostSeed.NATS.CAFile, hostSeed.NATS.CertificateFile} {
		if err := os.WriteFile(source, append(append([]byte(nil), certificatePEM...), privatePEM...), 0600); err != nil {
			t.Fatal(err)
		}
		if err := prepareBootstrapControlSeeds(lookup, &loaded); err == nil {
			t.Fatal("trailing private PEM accepted in public seed")
		}
		if err := os.WriteFile(source, certificatePEM, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ownerDER, err := x509.MarshalPKCS8PrivateKey(owner)
	if err != nil {
		t.Fatal(err)
	}
	combined := append(append([]byte(nil), privatePEM...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ownerDER})...)
	if err := validateBootstrapSeedContent(combined, true, loaded.activations); err == nil {
		t.Fatal("trailing owner signer admitted to private Vault reference")
	}
	loaded.declaration.Seeds[0].CommandTrust[0].PublicKeyFile = publicPath
	if err := prepareBootstrapControlSeeds(lookup, &loaded); err == nil {
		t.Fatal("owner key admitted as runtime authority")
	}
	loaded.declaration.Seeds[0].CommandTrust[0].PublicKeyFile = runtimePath
	loaded.declaration.Seeds[0].CommandTrust[0].CandidateID = "unknown-candidate"
	if err := prepareBootstrapControlSeeds(lookup, &loaded); err == nil {
		t.Fatal("unadmitted candidate accepted")
	}
	loaded.declaration.Seeds[0].CommandTrust[0].CandidateID = "gru-controller-gru-1"
	loaded.declaration.Seeds[0].PrivateKeySecretID = ""
	if err := prepareBootstrapControlSeeds(lookup, &loaded); err == nil {
		t.Fatal("private seed accepted without Vault reference")
	}
}
