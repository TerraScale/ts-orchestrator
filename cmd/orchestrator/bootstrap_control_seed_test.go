package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"

	"math/big"
	"os"
	"path/filepath"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
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
	hostSeed := bootstrapControlHostSeed{HostID: "gru-1", NATS: bootstrapControlCredentials{URL: "tls://nats.example:4222", CAFile: write("ca.pem", certificatePEM), CertificateFile: write("client.pem", certificatePEM), PrivateKeyFile: write("client.key", privatePEM), NKeySeedFile: write("user.seed", seed)}, PrivateKeySecretID: "ocid1.vaultsecret.oc1.test.client", PrivateKeyVersion: 1, NKeySecretID: "ocid1.vaultsecret.oc1.test.user", NKeyVersion: 2, CommandTrust: []bootstrapHostTrustReference{{CandidateID: "gru-controller-gru-1", PublicKeyFile: runtimePath}}}
	loaded := loadedBootstrapControl{declaration: bootstrapControlConfig{Generation: 1, Regions: []bootstrapControlRegion{{Code: "gru", OCIRegion: "sa-saopaulo-1", MemberCount: 1, CommandCandidateID: "gru-controller-gru-1"}}, Members: []bootstrapControlMember{{HostID: "gru-1", Region: "gru", Index: 1}}, Seeds: []bootstrapControlHostSeed{hostSeed}, Activations: []bootstrapControlActivation{{HostID: "gru-1", OwnerPublicKeyFile: publicPath}}}, activations: map[string]loadedControlActivation{"gru-1": activation}, signers: map[string]*security.CommandSignatureSigner{"gru": runtimeSigner}}
	lookup := func(key string) (string, bool) {
		values := map[string]string{ocireconcile.TSNodeVersionEnvironment: "1.2.3", ocireconcile.TSNodeSHA256Environment: strings.Repeat("ab", 32), ocireconcile.TSNodeURLEnvironment: "https://releases.terrascale.tech/ts-node", bootstrapReleaseKeyEnvironment: hex.EncodeToString(bytes.Repeat([]byte{1}, 32))}
		value, ok := values[key]
		return value, ok
	}
	if err := prepareBootstrapControlSeeds(lookup, &loaded); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(loaded.seeds["gru"][1])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, privatePEM) || bytes.Contains(raw, seed) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(privatePEM))) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(seed))) {
		t.Fatal("private credential leaked into OCI user-data")
	}
	if !bytes.Contains(raw, []byte("/etc/terrascale/host-secrets.json")) || !bytes.Contains(raw, []byte("User=root")) {
		t.Fatal("public secret references or canonical host unit missing")
	}
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
