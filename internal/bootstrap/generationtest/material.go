// Package generationtest builds complete, valid material generations for
// tests of TS-568 in-place renewal.
package generationtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/roleidentity"
)

// Authority is a certificate and the key that signs under it.
type Authority struct {
	Certificate *x509.Certificate
	Key         *ecdsa.PrivateKey
}

// Material is one generation's renewable files and the keys behind them.
// Files may hold controller-<slot>.json, which Generation pins as configs.
type Material struct {
	Files                                                map[string][]byte
	OperatorID, SystemID, CellID, HostSignerID, SignerID string
	Operator, System, Cell, HostSigner, Signer           nkeys.KeyPair
	CA, ControllerIssuer                                 Authority
	// RoleSignerID makes Generation write schema 2 (TS-668).
	RoleSignerID string
}

// Certificate issues template under parent, or self-signed when parent is
// nil, and returns its authority, certificate PEM and key PEM.
func Certificate(t testing.TB, template *x509.Certificate, parent *Authority) (Authority, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if template.SerialNumber == nil {
		template.SerialNumber, _ = rand.Int(rand.Reader, big.NewInt(1<<62))
	}
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.Certificate, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return Authority{Certificate: certificate, Key: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// CA is a CA template valid from an hour before now until notAfter.
func CA(name string, now, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
}

// ControllerIssuer is the controller TLS issuer template under a cell CA.
func ControllerIssuer(now, notAfter time.Time) *x509.Certificate {
	template := CA("TerraScale gru controller issuer", now, notAfter)
	template.MaxPathLenZero = true
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	return template
}

// HostIssuer is the host TLS issuer template of cell gru, as hostenroll loads it.
func HostIssuer(now, notAfter time.Time) *x509.Certificate {
	template := CA("TerraScale gru host issuer", now, notAfter)
	template.MaxPathLenZero = true
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	template.PermittedDNSDomainsCritical = true
	template.PermittedDNSDomains = []string{".hosts.gru.terrascale.internal"}
	template.PermittedURIDomains = []string{"hosts.gru.terrascale.internal"}
	return template
}

// New builds material valid for a year from now, for cell gru: a cell CA,
// controller and host issuers under it, and the operator, system and cell
// account JWTs with the host scope and a controller account signer.
func New(t testing.TB, now time.Time) Material {
	t.Helper()
	operator, _ := nkeys.CreateOperator()
	system, _ := nkeys.CreateAccount()
	cell, _ := nkeys.CreateAccount()
	hostSigner, _ := nkeys.CreateAccount()
	return Rollover(t, now, Material{Operator: operator, System: system, Cell: cell, HostSigner: hostSigner})
}

// Rollover builds a new CA, issuers and account signer for the NATS
// operator, system and cell accounts and host signer of previous.
func Rollover(t testing.TB, now time.Time, previous Material) Material {
	t.Helper()
	operator, system, cell, hostSigner := previous.Operator, previous.System, previous.Cell, previous.HostSigner
	year := now.AddDate(1, 0, 0)
	ca, caPEM, _ := Certificate(t, CA("TerraScale gru controller CA", now, year), nil)
	controllerIssuer, controllerCert, controllerKey := Certificate(t, ControllerIssuer(now, year.Add(-time.Hour)), &ca)
	_, hostCert, hostKey := Certificate(t, HostIssuer(now, year.Add(-time.Hour)), &ca)
	signer, _ := nkeys.CreateAccount()
	operatorID, _ := operator.PublicKey()
	systemID, _ := system.PublicKey()
	cellID, _ := cell.PublicKey()
	hostSignerID, _ := hostSigner.PublicKey()
	signerID, _ := signer.PublicKey()
	signerSeed, _ := signer.Seed()
	operatorClaims := jwt.NewOperatorClaims(operatorID)
	operatorClaims.SystemAccount = systemID
	operatorJWT, err := operatorClaims.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	systemClaims := jwt.NewAccountClaims(systemID)
	systemClaims.Expires = year.Unix()
	systemJWT, _ := systemClaims.Encode(operator)
	cellClaims := jwt.NewAccountClaims(cellID)
	cellClaims.Expires = year.Unix()
	cellClaims.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: jwt.NoLimit, DiskStorage: jwt.NoLimit,
		Streams: jwt.NoLimit, Consumer: jwt.NoLimit}
	cellClaims.SigningKeys.AddScopedSigner(bootstrapmaterial.HostScope("gru", hostSignerID))
	cellClaims.SigningKeys.Add(signerID)
	cellJWT, _ := cellClaims.Encode(operator)
	user, _ := nkeys.CreateUser()
	userID, _ := user.PublicKey()
	userSeed, _ := user.Seed()
	userClaims := jwt.NewUserClaims(userID)
	userClaims.Expires = year.Unix()
	userClaims.Pub.Allow = jwt.StringList{"$SYS.REQ.ACCOUNT." + cellID + ".CLAIMS.UPDATE"}
	userClaims.Sub.Allow = jwt.StringList{protocol.InboxGrant("gru", userID)}
	userJWT, _ := userClaims.Encode(system)
	systemCreds, _ := jwt.FormatUserConfig(userJWT, userSeed)
	return Material{Files: map[string][]byte{
		"ca.pem": caPEM, "operator.jwt": []byte(operatorJWT + "\n"), "system.jwt": []byte(systemJWT + "\n"),
		"cell.jwt": []byte(cellJWT + "\n"), "system.creds": systemCreds,
		"host-tls-issuer-cert.pem": hostCert, "host-tls-issuer-key.pem": hostKey,
		"controller-tls-issuer-cert.pem": controllerCert, "controller-tls-issuer-key.pem": controllerKey,
		"controller-account-signer.seed": append(signerSeed, '\n'),
	}, OperatorID: operatorID, SystemID: systemID, CellID: cellID, HostSignerID: hostSignerID, SignerID: signerID,
		Operator: operator, System: system, Cell: cell, HostSigner: hostSigner, Signer: signer,
		CA: ca, ControllerIssuer: controllerIssuer}
}

// Generation pins every file of the material for expected: schema 1, or
// schema 2 once the material has a role signer.
func (material Material) Generation(expected bootstrap.MaterialGenerationExpectation, number uint64, previous string,
) bootstrap.MaterialGeneration {
	generation := bootstrap.MaterialGeneration{SchemaVersion: 1,
		DeploymentID: expected.DeploymentID, Environment: expected.Environment, ClusterID: expected.ClusterID,
		Cell: expected.Cell, ControllerSlots: expected.ControllerSlots, Generation: number, Previous: previous,
		Operator: material.OperatorID, SystemAccount: material.SystemID, CellAccount: material.CellID,
		HostSigner: material.HostSignerID, AccountSigner: material.SignerID, RoleSigner: material.RoleSignerID}
	if material.RoleSignerID != "" {
		generation.SchemaVersion = 2
	}
	if material.SignerID != "" {
		generation.IssuedLifetimeHours = 24 * 7
	}
	for _, slot := range expected.ControllerSlots {
		if data, ok := material.Files["controller-"+slot+".json"]; ok {
			generation.ControllerConfigs = append(generation.ControllerConfigs, bootstrap.GenerationControllerConfig{
				Slot: slot, ManifestSHA256: digest([]byte("manifest of " + slot)), SHA256: digest(data), Size: int64(len(data))})
		}
	}
	for name, data := range material.Files {
		if strings.HasSuffix(name, ".json") {
			continue
		}
		purpose, slot := bootstrap.MaterialGenerationFiles()[name], ""
		if purpose == "" {
			purpose = bootstrap.SecretInterRegion
			for _, candidate := range expected.ControllerSlots {
				if cert, key := bootstrap.InterRegionTLSFiles(candidate); name == cert || name == key {
					slot = candidate
				}
			}
		}
		generation.Secrets = append(generation.Secrets, bootstrap.SecretReference{Purpose: purpose, Slot: slot,
			SecretOCID: fmt.Sprintf("ocid1.vaultsecret.oc1.sa-saopaulo-1.g%d-%s", number,
				strings.NewReplacer(".", "-", "_", "-").Replace(name)),
			VersionNumber: 1, SHA256: digest(data), MaxBytes: bootstrap.MaxSecretBytes, TargetFile: name})
	}
	return generation
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SchemaTwo adds the role signer (TS-651), derived from the host signer, to
// cell.jwt, so Generation writes schema 2.
func (material Material) SchemaTwo(t testing.TB) Material {
	t.Helper()
	signer, err := roleidentity.Signer(material.HostSigner)
	if err != nil {
		t.Fatal(err)
	}
	material.RoleSignerID, _ = signer.PublicKey()
	signer.Wipe()
	return material.With(map[string][]byte{"cell.jwt": material.Account(t, "cell.jwt", func(claims *jwt.AccountClaims) {
		claims.SigningKeys.AddScopedSigner(roleidentity.Scope(material.RoleSignerID))
	})})
}

// WithoutIssuers drops the controller issuers and the account signer, as
// gru-1 and sfo-1 were founded.
func (material Material) WithoutIssuers(t testing.TB) Material {
	t.Helper()
	cell := material.Account(t, "cell.jwt", func(claims *jwt.AccountClaims) { delete(claims.SigningKeys, material.SignerID) })
	copied := material.With(map[string][]byte{"cell.jwt": cell})
	for _, name := range []string{"controller-tls-issuer-cert.pem", "controller-tls-issuer-key.pem",
		"controller-account-signer.seed"} {
		delete(copied.Files, name)
	}
	copied.SignerID, copied.Signer = "", nil
	return copied
}

// InterRegion adds cell gru's leaf fabric (TS-668) in the tree
// sfo <- gru <- fra, so gru both dials a parent and accepts a child:
// system.jwt and cell.jwt with the contract, interregion.jwt, the
// interregion CA, each slot's leaf TLS, leaf-sfo.creds and each slot's
// controller config.
func (material Material) InterRegion(t testing.TB, now time.Time, slots []string) Material {
	t.Helper()
	year := now.AddDate(1, 0, 0)
	topology := natscell.LeafTopology{Hub: "sfo", Parents: map[string]string{"gru": "sfo", "fra": "gru"}}
	contract := natscell.InterRegionContract{Cell: "gru", Peers: topology.Peers("gru"), GlobalHome: "sfo",
		Subtrees: topology.Subtrees("gru")}
	account, _ := nkeys.CreateAccount()
	accountID, _ := account.PublicKey()
	child, _ := nkeys.CreateAccount()
	childID, _ := child.PublicKey()
	interregion := jwt.NewAccountClaims(accountID)
	interregion.Expires = year.Unix()
	contract.ApplyInterRegion(interregion, material.CellID, 2, map[string]string{"fra": childID})
	interregionJWT, err := interregion.Encode(material.Operator)
	if err != nil {
		t.Fatal(err)
	}
	parent, _ := nkeys.CreateAccount()
	parentID, _ := parent.PublicKey()
	parentSigner, _ := nkeys.CreateAccount()
	user, _ := nkeys.CreateUser()
	userID, _ := user.PublicKey()
	userSeed, _ := user.Seed()
	userClaims := jwt.NewUserClaims(userID)
	userClaims.UserPermissionLimits = jwt.UserPermissionLimits{}
	userClaims.IssuerAccount = parentID
	userClaims.Expires = year.Unix()
	userJWT, err := userClaims.Encode(parentSigner)
	if err != nil {
		t.Fatal(err)
	}
	leafCreds, _ := jwt.FormatUserConfig(userJWT, userSeed)
	ca, caPEM, _ := Certificate(t, CA("TerraScale interregion CA", now, year), nil)
	files := map[string][]byte{
		"system.jwt": material.Account(t, "system.jwt", func(claims *jwt.AccountClaims) { claims.Limits.LeafNodeConn = 0 }),
		"cell.jwt": material.Account(t, "cell.jwt", func(claims *jwt.AccountClaims) {
			contract.ApplyCell(claims, accountID)
		}),
		"interregion.jwt": []byte(interregionJWT + "\n"), "interregion-ca.pem": caPEM, "leaf-sfo.creds": leafCreds,
	}
	const directory = "/var/lib/terrascale-orchestrator-secrets/"
	for _, slot := range slots {
		certName, keyName := bootstrap.InterRegionTLSFiles(slot)
		_, files[certName], files[keyName] = Certificate(t, &x509.Certificate{Subject: pkix.Name{CommonName: "gru-" + slot},
			DNSNames: []string{"leaf.gru.interregion.terrascale.internal"}, NotBefore: now.Add(-time.Hour), NotAfter: year,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}, &ca)
		leafTLS := natscell.TLSFiles{CAFile: directory + "interregion-ca.pem", CertFile: directory + certName,
			KeyFile: directory + keyName}
		config, err := json.Marshal(map[string]any{"controller": map[string]any{"candidate_id": slot},
			"nats": natscell.Config{Cell: "gru", Instance: slot, Embedded: &natscell.Embedded{
				CellJWTFile: directory + "cell.jwt", SystemJWTFile: directory + "system.jwt",
				InterRegion: &natscell.InterRegion{Enabled: true, Peers: contract.Peers, GlobalHome: "sfo",
					AccountJWTFile: directory + "interregion.jwt", Subtrees: contract.Subtrees, Topology: &topology,
					Listen: &natscell.LeafListen{Host: "0.0.0.0", Port: 7422, TLS: leafTLS},
					Remotes: []natscell.LeafRemote{{Peer: "sfo", URLs: []string{"nats-leaf://10.1.0.10:7422"},
						ServerName:      "leaf.gru.interregion.terrascale.internal",
						CredentialsFile: directory + "leaf-sfo.creds", PeerAccount: parentID, TLS: leafTLS}}}}}},
			json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		files["controller-"+slot+".json"] = config
	}
	return material.With(files)
}

// Account re-signs one of the material's account JWTs after edit.
func (material Material) Account(t testing.TB, name string, edit func(*jwt.AccountClaims)) []byte {
	t.Helper()
	claims, err := jwt.DecodeAccountClaims(strings.TrimSpace(string(material.Files[name])))
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

// Read returns one file.
func (material Material) Read(name string) ([]byte, error) {
	data, ok := material.Files[name]
	if !ok {
		return nil, errors.New("missing")
	}
	return data, nil
}

// With copies the material with some files replaced.
func (material Material) With(files map[string][]byte) Material {
	copied := material
	copied.Files = map[string][]byte{}
	for name, data := range material.Files {
		copied.Files[name] = data
	}
	for name, data := range files {
		copied.Files[name] = data
	}
	return copied
}
