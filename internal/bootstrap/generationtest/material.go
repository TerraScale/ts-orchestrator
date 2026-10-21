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

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/roleconfig"
	"github.com/TerraScale/ts-orchestrator/internal/roleidentity"
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
	// RoleSignerID is the role-scoped account signer.
	RoleSignerID string
	// Region is the cell token whose hosts the host issuer and scope serve;
	// New's is gru.
	Region string
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
func HostIssuer(now, notAfter time.Time) *x509.Certificate { return hostIssuer("gru", now, notAfter) }

func hostIssuer(region string, now, notAfter time.Time) *x509.Certificate {
	template := CA("TerraScale "+region+" host issuer", now, notAfter)
	template.MaxPathLenZero = true
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	template.PermittedDNSDomainsCritical = true
	template.PermittedDNSDomains = []string{".hosts." + region + ".terrascale.internal"}
	template.PermittedURIDomains = []string{"hosts." + region + ".terrascale.internal"}
	return template
}

// New builds material valid for a year from now, for cell gru: a cell CA,
// controller and host issuers under it, and the operator, system and cell
// account JWTs with the host scope and a controller account signer.
func New(t testing.TB, now time.Time) Material { return NewCell(t, now, "gru") }

// NewCell is New for the cell whose token is region.
func NewCell(t testing.TB, now time.Time, region string) Material {
	t.Helper()
	operator, _ := nkeys.CreateOperator()
	system, _ := nkeys.CreateAccount()
	cell, _ := nkeys.CreateAccount()
	hostSigner, _ := nkeys.CreateAccount()
	return Rollover(t, now, Material{Operator: operator, System: system, Cell: cell, HostSigner: hostSigner, Region: region})
}

// Rollover builds a new CA, issuers and account signer for the NATS
// operator, system and cell accounts and host signer of previous.
func Rollover(t testing.TB, now time.Time, previous Material) Material {
	t.Helper()
	operator, system, cell, hostSigner, region := previous.Operator, previous.System, previous.Cell, previous.HostSigner, previous.Region
	year := now.AddDate(1, 0, 0)
	ca, caPEM, _ := Certificate(t, CA("TerraScale gru controller CA", now, year), nil)
	controllerIssuer, controllerCert, controllerKey := Certificate(t, ControllerIssuer(now, year.Add(-time.Hour)), &ca)
	_, hostCert, hostKey := Certificate(t, hostIssuer(region, now, year.Add(-time.Hour)), &ca)
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
	cellClaims.SigningKeys.AddScopedSigner(bootstrapmaterial.HostScope(region, hostSignerID))
	cellClaims.SigningKeys.Add(signerID)
	cellJWT, _ := cellClaims.Encode(operator)
	user, _ := nkeys.CreateUser()
	userID, _ := user.PublicKey()
	userSeed, _ := user.Seed()
	userClaims := jwt.NewUserClaims(userID)
	userClaims.Expires = year.Unix()
	userClaims.Pub.Allow = jwt.StringList{"$SYS.REQ.ACCOUNT." + cellID + ".CLAIMS.UPDATE"}
	userClaims.Sub.Allow = jwt.StringList{protocol.InboxGrant(region, userID)}
	userJWT, _ := userClaims.Encode(system)
	systemCreds, _ := jwt.FormatUserConfig(userJWT, userSeed)
	return Material{Files: map[string][]byte{
		"ca.pem": caPEM, "operator.jwt": []byte(operatorJWT + "\n"), "system.jwt": []byte(systemJWT + "\n"),
		"cell.jwt": []byte(cellJWT + "\n"), "system.creds": systemCreds,
		"host-tls-issuer-cert.pem": hostCert, "host-tls-issuer-key.pem": hostKey,
		"controller-tls-issuer-cert.pem": controllerCert, "controller-tls-issuer-key.pem": controllerKey,
		"controller-account-signer.seed": append(signerSeed, '\n'),
	}, OperatorID: operatorID, SystemID: systemID, CellID: cellID, HostSignerID: hostSignerID, SignerID: signerID,
		Operator: operator, System: system, Cell: cell, HostSigner: hostSigner, Signer: signer, Region: region,
		CA: ca, ControllerIssuer: controllerIssuer}.withRoleSigner(t)
}

// Generation pins every file of the material under the v1 contract.
func (material Material) Generation(expected bootstrap.MaterialGenerationExpectation, number uint64, previous string,
) bootstrap.MaterialGeneration {
	generation := bootstrap.MaterialGeneration{SchemaVersion: bootstrap.MaterialGenerationSchemaVersion,
		DeploymentID: expected.DeploymentID, Environment: expected.Environment, ClusterID: expected.ClusterID,
		Cell: expected.Cell, ControllerSlots: expected.ControllerSlots, Generation: number, Previous: previous,
		Operator: material.OperatorID, SystemAccount: material.SystemID, CellAccount: material.CellID,
		HostSigner: material.HostSignerID, AccountSigner: material.SignerID, RoleSigner: material.RoleSignerID}
	if material.SignerID != "" {
		generation.IssuedLifetimeHours = 24 * 7
	}
	for _, slot := range expected.ControllerSlots {
		if data, ok := material.Files["controller-"+slot+".json"]; ok {
			generation.ControllerConfigs = append(generation.ControllerConfigs, bootstrap.GenerationControllerConfig{
				Slot: slot, AcceptanceSHA256: digest([]byte("manifest of " + slot)), SHA256: digest(data), Size: int64(len(data))})
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
				if name == candidate+".creds" {
					purpose, slot = bootstrap.SecretController, candidate
				}
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

// WithControllerCredentials adds offline-issued, slot-bound controller users
// and points each supplied config at its own credentials.
func (material Material) WithControllerCredentials(t testing.TB, slots []string) Material {
	t.Helper()
	files := map[string][]byte{}
	for _, slot := range slots {
		name := "controller-" + slot + ".json"
		var config struct {
			Version    int             `json:"version"`
			Controller map[string]any  `json:"controller"`
			NATS       natscell.Config `json:"nats"`
		}
		data, exists := material.Files[name]
		if !exists {
			t.Fatalf("WithControllerCredentials: slot %s has no %s", slot, name)
		}
		if err := json.Unmarshal(data, &config); err != nil {
			t.Fatalf("WithControllerCredentials: decode %s: %v", name, err)
		}
		config.NATS.CredentialsFile = bootstrap.MaterialDirectory + "/" + slot + ".creds"
		var ir *natscell.InterRegion
		if embedded := config.NATS.Embedded; embedded != nil {
			ir = embedded.InterRegion
		}
		home, err := ir.GlobalControlHome(config.NATS.Cell)
		if err != nil {
			t.Fatal(err)
		}
		globalHome := home == config.NATS.Cell
		user, _ := nkeys.CreateUser()
		public, _ := user.PublicKey()
		seed, _ := user.Seed()
		claim := jwt.NewUserClaims(public)
		claim.Expires = material.CA.Certificate.NotAfter.Unix()
		claim.Pub.Allow = natscell.ControllerPublishes("gru")
		if globalHome {
			claim.Pub.Allow.Add(natscell.GlobalControllerPublishes()...)
		}
		claim.Sub.Allow = jwt.StringList{protocol.InboxGrant("gru", public), protocol.Broker("gru", "ticket", ">"),
			protocol.Broker("gru", "fence", slot)}
		claim.Sub.Allow.Add(natscell.ControllerSubscriptions("gru")...)
		claim.Sub.Allow.Add(protocol.ObservabilityGrant("gru"))
		claim.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second}
		raw, err := claim.Encode(material.Cell)
		if err != nil {
			t.Fatal(err)
		}
		files[slot+".creds"], _ = jwt.FormatUserConfig(raw, seed)
		files[name], err = json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		clear(seed)
		user.Wipe()
	}
	return material.With(files)
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// withRoleSigner pins the host-derived role signer in cell.jwt.
func (material Material) withRoleSigner(t testing.TB) Material {
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
// gru-1 and sjc-1 were founded.
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
// sjc <- gru <- fra, so gru both dials a parent and accepts a child:
// system.jwt and cell.jwt with the contract, interregion.jwt, the
// interregion CA, each slot's leaf TLS, leaf-sjc.creds and each slot's
// controller config.
func (material Material) InterRegion(t testing.TB, now time.Time, slots []string) Material {
	t.Helper()
	year := now.AddDate(1, 0, 0)
	topology := natscell.LeafTopology{Hub: "sjc", Parents: map[string]string{"gru": "sjc", "fra": "gru"}}
	contract := natscell.InterRegionContract{Cell: "gru", Peers: topology.Peers("gru"), GlobalHome: "sjc",
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
		"interregion.jwt": []byte(interregionJWT + "\n"), "interregion-ca.pem": caPEM, "leaf-sjc.creds": leafCreds,
	}
	const directory = bootstrap.MaterialDirectory + "/"
	for _, slot := range slots {
		certName, keyName := bootstrap.InterRegionTLSFiles(slot)
		_, files[certName], files[keyName] = Certificate(t, &x509.Certificate{Subject: pkix.Name{CommonName: "gru-" + slot},
			DNSNames: []string{"leaf.gru.interregion.terrascale.internal"}, NotBefore: now.Add(-time.Hour), NotAfter: year,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}, &ca)
		leafTLS := natscell.TLSFiles{CAFile: directory + "interregion-ca.pem", CertFile: directory + certName,
			KeyFile: directory + keyName}
		config, err := json.Marshal(map[string]any{"version": roleconfig.Version, "controller": map[string]any{"candidate_id": slot},
			"nats": natscell.Config{Cell: "gru", Instance: slot, Embedded: &natscell.Embedded{
				CellJWTFile: directory + "cell.jwt", SystemJWTFile: directory + "system.jwt",
				InterRegion: &natscell.InterRegion{Peers: contract.Peers, GlobalHome: "sjc",
					AccountJWTFile: directory + "interregion.jwt", Subtrees: contract.Subtrees, Topology: &topology,
					Listen: &natscell.LeafListen{Host: "0.0.0.0", Port: 7422, TLS: leafTLS},
					Remotes: []natscell.LeafRemote{{Peer: "sjc", URLs: []string{"nats-leaf://10.1.0.10:7422"},
						ServerName:      "leaf.gru.interregion.terrascale.internal",
						CredentialsFile: directory + "leaf-sjc.creds", PeerAccount: parentID, TLS: leafTLS}}}}}},
			json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		files["controller-"+slot+".json"] = config
	}
	return material.With(files)
}

// Link adds the region link (TS-803): cell.jwt with the link signer, the
// interregion CA, each slot's leaf TLS and a controller config with a link
// block, and outside the home link.creds for another account.
func (material Material) Link(t testing.TB, now time.Time, slots []string) Material {
	t.Helper()
	year := now.AddDate(1, 0, 0)
	signer, _ := nkeys.CreateAccount()
	signerID, _ := signer.PublicKey()
	ca, caPEM, _ := Certificate(t, CA("TerraScale interregion CA", now, year), nil)
	files := map[string][]byte{"interregion-ca.pem": caPEM,
		"cell.jwt": material.Account(t, "cell.jwt", func(claims *jwt.AccountClaims) { natscell.ApplyLink(claims, signerID) })}
	const directory = bootstrap.MaterialDirectory + "/"
	var credentials string
	if material.Region != natscell.LinkHome {
		home, _ := nkeys.CreateAccount()
		homeID, _ := home.PublicKey()
		creds, err := natscell.IssueLinkUser(signer, homeID, material.Region, now, year)
		if err != nil {
			t.Fatal(err)
		}
		files[bootstrap.LinkCredentialsFile], credentials = creds, directory+bootstrap.LinkCredentialsFile
	}
	for _, slot := range slots {
		certName, keyName := bootstrap.InterRegionTLSFiles(slot)
		_, files[certName], files[keyName] = Certificate(t, &x509.Certificate{Subject: pkix.Name{CommonName: material.Region + "-" + slot},
			DNSNames: []string{"leaf." + material.Region + ".interregion.terrascale.internal"}, NotBefore: now.Add(-time.Hour),
			NotAfter: year, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}, &ca)
		config, err := json.Marshal(map[string]any{"version": roleconfig.Version, "controller": map[string]any{"candidate_id": slot},
			"nats": natscell.Config{Cell: material.Region, Instance: slot, Embedded: &natscell.Embedded{
				CellJWTFile: directory + "cell.jwt", SystemJWTFile: directory + "system.jwt",
				Link: &natscell.Link{CredentialsFile: credentials, TLS: natscell.TLSFiles{CAFile: directory + "interregion-ca.pem",
					CertFile: directory + certName, KeyFile: directory + keyName}}}}}, json.Deterministic(true))
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
