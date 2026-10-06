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
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// Authority is a certificate and the key that signs under it.
type Authority struct {
	Certificate *x509.Certificate
	Key         *ecdsa.PrivateKey
}

// Material is one generation's renewable files and the keys behind them.
type Material struct {
	Files                                                map[string][]byte
	OperatorID, SystemID, CellID, HostSignerID, SignerID string
	Operator, System, Cell, HostSigner, Signer           nkeys.KeyPair
	CA, ControllerIssuer                                 Authority
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

// Generation pins every file of the material for expected.
func (material Material) Generation(expected bootstrap.MaterialGenerationExpectation, number uint64, previous string,
) bootstrap.MaterialGeneration {
	generation := bootstrap.MaterialGeneration{SchemaVersion: bootstrap.MaterialGenerationSchemaVersion,
		DeploymentID: expected.DeploymentID, Environment: expected.Environment, ClusterID: expected.ClusterID,
		Cell: expected.Cell, ControllerSlots: expected.ControllerSlots, Generation: number, Previous: previous,
		Operator: material.OperatorID, SystemAccount: material.SystemID, CellAccount: material.CellID,
		HostSigner: material.HostSignerID, AccountSigner: material.SignerID, IssuedLifetimeHours: 24 * 7}
	for name, purpose := range bootstrap.MaterialGenerationFiles() {
		digest := sha256.Sum256(material.Files[name])
		generation.Secrets = append(generation.Secrets, bootstrap.SecretReference{Purpose: purpose,
			SecretOCID: fmt.Sprintf("ocid1.vaultsecret.oc1.sa-saopaulo-1.g%d-%s", number,
				strings.NewReplacer(".", "-", "_", "-").Replace(name)),
			VersionNumber: 1, SHA256: hex.EncodeToString(digest[:]), MaxBytes: bootstrap.MaxSecretBytes, TargetFile: name})
	}
	return generation
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
