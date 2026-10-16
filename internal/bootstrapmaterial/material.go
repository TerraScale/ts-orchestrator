// Package bootstrapmaterial prepares one durable, owner-only source for the
// initial regional controller credentials. Vault publication reads these exact
// bytes; a second invocation never creates replacement keys.
package bootstrapmaterial

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

const (
	MaxValidity  = 365 * 24 * time.Hour
	minValidity  = 24 * time.Hour
	metadataName = "material.json"
	readyName    = "READY"
)

var ErrMaterial = errors.New("controller bootstrap material is invalid or incomplete")

type Slot struct {
	Name      string `json:"name"`
	PrivateIP string `json:"privateIp"`
}

type Config struct {
	Environment   string `json:"environment"`
	Region        string `json:"region"`
	Cell          string `json:"cell"`
	DeploymentID  string `json:"deploymentId"`
	ClusterID     string `json:"clusterId"`
	SubnetCIDR    string `json:"subnetCidr"`
	Slots         []Slot `json:"slots"`
	ValidityHours int    `json:"validityHours"`
	// LinkSigner is the public account key of the home region's link signer.
	// When set, the cell account carries the link signing key (natscell.ApplyLink).
	LinkSigner string `json:"linkSigner,omitempty"`
}

type File struct {
	Name     string                  `json:"name"`
	Purpose  bootstrap.SecretPurpose `json:"purpose"`
	Slot     string                  `json:"slot,omitempty"`
	SHA256   string                  `json:"sha256"`
	MaxBytes int64                   `json:"maxBytes"`
}

type Public struct {
	PeerSignerPublicKey         string `json:"peerSignerPublicKey"`
	LedgerSignerPublicKey       string `json:"ledgerSignerPublicKey"`
	TicketSignerPublicKey       string `json:"ticketSignerPublicKey"`
	ControllerResponsePublicKey string `json:"controllerResponsePublicKey"`
	HostNATSIssuerNKey          string `json:"hostNatsIssuerNkey"`
	OperatorNKey                string `json:"operatorNkey"`
	SystemAccountNKey           string `json:"systemAccountNkey"`
	CellAccountNKey             string `json:"cellAccountNkey"`
}

type Record struct {
	SchemaVersion int       `json:"schemaVersion"`
	Config        Config    `json:"config"`
	IssuedAt      time.Time `json:"issuedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
	Public        Public    `json:"public"`
	Files         []File    `json:"files"`
}

// MappedOCIRegion accepts the canonical lower-case material cell name and
// returns its fixed product OCI region.
func MappedOCIRegion(cell string) (string, error) {
	if cell != strings.ToLower(cell) {
		return "", ErrMaterial
	}
	return oci.Region(strings.ToUpper(cell)).OCIRegion()
}

func (cfg Config) validate() error {
	if cfg.Environment != "production" && cfg.Environment != "canary" {
		return ErrMaterial
	}
	region, err := MappedOCIRegion(cfg.Cell)
	if err != nil || cfg.Region != region ||
		cfg.LinkSigner != "" && !nkeys.IsValidPublicAccountKey(cfg.LinkSigner) ||
		!entityid.Valid(cfg.DeploymentID) ||
		!entityid.Valid(cfg.ClusterID) ||
		cfg.ValidityHours < int(minValidity.Hours()) || cfg.ValidityHours > int(MaxValidity.Hours()) ||
		len(cfg.Slots) != 3 {
		return ErrMaterial
	}
	prefix, err := netip.ParsePrefix(cfg.SubnetCIDR)
	if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Masked() != prefix {
		return ErrMaterial
	}
	for index, name := range []string{"controller-a", "controller-b", "controller-c"} {
		address, err := netip.ParseAddr(cfg.Slots[index].PrivateIP)
		if cfg.Slots[index].Name != name || err != nil || !address.Is4() || !prefix.Contains(address) ||
			address == prefix.Addr() || address == prefix.Addr().Next() {
			return ErrMaterial
		}
		for prior := range index {
			if cfg.Slots[prior].PrivateIP == cfg.Slots[index].PrivateIP {
				return ErrMaterial
			}
		}
	}
	return nil
}

// Validate binds the material cell to the canonical supported OCI region.
func (cfg Config) Validate() error { return cfg.validate() }

var (
	identityRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	clusterRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

// Generate creates an immutable local source. An incomplete directory is an
// operator hold: no automatic cleanup can prove that publication never began.
func Generate(directory string, cfg Config, now time.Time) (Record, error) {
	if err := cfg.validate(); err != nil || !filepath.IsAbs(directory) || now.IsZero() || secureParents(directory) != nil {
		return Record{}, ErrMaterial
	}
	if _, err := os.Lstat(directory); err == nil {
		record, loadErr := Load(directory)
		if loadErr != nil || !sameConfig(record.Config, cfg) {
			return Record{}, ErrMaterial
		}
		return record, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Record{}, ErrMaterial
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return Record{}, fmt.Errorf("create private material directory: %w", err)
	}
	files, public, err := build(cfg, now.UTC())
	if err != nil {
		return Record{}, err
	}
	defer func() {
		for _, body := range files {
			clear(body)
		}
	}()
	record := Record{SchemaVersion: 1, Config: cfg, IssuedAt: now.UTC(),
		ExpiresAt: now.UTC().Add(time.Duration(cfg.ValidityHours) * time.Hour), Public: public}
	for name, body := range files {
		purpose, slot := classify(name)
		if purpose == "" || len(body) == 0 || len(body) > int(bootstrap.MaxSecretBytes) {
			return Record{}, ErrMaterial
		}
		record.Files = append(record.Files, File{Name: name, Purpose: purpose, Slot: slot,
			SHA256: digest(body), MaxBytes: int64(len(body))})
	}
	slices.SortFunc(record.Files, func(a, b File) int { return strings.Compare(a.Name, b.Name) })
	for _, file := range record.Files {
		if err := writeOnce(filepath.Join(directory, file.Name), files[file.Name]); err != nil {
			return Record{}, fmt.Errorf("write private material %s: %w", file.Name, err)
		}
	}
	metadata, err := json.Marshal(record)
	if err != nil {
		return Record{}, err
	}
	if err := writeOnce(filepath.Join(directory, metadataName), metadata); err != nil {
		return Record{}, err
	}
	if err := writeOnce(filepath.Join(directory, readyName), []byte(digest(metadata)+"\n")); err != nil {
		return Record{}, err
	}
	if err := syncDirectory(directory); err != nil {
		return Record{}, err
	}
	return record, nil
}

// Load verifies a complete material source and every exact byte digest.
func Load(directory string) (Record, error) {
	if !filepath.IsAbs(directory) || secureParents(directory) != nil || secureDirectory(directory) != nil {
		return Record{}, ErrMaterial
	}
	metadata, err := readOwnedFile(filepath.Join(directory, metadataName), 1<<20)
	if err != nil {
		return Record{}, ErrMaterial
	}
	ready, err := readOwnedFile(filepath.Join(directory, readyName), 128)
	if err != nil || string(ready) != digest(metadata)+"\n" {
		return Record{}, ErrMaterial
	}
	var record Record
	if err := json.Unmarshal(metadata, &record, json.RejectUnknownMembers(true)); err != nil || record.SchemaVersion != 1 ||
		record.Config.validate() != nil ||
		len(record.Files) != len(expectedNames())+len(memberCANames)*boolInt(record.HasMemberCA()) ||
		record.ExpiresAt.Sub(record.IssuedAt) != time.Duration(record.Config.ValidityHours)*time.Hour {
		return Record{}, ErrMaterial
	}
	seen := make(map[string]bool, len(record.Files))
	for _, file := range record.Files {
		purpose, slot := classify(file.Name)
		if seen[file.Name] || file.Purpose != purpose || file.Slot != slot || purpose == "" ||
			file.MaxBytes <= 0 || file.MaxBytes > bootstrap.MaxSecretBytes {
			return Record{}, ErrMaterial
		}
		seen[file.Name] = true
		body, err := readOwnedFile(filepath.Join(directory, file.Name), file.MaxBytes)
		if err != nil || int64(len(body)) != file.MaxBytes || digest(body) != file.SHA256 {
			return Record{}, ErrMaterial
		}
		clear(body)
	}
	for _, name := range expectedNames() {
		if !seen[name] {
			return Record{}, ErrMaterial
		}
	}
	if seen[memberCANames[0]] != seen[memberCANames[1]] {
		return Record{}, ErrMaterial
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return Record{}, ErrMaterial
	}
	allowed := map[string]bool{metadataName: true, readyName: true, journalName: true, journalTempName: true, journalLockName: true}
	for _, file := range record.Files {
		allowed[file.Name] = true
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return Record{}, ErrMaterial
		}
		if entry.Name() == journalName {
			if _, err := readOwnedFile(filepath.Join(directory, entry.Name()), 1<<20); err != nil {
				return Record{}, ErrMaterial
			}
		} else if entry.Name() == journalTempName {
			if err := ownedRegular(filepath.Join(directory, entry.Name()), 0, 1<<20); err != nil {
				return Record{}, ErrMaterial
			}
		} else if entry.Name() == journalLockName {
			if err := ownedRegular(filepath.Join(directory, entry.Name()), 0, 0); err != nil {
				return Record{}, ErrMaterial
			}
		}
	}
	if len(entries) < len(record.Files)+2 {
		return Record{}, ErrMaterial
	}
	return record, nil
}

func sameConfig(a, b Config) bool {
	return a.Environment == b.Environment && a.Region == b.Region && a.Cell == b.Cell && a.DeploymentID == b.DeploymentID && a.ClusterID == b.ClusterID &&
		a.SubnetCIDR == b.SubnetCIDR && a.ValidityHours == b.ValidityHours && a.LinkSigner == b.LinkSigner &&
		slices.Equal(a.Slots, b.Slots)
}

// memberCANames are the cell's C# TerraBase member CA. Generate always
// creates them; material generated before they existed lacks both and still
// loads, but cannot serve a TerraBase workload.
var memberCANames = [2]string{"terrabase-member-ca.pem", "terrabase-member-ca.key"}

// HasMemberCA reports whether the material carries the member CA pair.
func (record Record) HasMemberCA() bool {
	return slices.ContainsFunc(record.Files, func(file File) bool { return file.Name == memberCANames[0] })
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// expectedNames are the files every material source has.
func expectedNames() []string {
	names := []string{"issuer-operator.seed", "issuer-system.seed", "issuer-cell.seed", "issuer-ca.key",
		"operator.jwt", "operator.creds", "operator-tls-cert.pem", "operator-tls-key.pem",
		"system.jwt", "cell.jwt", "system.creds", "ca.pem", "route-password",
		"ticket.pub", "ticket.key", "founder-peer.key", "founder-ledger.key",
		"host-nats-issuer.seed", "host-tls-issuer-key.pem", "host-tls-issuer-cert.pem"}
	for _, slot := range []string{"controller-a", "controller-b", "controller-c"} {
		names = append(names, slot+".creds", slot+"-tls-cert.pem", slot+"-tls-key.pem", slot+"-response.key")
	}
	return names
}

func build(cfg Config, now time.Time) (map[string][]byte, Public, error) {
	files := make(map[string][]byte)
	expires := now.Add(time.Duration(cfg.ValidityHours) * time.Hour)
	op, err := nkeys.CreateOperator()
	if err != nil {
		return nil, Public{}, err
	}
	defer op.Wipe()
	sys, err := nkeys.CreateAccount()
	if err != nil {
		return nil, Public{}, err
	}
	defer sys.Wipe()
	cell, err := nkeys.CreateAccount()
	if err != nil {
		return nil, Public{}, err
	}
	defer cell.Wipe()
	opID, _ := op.PublicKey()
	sysID, _ := sys.PublicKey()
	cellID, _ := cell.PublicKey()
	hostIssuer, err := nkeys.CreateAccount()
	if err != nil {
		return nil, Public{}, err
	}
	defer hostIssuer.Wipe()
	hostIssuerID, err := hostIssuer.PublicKey()
	if err != nil {
		return nil, Public{}, err
	}
	hostIssuerSeed, err := hostIssuer.Seed()
	if err != nil {
		return nil, Public{}, err
	}
	files["host-nats-issuer.seed"] = bytes.Clone(hostIssuerSeed)
	for name, pair := range map[string]nkeys.KeyPair{"issuer-operator.seed": op, "issuer-system.seed": sys, "issuer-cell.seed": cell} {
		seed, err := pair.Seed()
		if err != nil {
			return nil, Public{}, err
		}
		files[name] = bytes.Clone(seed)
	}
	opClaim := jwt.NewOperatorClaims(opID)
	opClaim.SystemAccount = sysID
	opClaim.IssuedAt, opClaim.Expires = now.Unix(), expires.Unix()
	opJWT, err := opClaim.Encode(op)
	if err != nil {
		return nil, Public{}, err
	}
	sysClaim := jwt.NewAccountClaims(sysID)
	sysClaim.IssuedAt, sysClaim.Expires = now.Unix(), expires.Unix()
	sysJWT, err := sysClaim.Encode(op)
	if err != nil {
		return nil, Public{}, err
	}
	cellClaim := jwt.NewAccountClaims(cellID)
	cellClaim.IssuedAt, cellClaim.Expires = now.Unix(), expires.Unix()
	// Operator mode enables JetStream only for accounts whose JWT carries
	// JetStream limits. The server-wide store limit still bounds the cell.
	cellClaim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: jwt.NoLimit, DiskStorage: jwt.NoLimit,
		Streams: jwt.NoLimit, Consumer: jwt.NoLimit}
	hostScope := expectedHostScope(cfg.Cell, hostIssuerID)
	cellClaim.SigningKeys.AddScopedSigner(hostScope)
	// The role signer (TS-651) from the start, so a new cell's roles get
	// NATS identities without a role-claim and broker-claim-apply.
	role, err := roleScope(hostIssuer)
	if err != nil {
		return nil, Public{}, err
	}
	cellClaim.SigningKeys.AddScopedSigner(role)
	if cfg.LinkSigner != "" {
		natscell.ApplyLink(cellClaim, cfg.LinkSigner)
	}
	cellJWT, err := cellClaim.Encode(op)
	if err != nil {
		return nil, Public{}, err
	}
	files["operator.jwt"], files["system.jwt"], files["cell.jwt"] = []byte(opJWT), []byte(sysJWT), []byte(cellJWT)
	systemUser, err := nkeys.CreateUser()
	if err != nil {
		return nil, Public{}, err
	}
	defer systemUser.Wipe()
	systemID, _ := systemUser.PublicKey()
	systemClaim := jwt.NewUserClaims(systemID)
	systemClaim.IssuerAccount = sysID
	systemClaim.IssuedAt, systemClaim.Expires = now.Unix(), expires.Unix()
	systemClaim.Pub.Allow = jwt.StringList{"$SYS.REQ.ACCOUNT." + cellID + ".CLAIMS.UPDATE"}
	systemClaim.Sub.Allow = jwt.StringList{inbox(cfg.Cell, systemID)}
	files["system.creds"], err = credentials(systemClaim, sys, systemUser)
	if err != nil {
		return nil, Public{}, err
	}
	operatorUser, err := nkeys.CreateUser()
	if err != nil {
		return nil, Public{}, err
	}
	defer operatorUser.Wipe()
	operatorID, err := operatorUser.PublicKey()
	if err != nil {
		return nil, Public{}, err
	}
	operatorClaim := jwt.NewUserClaims(operatorID)
	operatorClaim.IssuerAccount = cellID
	operatorClaim.IssuedAt, operatorClaim.Expires = now.Unix(), expires.Unix()
	operatorClaim.Pub.Allow = natscell.BrokerOperatorPublishPermissions(cfg.Cell)
	operatorClaim.Sub.Allow = jwt.StringList{inbox(cfg.Cell, operatorID)}
	files["operator.creds"], err = credentials(operatorClaim, cell, operatorUser)
	if err != nil {
		return nil, Public{}, err
	}
	caPEM, caKey, ca, err := makeCA(cfg, now, expires)
	if err != nil {
		return nil, Public{}, err
	}
	files["ca.pem"] = caPEM
	caDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, Public{}, err
	}
	files["issuer-ca.key"] = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caDER})
	hostCAPEM, hostCAKeyPEM, err := makeHostIssuerCA(cfg, now, expires, ca, caKey)
	if err != nil {
		return nil, Public{}, err
	}
	files["host-tls-issuer-cert.pem"] = hostCAPEM
	files["host-tls-issuer-key.pem"] = hostCAKeyPEM
	// Every controller holds the cell's C# TerraBase member CA and signs
	// member certificates with it; database hosts never see the key.
	memberCell, err := naming.RegionCell(strings.ToUpper(cfg.Cell)).Name()
	if err != nil {
		return nil, Public{}, err
	}
	files["terrabase-member-ca.pem"], files["terrabase-member-ca.key"], err = terrabase.NewCA(memberCell, now)
	if err != nil {
		return nil, Public{}, err
	}
	operatorCert, operatorKey, err := makeOperatorLeaf(cfg, now, expires, ca, caKey)
	if err != nil {
		return nil, Public{}, err
	}
	files["operator-tls-cert.pem"], files["operator-tls-key.pem"] = operatorCert, operatorKey
	password := make([]byte, 32)
	if _, err := rand.Read(password); err != nil {
		return nil, Public{}, err
	}
	files["route-password"] = []byte(base64.RawURLEncoding.EncodeToString(password) + "\n")
	clear(password)
	ticketPub, ticketKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, Public{}, err
	}
	ticketPub = bytes.Clone(ticketPub)
	files["ticket.pub"] = []byte(base64.StdEncoding.EncodeToString(ticketPub) + "\n")
	files["ticket.key"] = []byte(base64.StdEncoding.EncodeToString(ticketKey) + "\n")
	clear(ticketKey)
	peerPub, peerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, Public{}, err
	}
	ledgerPub, ledgerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, Public{}, err
	}
	peerPub, ledgerPub = bytes.Clone(peerPub), bytes.Clone(ledgerPub)
	files["founder-peer.key"], files["founder-ledger.key"] = bytes.Clone(peerKey), bytes.Clone(ledgerKey)
	clear(peerKey)
	clear(ledgerKey)
	responsePub, responseKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, Public{}, err
	}
	responsePublic := base64.StdEncoding.EncodeToString(responsePub)
	responseWire := []byte(base64.StdEncoding.EncodeToString(responseKey) + "\n")
	clear(responseKey)
	defer clear(responseWire)
	for _, slot := range cfg.Slots {
		user, err := nkeys.CreateUser()
		if err != nil {
			return nil, Public{}, err
		}
		userID, _ := user.PublicKey()
		claim := jwt.NewUserClaims(userID)
		claim.IssuerAccount = cellID
		claim.IssuedAt, claim.Expires = now.Unix(), expires.Unix()
		claim.Pub.Allow = natscell.ControllerPublishes(cfg.Cell)
		// Fresh material has no link topology: the standalone cell is its own home.
		claim.Pub.Allow.Add(natscell.GlobalControllerPublishes()...)
		claim.Sub.Allow = jwt.StringList{inbox(cfg.Cell, userID), protocol.Broker(cfg.Cell, "ticket", ">"), protocol.Broker(cfg.Cell, "fence", slot.Name)}
		claim.Sub.Allow = append(claim.Sub.Allow, natscell.ControllerSubscriptions(cfg.Cell)...)
		claim.Sub.Allow.Add(protocol.ObservabilityGrant(cfg.Cell))
		claim.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second}
		files[slot.Name+".creds"], err = credentials(claim, cell, user)
		user.Wipe()
		if err != nil {
			return nil, Public{}, err
		}
		cert, key, err := makeLeaf(cfg, slot, now, expires, ca, caKey)
		if err != nil {
			return nil, Public{}, err
		}
		files[slot.Name+"-tls-cert.pem"], files[slot.Name+"-tls-key.pem"] = cert, key
		files[slot.Name+"-response.key"] = bytes.Clone(responseWire)
	}
	public := Public{PeerSignerPublicKey: base64.StdEncoding.EncodeToString(peerPub), LedgerSignerPublicKey: base64.StdEncoding.EncodeToString(ledgerPub),
		TicketSignerPublicKey: base64.StdEncoding.EncodeToString(ticketPub), ControllerResponsePublicKey: responsePublic,
		HostNATSIssuerNKey: hostIssuerID, OperatorNKey: opID, SystemAccountNKey: sysID, CellAccountNKey: cellID}
	return files, public, nil
}

func credentials(claim *jwt.UserClaims, account, user nkeys.KeyPair) ([]byte, error) {
	raw, err := claim.Encode(account)
	if err != nil {
		return nil, err
	}
	seed, err := user.Seed()
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	return jwt.FormatUserConfig(raw, seed)
}

func inbox(cell, public string) string { return protocol.InboxGrant(cell, public) }

// HostScope is the cell account's scope for the host NATS issuer: hosts may
// publish only their own observations and read their own inbox.
func HostScope(cell, issuer string) *jwt.UserScope { return expectedHostScope(cell, issuer) }

func expectedHostScope(cell, issuer string) *jwt.UserScope {
	scope := jwt.NewUserScope()
	scope.Key = issuer
	scope.Role = "host"
	scope.Template.Pub.Allow = jwt.StringList{protocol.AgentObservation(cell, protocol.TemplateSubject, "*")}
	scope.Template.Sub.Allow = jwt.StringList{protocol.InboxGrant(cell, protocol.TemplateSubject)}
	return scope
}

func makeCA(cfg Config, now, expires time.Time) ([]byte, *ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "TerraScale " + cfg.Cell + " controller CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: expires, IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key, parsed, nil
}

func makeHostIssuerCA(cfg Config, now, expires time.Time, root *x509.Certificate, rootKey *ecdsa.PrivateKey) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	domain := "hosts." + cfg.Cell + ".terrascale.internal"
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "TerraScale " + cfg.Cell + " host issuer"},
		NotBefore: now.Add(-time.Minute), NotAfter: expires, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"." + domain}, PermittedURIDomains: []string{domain}}
	der, err := x509.CreateCertificate(rand.Reader, cert, root, &key.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

func makeLeaf(cfg Config, slot Slot, now, expires time.Time, ca *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: naming.NATSServer(cfg.Cell, slot.Name)},
		NotBefore: now.Add(-time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP(slot.PrivateIP)}, DNSNames: []string{slot.Name}}
	der, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

func makeOperatorLeaf(cfg Config, now, expires time.Time, ca *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "TerraScale " + cfg.Cell + " operator"},
		NotBefore: now.Add(-time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

func classify(name string) (bootstrap.SecretPurpose, string) {
	switch name {
	case "issuer-operator.seed", "issuer-system.seed", "issuer-cell.seed", "issuer-ca.key",
		"operator.creds", "operator-tls-cert.pem", "operator-tls-key.pem":
		return "owner-only", ""
	case "founder-peer.key":
		return bootstrap.SecretSeedFounder, "controller-a"
	case "founder-ledger.key":
		return bootstrap.SecretSeedLedgerSigner, "controller-a"
	case "host-nats-issuer.seed", "host-tls-issuer-key.pem", "host-tls-issuer-cert.pem",
		"terrabase-member-ca.pem", "terrabase-member-ca.key":
		return bootstrap.SecretHostIssuer, ""
	case "operator.jwt", "system.jwt", "cell.jwt", "system.creds", "ca.pem", "route-password", "ticket.pub", "ticket.key":
		return bootstrap.SecretRegionalShared, ""
	}
	for _, slot := range []string{"controller-a", "controller-b", "controller-c"} {
		if slices.Contains([]string{slot + ".creds", slot + "-tls-cert.pem", slot + "-tls-key.pem", slot + "-response.key"}, name) {
			return bootstrap.SecretController, slot
		}
	}
	return "", ""
}

func digest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }

func writeOnce(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(body); err != nil {
		return err
	}
	return file.Sync()
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func secureDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return ErrMaterial
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Getuid()) {
		return ErrMaterial
	}
	return nil
}

func secureParents(path string) error {
	for parent := filepath.Dir(filepath.Clean(path)); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() {
			return ErrMaterial
		}
		if filepath.Base(parent) == ".qualification" || filepath.Base(parent) == "evidence" {
			return ErrMaterial
		}
		if _, err := os.Lstat(filepath.Join(parent, ".git")); err == nil || !errors.Is(err, os.ErrNotExist) {
			return ErrMaterial
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) && stat.Uid != 0 ||
			info.Mode().Perm()&0o022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return ErrMaterial
		}
		if parent == string(filepath.Separator) {
			return nil
		}
	}
}

func readOwnedFile(path string, maximum int64) ([]byte, error) {
	if err := ownedRegular(path, 1, maximum); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, ErrMaterial
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrMaterial
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || opened.Size() != before.Size() ||
		!opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 || opened.Size() <= 0 || opened.Size() > maximum {
		return nil, ErrMaterial
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		return nil, ErrMaterial
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(body)) != opened.Size() {
		clear(body)
		return nil, ErrMaterial
	}
	return body, nil
}

func ownedRegular(path string, minimum, maximum int64) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < minimum || info.Size() > maximum {
		return ErrMaterial
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		return ErrMaterial
	}
	return nil
}

// ValidateLive runs the production broker credential validator for every
// controller using the exact generated local files before Vault publication.
func ValidateLive(directory string, record Record) error {
	if _, err := Load(directory); err != nil {
		return err
	}
	if err := validateSignerFiles(directory, record); err != nil {
		return err
	}
	for _, slot := range record.Config.Slots {
		path := func(name string) string { return filepath.Join(directory, name) }
		tls := natscell.TLSFiles{CAFile: path("ca.pem"), CertFile: path(slot.Name + "-tls-cert.pem"), KeyFile: path(slot.Name + "-tls-key.pem")}
		routes := make([]string, 0, 2)
		for _, peer := range record.Config.Slots {
			if peer.Name != slot.Name {
				routes = append(routes, "nats-route://"+peer.PrivateIP+":6222")
			}
		}
		cfg := natscell.Config{Cell: record.Config.Cell, Instance: slot.Name, Replicas: 3, ClientRole: "controller",
			CredentialsFile: path(slot.Name + ".creds"), TLS: tls, Embedded: &natscell.Embedded{
				Host: slot.PrivateIP, Port: 4222, RouteHost: slot.PrivateIP, RoutePort: 6222, Routes: routes,
				StoreDir: path("unused-" + slot.Name), TLS: tls, RouteTLS: tls, RouteUser: "ts-route", RoutePasswordFile: path("route-password"),
				OperatorJWTFile: path("operator.jwt"), SystemJWTFile: path("system.jwt"), CellJWTFile: path("cell.jwt"),
				SystemCredentialsFile: path("system.creds"), TicketPublicKeyFile: path("ticket.pub"),
				BrokerIDs: []string{"controller-a", "controller-b", "controller-c"}}}
		if err := natscell.ValidateProductionCredentials(cfg); err != nil {
			return fmt.Errorf("controller %s credential validation: %w", slot.Name, err)
		}
		certPEM, err := readOwnedFile(path(slot.Name+"-tls-cert.pem"), 64<<10)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return ErrMaterial
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !slices.ContainsFunc(cert.IPAddresses, func(ip net.IP) bool { return ip.Equal(net.ParseIP(slot.PrivateIP)) }) {
			return ErrMaterial
		}
	}
	return nil
}

func validateSignerFiles(directory string, record Record) error {
	read := func(name string) ([]byte, error) { return readOwnedFile(filepath.Join(directory, name), 64<<10) }
	issuerSeed, err := read("host-nats-issuer.seed")
	if err != nil {
		return ErrMaterial
	}
	issuer, err := nkeys.FromSeed(issuerSeed)
	clear(issuerSeed)
	if err != nil {
		return ErrMaterial
	}
	issuerID, err := issuer.PublicKey()
	if err != nil || issuerID != record.Public.HostNATSIssuerNKey {
		issuer.Wipe()
		return ErrMaterial
	}
	role, err := roleScope(issuer)
	issuer.Wipe()
	if err != nil {
		return ErrMaterial
	}
	cellWire, err := read("cell.jwt")
	if err != nil {
		return ErrMaterial
	}
	cellClaim, err := jwt.DecodeAccountClaims(string(cellWire))
	clear(cellWire)
	if err != nil {
		return ErrMaterial
	}
	scope, ok := cellClaim.SigningKeys.GetScope(issuerID)
	hostScope, ok := scope.(*jwt.UserScope)
	// Material generated before TS-663 has no role signer.
	bound, hasRole := cellClaim.SigningKeys.GetScope(role.Key)
	roleBound, _ := bound.(*jwt.UserScope)
	// A link signer, when configured, is the only other scoped key.
	hasLink := record.Config.LinkSigner != ""
	if hasLink {
		if _, linked := cellClaim.SigningKeys.GetScope(record.Config.LinkSigner); !linked {
			return ErrMaterial
		}
	}
	if !ok || !reflect.DeepEqual(hostScope, expectedHostScope(record.Config.Cell, issuerID)) ||
		hasRole && !reflect.DeepEqual(roleBound, role) || len(cellClaim.SigningKeys) != 1+boolInt(hasRole)+boolInt(hasLink) {
		return ErrMaterial
	}
	operatorWire, err := read("operator.creds")
	if err != nil {
		return ErrMaterial
	}
	operatorJWT, err := nkeys.ParseDecoratedJWT(operatorWire)
	if err != nil {
		clear(operatorWire)
		return ErrMaterial
	}
	operatorClaim, err := jwt.DecodeUserClaims(operatorJWT)
	if err != nil {
		clear(operatorWire)
		return ErrMaterial
	}
	operatorPair, err := nkeys.ParseDecoratedUserNKey(operatorWire)
	clear(operatorWire)
	if err != nil {
		return ErrMaterial
	}
	operatorID, err := operatorPair.PublicKey()
	operatorPair.Wipe()
	if err != nil || operatorID != operatorClaim.Subject || operatorClaim.Issuer != cellClaim.Subject ||
		operatorClaim.IssuerAccount != cellClaim.Subject || !cellClaim.DidSign(operatorClaim) ||
		!slices.Equal(operatorClaim.Pub.Allow, natscell.BrokerOperatorPublishPermissions(record.Config.Cell)) ||
		!slices.Equal(operatorClaim.Sub.Allow, jwt.StringList{inbox(record.Config.Cell, operatorID)}) ||
		len(operatorClaim.Pub.Deny) != 0 || len(operatorClaim.Sub.Deny) != 0 || operatorClaim.Resp != nil {
		return ErrMaterial
	}
	for name, want := range map[string]string{"issuer-operator.seed": record.Public.OperatorNKey,
		"issuer-system.seed": record.Public.SystemAccountNKey, "issuer-cell.seed": record.Public.CellAccountNKey} {
		seed, err := read(name)
		if err != nil {
			return ErrMaterial
		}
		pair, err := nkeys.FromSeed(seed)
		clear(seed)
		if err != nil {
			return ErrMaterial
		}
		public, err := pair.PublicKey()
		pair.Wipe()
		if err != nil || public != want {
			return ErrMaterial
		}
	}
	for name, want := range map[string]string{"founder-peer.key": record.Public.PeerSignerPublicKey,
		"founder-ledger.key": record.Public.LedgerSignerPublicKey} {
		wire, err := read(name)
		if err != nil {
			return ErrMaterial
		}
		if !validEd25519Private(wire) || base64.StdEncoding.EncodeToString(ed25519.PrivateKey(wire).Public().(ed25519.PublicKey)) != want {
			clear(wire)
			return ErrMaterial
		}
		clear(wire)
	}
	ticket, err := read("ticket.key")
	if err != nil {
		return ErrMaterial
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(string(ticket), "\n"))
	clear(ticket)
	if err != nil || !validEd25519Private(decoded) {
		clear(decoded)
		return ErrMaterial
	}
	public := base64.StdEncoding.EncodeToString(ed25519.PrivateKey(decoded).Public().(ed25519.PublicKey))
	clear(decoded)
	registered, err := read("ticket.pub")
	if err != nil || string(registered) != public+"\n" || public != record.Public.TicketSignerPublicKey {
		clear(registered)
		return ErrMaterial
	}
	clear(registered)
	for _, slot := range record.Config.Slots {
		wire, err := read(slot.Name + "-response.key")
		if err != nil {
			return ErrMaterial
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(string(wire), "\n"))
		clear(wire)
		if err != nil || !validEd25519Private(decoded) {
			clear(decoded)
			return ErrMaterial
		}
		if base64.StdEncoding.EncodeToString(ed25519.PrivateKey(decoded).Public().(ed25519.PublicKey)) != record.Public.ControllerResponsePublicKey {
			clear(decoded)
			return ErrMaterial
		}
		clear(decoded)
	}
	caKeyWire, err := read("issuer-ca.key")
	if err != nil {
		return ErrMaterial
	}
	keyBlock, _ := pem.Decode(caKeyWire)
	clear(caKeyWire)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		return ErrMaterial
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return ErrMaterial
	}
	caWire, err := read("ca.pem")
	if err != nil {
		return ErrMaterial
	}
	certBlock, _ := pem.Decode(caWire)
	clear(caWire)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return ErrMaterial
	}
	ca, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil || !key.PublicKey.Equal(ca.PublicKey) {
		return ErrMaterial
	}
	if ca.MaxPathLen != 1 || ca.MaxPathLenZero {
		return ErrMaterial
	}
	operatorCertWire, err := read("operator-tls-cert.pem")
	if err != nil {
		return ErrMaterial
	}
	operatorKeyWire, err := read("operator-tls-key.pem")
	if err != nil {
		clear(operatorCertWire)
		return ErrMaterial
	}
	operatorTLS, err := tls.X509KeyPair(operatorCertWire, operatorKeyWire)
	clear(operatorCertWire)
	clear(operatorKeyWire)
	if err != nil || len(operatorTLS.Certificate) != 1 {
		return ErrMaterial
	}
	operatorCert, err := x509.ParseCertificate(operatorTLS.Certificate[0])
	if err != nil || operatorCert.IsCA || operatorCert.KeyUsage != x509.KeyUsageDigitalSignature ||
		!slices.Equal(operatorCert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) ||
		len(operatorCert.DNSNames) != 0 || len(operatorCert.URIs) != 0 || len(operatorCert.IPAddresses) != 0 ||
		operatorCert.NotAfter.After(ca.NotAfter) {
		return ErrMaterial
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := operatorCert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return ErrMaterial
	}
	hostKeyWire, err := read("host-tls-issuer-key.pem")
	if err != nil {
		return ErrMaterial
	}
	hostKeyBlock, rest := pem.Decode(hostKeyWire)
	clear(hostKeyWire)
	if hostKeyBlock == nil || hostKeyBlock.Type != "EC PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return ErrMaterial
	}
	hostKey, err := x509.ParseECPrivateKey(hostKeyBlock.Bytes)
	if err != nil {
		return ErrMaterial
	}
	hostWire, err := read("host-tls-issuer-cert.pem")
	if err != nil {
		return ErrMaterial
	}
	hostBlock, rest := pem.Decode(hostWire)
	clear(hostWire)
	if hostBlock == nil || hostBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return ErrMaterial
	}
	hostCert, err := x509.ParseCertificate(hostBlock.Bytes)
	if err != nil || !hostKey.PublicKey.Equal(hostCert.PublicKey) || !hostCert.IsCA || !hostCert.MaxPathLenZero ||
		hostCert.KeyUsage != x509.KeyUsageCertSign || !slices.Equal(hostCert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) ||
		!hostCert.PermittedDNSDomainsCritical ||
		!slices.Equal(hostCert.PermittedDNSDomains, []string{".hosts." + record.Config.Cell + ".terrascale.internal"}) ||
		!slices.Equal(hostCert.PermittedURIDomains, []string{"hosts." + record.Config.Cell + ".terrascale.internal"}) ||
		hostCert.CheckSignatureFrom(ca) != nil || hostCert.NotAfter.After(ca.NotAfter) {
		return ErrMaterial
	}
	// Controllers load the member CA exactly this way at start.
	if record.HasMemberCA() {
		if _, err := terrabase.LoadCA(filepath.Join(directory, memberCANames[0]),
			filepath.Join(directory, memberCANames[1])); err != nil {
			return ErrMaterial
		}
	}
	return nil
}

func validEd25519Private(wire []byte) bool {
	return len(wire) == ed25519.PrivateKeySize &&
		bytes.Equal(ed25519.NewKeyFromSeed(wire[:ed25519.SeedSize]), wire)
}
