package bootstrapmaterial

import (
	"bytes"
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
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/manager"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// Interregion material links one region into the leaf tree. It is issued
// from, and bound to, that region's controller material (the regional
// operator signs every account JWT), into its own immutable, owner-only
// directory:
//
//   - interregion.jwt: the interregion account. Its exports and imports are
//     exactly natscell.InterRegionContract, its default leaf permissions deny
//     everything, bearer users are disallowed, it holds no JetStream state,
//     and each direct child of this region gets one scoped signing key whose
//     template is that child's subtree permissions, leafnode-only.
//   - cell-interregion.jwt and system-interregion.jwt: the material's cell
//     and system accounts reissued with the contract and LeafNodeConn = 0,
//     so the server refuses a leaf user of either.
//   - child-<cell>.seed and leaf-<cell>.creds per child: the child's scoped
//     signing key, and one leaf-only user it issued with no permissions of
//     its own. The credentials are handed to that child, which dials this
//     region with them (pairwise: one credential per parent/child link).
//   - interregion-ca.pem: the one interregion CA, P-256 and name-constrained
//     to .interregion.terrascale.internal. The hub (tree root) creates it
//     with its owner-only interregion-ca.key; every other region signs with
//     the hub's.
//   - interregion-tls-<slot>-cert.pem and -key.pem per controller slot, named
//     InterRegionLeafName: server and client certificates in a region with
//     children, client-only otherwise.
//
// Every claim is checked with the same contract verifier the server runs at
// startup before anything is written. The metadata records each file's
// SHA-256 and a LedgerDigest over the whole record, which is what the
// deployment's signed bootstrap ledger records for this material. Files with
// purpose owner-only (the CA key, child seeds) are never published.
const (
	interRegionMetadataName = "interregion.json"
	interRegionSchema       = 1
	maxInterRegionFile      = 64 << 10
	interRegionDomain       = "interregion.terrascale.internal"
)

// InterRegionLeafName is the DNS name of cell's interregion leaf
// certificates, the server_name its children pin.
func InterRegionLeafName(cell string) string { return "leaf." + cell + "." + interRegionDomain }

// InterRegionInputs are the reviewed inputs besides the controller material.
type InterRegionInputs struct {
	// CellJWT is the cell account claim the brokers hold, when one newer
	// than the material's cell.jwt was applied (a role claim): the reissued
	// claim keeps its signers and limits.
	CellJWT string
	// CACert and CAKeyFile are the hub's interregion-ca.pem and the path of
	// its owner-only interregion-ca.key. Every region but the hub needs them.
	CACert    []byte
	CAKeyFile string
}

// PrivatePeerReceiptKind and PrivatePeerReceiptPass identify the reviewed
// private-peer foundation readback (ociregion InspectPrivatePeer).
const (
	PrivatePeerReceiptKind = "oci_private_peer_foundation_configuration_readback"
	PrivatePeerReceiptPass = "configuration_readback_pass"
)

// InterRegionConfig is the reviewed leaf tree and this region's leaf
// listener port; the port is required exactly when this region has children.
type InterRegionConfig struct {
	Topology   natscell.LeafTopology `json:"topology"`
	ListenPort int                   `json:"listenPort,omitzero"`
}

// InterRegionRecord is the interregion material's metadata.
type InterRegionRecord struct {
	SchemaVersion int               `json:"schemaVersion"`
	Cell          string            `json:"cell"`
	Config        InterRegionConfig `json:"config"`
	// MaterialSHA256 binds this material to the controller material it was
	// issued from (the digest of that material's metadata).
	MaterialSHA256 string `json:"materialSha256"`
	// CellJWTSHA256 is the digest of InterRegionInputs.CellJWT, empty when
	// the cell claim was reissued from the material's cell.jwt.
	CellJWTSHA256 string    `json:"cellJwtSha256,omitempty"`
	OperatorNKey  string    `json:"operatorNkey"`
	IssuedAt      time.Time `json:"issuedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
	// InterRegionAccountNKey is what each child pins as its remote's
	// peer_account.
	InterRegionAccountNKey string `json:"interregionAccountNkey"`
	// ChildSigningKeys maps each direct child to its scoped signing key.
	ChildSigningKeys map[string]string `json:"childSigningKeys,omitempty"`
	// Slots are this region's controllers, whose private addresses children
	// dial (after the private-peer receipt admits them).
	Slots []Slot `json:"slots"`
	Files []File `json:"files"`
	// LedgerDigest is the SHA-256 of this record with LedgerDigest empty.
	LedgerDigest string `json:"ledgerDigest"`
}

func (cfg InterRegionConfig) contract(cell string) (natscell.InterRegionContract, int, error) {
	topology := cfg.Topology
	if err := topology.Validate(); err != nil {
		return natscell.InterRegionContract{}, 0, err
	}
	if !slices.Contains(topology.Regions(), cell) || len(topology.Regions()) > 64 {
		return natscell.InterRegionContract{}, 0, errors.New("interregion topology must contain this region and at most 63 peers")
	}
	subtrees := topology.Subtrees(cell)
	if (len(subtrees) != 0) != (cfg.ListenPort > 0) || cfg.ListenPort < 0 || cfg.ListenPort > 65535 {
		return natscell.InterRegionContract{}, 0, errors.New("a leaf listener port is required exactly when this region has children")
	}
	return natscell.InterRegionContract{Cell: cell, Peers: topology.Peers(cell), GlobalHome: topology.Hub,
		Subtrees: subtrees}, topology.Links(cell), nil
}

// ledgerDigest is the SHA-256 of the record's deterministic JSON with
// LedgerDigest cleared.
func (record InterRegionRecord) ledgerDigest() (string, error) {
	record.LedgerDigest = ""
	wire, err := json.Marshal(record, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digest(wire), nil
}

// GenerateInterRegion issues interregion material for the region whose
// controller material is in materialDirectory. Like Generate, it never
// replaces anything: an existing directory must already hold the material of
// the same inputs, which is returned.
func GenerateInterRegion(materialDirectory, directory string, cfg InterRegionConfig, inputs InterRegionInputs,
	now time.Time,
) (InterRegionRecord, error) {
	material, err := Load(materialDirectory)
	if err != nil {
		return InterRegionRecord{}, err
	}
	materialDigest, err := metadataDigest(materialDirectory)
	if err != nil {
		return InterRegionRecord{}, err
	}
	cell := material.Config.Cell
	contract, links, err := cfg.contract(cell)
	if err != nil {
		return InterRegionRecord{}, fmt.Errorf("%w: %w", ErrMaterial, err)
	}
	if !filepath.IsAbs(directory) || now.IsZero() || secureParents(directory) != nil || !now.Before(material.ExpiresAt) ||
		nested(materialDirectory, directory) || nested(directory, materialDirectory) {
		// A directory inside the controller material would add an entry
		// Load refuses, making the source unusable.
		return InterRegionRecord{}, ErrMaterial
	}
	if hub, given := cell == cfg.Topology.Hub, len(inputs.CACert) != 0 || inputs.CAKeyFile != ""; hub && given ||
		!hub && (len(inputs.CACert) == 0 || inputs.CAKeyFile == "") {
		return InterRegionRecord{}, fmt.Errorf("%w: the hub creates the interregion CA; every other region needs its certificate and key",
			ErrMaterial)
	}
	cellDigest := ""
	if inputs.CellJWT != "" {
		cellDigest = digest([]byte(inputs.CellJWT))
	}
	if _, err := os.Lstat(directory); err == nil {
		record, loadErr := LoadInterRegion(directory)
		ca, _ := record.file("interregion-ca.pem")
		if loadErr != nil || record.MaterialSHA256 != materialDigest || !sameTopology(record.Config, cfg) ||
			record.CellJWTSHA256 != cellDigest || len(inputs.CACert) != 0 && ca.SHA256 != digest(inputs.CACert) {
			return InterRegionRecord{}, ErrMaterial
		}
		return record, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return InterRegionRecord{}, ErrMaterial
	}
	files, record, err := issueInterRegion(materialDirectory, material, contract, links, cfg, inputs, now.UTC())
	if err != nil {
		return InterRegionRecord{}, err
	}
	defer func() {
		for _, body := range files {
			clear(body)
		}
	}()
	// The server reads a signed JWT of at most 64 KiB; a wide tree's
	// interregion account (one child template per child, each naming every
	// region) can exceed it, and such material must never be written.
	for name, body := range files {
		if len(body) > maxInterRegionFile {
			return InterRegionRecord{}, fmt.Errorf("%w: %s is %d bytes, over the %d byte limit; split the tree so this region has fewer children",
				ErrMaterial, name, len(body), maxInterRegionFile)
		}
	}
	record.MaterialSHA256, record.CellJWTSHA256 = materialDigest, cellDigest
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for name := range files {
			if !yield(name) {
				return
			}
		}
	}) {
		purpose, slot := interRegionPurpose(name)
		record.Files = append(record.Files, File{Name: name, Purpose: purpose, Slot: slot, SHA256: digest(files[name]),
			MaxBytes: int64(len(files[name]))})
	}
	if record.LedgerDigest, err = record.ledgerDigest(); err != nil {
		return InterRegionRecord{}, err
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return InterRegionRecord{}, fmt.Errorf("create private interregion directory: %w", err)
	}
	for _, file := range record.Files {
		if err := writeOnce(filepath.Join(directory, file.Name), files[file.Name]); err != nil {
			return InterRegionRecord{}, fmt.Errorf("write interregion material %s: %w", file.Name, err)
		}
	}
	metadata, err := json.Marshal(record, json.Deterministic(true))
	if err != nil {
		return InterRegionRecord{}, err
	}
	if err := writeOnce(filepath.Join(directory, interRegionMetadataName), metadata); err != nil {
		return InterRegionRecord{}, err
	}
	if err := writeOnce(filepath.Join(directory, readyName), []byte(digest(metadata)+"\n")); err != nil {
		return InterRegionRecord{}, err
	}
	if err := syncDirectory(directory); err != nil {
		return InterRegionRecord{}, err
	}
	// The written credentials must pass the dialing side's own check.
	for child := range contract.Subtrees {
		if err := natscell.ValidateLeafCredentials(filepath.Join(directory, "leaf-"+child+".creds"),
			record.InterRegionAccountNKey); err != nil {
			return InterRegionRecord{}, fmt.Errorf("%w: leaf credentials of %s: %w", ErrMaterial, child, err)
		}
	}
	return record, nil
}

// nested reports whether path is parent or inside it.
func nested(parent, path string) bool {
	relative, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(path))
	return err == nil && (relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func sameTopology(a, b InterRegionConfig) bool {
	left, errLeft := json.Marshal(a, json.Deterministic(true))
	right, errRight := json.Marshal(b, json.Deterministic(true))
	return errLeft == nil && errRight == nil && bytes.Equal(left, right)
}

func metadataDigest(directory string) (string, error) {
	metadata, err := readOwnedFile(filepath.Join(directory, metadataName), 1<<20)
	if err != nil {
		return "", ErrMaterial
	}
	return digest(metadata), nil
}

func issueInterRegion(materialDirectory string, material Record, contract natscell.InterRegionContract, links int,
	cfg InterRegionConfig, inputs InterRegionInputs, now time.Time,
) (map[string][]byte, InterRegionRecord, error) {
	seed, err := readOwnedFile(filepath.Join(materialDirectory, "issuer-operator.seed"), 4096)
	if err != nil {
		return nil, InterRegionRecord{}, ErrMaterial
	}
	operator, err := nkeys.FromSeed(seed)
	// FromSeed keeps the seed bytes; Wipe below clears them.
	if err != nil {
		return nil, InterRegionRecord{}, ErrMaterial
	}
	defer operator.Wipe()
	if public, err := operator.PublicKey(); err != nil || public != material.Public.OperatorNKey {
		return nil, InterRegionRecord{}, ErrMaterial
	}
	readClaim := func(name, subject string) (*jwt.AccountClaims, error) {
		raw, err := readOwnedFile(filepath.Join(materialDirectory, name), 64<<10)
		if err != nil {
			return nil, ErrMaterial
		}
		claim, err := jwt.DecodeAccountClaims(string(bytes.TrimSpace(raw)))
		if err != nil || claim.Subject != subject || claim.Issuer != material.Public.OperatorNKey {
			return nil, ErrMaterial
		}
		return claim, nil
	}
	system, err := readClaim("system.jwt", material.Public.SystemAccountNKey)
	if err != nil {
		return nil, InterRegionRecord{}, err
	}
	// The cell claim starts from the one the brokers hold, so the host and
	// role signers and the limits survive; the contract replaces only its
	// exports, imports and leafnode limit.
	cell, err := readClaim("cell.jwt", material.Public.CellAccountNKey)
	if err != nil {
		return nil, InterRegionRecord{}, err
	}
	if inputs.CellJWT != "" {
		if cell, err = jwt.DecodeAccountClaims(inputs.CellJWT); err != nil || cell.Subject != material.Public.CellAccountNKey ||
			cell.Issuer != material.Public.OperatorNKey {
			return nil, InterRegionRecord{}, errors.New("the cell claim is not this material's cell account signed by its operator")
		}
	}
	if host, ok := cell.SigningKeys.GetScope(material.Public.HostNATSIssuerNKey); !ok ||
		!reflect.DeepEqual(host, expectedHostScope(material.Config.Cell, material.Public.HostNATSIssuerNKey)) {
		return nil, InterRegionRecord{}, errors.New("the cell claim lacks the material's host signer")
	}
	cellIssued := cell.IssuedAt
	account, err := nkeys.CreateAccount()
	if err != nil {
		return nil, InterRegionRecord{}, err
	}
	defer account.Wipe()
	accountID, err := account.PublicKey()
	if err != nil {
		return nil, InterRegionRecord{}, err
	}
	files := map[string][]byte{}
	children := slices.Sorted(func(yield func(string) bool) {
		for child := range contract.Subtrees {
			if !yield(child) {
				return
			}
		}
	})
	signers := map[string]nkeys.KeyPair{}
	defer func() {
		for _, signer := range signers {
			signer.Wipe()
		}
	}()
	childKeys := map[string]string{}
	for _, child := range children {
		signer, err := nkeys.CreateAccount()
		if err != nil {
			return nil, InterRegionRecord{}, err
		}
		signers[child] = signer
		if childKeys[child], err = signer.PublicKey(); err != nil {
			return nil, InterRegionRecord{}, err
		}
		signerSeed, err := signer.Seed()
		if err != nil {
			return nil, InterRegionRecord{}, err
		}
		files["child-"+child+".seed"] = bytes.Clone(signerSeed)
	}
	expires := material.ExpiresAt.UTC()
	interregion := jwt.NewAccountClaims(accountID)
	interregion.Name = "interregion-" + material.Config.Cell
	interregion.Expires = expires.Unix()
	contract.ApplyInterRegion(interregion, cell.Subject, links, childKeys)
	contract.ApplyCell(cell, accountID)
	system.Limits.LeafNodeConn = 0
	system.Expires = expires.Unix()
	if err := contract.VerifyClaims(system, cell, interregion, links); err != nil {
		return nil, InterRegionRecord{}, fmt.Errorf("%w: issued claims fail the interregion contract: %w", ErrMaterial, err)
	}
	for name, claim := range map[string]*jwt.AccountClaims{"interregion.jwt": interregion,
		"cell-interregion.jwt": cell, "system-interregion.jwt": system} {
		raw, err := claim.Encode(operator)
		if err != nil {
			return nil, InterRegionRecord{}, err
		}
		files[name] = []byte(raw)
	}
	// Encode stamps the time; brokers take only a strictly newer claim.
	if cell.IssuedAt <= cellIssued {
		return nil, InterRegionRecord{}, errors.New("the cell claim was issued this second; run again")
	}
	if err := interRegionTLS(files, material, cfg, inputs, now, expires); err != nil {
		return nil, InterRegionRecord{}, err
	}
	for _, child := range children {
		user, err := nkeys.CreateUser()
		if err != nil {
			return nil, InterRegionRecord{}, err
		}
		userID, _ := user.PublicKey()
		claim := jwt.NewUserClaims(userID)
		claim.Name = "leaf-" + child + "-to-" + material.Config.Cell
		// The scoped key's template (the child's subtree, leafnode-only)
		// supplies every permission; the user carries none of its own, not
		// even the default unlimited limits.
		claim.UserPermissionLimits = jwt.UserPermissionLimits{}
		claim.IssuerAccount = accountID
		claim.Expires = expires.Unix()
		creds, err := credentials(claim, signers[child], user)
		user.Wipe()
		if err != nil {
			return nil, InterRegionRecord{}, err
		}
		files["leaf-"+child+".creds"] = creds
	}
	return files, InterRegionRecord{SchemaVersion: interRegionSchema, Cell: material.Config.Cell, Config: cfg,
		OperatorNKey: material.Public.OperatorNKey, IssuedAt: now, ExpiresAt: expires,
		InterRegionAccountNKey: accountID, ChildSigningKeys: childKeys, Slots: slices.Clone(material.Config.Slots)}, nil
}

// interRegionTLS adds the interregion CA (created on the hub, the hub's
// otherwise) and each controller slot's leaf certificate and key to files.
func interRegionTLS(files map[string][]byte, material Record, cfg InterRegionConfig, inputs InterRegionInputs,
	now, expires time.Time,
) error {
	cell := material.Config.Cell
	var ca *x509.Certificate
	var caKey *ecdsa.PrivateKey
	var err error
	if cell == cfg.Topology.Hub {
		template := &x509.Certificate{Subject: pkix.Name{CommonName: "TerraScale interregion CA"},
			NotBefore: now.Add(-time.Minute), NotAfter: expires, IsCA: true, BasicConstraintsValid: true,
			MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"." + interRegionDomain}}
		if files["interregion-ca.pem"], files["interregion-ca.key"], ca, caKey, err = interRegionCertificate(template,
			nil, nil); err != nil {
			return err
		}
	} else {
		if ca, caKey, err = loadInterRegionCA(inputs.CACert, inputs.CAKeyFile, now); err != nil {
			return err
		}
		files["interregion-ca.pem"] = bytes.Clone(inputs.CACert)
	}
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if cfg.ListenPort > 0 {
		usage = append(usage, x509.ExtKeyUsageServerAuth)
	}
	for _, slot := range material.Config.Slots {
		template := &x509.Certificate{Subject: pkix.Name{CommonName: naming.NATSServer(cell, slot.Name)},
			NotBefore: now.Add(-time.Minute), NotAfter: minTime(expires, ca.NotAfter),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage, DNSNames: []string{InterRegionLeafName(cell)}}
		prefix := "interregion-tls-" + slot.Name
		if files[prefix+"-cert.pem"], files[prefix+"-key.pem"], _, _, err = interRegionCertificate(template, ca,
			caKey); err != nil {
			return err
		}
	}
	return nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// interRegionCertificate issues template for a new P-256 key, signed by
// parent's key, or by its own when parent is nil.
func interRegionCertificate(template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey,
) ([]byte, []byte, *x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if template.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)); err != nil {
		return nil, nil, nil, nil, err
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer clear(keyDER)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), cert, key, nil
}

// loadInterRegionCA accepts only the hub's interregion CA, current, with its
// owner-only key.
func loadInterRegionCA(certPEM []byte, keyFile string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	refuse := fmt.Errorf("%w: the interregion CA is not a current, name-constrained P-256 root with its owner-only key",
		ErrMaterial)
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, refuse
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || !ca.MaxPathLenZero || ca.CheckSignatureFrom(ca) != nil ||
		!ca.PermittedDNSDomainsCritical || !slices.Equal(ca.PermittedDNSDomains, []string{"." + interRegionDomain}) ||
		now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return nil, nil, refuse
	}
	public, ok := ca.PublicKey.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return nil, nil, refuse
	}
	// readOwnedFile refuses anything but a 0600 regular file of this user.
	keyPEM, err := readOwnedFile(keyFile, 4096)
	if err != nil {
		return nil, nil, refuse
	}
	defer clear(keyPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		return nil, nil, refuse
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	clear(keyBlock.Bytes)
	if err != nil || !key.PublicKey.Equal(public) {
		return nil, nil, refuse
	}
	return ca, key, nil
}

// interRegionPurpose classifies an interregion file: owner-only files are
// never published, slot files belong to one controller.
func interRegionPurpose(name string) (bootstrap.SecretPurpose, string) {
	if name == "interregion-ca.key" || strings.HasPrefix(name, "child-") {
		return "owner-only", ""
	}
	if slot, ok := strings.CutPrefix(name, "interregion-tls-"); ok {
		return "interregion", strings.TrimSuffix(strings.TrimSuffix(slot, "-cert.pem"), "-key.pem")
	}
	return "interregion", ""
}

// interRegionNames lists the files of a region's interregion material.
func interRegionNames(hub bool, slots []Slot, children []string) []string {
	names := []string{"interregion.jwt", "cell-interregion.jwt", "system-interregion.jwt", "interregion-ca.pem"}
	if hub {
		names = append(names, "interregion-ca.key")
	}
	for _, slot := range slots {
		names = append(names, "interregion-tls-"+slot.Name+"-cert.pem", "interregion-tls-"+slot.Name+"-key.pem")
	}
	for _, child := range children {
		names = append(names, "child-"+child+".seed", "leaf-"+child+".creds")
	}
	slices.Sort(names)
	return names
}

// LoadInterRegion verifies complete interregion material: its metadata,
// READY marker, ledger digest and every exact file digest.
func LoadInterRegion(directory string) (InterRegionRecord, error) {
	if !filepath.IsAbs(directory) || secureParents(directory) != nil || secureDirectory(directory) != nil {
		return InterRegionRecord{}, ErrMaterial
	}
	metadata, err := readOwnedFile(filepath.Join(directory, interRegionMetadataName), 1<<20)
	if err != nil {
		return InterRegionRecord{}, ErrMaterial
	}
	ready, err := readOwnedFile(filepath.Join(directory, readyName), 128)
	if err != nil || string(ready) != digest(metadata)+"\n" {
		return InterRegionRecord{}, ErrMaterial
	}
	var record InterRegionRecord
	if err := protocol.DecodeStrict(metadata, &record, 1<<20); err != nil || record.SchemaVersion != interRegionSchema {
		return InterRegionRecord{}, ErrMaterial
	}
	contract, _, err := record.Config.contract(record.Cell)
	if err != nil || !nkeys.IsValidPublicAccountKey(record.InterRegionAccountNKey) ||
		!nkeys.IsValidPublicOperatorKey(record.OperatorNKey) || len(record.ChildSigningKeys) != len(contract.Subtrees) {
		return InterRegionRecord{}, ErrMaterial
	}
	if ledger, err := record.ledgerDigest(); err != nil || ledger != record.LedgerDigest {
		return InterRegionRecord{}, ErrMaterial
	}
	children := make([]string, 0, len(contract.Subtrees))
	for child := range contract.Subtrees {
		if !nkeys.IsValidPublicAccountKey(record.ChildSigningKeys[child]) {
			return InterRegionRecord{}, ErrMaterial
		}
		children = append(children, child)
	}
	names := interRegionNames(record.Cell == record.Config.Topology.Hub, record.Slots, children)
	if len(record.Files) != len(names) {
		return InterRegionRecord{}, ErrMaterial
	}
	for index, file := range record.Files {
		purpose, slot := interRegionPurpose(file.Name)
		if file.Name != names[index] || file.Purpose != purpose || file.Slot != slot || file.MaxBytes <= 0 ||
			file.MaxBytes > maxInterRegionFile {
			return InterRegionRecord{}, ErrMaterial
		}
		body, err := readOwnedFile(filepath.Join(directory, file.Name), file.MaxBytes)
		if err != nil || int64(len(body)) != file.MaxBytes || digest(body) != file.SHA256 {
			return InterRegionRecord{}, ErrMaterial
		}
		clear(body)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(names)+2 {
		return InterRegionRecord{}, ErrMaterial
	}
	return record, nil
}

// privatePeerReceipt is the part of the private-peer readback that admits
// leaf URLs.
type privatePeerReceipt struct {
	SchemaVersion     int       `json:"schema_version"`
	Kind              string    `json:"kind"`
	Status            string    `json:"status"`
	ReadbackExpiresAt time.Time `json:"readback_expires_at"`
	Cells             map[string]struct {
		SubnetCIDR string `json:"subnet_cidr"`
	} `json:"cells"`
	AllowedTCPPorts []int `json:"allowed_tcp_ports"`
}

// Readback is reviewed evidence: its exact bytes and the SHA-256 the
// reviewer pinned.
type Readback struct {
	Body   []byte
	SHA256 string
}

func (readback Readback) reviewed() bool {
	sum := sha256.Sum256(readback.Body)
	return len(readback.SHA256) == 64 && hex.EncodeToString(sum[:]) == strings.ToLower(readback.SHA256)
}

// LeafRemote builds the remote that controller slot rotation (its index) of
// a child region dials to reach the region of parent. Its URLs are the
// parent controllers' private addresses, then, given a NetBird inventory,
// their NetBird addresses, each list starting at the parent controller of
// index rotation so the child's brokers spread over the parent's.
//
// The private addresses come from the reviewed private-peer receipt: it
// must be a passing, unexpired readback of the private peering between
// parent and child that allows the parent's leaf port, and every address is
// inside the parent subnet it observed. The NetBird addresses come from a
// reviewed `ts-orch netbird inventory` (see netBirdAddresses); an inventory
// that does not admit every parent controller is refused, never skipped.
// credentialsFile is the child's copy of the parent's leaf-<child>.creds;
// its digest must match the parent's record, which itself must be unexpired
// and still match its own ledger digest. ServerName is the parent's
// InterRegionLeafName; TLS (the reviewed interregion CA) stays the caller's.
func LeafRemote(parent InterRegionRecord, child string, rotation int, receipt, netbird Readback,
	credentialsFile string, tls natscell.TLSFiles, now time.Time,
) (natscell.LeafRemote, error) {
	if parent.SchemaVersion != interRegionSchema || parent.Topology().Hub == "" || len(parent.Slots) == 0 || rotation < 0 {
		return natscell.LeafRemote{}, ErrMaterial
	}
	// An edited inventory (a slot address or account changed after issue)
	// no longer matches its ledger digest, and expired material's
	// credentials would be refused by the parent anyway.
	if ledger, err := parent.ledgerDigest(); err != nil || ledger != parent.LedgerDigest {
		return natscell.LeafRemote{}, fmt.Errorf("%w: parent interregion record does not match its ledger digest", ErrMaterial)
	}
	if !now.Before(parent.ExpiresAt) {
		return natscell.LeafRemote{}, fmt.Errorf("%w: parent interregion material has expired", ErrMaterial)
	}
	if dialed, ok := parent.Config.Topology.Parent(child); !ok || dialed != parent.Cell {
		return natscell.LeafRemote{}, fmt.Errorf("%w: %s does not dial %s in the topology", ErrMaterial, child, parent.Cell)
	}
	if !receipt.reviewed() {
		return natscell.LeafRemote{}, fmt.Errorf("%w: private-peer receipt is not the reviewed one", ErrMaterial)
	}
	var readback privatePeerReceipt
	if err := json.Unmarshal(receipt.Body, &readback); err != nil || readback.SchemaVersion != 1 ||
		readback.Kind != PrivatePeerReceiptKind || readback.Status != PrivatePeerReceiptPass ||
		!now.Before(readback.ReadbackExpiresAt) || !slices.Contains(readback.AllowedTCPPorts, parent.Config.ListenPort) {
		return natscell.LeafRemote{}, fmt.Errorf("%w: private-peer receipt does not admit this leaf link", ErrMaterial)
	}
	subnet, childSeen := netip.Prefix{}, false
	for name, observed := range readback.Cells {
		switch {
		case strings.EqualFold(name, parent.Cell):
			prefix, err := netip.ParsePrefix(observed.SubnetCIDR)
			if err != nil || prefix.Masked() != prefix || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() {
				return natscell.LeafRemote{}, fmt.Errorf("%w: receipt subnet of %s is invalid", ErrMaterial, parent.Cell)
			}
			subnet = prefix
		case strings.EqualFold(name, child):
			childSeen = true
		}
	}
	if !subnet.IsValid() || !childSeen || len(readback.Cells) != 2 {
		return natscell.LeafRemote{}, fmt.Errorf("%w: receipt is not the %s/%s peering", ErrMaterial, parent.Cell, child)
	}
	private := make([]netip.Addr, 0, len(parent.Slots))
	for _, slot := range parent.Slots {
		address, err := netip.ParseAddr(slot.PrivateIP)
		if err != nil || !subnet.Contains(address) {
			return natscell.LeafRemote{}, fmt.Errorf("%w: controller %s is outside the peered subnet", ErrMaterial, slot.Name)
		}
		private = append(private, address)
	}
	paths := [][]netip.Addr{private}
	if netbird.Body != nil || netbird.SHA256 != "" {
		addresses, err := netBirdAddresses(parent, child, netbird)
		if err != nil {
			return natscell.LeafRemote{}, err
		}
		paths = append(paths, addresses)
	}
	remote := natscell.LeafRemote{Peer: parent.Cell, CredentialsFile: credentialsFile,
		PeerAccount: parent.InterRegionAccountNKey, TLS: tls, ServerName: InterRegionLeafName(parent.Cell)}
	for _, addresses := range paths {
		for index := range addresses {
			address := addresses[(rotation+index)%len(addresses)]
			remote.URLs = append(remote.URLs, "nats-leaf://"+netip.AddrPortFrom(address, uint16(parent.Config.ListenPort)).String())
		}
	}
	file, ok := parent.file("leaf-" + child + ".creds")
	if !ok {
		return natscell.LeafRemote{}, ErrMaterial
	}
	body, err := readOwnedFile(credentialsFile, file.MaxBytes)
	if err != nil || digest(body) != file.SHA256 {
		clear(body)
		return natscell.LeafRemote{}, fmt.Errorf("%w: leaf credentials are not the parent's issued file", ErrMaterial)
	}
	clear(body)
	if err := natscell.ValidateLeafCredentials(credentialsFile, parent.InterRegionAccountNKey); err != nil {
		return natscell.LeafRemote{}, fmt.Errorf("%w: %w", ErrMaterial, err)
	}
	return remote, nil
}

// netBirdAddresses returns each parent controller's NetBird address, in
// parent.Slots order, from a reviewed `ts-orch netbird inventory`. The
// inventory must be of the managed network (manager.GRU's range), hold for
// every controller exactly one connected peer of <parent>-servers that
// registered from the controller's private IP and is addressed inside that
// range, and hold the enabled fabric policy
// <child>-servers-to-<parent>-servers-fabric that accepts TCP on the parent's
// leaf port.
func netBirdAddresses(parent InterRegionRecord, child string, readback Readback) ([]netip.Addr, error) {
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%w: NetBird inventory %s", ErrMaterial, fmt.Sprintf(format, args...))
	}
	if !readback.reviewed() {
		return nil, refuse("is not the reviewed one")
	}
	var inventory manager.Inventory
	if err := json.Unmarshal(readback.Body, &inventory); err != nil {
		return nil, refuse("does not decode: %v", err)
	}
	network, err := netip.ParsePrefix(inventory.Account.NetworkRange)
	if err != nil || inventory.Account.NetworkRange != manager.GRU().NetworkRange {
		return nil, refuse("network range %q is not the managed %s", inventory.Account.NetworkRange, manager.GRU().NetworkRange)
	}
	parentGroup, childGroup := parent.Cell+"-servers", child+"-servers"
	policy, port := childGroup+"-to-"+parentGroup+"-fabric", strconv.Itoa(parent.Config.ListenPort)
	if !slices.ContainsFunc(inventory.Policies, func(candidate manager.InventoryPolicy) bool {
		return candidate.Name == policy && candidate.Enabled && slices.ContainsFunc(candidate.Rules, func(rule manager.InventoryRule) bool {
			return rule.Enabled && rule.Action == "accept" && rule.Protocol == "tcp" && slices.Contains(rule.Ports, port) &&
				slices.Contains(rule.Sources, childGroup) && slices.Contains(rule.Destinations, parentGroup)
		})
	}) {
		return nil, refuse("has no enabled policy %s accepting TCP %s", policy, port)
	}
	addresses := make([]netip.Addr, 0, len(parent.Slots))
	for _, slot := range parent.Slots {
		var found []netip.Addr
		for _, peer := range inventory.Peers {
			registered, err := netip.ParseAddr(peer.ConnectionIP)
			if err != nil || !peer.Connected || !slices.Contains(peer.Groups, parentGroup) ||
				registered.Unmap().String() != slot.PrivateIP {
				continue
			}
			address, err := netip.ParseAddr(peer.IP)
			if err != nil || !address.Is4() || !network.Contains(address) {
				return nil, refuse("peer %s of controller %s is addressed outside %s", peer.Name, slot.Name, network)
			}
			found = append(found, address)
		}
		if len(found) != 1 {
			return nil, refuse("has %d connected %s peers for controller %s at %s, not one", len(found), parentGroup,
				slot.Name, slot.PrivateIP)
		}
		addresses = append(addresses, found[0])
	}
	return addresses, nil
}

// ParentLink is what a child region's remote is built from: the parent's
// interregion record, the reviewed private-peer receipt, the optional
// reviewed NetBird inventory, and the child's local copy of the parent's
// leaf-<child>.creds.
type ParentLink struct {
	Record          InterRegionRecord
	Receipt         Readback
	NetBird         Readback
	CredentialsFile string
}

// RenderInterRegion is the nats.embedded.interregion block of controller
// slot of record's region, with every file at its installed path in
// directory (the controller's credential directory): interregion.jwt,
// interregion-ca.pem, the slot's interregion-tls-<slot>-cert.pem and
// -key.pem, and in a child leaf-<parent>.creds. A region with children
// listens on 0.0.0.0 at its leaf port; a region with a parent dials it with
// the remote LeafRemote builds from link. The block passes the broker's
// startup check. The broker's cell_jwt_file and system_jwt_file stay
// cell.jwt and system.jwt, which must then hold this material's
// cell-interregion.jwt and system-interregion.jwt.
func RenderInterRegion(record InterRegionRecord, slot, directory string, link *ParentLink, now time.Time,
) (natscell.InterRegion, error) {
	if ledger, err := record.ledgerDigest(); err != nil || record.SchemaVersion != interRegionSchema ||
		ledger != record.LedgerDigest || !now.Before(record.ExpiresAt) {
		return natscell.InterRegion{}, fmt.Errorf("%w: interregion record must use schema 1, be unexpired and match its ledger digest", ErrMaterial)
	}
	index := slices.IndexFunc(record.Slots, func(candidate Slot) bool { return candidate.Name == slot })
	if index < 0 || !filepath.IsAbs(directory) {
		return natscell.InterRegion{}, fmt.Errorf("%w: %q is not a controller slot of %s", ErrMaterial, slot, record.Cell)
	}
	path := func(name string) string { return filepath.Join(directory, name) }
	tls := natscell.TLSFiles{CAFile: path("interregion-ca.pem"), CertFile: path("interregion-tls-" + slot + "-cert.pem"),
		KeyFile: path("interregion-tls-" + slot + "-key.pem")}
	topology := record.Topology()
	block := natscell.InterRegion{Peers: topology.Peers(record.Cell), AccountJWTFile: path("interregion.jwt"),
		GlobalHome: topology.Hub, Topology: &topology}
	if record.Config.ListenPort > 0 {
		block.Listen = &natscell.LeafListen{Host: "0.0.0.0", Port: record.Config.ListenPort, TLS: tls}
		block.Subtrees = topology.Subtrees(record.Cell)
	}
	parent, dials := topology.Parent(record.Cell)
	switch {
	case dials && (link == nil || link.Record.Cell != parent || !reflect.DeepEqual(link.Record.Topology(), topology)):
		return natscell.InterRegion{}, fmt.Errorf("%w: %s needs the interregion record of its parent %s, of the same topology",
			ErrMaterial, record.Cell, parent)
	case !dials && link != nil:
		return natscell.InterRegion{}, fmt.Errorf("%w: %s dials no parent", ErrMaterial, record.Cell)
	case dials:
		remote, err := LeafRemote(link.Record, record.Cell, index, link.Receipt, link.NetBird, link.CredentialsFile, tls, now)
		if err != nil {
			return natscell.InterRegion{}, err
		}
		remote.CredentialsFile = path("leaf-" + parent + ".creds")
		block.Remotes = []natscell.LeafRemote{remote}
	}
	if err := block.Validate(record.Cell); err != nil {
		return natscell.InterRegion{}, fmt.Errorf("%w: rendered interregion block: %w", ErrMaterial, err)
	}
	return block, nil
}

// Topology returns the record's leaf tree.
func (record InterRegionRecord) Topology() natscell.LeafTopology { return record.Config.Topology }

func (record InterRegionRecord) file(name string) (File, bool) {
	for _, file := range record.Files {
		if file.Name == name {
			return file, true
		}
	}
	return File{}, false
}
