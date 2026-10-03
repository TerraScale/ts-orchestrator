package bootstrapmaterial

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
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
//
// Every claim is checked with the same contract verifier the server runs at
// startup before anything is written. The metadata records each file's
// SHA-256 and a LedgerDigest over the whole record, which is what the
// deployment's signed bootstrap ledger records for this material.
const (
	interRegionMetadataName = "interregion.json"
	interRegionSchema       = 1
	maxInterRegionFile      = 64 << 10
)

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
	OperatorNKey   string `json:"operatorNkey"`
	IssuedAt       time.Time `json:"issuedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
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
	if !slices.Contains(topology.Regions(), cell) || len(topology.Regions()) < 2 || len(topology.Regions()) > 64 {
		return natscell.InterRegionContract{}, 0, errors.New("interregion topology must contain this region and a peer")
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
// replaces anything: an existing directory must already hold the same
// material, which is returned.
func GenerateInterRegion(materialDirectory, directory string, cfg InterRegionConfig, now time.Time,
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
	if !filepath.IsAbs(directory) || now.IsZero() || secureParents(directory) != nil || !now.Before(material.ExpiresAt) {
		return InterRegionRecord{}, ErrMaterial
	}
	if _, err := os.Lstat(directory); err == nil {
		record, loadErr := LoadInterRegion(directory)
		if loadErr != nil || record.MaterialSHA256 != materialDigest || !sameTopology(record.Config, cfg) {
			return InterRegionRecord{}, ErrMaterial
		}
		return record, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return InterRegionRecord{}, ErrMaterial
	}
	files, record, err := issueInterRegion(materialDirectory, material, contract, links, cfg, now.UTC())
	if err != nil {
		return InterRegionRecord{}, err
	}
	defer func() {
		for _, body := range files {
			clear(body)
		}
	}()
	record.MaterialSHA256 = materialDigest
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for name := range files {
			if !yield(name) {
				return
			}
		}
	}) {
		record.Files = append(record.Files, File{Name: name, Purpose: "interregion", SHA256: digest(files[name]),
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
	cfg InterRegionConfig, now time.Time,
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
	cell, err := readClaim("cell.jwt", material.Public.CellAccountNKey)
	if err != nil {
		return nil, InterRegionRecord{}, err
	}
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
	for _, claim := range []*jwt.AccountClaims{system, cell} {
		claim.Expires = expires.Unix()
	}
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

// interRegionNames lists the files interregion material for children holds.
func interRegionNames(children []string) []string {
	names := []string{"interregion.jwt", "cell-interregion.jwt", "system-interregion.jwt"}
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
	if err := json.Unmarshal(metadata, &record); err != nil || record.SchemaVersion != interRegionSchema {
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
	names := interRegionNames(children)
	if len(record.Files) != len(names) {
		return InterRegionRecord{}, ErrMaterial
	}
	for index, file := range record.Files {
		if file.Name != names[index] || file.Purpose != "interregion" || file.MaxBytes <= 0 ||
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

// LeafRemote builds the remote a child region dials to reach the region of
// parent. The URLs come only from the reviewed private-peer receipt: the
// receipt's exact bytes must hash to reviewedSHA256, it must be a passing,
// unexpired readback of the private peering between parent and child that
// allows the parent's leaf port, and every URL is a parent controller
// address inside the parent subnet the receipt observed. credentialsFile is
// the child's copy of the parent's leaf-<child>.creds; its digest must match
// the parent's record. TLS stays the caller's (the reviewed interregion CA).
func LeafRemote(parent InterRegionRecord, child string, receipt []byte, reviewedSHA256, credentialsFile string,
	tls natscell.TLSFiles, now time.Time,
) (natscell.LeafRemote, error) {
	if parent.Topology().Hub == "" {
		return natscell.LeafRemote{}, ErrMaterial
	}
	if dialed, ok := parent.Config.Topology.Parent(child); !ok || dialed != parent.Cell {
		return natscell.LeafRemote{}, fmt.Errorf("%w: %s does not dial %s in the topology", ErrMaterial, child, parent.Cell)
	}
	sum := sha256.Sum256(receipt)
	if len(reviewedSHA256) != 64 || hex.EncodeToString(sum[:]) != strings.ToLower(reviewedSHA256) {
		return natscell.LeafRemote{}, fmt.Errorf("%w: private-peer receipt is not the reviewed one", ErrMaterial)
	}
	var readback privatePeerReceipt
	if err := json.Unmarshal(receipt, &readback); err != nil || readback.SchemaVersion != 1 ||
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
	remote := natscell.LeafRemote{Peer: parent.Cell, CredentialsFile: credentialsFile,
		PeerAccount: parent.InterRegionAccountNKey, TLS: tls}
	for _, slot := range parent.Slots {
		address, err := netip.ParseAddr(slot.PrivateIP)
		if err != nil || !subnet.Contains(address) {
			return natscell.LeafRemote{}, fmt.Errorf("%w: controller %s is outside the peered subnet", ErrMaterial, slot.Name)
		}
		remote.URLs = append(remote.URLs, "nats-leaf://"+netip.AddrPortFrom(address, uint16(parent.Config.ListenPort)).String())
	}
	if len(remote.URLs) == 0 {
		return natscell.LeafRemote{}, ErrMaterial
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

