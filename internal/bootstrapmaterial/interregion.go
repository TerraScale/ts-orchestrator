package bootstrapmaterial

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"time"
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

// PrivatePeerReceiptKind and PrivatePeerReceiptPass identify the reviewed
// private-peer foundation readback (ociregion InspectPrivatePeer).

// nested reports whether path is parent or inside it.
func nested(parent, path string) bool {
	relative, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(path))
	return err == nil && (relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func metadataDigest(directory string) (string, error) {
	metadata, err := readOwnedFile(filepath.Join(directory, metadataName), 1<<20)
	if err != nil {
		return "", ErrMaterial
	}
	return digest(metadata), nil
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
