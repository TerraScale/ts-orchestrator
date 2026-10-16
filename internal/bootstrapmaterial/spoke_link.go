package bootstrapmaterial

import (
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

// GenerateSpokeLink issues only a recipient's leaf material from the GRU source.
// The caller must authenticate the public recipient record through its current
// bootstrap authority; no recipient private source is needed or accepted.
func GenerateSpokeLink(homeMaterialDirectory, homeLinkDirectory string, recipient Record, sourceMetadataSHA, directory string, now time.Time) (LinkRecord, error) {
	wire, err := json.Marshal(recipient)
	if err != nil || digest(wire) != sourceMetadataSHA || recipient.SchemaVersion != 1 || recipient.Config.validate() != nil || recipient.Config.Cell == natscell.LinkHome || now.IsZero() || now.Before(recipient.IssuedAt) || !now.Before(recipient.ExpiresAt) || recipient.ExpiresAt.Sub(recipient.IssuedAt) != time.Duration(recipient.Config.ValidityHours)*time.Hour {
		return LinkRecord{}, ErrMaterial
	}
	if !nkeys.IsValidPublicOperatorKey(recipient.Public.OperatorNKey) {
		return LinkRecord{}, ErrMaterial
	}
	keys := []string{recipient.Public.SystemAccountNKey, recipient.Public.CellAccountNKey, recipient.Public.HostNATSIssuerNKey}
	for index, key := range keys {
		if !nkeys.IsValidPublicAccountKey(key) || slices.Contains(keys[:index], key) {
			return LinkRecord{}, ErrMaterial
		}
	}
	for _, key := range []string{recipient.Public.PeerSignerPublicKey, recipient.Public.LedgerSignerPublicKey, recipient.Public.TicketSignerPublicKey, recipient.Public.ControllerResponsePublicKey} {
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return LinkRecord{}, ErrMaterial
		}
	}
	home, err := Load(homeMaterialDirectory)
	if err != nil || home.Config.Cell != natscell.LinkHome || recipient.Config.Environment != home.Config.Environment || recipient.Config.DeploymentID != home.Config.DeploymentID || recipient.Public.CellAccountNKey == home.Public.CellAccountNKey || recipient.Public.OperatorNKey == home.Public.OperatorNKey {
		return LinkRecord{}, ErrMaterial
	}
	if !filepath.IsAbs(directory) || secureParents(directory) != nil || nested(homeMaterialDirectory, directory) || nested(directory, homeMaterialDirectory) || nested(homeLinkDirectory, directory) || nested(directory, homeLinkDirectory) {
		return LinkRecord{}, ErrMaterial
	}
	homeLink, err := GenerateLink(homeMaterialDirectory, homeMaterialDirectory, homeLinkDirectory, homeLinkDirectory, now)
	if err != nil {
		return LinkRecord{}, err
	}
	homeDigest, err := metadataDigest(homeMaterialDirectory)
	if err != nil {
		return LinkRecord{}, err
	}
	linkDigest, err := metadataDigest(homeLinkDirectory)
	if err != nil {
		return LinkRecord{}, err
	}
	if _, err := os.Lstat(directory); err == nil {
		record, err := LoadLink(directory, now)
		if err != nil || record.SourceSHA256 != sourceMetadataSHA || record.HomeSHA256 != homeDigest || record.HomeLinkSHA256 != linkDigest || record.HomeAccount != homeLink.HomeAccount || record.Signer != homeLink.Signer || !reflect.DeepEqual(record.Config, recipient.Config) || !reflect.DeepEqual(record.Public, recipient.Public) {
			return LinkRecord{}, ErrMaterial
		}
		return record, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return LinkRecord{}, ErrMaterial
	}
	seed, err := readOwnedFile(filepath.Join(homeLinkDirectory, "issuer-link.seed"), 4096)
	if err != nil {
		return LinkRecord{}, err
	}
	signer, err := nkeys.FromSeed(seed)
	clear(seed)
	if err != nil {
		return LinkRecord{}, err
	}
	defer signer.Wipe()
	record := LinkRecord{SchemaVersion: 1, Config: recipient.Config, Public: recipient.Public, IssuedAt: now.UTC(), ExpiresAt: minTime(recipient.ExpiresAt, homeLink.ExpiresAt), SourceSHA256: sourceMetadataSHA, HomeSHA256: homeDigest, HomeLinkSHA256: linkDigest, HomeAccount: homeLink.HomeAccount, Signer: homeLink.Signer}
	files := map[string][]byte{}
	defer func() {
		for _, body := range files {
			clear(body)
		}
	}()
	files[bootstrap.LinkCredentialsFile], err = natscell.IssueLinkUser(signer, record.HomeAccount, recipient.Config.Cell, now, record.ExpiresAt)
	if err != nil {
		return LinkRecord{}, err
	}
	files["interregion-ca.pem"], err = readOwnedFile(filepath.Join(homeMaterialDirectory, "ca.pem"), 64<<10)
	if err != nil {
		return LinkRecord{}, err
	}
	ca, caKey, err := linkCA(files["interregion-ca.pem"], filepath.Join(homeMaterialDirectory, "issuer-ca.key"))
	if err != nil {
		return LinkRecord{}, err
	}
	for _, slot := range recipient.Config.Slots {
		certificate := &x509.Certificate{Subject: pkix.Name{CommonName: recipient.Config.Cell + " " + slot.Name + " link"}, NotBefore: now.Add(-time.Minute), NotAfter: record.ExpiresAt, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, DNSNames: []string{InterRegionLeafName(recipient.Config.Cell)}}
		cert, key := bootstrap.InterRegionTLSFiles(slot.Name)
		files[cert], files[key], _, _, err = interRegionCertificate(certificate, ca, caKey)
		if err != nil {
			return LinkRecord{}, err
		}
	}
	staging, err := os.MkdirTemp(filepath.Dir(directory), ".spoke-link-")
	if err != nil {
		return LinkRecord{}, err
	}
	defer os.RemoveAll(staging)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		body := files[name]
		if len(body) == 0 || len(body) > maxInterRegionFile {
			return LinkRecord{}, ErrMaterial
		}
		purpose, slot := linkPurpose(name)
		record.Files = append(record.Files, File{Name: name, Purpose: purpose, Slot: slot, SHA256: digest(body), MaxBytes: int64(len(body))})
		if err := writeOnce(filepath.Join(staging, name), body); err != nil {
			return LinkRecord{}, err
		}
	}
	wire, err = json.Marshal(record)
	if err != nil {
		return LinkRecord{}, err
	}
	if err := writeOnce(filepath.Join(staging, metadataName), wire); err != nil {
		return LinkRecord{}, err
	}
	if err := writeOnce(filepath.Join(staging, readyName), []byte(digest(wire)+"\n")); err != nil {
		return LinkRecord{}, err
	}
	if err := syncDirectory(staging); err != nil {
		return LinkRecord{}, err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, directory, unix.RENAME_NOREPLACE); err != nil && !errors.Is(err, unix.EEXIST) {
		return LinkRecord{}, err
	}
	if err := syncDirectory(filepath.Dir(directory)); err != nil {
		return LinkRecord{}, err
	}
	return GenerateSpokeLink(homeMaterialDirectory, homeLinkDirectory, recipient, sourceMetadataSHA, directory, now)
}
