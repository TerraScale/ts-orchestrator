package bootstrapmaterial

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
)

// LinkRecord binds immutable leaf credentials to both regional material sources.
// The home-only signer reference is never part of a controller generation.
type LinkRecord struct {
	Record
	SourceSHA256   string `json:"sourceSha256"`
	HomeSHA256     string `json:"homeSha256"`
	HomeLinkSHA256 string `json:"homeLinkSha256,omitempty"`
	HomeAccount    string `json:"homeAccount"`
	Signer         string `json:"signer"`
}

// GenerateLink prepares a fixed GRU-rooted link, preserving existing sources.
// A spoke first recovers the home's immutable link source. Incomplete output
// holds for inspection; it never causes replacement keys to be generated.
func GenerateLink(materialDirectory, homeMaterialDirectory, homeLinkDirectory, directory string, now time.Time) (LinkRecord, error) {
	material, err := Load(materialDirectory)
	if err != nil {
		return LinkRecord{}, err
	}
	home, err := Load(homeMaterialDirectory)
	if err != nil || home.Config.Cell != natscell.LinkHome || material.Config.Environment != home.Config.Environment || material.Config.DeploymentID != home.Config.DeploymentID || now.IsZero() || now.Before(material.IssuedAt) || now.Before(home.IssuedAt) || !now.Before(material.ExpiresAt) || !now.Before(home.ExpiresAt) {
		return LinkRecord{}, ErrMaterial
	}
	isHome := material.Config.Cell == natscell.LinkHome
	if isHome && filepath.Clean(materialDirectory) != filepath.Clean(homeMaterialDirectory) || isHome && filepath.Clean(homeLinkDirectory) != filepath.Clean(directory) || !isHome && (nested(homeLinkDirectory, directory) || nested(directory, homeLinkDirectory)) {
		return LinkRecord{}, ErrMaterial
	}
	for _, source := range []string{materialDirectory, homeMaterialDirectory} {
		if !filepath.IsAbs(directory) || secureParents(directory) != nil || nested(source, directory) || nested(directory, source) {
			return LinkRecord{}, ErrMaterial
		}
	}
	if err := ValidateLive(materialDirectory, material); err != nil {
		return LinkRecord{}, err
	}
	if err := ValidateLive(homeMaterialDirectory, home); err != nil {
		return LinkRecord{}, err
	}
	sourceDigest, err := metadataDigest(materialDirectory)
	if err != nil {
		return LinkRecord{}, err
	}
	homeDigest, err := metadataDigest(homeMaterialDirectory)
	if err != nil {
		return LinkRecord{}, err
	}
	var homeLink LinkRecord
	homeLinkDigest := ""
	if !isHome {
		homeLink, err = GenerateLink(homeMaterialDirectory, homeMaterialDirectory, homeLinkDirectory, homeLinkDirectory, now)
		if err != nil {
			return LinkRecord{}, err
		}
		homeLinkDigest, err = metadataDigest(homeLinkDirectory)
		if err != nil {
			return LinkRecord{}, err
		}
	}
	if _, err := os.Lstat(directory); err == nil {
		record, err := LoadLink(directory, now)
		if err != nil || record.SourceSHA256 != sourceDigest || record.HomeSHA256 != homeDigest || record.HomeLinkSHA256 != homeLinkDigest || !reflect.DeepEqual(record.Config, material.Config) || !reflect.DeepEqual(record.Public, material.Public) || record.HomeAccount != home.Public.CellAccountNKey || !isHome && record.Signer != homeLink.Signer {
			return LinkRecord{}, ErrMaterial
		}
		return record, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return LinkRecord{}, ErrMaterial
	}
	var homeClaim *jwt.AccountClaims
	if isHome {
		raw, err := readOwnedFile(filepath.Join(materialDirectory, "cell.jwt"), 64<<10)
		if err != nil {
			return LinkRecord{}, err
		}
		homeClaim, err = jwt.DecodeAccountClaims(string(raw))
		if err != nil || homeClaim.Subject != home.Public.CellAccountNKey || len(homeClaim.Imports) != 0 || len(homeClaim.Exports) != 0 || len(homeClaim.Mappings) != 0 || material.Config.LinkSigner != "" {
			return LinkRecord{}, ErrMaterial
		}
		if homeClaim.IssuedAt >= time.Now().Unix() {
			return LinkRecord{}, fmt.Errorf("%w: home cell claim was issued this second; retry after its issuance second", ErrMaterial)
		}
	}
	// Publish complete source bytes atomically; a crash before publication grants no authority.
	staging, err := os.MkdirTemp(filepath.Dir(directory), ".link-material-")
	if err != nil {
		return LinkRecord{}, err
	}
	defer os.RemoveAll(staging)
	files := map[string][]byte{}
	defer func() {
		for _, body := range files {
			clear(body)
		}
	}()
	record := LinkRecord{SchemaVersion: 1, Config: material.Config, Public: material.Public, IssuedAt: now.UTC(), ExpiresAt: minTime(material.ExpiresAt, home.ExpiresAt), SourceSHA256: sourceDigest, HomeSHA256: homeDigest, HomeLinkSHA256: homeLinkDigest, HomeAccount: home.Public.CellAccountNKey}
	var signer nkeys.KeyPair
	if isHome {
		signer, err = nkeys.CreateAccount()
		if err != nil {
			return LinkRecord{}, err
		}
		files["issuer-link.seed"], err = signer.Seed()
	} else {
		record.ExpiresAt = minTime(record.ExpiresAt, homeLink.ExpiresAt)
		seed, readErr := readOwnedFile(filepath.Join(homeLinkDirectory, "issuer-link.seed"), 4096)
		if readErr != nil {
			return LinkRecord{}, readErr
		}
		signer, err = nkeys.FromSeed(seed)
		clear(seed)
	}
	if err != nil {
		return LinkRecord{}, err
	}
	defer signer.Wipe()
	record.Signer, err = signer.PublicKey()
	if err != nil {
		return LinkRecord{}, err
	}
	if isHome {
		claim := homeClaim
		previousIssue := claim.IssuedAt
		natscell.ApplyLink(claim, record.Signer)
		seed, readErr := readOwnedFile(filepath.Join(materialDirectory, "issuer-operator.seed"), 4096)
		if readErr != nil {
			return LinkRecord{}, readErr
		}
		operator, decodeErr := nkeys.FromSeed(seed)
		clear(seed)
		if decodeErr != nil {
			return LinkRecord{}, decodeErr
		}
		claim.IssuedAt, claim.Expires = now.Unix(), record.ExpiresAt.Unix()
		encoded, encodeErr := claim.Encode(operator)
		operator.Wipe()
		if encodeErr != nil {
			return LinkRecord{}, encodeErr
		}
		if claim.IssuedAt <= previousIssue {
			return LinkRecord{}, ErrMaterial
		}
		files["link-cell.jwt"] = []byte(encoded)
	} else {
		files[bootstrap.LinkCredentialsFile], err = natscell.IssueLinkUser(signer, record.HomeAccount, material.Config.Cell, now, record.ExpiresAt)
		if err != nil {
			return LinkRecord{}, err
		}
	}
	files["interregion-ca.pem"], err = readOwnedFile(filepath.Join(homeMaterialDirectory, "ca.pem"), 64<<10)
	if err != nil {
		return LinkRecord{}, err
	}
	ca, key, err := linkCA(files["interregion-ca.pem"], filepath.Join(homeMaterialDirectory, "issuer-ca.key"))
	if err != nil {
		return LinkRecord{}, err
	}
	for _, slot := range material.Config.Slots {
		template := &x509.Certificate{Subject: pkix.Name{CommonName: material.Config.Cell + " " + slot.Name + " link"}, NotBefore: now.Add(-time.Minute), NotAfter: record.ExpiresAt, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, DNSNames: []string{InterRegionLeafName(material.Config.Cell)}}
		if isHome {
			template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
			template.DNSNames = []string{natscell.LinkServerName}
		}
		certName, keyName := bootstrap.InterRegionTLSFiles(slot.Name)
		files[certName], files[keyName], _, _, err = interRegionCertificate(template, ca, key)
		if err != nil {
			return LinkRecord{}, err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		purpose, slot := linkPurpose(name)
		body := files[name]
		if len(body) == 0 || len(body) > maxInterRegionFile {
			return LinkRecord{}, ErrMaterial
		}
		record.Files = append(record.Files, File{Name: name, Purpose: purpose, Slot: slot, SHA256: digest(body), MaxBytes: int64(len(body))})
		if err := writeOnce(filepath.Join(staging, name), body); err != nil {
			return LinkRecord{}, err
		}
	}
	wire, err := json.Marshal(record)
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
	return GenerateLink(materialDirectory, homeMaterialDirectory, homeLinkDirectory, directory, now)
}

func linkCA(certPEM []byte, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	keyPEM, err := readOwnedFile(keyPath, 4096)
	if err != nil {
		return nil, nil, err
	}
	defer clear(keyPEM)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(pair.Certificate) != 1 {
		return nil, nil, ErrMaterial
	}
	ca, err := x509.ParseCertificate(pair.Certificate[0])
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if err != nil || !ok || !ca.IsCA || ca.CheckSignatureFrom(ca) != nil {
		return nil, nil, ErrMaterial
	}
	return ca, key, nil
}

func linkPurpose(name string) (bootstrap.SecretPurpose, string) {
	if name == "issuer-link.seed" {
		return "owner-only", ""
	}
	if name == "link-cell.jwt" {
		return bootstrap.SecretRegionalShared, ""
	}
	if name == "interregion-ca.pem" || name == bootstrap.LinkCredentialsFile {
		return bootstrap.SecretInterRegion, ""
	}
	for _, slot := range []string{"controller-a", "controller-b", "controller-c"} {
		cert, key := bootstrap.InterRegionTLSFiles(slot)
		if name == cert || name == key {
			return bootstrap.SecretInterRegion, slot
		}
	}
	return "", ""
}

// LoadLink checks exact immutable bytes, credential identity and TLS chain.
func LoadLink(directory string, now time.Time) (LinkRecord, error) {
	if !filepath.IsAbs(directory) || secureParents(directory) != nil || secureDirectory(directory) != nil {
		return LinkRecord{}, ErrMaterial
	}
	wire, err := readOwnedFile(filepath.Join(directory, metadataName), 1<<20)
	if err != nil {
		return LinkRecord{}, err
	}
	ready, err := readOwnedFile(filepath.Join(directory, readyName), 128)
	if err != nil || string(ready) != digest(wire)+"\n" {
		return LinkRecord{}, ErrMaterial
	}
	var record LinkRecord
	if json.Unmarshal(wire, &record, json.RejectUnknownMembers(true)) != nil || record.SchemaVersion != 1 || record.Config.validate() != nil || len(record.SourceSHA256) != 64 || len(record.HomeSHA256) != 64 || !nkeys.IsValidPublicAccountKey(record.HomeAccount) || !nkeys.IsValidPublicAccountKey(record.Signer) || record.Signer == record.HomeAccount || now.Before(record.IssuedAt) || !now.Before(record.ExpiresAt) {
		return LinkRecord{}, ErrMaterial
	}
	home := record.Config.Cell == natscell.LinkHome
	expected := map[string]bool{"interregion-ca.pem": true}
	if home {
		expected["link-cell.jwt"], expected["issuer-link.seed"] = true, true
	} else {
		expected[bootstrap.LinkCredentialsFile] = true
		if len(record.HomeLinkSHA256) != 64 {
			return LinkRecord{}, ErrMaterial
		}
	}
	for _, slot := range record.Config.Slots {
		cert, key := bootstrap.InterRegionTLSFiles(slot.Name)
		expected[cert], expected[key] = true, true
	}
	if len(record.Files) != len(expected) {
		return LinkRecord{}, ErrMaterial
	}
	files := map[string][]byte{}
	defer func() {
		for _, body := range files {
			clear(body)
		}
	}()
	allowed := map[string]bool{metadataName: true, readyName: true, journalName: true, journalTempName: true, journalLockName: true}
	for _, file := range record.Files {
		purpose, slot := linkPurpose(file.Name)
		if !expected[file.Name] || files[file.Name] != nil || purpose != file.Purpose || slot != file.Slot || file.MaxBytes <= 0 || file.MaxBytes > maxInterRegionFile {
			return LinkRecord{}, ErrMaterial
		}
		body, err := readOwnedFile(filepath.Join(directory, file.Name), file.MaxBytes)
		if err != nil || int64(len(body)) != file.MaxBytes || digest(body) != file.SHA256 {
			clear(body)
			return LinkRecord{}, ErrMaterial
		}
		files[file.Name] = body
		allowed[file.Name] = true
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return LinkRecord{}, err
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return LinkRecord{}, ErrMaterial
		}
	}
	if home {
		claim, err := jwt.DecodeAccountClaims(string(files["link-cell.jwt"]))
		if err != nil || claim.Subject != record.HomeAccount || claim.Issuer != record.Public.OperatorNKey || natscell.VerifyLinkScope(claim) != nil {
			return LinkRecord{}, ErrMaterial
		}
		if scope, ok := claim.SigningKeys.GetScope(record.Signer); !ok || !reflect.DeepEqual(scope, natscell.LinkScope(record.Signer)) {
			return LinkRecord{}, ErrMaterial
		}
		signer, err := nkeys.FromSeed(files["issuer-link.seed"])
		if err != nil {
			return LinkRecord{}, ErrMaterial
		}
		public, err := signer.PublicKey()
		signer.Wipe()
		if err != nil || public != record.Signer {
			return LinkRecord{}, ErrMaterial
		}
	} else {
		if natscell.ValidateLinkCredentialBytes(files[bootstrap.LinkCredentialsFile], record.Config.Cell) != nil {
			return LinkRecord{}, ErrMaterial
		}
		raw, err := jwt.ParseDecoratedJWT(files[bootstrap.LinkCredentialsFile])
		if err != nil {
			return LinkRecord{}, ErrMaterial
		}
		claim, err := jwt.DecodeUserClaims(raw)
		if err != nil || claim.Issuer != record.Signer || claim.IssuerAccount != record.HomeAccount {
			return LinkRecord{}, ErrMaterial
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(files["interregion-ca.pem"]) {
		return LinkRecord{}, ErrMaterial
	}
	for _, slot := range record.Config.Slots {
		cert, key := bootstrap.InterRegionTLSFiles(slot.Name)
		pair, err := tls.X509KeyPair(files[cert], files[key])
		if err != nil {
			return LinkRecord{}, ErrMaterial
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return LinkRecord{}, ErrMaterial
		}
		usages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		if home {
			usages = append(usages, x509.ExtKeyUsageServerAuth)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, DNSName: InterRegionLeafName(record.Config.Cell), KeyUsages: usages}); err != nil || leaf.IsCA || leaf.NotAfter.After(record.ExpiresAt) {
			return LinkRecord{}, ErrMaterial
		}
	}
	return record, nil
}

// RenderLink uses the same pinned target names as MaterialGeneration. The home
// uses this publication's link-cell.jwt; spokes keep their regional account claim.
func RenderLink(record LinkRecord, slot, directory string) (natscell.Link, error) {
	if !filepath.IsAbs(directory) || !slices.ContainsFunc(record.Config.Slots, func(s Slot) bool { return s.Name == slot }) {
		return natscell.Link{}, ErrMaterial
	}
	cert, key := bootstrap.InterRegionTLSFiles(slot)
	link := natscell.Link{TLS: natscell.TLSFiles{CAFile: filepath.Join(directory, "interregion-ca.pem"), CertFile: filepath.Join(directory, cert), KeyFile: filepath.Join(directory, key)}}
	if record.Config.Cell != natscell.LinkHome {
		link.CredentialsFile = filepath.Join(directory, bootstrap.LinkCredentialsFile)
	}
	return link, nil
}

// ProvisionLink publishes host files using regional recovery and OCI retry tokens.
// The home signing seed stays in the founder-only source escrow.
func ProvisionLink(ctx context.Context, directory string, target VaultTarget, management VaultClient, bundles BundleClient, now time.Time) (Publication, error) {
	return provisionLink(ctx, directory, target, management, bundles, now, nil)
}

// ProvisionLinkDurable preserves the publication journal through source authority
// checkpoints before issuing any Vault secret create.
func ProvisionLinkDurable(ctx context.Context, directory string, target VaultTarget, management VaultClient, bundles BundleClient, now time.Time, checkpoint func([]byte) error) (Publication, error) {
	if checkpoint == nil {
		return Publication{}, ErrProvision
	}
	return provisionLink(ctx, directory, target, management, bundles, now, checkpoint)
}

func provisionLink(ctx context.Context, directory string, target VaultTarget, management VaultClient, bundles BundleClient, now time.Time, checkpoint func([]byte) error) (Publication, error) {
	record, err := LoadLink(directory, now)
	if err != nil || management == nil || bundles == nil || ctx.Err() != nil || target.validate(record.Config.Region) != nil {
		return Publication{}, ErrProvision
	}
	fd, err := syscall.Open(filepath.Join(directory, journalLockName), syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return Publication{}, ErrProvision
	}
	lock := os.NewFile(uintptr(fd), journalLockName)
	defer lock.Close()
	if ownedRegular(filepath.Join(directory, journalLockName), 0, 0) != nil {
		return Publication{}, ErrProvision
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return Publication{}, ErrProvision
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	materialDigest, err := metadataDigest(directory)
	if err != nil {
		return Publication{}, ErrProvision
	}
	state, err := loadJournal(directory, record.Record, target, materialDigest, checkpoint)
	if err != nil {
		return Publication{}, err
	}
	result := Publication{SchemaVersion: 1, Target: target, MaterialSHA256: materialDigest}
	for index := range state.Entries {
		entry := &state.Entries[index]
		file, ok := findFile(record.Record, entry.FileName)
		if !ok || ctx.Err() != nil {
			return Publication{}, ErrProvision
		}
		if err := publishOne(ctx, directory, target, record.Config.Region, management, bundles, file, entry, &state, now, checkpoint); err != nil {
			return Publication{}, err
		}
		result.References = append(result.References, PublicReference{SecretName: entry.Name, Reference: bootstrap.SecretReference{Purpose: file.Purpose, Slot: file.Slot, SecretOCID: entry.SecretOCID, VersionNumber: 1, SHA256: file.SHA256, MaxBytes: file.MaxBytes, TargetFile: file.Name}})
	}
	return result, nil
}

// GenerationReferences excludes the home signing authority from delivery to
// controllers; the existing signed generation consumer installs all other pins.
func (publication Publication) LinkGenerationReferences() []bootstrap.SecretReference {
	var refs []bootstrap.SecretReference
	for _, ref := range publication.References {
		if ref.Reference.Purpose == bootstrap.SecretInterRegion || ref.Reference.TargetFile == "link-cell.jwt" {
			reference := ref.Reference
			if reference.TargetFile == "link-cell.jwt" {
				reference.TargetFile = "cell.jwt"
			}
			refs = append(refs, reference)
		}
	}
	return refs
}
