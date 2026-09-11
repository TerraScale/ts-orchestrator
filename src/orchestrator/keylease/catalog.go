// Package keylease serves short-lived, database-scoped provider data keys to
// the local TerraBase process. Durable state contains provider references and
// wrapped ciphertext only; credentials and plaintext keys never enter it.
package keylease

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/byokauthority"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

var ErrUnavailable = errors.New("keylease: key unavailable")

const maximumCatalogBytes = 4 << 20

// Binding is authenticated as OCI associated data, including the intended use.
// Versions are explicit; the service never substitutes the newest version.
type Binding struct {
	Environment string `json:"environment"`
	TenantID    string `json:"tenant_id"`
	ProjectID   string `json:"project_id"`
	DatabaseID  string `json:"database_id"`
	KeyVersion  string `json:"key_version"`
	Region      string `json:"region"`
	Purpose     string `json:"purpose"`
}

type Entry struct {
	Binding              Binding       `json:"binding"`
	Provider             string        `json:"provider,omitempty"`
	KeyID                string        `json:"key_id,omitempty"`
	KeyRegion            string        `json:"key_region,omitempty"`
	KeyEndpoint          string        `json:"key_endpoint,omitempty"`
	CryptoEndpoint       string        `json:"crypto_endpoint"`
	KEKID                string        `json:"kek_id"`
	KEKVersionID         string        `json:"kek_version_id"`
	Ciphertext           string        `json:"ciphertext"`
	LeaseSeconds         uint32        `json:"lease_seconds"`
	Revoked              bool          `json:"revoked"`
	NotAfter             time.Time     `json:"not_after"`
	AdmissionOperationID string        `json:"admission_operation_id,omitempty"`
	BYOK                 *BYOKMetadata `json:"byok,omitempty"`
}

type BYOKMetadata struct {
	BackupEndpoint         string `json:"backup_endpoint"`
	BackupBucket           string `json:"backup_bucket"`
	BackupRegion           string `json:"backup_region"`
	BackupRoleARN          string `json:"backup_role_arn"`
	BackupExternalID       string `json:"backup_external_id,omitempty"`
	KeyProvider            string `json:"key_provider"`
	KeyID                  string `json:"key_id"`
	KeyRegion              string `json:"key_region"`
	KeyEndpoint            string `json:"key_endpoint"`
	ConfigurationUpdatedAt string `json:"configuration_updated_at"`
}

type Catalog struct {
	Version    int                 `json:"version"`
	Entries    []Entry             `json:"entries"`
	Tombstones []DatabaseTombstone `json:"tombstones,omitempty"`
}

func validULID(s string) bool {
	if len(s) != 26 || s[0] > '7' {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", c) {
			return false
		}
	}
	return true
}
func validEnvironment(environment string) bool {
	if len(environment) < 1 || len(environment) > 128 {
		return false
	}
	for _, c := range environment {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}
func (b Binding) valid() bool {
	if !validEnvironment(b.Environment) {
		return false
	}
	return validULID(b.TenantID) && validULID(b.ProjectID) && validULID(b.DatabaseID) && validULID(b.KeyVersion) && ociRegion(b.Region) != "" && (b.Purpose == "data" || b.Purpose == "backup" || b.Purpose == "checkpoint")
}
func ociRegion(region string) string {
	switch region {
	case "GRU":
		return "sa-saopaulo-1"
	case "SFO":
		return "us-sanjose-1"
	case "FRA":
		return "eu-frankfurt-1"
	}
	return ""
}
func (b Binding) AssociatedData() map[string]string {
	return map[string]string{"environment": b.Environment, "tenant_id": b.TenantID, "project_id": b.ProjectID, "database_id": b.DatabaseID, "key_version": b.KeyVersion, "region": b.Region, "purpose": b.Purpose}
}
func (c Catalog) validate() error {
	if c.Version != 1 || len(c.Entries) > 10000 {
		return ErrUnavailable
	}
	if len(c.Tombstones) > 100000 {
		return ErrUnavailable
	}
	destroyed := map[DatabaseScope]bool{}
	for _, tombstone := range c.Tombstones {
		if !tombstone.valid() || destroyed[tombstone.Scope] {
			return ErrUnavailable
		}
		destroyed[tombstone.Scope] = true
	}
	seen := map[Binding]bool{}
	for _, e := range c.Entries {
		if !e.Binding.valid() || seen[e.Binding] || destroyed[e.Binding.Scope()] || !validEntryProvider(e) || len(e.Ciphertext) == 0 || len(e.Ciphertext) > 8192 || e.LeaseSeconds < 1 || e.LeaseSeconds > 1800 || e.NotAfter.IsZero() {
			return ErrUnavailable
		}
		seen[e.Binding] = true
	}
	return nil
}

func validEntryProvider(e Entry) bool {
	if e.Provider == "" {
		return e.BYOK == nil && e.KeyID == "" && e.KeyRegion == "" && e.KeyEndpoint == "" && hostsecrets.ValidVaultCryptoEndpoint(ociRegion(e.Binding.Region), e.CryptoEndpoint) && provider.IsOCID(e.KEKID, "key") && provider.IsOCID(e.KEKVersionID, "keyversion")
	}
	if e.Provider != "aws-kms" || !byokauthority.ValidKMSKeyARN(e.KeyID, e.KeyRegion) || !validEnvironment(e.KeyRegion) || e.CryptoEndpoint != "" || e.KEKID != "" || e.KEKVersionID != "" {
		return false
	}
	if b := e.BYOK; b != nil && (e.AdmissionOperationID == "" || b.KeyProvider != e.Provider || b.KeyID != e.KeyID || b.KeyRegion != e.KeyRegion || b.KeyEndpoint != e.KeyEndpoint) {
		return false
	}
	if e.KeyEndpoint == "" {
		return true // The AWS SDK resolves the admitted regional endpoint.
	}
	u, err := url.Parse(e.KeyEndpoint)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && len(e.KeyEndpoint) <= 2048 && !strings.ContainsAny(e.KeyEndpoint, "\r\n\x00")
}

// privateRoot refuses symlinked parent directories and requires owner-only
// access. OpenRoot confines subsequent file operations to that directory.
func privateRoot(path string) (*os.Root, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, "", ErrUnavailable
	}
	dir := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved != dir {
		return nil, "", ErrUnavailable
	}
	for ancestor := dir; ; ancestor = filepath.Dir(ancestor) {
		var st unix.Stat_t
		if unix.Lstat(ancestor, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
			return nil, "", ErrUnavailable
		}
		if ancestor == "/" {
			break
		}
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, "", ErrUnavailable
	}
	// os.FileInfo.Sys is syscall.Stat_t, so inspect ownership through fstat below.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", ErrUnavailable
	}
	f, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, "", ErrUnavailable
	}
	var st unix.Stat_t
	err = unix.Fstat(int(f.Fd()), &st)
	f.Close()
	if err != nil || st.Uid != uint32(os.Geteuid()) {
		root.Close()
		return nil, "", ErrUnavailable
	}
	return root, filepath.Base(path), nil
}

func ReadCatalog(path string) (Catalog, error) {
	root, name, err := privateRoot(path)
	if err != nil {
		return Catalog{}, ErrUnavailable
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > maximumCatalogBytes {
		return Catalog{}, ErrUnavailable
	}
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return Catalog{}, ErrUnavailable
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return Catalog{}, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(f, maximumCatalogBytes+1))
	if err != nil || len(body) > maximumCatalogBytes {
		return Catalog{}, ErrUnavailable
	}
	var catalog Catalog
	if json.Unmarshal(body, &catalog, json.RejectUnknownMembers(true)) != nil || catalog.validate() != nil {
		return Catalog{}, ErrUnavailable
	}
	return catalog, nil
}

// WriteCatalog durably replaces a catalog after the caller has obtained wrapped
// material from Vault. Issuance must persist this record before admitting data.
func WriteCatalog(path string, catalog Catalog) error {
	unlock, err := catalogLock(path)
	if err != nil {
		return ErrUnavailable
	}
	defer unlock()
	if existing, readErr := ReadCatalog(path); readErr == nil {
		for _, old := range existing.Tombstones {
			retained := false
			for _, next := range catalog.Tombstones {
				if next.Scope == old.Scope && sameTombstone(old, next) {
					retained = true
					break
				}
			}
			if !retained {
				return ErrUnavailable
			}
		}
	} else {
		root, name, rootErr := privateRoot(path)
		if rootErr != nil {
			return ErrUnavailable
		}
		_, statErr := root.Lstat(name)
		root.Close()
		if !os.IsNotExist(statErr) {
			return ErrUnavailable
		}
	}
	return writeCatalog(path, catalog)
}
func writeCatalog(path string, catalog Catalog) error {
	if catalog.validate() != nil {
		return ErrUnavailable
	}
	body, err := json.Marshal(catalog)
	if err != nil || len(body) > maximumCatalogBytes {
		return ErrUnavailable
	}
	root, name, err := privateRoot(path)
	if err != nil {
		return ErrUnavailable
	}
	defer root.Close()
	// A unique, exclusive staging file avoids clobbering another writer's staging.
	f, err := os.CreateTemp(filepath.Dir(path), ".wrapped-key-*")
	if err != nil {
		return ErrUnavailable
	}
	temp := filepath.Base(f.Name())
	defer root.Remove(temp)
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return ErrUnavailable
	}
	if root.Rename(temp, name) != nil {
		return ErrUnavailable
	}
	dir, err := root.Open(".")
	if err != nil {
		return ErrUnavailable
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}

type UnwrapFunc func(context.Context, Entry) (*hostsecrets.DataKey, error)

func unwrapOCI(ctx context.Context, e Entry) (*hostsecrets.DataKey, error) {
	return hostsecrets.UnwrapDataKey(ctx, ociRegion(e.Binding.Region), e.CryptoEndpoint, e.KEKID, e.KEKVersionID, e.Ciphertext, e.Binding.AssociatedData())
}

// MergeEntries admits delivered wrapped records without replacing any existing
// binding. A revoked record can never be revived by a delayed delivery retry.
func MergeEntries(path string, entries []Entry) error {
	if len(entries) == 0 || (Catalog{Version: 1, Entries: entries}).validate() != nil {
		return ErrUnavailable
	}
	unlock, err := catalogLock(path)
	if err != nil {
		return ErrUnavailable
	}
	defer unlock()
	catalog, err := ReadCatalog(path)
	if err != nil {
		return ErrUnavailable
	}
	changed := false
	for _, incoming := range entries {
		if catalog.destroyed(incoming.Binding.Scope()) {
			return ErrUnavailable
		}
		found := false
		for _, existing := range catalog.Entries {
			if existing.Binding == incoming.Binding {
				found = true
				if existing.Revoked || !sameEntry(existing, incoming) {
					return ErrUnavailable
				}
				break
			}
		}
		if !found {
			catalog.Entries = append(catalog.Entries, incoming)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return writeCatalog(path, catalog)
}
func sameEntry(a, b Entry) bool {
	at, bt := a.NotAfter, b.NotAfter
	ab, bb := a.BYOK, b.BYOK
	a.NotAfter = time.Time{}
	b.NotAfter = time.Time{}
	a.BYOK = nil
	b.BYOK = nil
	// BYOK metadata is compared by value: entries are JSON-decoded
	// independently from the catalog file and from NATS deliveries, so the
	// pointer identity of the metadata would defeat idempotent retries.
	return a == b && at.Equal(bt) && sameBYOKMetadata(ab, bb)
}

// InitializeCatalog creates an empty durable catalog only when none exists.
// Valid existing state is retained, and corrupt/unsafe state is never replaced.
func InitializeCatalog(path string) error {
	unlock, err := catalogLock(path)
	if err != nil {
		return ErrUnavailable
	}
	defer unlock()
	if _, err := ReadCatalog(path); err == nil {
		return nil
	}
	root, name, err := privateRoot(path)
	if err != nil {
		return ErrUnavailable
	}
	defer root.Close()
	if _, err := root.Lstat(name); !os.IsNotExist(err) {
		return ErrUnavailable
	}
	return writeCatalog(path, Catalog{Version: 1})
}
