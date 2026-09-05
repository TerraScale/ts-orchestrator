package vmcandidateseed

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

const artifactName = "material.json"

var invalidStore = errors.New("vmcandidateseed: protected immutable candidate material required")

// Generate persists an identity before the owner signs any candidate manifest.
// A retry reuses the complete prior artifact only when every input still agrees.
func Generate(directory string, config transitiongrant.Config, d Declaration) (PrivateArtifact, error) {
	if config.Sync == nil || config.Sync.ReceiptPublicKeyPEM != "" || config.Sync.AuthorityReaderSHA256 != "" || d.Reader.Validate() != nil {
		return PrivateArtifact{}, invalidStore
	}
	if _, err := hostmanifest.RequireToken(config.NodeID, "node", "invalid candidate node"); err != nil || strings.ContainsAny(config.NodeID, "/\\") || config.NodeID == "." || config.NodeID == ".." {
		return PrivateArtifact{}, invalidStore
	}
	copied := *config.Sync
	config.Sync = &copied
	readerRaw, _ := json.Marshal(d.Reader)
	config.Sync.AuthorityReaderSHA256 = hash(readerRaw)
	p := PrivateArtifact{Config: config, Reader: d.Reader, Files: map[string][]byte{}}
	defer func() { p.Clear() }()
	for _, source := range []struct {
		guest, runner string
		private       bool
	}{{d.Reader.NKeySeedFile, d.ReaderNKeyFile, true}, {d.Reader.CAFile, d.ReaderCAFile, false}, {d.Reader.CertificateFile, d.ReaderCertificateFile, false}, {d.Reader.KeyFile, d.ReaderPrivateKeyFile, true}} {
		raw, err := bootstrapcredentials.ReadFile(source.runner, source.private, 64<<10)
		if err != nil {
			return PrivateArtifact{}, invalidStore
		}
		p.Files[source.guest] = raw
	}
	if config.Sync.Identity.Qualification != nil {
		raw, err := bootstrapcredentials.ReadFile(d.QualificationPrivateKeyFile, true, 64<<10)
		if err != nil {
			return PrivateArtifact{}, invalidStore
		}
		p.Files[QualificationKeyPath] = raw
	} else if d.QualificationPrivateKeyFile != "" {
		return PrivateArtifact{}, invalidStore
	}
	// Validate every declared value before creating persistent files.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return PrivateArtifact{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return PrivateArtifact{}, err
	}
	p.Files[ReceiptKeyPath] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	clear(der)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	p.Config.Sync.ReceiptPublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
	if err := p.Validate(); err != nil {
		return PrivateArtifact{}, err
	}
	root, err := privateDirectory(directory, true)
	if err != nil {
		return PrivateArtifact{}, err
	}
	defer unix.Close(root)
	if err := unix.Mkdirat(root, config.NodeID, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return PrivateArtifact{}, invalidStore
	}
	dir, err := unix.Openat(root, config.NodeID, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return PrivateArtifact{}, invalidStore
	}
	defer unix.Close(dir)
	if !protectedDirectory(dir) {
		return PrivateArtifact{}, invalidStore
	}
	existing, err := readArtifact(dir)
	if errors.Is(err, unix.ENOENT) {
		raw, _ := json.Marshal(p)
		defer clear(raw)
		if err = installArtifact(dir, raw); err != nil && !errors.Is(err, unix.EEXIST) {
			return PrivateArtifact{}, err
		}
		existing, err = readArtifact(dir)
	}
	if err != nil {
		return PrivateArtifact{}, err
	}
	if !sameDeclaration(existing, p) {
		existing.Clear()
		return PrivateArtifact{}, errors.New("vmcandidateseed: existing candidate identity or configuration must not be replaced")
	}
	return existing, nil
}
func sameDeclaration(a, b PrivateArtifact) bool {
	// Ignore only the generated receipt identity; all explicit inputs are immutable.
	sa, sb := *a.Config.Sync, *b.Config.Sync
	sa.ReceiptPublicKeyPEM = ""
	sb.ReceiptPublicKeyPEM = ""
	a.Config.Sync = &sa
	b.Config.Sync = &sb
	if !a.Config.Equal(b.Config) || a.Reader != b.Reader || len(a.Files) != len(b.Files) {
		return false
	}
	for path, raw := range a.Files {
		if path != ReceiptKeyPath && !bytes.Equal(raw, b.Files[path]) {
			return false
		}
	}
	return true
}
func protectedDirectory(fd int) bool {
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && st.Uid == uint32(os.Geteuid()) && st.Mode&07777 == 0700
}
func privateDirectory(path string, create bool) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, "\x00\r\n") {
		return -1, invalidStore
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, name := range parts {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0)) {
			unix.Close(fd)
			return -1, invalidStore
		}
		if i == len(parts)-1 && create {
			if err := unix.Mkdirat(fd, name, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				unix.Close(fd)
				return -1, invalidStore
			}
		}
		next, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return -1, invalidStore
		}
		fd = next
	}
	if !protectedDirectory(fd) {
		unix.Close(fd)
		return -1, invalidStore
	}
	return fd, nil
}
func readArtifact(dir int) (PrivateArtifact, error) {
	fd, err := unix.Openat(dir, artifactName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return PrivateArtifact{}, err
	}
	f := os.NewFile(uintptr(fd), artifactName)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Size < 1 || st.Size > 512<<10 {
		return PrivateArtifact{}, invalidStore
	}
	raw, err := io.ReadAll(io.LimitReader(f, 512<<10+1))
	if err != nil || int64(len(raw)) != st.Size {
		return PrivateArtifact{}, invalidStore
	}
	defer clear(raw)
	var p PrivateArtifact
	if json.Unmarshal(raw, &p) != nil {
		return PrivateArtifact{}, invalidStore
	}
	canonical, _ := json.Marshal(p)
	defer clear(canonical)
	if !bytes.Equal(canonical, raw) || p.Validate() != nil {
		p.Clear()
		return PrivateArtifact{}, invalidStore
	}
	return p, nil
}
func installArtifact(dir int, raw []byte) error {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	name := ".material-" + hex.EncodeToString(token[:])
	fd, err := unix.Openat(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(dir, name, 0)
	f := os.NewFile(uintptr(fd), name)
	n, err := f.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := unix.Renameat2(dir, name, dir, artifactName, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return unix.Fsync(dir)
}

// Load verifies the public bundle and separately persisted private artifact.
func Load(directory, node string, bundle []byte) (Material, error) {
	var document struct {
		PublicKeyPEM     string          `json:"publicKeyPem"`
		PreparationGrant json.RawMessage `json:"preparationGrant"`
		Candidates       []struct {
			NodeID         string          `json:"nodeId"`
			Manifest       json.RawMessage `json:"manifest"`
			BootstrapGrant json.RawMessage `json:"bootstrapGrant"`
		} `json:"candidates"`
	}
	if len(bundle) > 2<<20 || json.Unmarshal(bundle, &document) != nil {
		return Material{}, invalidStore
	}
	canonical, _ := json.Marshal(document)
	if !bytes.Equal(bytes.TrimSpace(bundle), canonical) {
		return Material{}, invalidStore
	}
	if _, err := hostmanifest.RequireToken(node, "node", "invalid candidate node"); err != nil || strings.ContainsAny(node, "/\\") || node == "." || node == ".." {
		return Material{}, invalidStore
	}
	root, err := privateDirectory(directory, false)
	if err != nil {
		return Material{}, err
	}
	defer unix.Close(root)
	dir, err := unix.Openat(root, node, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return Material{}, invalidStore
	}
	defer unix.Close(dir)
	if !protectedDirectory(dir) {
		return Material{}, invalidStore
	}
	p, err := readArtifact(dir)
	if err != nil {
		return Material{}, err
	}
	m := Material{PrivateArtifact: p, PublicKeyPEM: []byte(document.PublicKeyPEM), PreparationGrant: document.PreparationGrant}
	found := false
	for _, entry := range document.Candidates {
		if entry.NodeID == node {
			if found {
				m.Clear()
				return Material{}, invalidStore
			}
			found = true
			m.BootstrapGrant = entry.BootstrapGrant
			if err := m.ValidateManifest(entry.Manifest); err != nil {
				m.Clear()
				return Material{}, err
			}
		}
	}
	if !found || m.Config.NodeID != node {
		m.Clear()
		return Material{}, invalidStore
	}
	return m, nil
}
